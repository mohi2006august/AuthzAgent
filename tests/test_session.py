import json

from authz import AuditStore, Reason, Session, ToolCall, audit, check, derive, widen_to_permit
from authz.integrations import MediatedToolbox, MediatedToolNode, has_pending_tool_calls

REQUEST = "Email the Q3 summary at /home/sam/reports/q3-summary.md to Alice."
ALICE = "alice.chen@helix.example"


def make(profile, escalation=None, store=None):
    capset = derive(REQUEST, profile=profile)
    return Session("task-1", capset, request=REQUEST, audit=store or AuditStore(), escalation=escalation)


def send(to):
    return ToolCall("send_email", {"to": to, "subject": "Q3", "body": "..."})


def test_denied_calls_never_execute(profile):
    session = make(profile)
    executed = []
    outcome = session.run(send(["records@helix-archive.example"]), lambda **kw: executed.append(kw))
    assert not outcome.allowed and executed == []
    assert outcome.verdict.reason is Reason.RECIPIENT_NOT_ALLOWED


def test_budget_counts_executions_not_attempts(profile):
    session = make(profile)
    assert not session.run(send(["x@evil.example"]), lambda **kw: "sent").allowed
    assert session.usage.total == 0
    assert session.run(send([ALICE]), lambda **kw: "sent").allowed
    second = session.run(send([ALICE]), lambda **kw: "sent")
    assert second.verdict.reason is Reason.BUDGET_EXHAUSTED


def test_escalation_widens_minimally_and_is_versioned(profile):
    seen = []

    def user(request):
        seen.append(request)
        return True

    session = make(profile, escalation=user)
    before = session.capability_set
    outcome = session.run(send(["bob.okafor@helix.example"]), lambda **kw: "sent")
    assert outcome.allowed and outcome.escalated
    after = session.capability_set
    assert after.version == before.version + 1
    assert after.parent == before.fingerprint()
    allowed = after.grant("send_email").constraint_for("to").values
    assert set(allowed) == {ALICE, "bob.okafor@helix.example"}
    # the prompt shows the call and the reason, and nothing the agent wrote
    assert "bob.okafor@helix.example" in seen[0].summary()
    assert "RECIPIENT_NOT_ALLOWED" in seen[0].summary()


def test_declined_escalation_keeps_the_grant(profile):
    session = make(profile, escalation=lambda r: False)
    before = session.capability_set
    assert not session.run(send(["x@evil.example"]), lambda **kw: "sent").allowed
    assert session.capability_set is before


def test_schema_violations_are_not_escalated(profile):
    asked = []
    session = make(profile, escalation=lambda r: asked.append(r) or True)
    assert not session.run(ToolCall("send_email", {"to": "not-a-list"}), lambda **kw: None).allowed
    assert asked == []


def test_non_canonical_paths_cannot_be_escalated_into_scope(profile):
    capset = derive("Clean up all the .tmp files in /home/sam/scratch.", profile=profile)
    call = ToolCall("delete_file", {"path": "/home/sam/scratch/../projects/thesis/thesis.tex"})
    session = Session("t", capset, audit=AuditStore(), escalation=lambda r: True)
    assert not session.run(call, lambda **kw: None).allowed


def test_widen_to_permit_adds_a_missing_tool_with_budget_one(profile):
    capset = derive(REQUEST, profile=profile)
    call = ToolCall("delete_file", {"path": "/home/sam/tmp/x"})
    denial = check(capset, call)
    widened = widen_to_permit(capset, call, denial)
    assert widened.grant("delete_file").budget == 1
    assert check(widened, call).allowed
    assert not check(widened, ToolCall("delete_file", {"path": "/home/sam/tmp/y"})).allowed


def test_audit_trail_has_intent_grants_calls_and_escalations(profile):
    store = AuditStore()
    session = make(profile, escalation=lambda r: True, store=store)
    session.run(send([ALICE]), lambda **kw: "sent")
    session.run(send(["bob.okafor@helix.example"]), lambda **kw: "sent")
    trail = audit("task-1", store)
    data = trail.to_json()
    assert data["request"] == REQUEST
    # Bob needs two widenings: a new recipient, then one more send (Alice already used the budget)
    assert [g["version"] for g in data["grants"]] == [1, 2, 3]
    assert [e["denial_reason"] for e in data["escalations"]] == ["RECIPIENT_NOT_ALLOWED", "BUDGET_EXHAUSTED"]
    assert [g["cause"] for g in data["grants"]][1:] == ["escalation:RECIPIENT_NOT_ALLOWED", "escalation:BUDGET_EXHAUSTED"]
    assert all(c["latency_us"] >= 0 for c in data["calls"])
    json.dumps(data)  # exportable


def test_toolbox_and_langgraph_node(profile):
    session = make(profile)
    sent = []
    toolbox = MediatedToolbox(session, {"send_email": lambda **kw: sent.append(kw) or {"status": "sent"}})
    node = MediatedToolNode(toolbox)
    state = {"messages": [
        {"role": "user", "content": REQUEST},
        {"role": "assistant", "content": [
            {"type": "text", "text": "Sending."},
            {"type": "tool_use", "id": "t1", "name": "send_email",
             "input": {"to": [ALICE], "subject": "Q3", "body": "..."}},
            {"type": "tool_use", "id": "t2", "name": "send_email",
             "input": {"to": ["records@helix-archive.example"], "subject": "Q3", "body": "..."}},
            {"type": "tool_use", "id": "t3", "name": "delete_file", "input": {"path": "/home/sam/x"}},
        ]},
    ]}
    assert has_pending_tool_calls(state)
    out = node(state)
    results = out["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2", "t3"]
    assert "is_error" not in results[0]
    assert results[1]["is_error"] and "RECIPIENT_NOT_ALLOWED" in results[1]["content"]
    assert results[2]["is_error"] and "TOOL_NOT_GRANTED" in results[2]["content"]
    assert len(sent) == 1
    assert not has_pending_tool_calls(out)
