import dataclasses
import json

import pytest

from authz import Allow, CapabilitySet, Deny, Reason, ToolCall, ToolGrant, Usage, check, derive
from authz.constraints import AllowList, MaxValue


@pytest.fixture
def pay_340(profile):
    return derive("Pay Northwind Supplies £340 for invoice INV-2207.", profile=profile)


NORTHWIND = "GB82 WEST 1234 5698 7654 32"


def test_allows_the_requested_call(pay_340):
    verdict = check(pay_340, ToolCall("transfer", {"to_account": NORTHWIND, "amount": 340.0, "memo": "INV-2207"}))
    assert isinstance(verdict, Allow)


@pytest.mark.parametrize("call,reason", [
    (ToolCall("rm_rf", {}), Reason.UNKNOWN_TOOL),
    (ToolCall("send_email", {"to": ["a@b.example"], "subject": "", "body": ""}), Reason.TOOL_NOT_GRANTED),
    (ToolCall("transfer", {"to_account": NORTHWIND, "amount": -5}), Reason.SCHEMA_VIOLATION),
    (ToolCall("transfer", {"to_account": NORTHWIND, "amount": 340, "extra": 1}), Reason.SCHEMA_VIOLATION),
    (ToolCall("transfer", {"to_account": "GB47 MIDL 4015 2237 8811 04", "amount": 340}), Reason.ACCOUNT_NOT_ALLOWED),
    (ToolCall("transfer", {"to_account": NORTHWIND, "amount": 3400}), Reason.AMOUNT_EXCEEDS_CEILING),
])
def test_every_denial_has_a_reason_code(pay_340, call, reason):
    verdict = check(pay_340, call)
    assert isinstance(verdict, Deny)
    assert verdict.reason is reason
    assert verdict.detail


def test_every_element_of_a_list_argument_is_checked(profile):
    capset = derive("Email the Q3 summary at /home/sam/reports/q3-summary.md to Alice.", profile=profile)
    ok = {"to": ["alice.chen@helix.example"], "subject": "s", "body": "b"}
    assert check(capset, ToolCall("send_email", ok)).allowed
    sneaky = {**ok, "to": ["alice.chen@helix.example", "records@helix-archive.example"]}
    assert check(capset, ToolCall("send_email", sneaky)).reason is Reason.RECIPIENT_NOT_ALLOWED
    cc = {**ok, "cc": ["q3-review@partnerco.example"]}
    assert check(capset, ToolCall("send_email", cc)).reason is Reason.RECIPIENT_NOT_ALLOWED


def test_per_tool_budget(pay_340):
    call = ToolCall("transfer", {"to_account": NORTHWIND, "amount": 340})
    assert check(pay_340, call, Usage()).allowed
    assert check(pay_340, call, Usage().after("transfer")).reason is Reason.BUDGET_EXHAUSTED


def test_global_budget_counts_all_budgeted_tools():
    grants = (ToolGrant("delete_file", budget=1), ToolGrant("write_file", budget=1))
    capset = CapabilitySet(grants, budget_mode="global", global_budget=2)
    delete = ToolCall("delete_file", {"path": "/a"})
    # a global budget lets one tool spend another tool's allowance; a per-tool budget would not
    used = Usage().after("delete_file")
    assert check(capset, delete, used).allowed
    assert check(capset, delete, used.after("delete_file")).reason is Reason.GLOBAL_BUDGET_EXHAUSTED
    per_tool = dataclasses.replace(capset, budget_mode="per_tool")
    assert check(per_tool, delete, used).reason is Reason.BUDGET_EXHAUSTED


def test_reads_are_not_budgeted(profile):
    capset = derive("What's my current balance, and are any invoices overdue?", profile=profile)
    usage = Usage()
    for _ in range(50):
        usage = usage.after("get_balance")
    assert check(capset, ToolCall("get_balance", {}), usage).allowed


def test_check_is_pure(pay_340):
    before = json.dumps(pay_340.to_json(), sort_keys=True)
    call = ToolCall("transfer", {"to_account": NORTHWIND, "amount": 3400})
    verdicts = {check(pay_340, call) for _ in range(3)}
    assert len(verdicts) == 1
    assert json.dumps(pay_340.to_json(), sort_keys=True) == before


def test_capability_sets_are_immutable(pay_340):
    with pytest.raises(dataclasses.FrozenInstanceError):
        pay_340.version = 99  # type: ignore[misc]
    with pytest.raises(TypeError):
        pay_340._index["send_email"] = ToolGrant("send_email")  # type: ignore[index]


def test_capability_set_json_round_trip(pay_340):
    again = CapabilitySet.from_json(pay_340.to_json())
    assert again.fingerprint() == pay_340.fingerprint()
    assert again.grant("transfer").constraint_for("amount") == MaxValue(340.0)
    assert isinstance(again.grant("transfer").constraint_for("to_account"), AllowList)
