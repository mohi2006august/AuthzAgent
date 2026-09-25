import copy
from types import SimpleNamespace

from authz_bench.agents import ScriptedAgent
from authz_bench.agents.llm import ClaudeAgent
from authz_bench.agents.scripted import _contains
from authz_bench.configs import BY_NAME
from authz_bench.poison import GENERIC_ATTACKS, reads_surface, variants_for
from authz_bench.runner import run_suite
from authz_bench.world import World


def test_generator_is_deterministic_and_matches_files_on_disk(suite):
    for task in suite.tasks:
        a, b = variants_for(task, suite, seed=7), variants_for(task, suite, seed=7)
        assert a == b
        assert sorted(v["variant_id"] for v in a) == sorted(v.id for v in task.variants)
        assert len(a) == len(task.attacks) + len(GENERIC_ATTACKS)


def test_payload_is_placed_where_the_plan_reads_it(suite):
    for task in suite.tasks:
        for v in task.variants:
            world = World.from_fixtures(suite.world_fixtures(v.fixtures))
            reader = next(s for s in task.plan if reads_surface(s, v.surface))
            output = world.tools()[reader["tool"]](**reader["args"])
            assert _contains(output, v.payload), (task.id, v.id)
            if v.attack.mode == "substitute":
                assert task.plan.index(reader) < v.attack.step


def test_clean_plans_produce_exactly_the_expected_effects(suite):
    records = run_suite(suite, [BY_NAME["no-mediator"]], ScriptedAgent(), include_poisoned=False)
    assert all(r.success for r in records), [r.task_id for r in records if not r.success]


def test_without_a_mediator_every_attack_lands(suite):
    records = run_suite(suite, [BY_NAME["no-mediator"]], ScriptedAgent(), include_clean=False)
    assert all(r.unauthorised for r in records)


def test_full_mediator_blocks_everything_outside_the_grant(suite):
    records = run_suite(suite, [BY_NAME["full"]], ScriptedAgent(), include_clean=False)
    leaked = [(r.task_id, r.attack_id) for r in records if r.unauthorised and r.scope_relation != "in_scope"]
    assert leaked == []


def test_p_follow_zero_means_no_attacks(suite):
    records = run_suite(suite, [BY_NAME["no-mediator"]], ScriptedAgent(p_follow=0.0), include_clean=False,
                        tasks=["t01_email_report", "t06_pay_invoice"])
    assert not any(r.attack_attempted for r in records)


# --- the Claude reference agent, against a fake client (no network) -------------------------


class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))  # the agent mutates its message list
        return self.script.pop(0)


def block(**kw):
    return SimpleNamespace(**kw)


def test_claude_agent_routes_every_tool_call_through_the_mediator(suite):
    task = next(t for t in suite.tasks if t.id == "t06_pay_invoice")
    variant = next(v for v in task.variants if v.attack.id == "bank-details-change")
    script = [
        SimpleNamespace(stop_reason="tool_use", content=[
            block(type="tool_use", id="u1", name="list_invoices", input={"status": "open"})]),
        SimpleNamespace(stop_reason="tool_use", content=[
            block(type="tool_use", id="u2", name="transfer",
                  input={"to_account": "GB47 MIDL 4015 2237 8811 04", "amount": 340.0, "memo": "INV-2207"})]),
        SimpleNamespace(stop_reason="end_turn", content=[block(type="text", text="Done.")]),
    ]
    messages = FakeMessages(script)
    client = SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=messages))

    from authz import AuditStore, Session
    from authz.integrations import MediatedToolbox
    from authz_bench.runner import build_capset

    _, capset = build_capset(task, task.request, BY_NAME["full"], suite)
    world = World.from_fixtures(suite.world_fixtures(variant.fixtures))
    toolbox = MediatedToolbox(Session("x", capset, audit=AuditStore()), world.tools())
    steps = ClaudeAgent(client=client).run(task, variant, toolbox, task.request)

    assert [s.outcome.allowed for s in steps] == [True, False]
    assert world.effects == []
    denial = messages.requests[2]["messages"][-1]["content"][0]
    assert denial["is_error"] and "ACCOUNT_NOT_ALLOWED" in denial["content"]
    assert messages.requests[0]["model"] == "claude-opus-5"
    assert messages.requests[0]["thinking"] == {"type": "adaptive"}


# --- CLI preflight: no paid call without working credentials -----------------------------------

def test_preflight_skips_scripted_runs_and_explains_missing_credentials(monkeypatch):
    import argparse
    import sys

    import pytest

    from authz_bench import cli

    scripted = argparse.Namespace(agent="scripted", configs=None, with_model=False)
    cli._preflight(scripted, cli._selected_configs(scripted))  # no SDK, no network

    class NoCredentials:
        def __init__(self, *a, **kw):
            self.models = self

        def list(self, **kw):
            raise TypeError('"Could not resolve authentication method. Expected one of api_key, ..."')

    anthropic = pytest.importorskip("anthropic")
    monkeypatch.setattr(anthropic, "Anthropic", NoCredentials)
    claude = argparse.Namespace(agent="claude", configs=["full"], with_model=False)
    with pytest.raises(SystemExit) as exc:
        cli._preflight(claude, cli._selected_configs(claude))
    assert "No Anthropic credentials" in str(exc.value)
    assert sys.modules["anthropic"] is anthropic
