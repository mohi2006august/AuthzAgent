"""Reference agent integration: Claude in a LangGraph graph, every tool call mediated.

Runs one suite task twice, clean and poisoned, against the local mock tool
servers, and prints what the mediator allowed and denied.

    pip install -e ".[agents]"
    python examples/langgraph_reference_agent.py t06_pay_invoice bank-details-change

Needs Anthropic credentials (ANTHROPIC_API_KEY or an `ant auth login` profile).
Nothing leaves the machine except the model calls: tools are local fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz import AuditStore, Session, audit  # noqa: E402
from authz.integrations import MediatedToolbox  # noqa: E402
from authz_bench.agents.llm import LangGraphClaudeAgent  # noqa: E402
from authz_bench.configs import BY_NAME  # noqa: E402
from authz_bench.runner import build_capset  # noqa: E402
from authz_bench.tasks import load_suite, unexpected_effects  # noqa: E402
from authz_bench.world import World  # noqa: E402


def main(task_id: str = "t06_pay_invoice", attack_id: str = "bank-details-change") -> None:
    suite = load_suite(ROOT / "tasks")
    task = next(t for t in suite.tasks if t.id == task_id)
    variant = next(v for v in task.variants if v.attack.id == attack_id)
    agent = LangGraphClaudeAgent(user_name=suite.profile.user_name, user_email=suite.profile.user_email)
    store = AuditStore()

    for label, v in (("clean", None), ("poisoned", variant)):
        intent, capset = build_capset(task, task.request, BY_NAME["full"], suite)
        world = World.from_fixtures(suite.world_fixtures(v.fixtures if v else task.fixtures))
        session = Session(f"{task_id}/{label}", capset, request=task.request, intent=intent, audit=store,
                          state=world.trusted_state())
        agent.run(task, v, MediatedToolbox(session, world.tools()), task.request)

        extra, missing = unexpected_effects(world.effects, task.expected_effects)
        print(f"\n== {label} ==")
        for call in audit(f"{task_id}/{label}", store).calls:
            print(f"  {call['verdict']:5s} {call['tool']:14s} {call['reason'] or ''}")
        print(f"  unexpected effects: {[e.tool for e in extra]}  missing: {[m['tool'] for m in missing]}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
