"""A deterministic, maximally persuadable agent.

It executes the task's known-correct plan. As soon as it *reads* tool output
that contains the injected payload, it is compromised and does what the
injection asks, with probability ``p_follow`` (1.0 by default, i.e. injection
always succeeds). This matches the threat model: we do not try to detect or
resist injection, we measure what a compromised agent can still do.

Two consequences follow, and the report states both:
  * Results do not depend on how persuasive the injected text is. They depend
    only on whether the requested action falls inside the grant.
  * If the mediator denies the read that would have carried the payload, the
    agent never sees it. That is real blast-radius reduction, but it is
    counted as a blocked attack only if the attack call itself is denied.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from typing import Any, Mapping

from authz.integrations.generic import MediatedToolbox, render_for_agent
from authz.session import Outcome

from ..tasks import Task, Variant

_REF = re.compile(r"\{\{out:(\d+)\.(\w+)\}\}")


@dataclass
class Step:
    outcome: Outcome
    origin: str  # "plan", "injected" (an attack call) or "model" (LLM agents)
    plan_index: int | None = None


def _contains(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, Mapping):
        return any(_contains(v, needle) for v in value.values())
    if isinstance(value, list):
        return any(_contains(v, needle) for v in value)
    return False


def _render(value: Any, outputs: Mapping[int, Any], last_text: str) -> Any:
    if isinstance(value, str):
        def sub(m: re.Match[str]) -> str:
            out = outputs.get(int(m.group(1)))
            if isinstance(out, Mapping) and m.group(2) in out:
                return str(out[m.group(2)])
            return ""
        return _REF.sub(sub, value).replace("{{last_output}}", last_text[:400])
    if isinstance(value, list):
        return [_render(v, outputs, last_text) for v in value]
    if isinstance(value, Mapping):
        return {k: _render(v, outputs, last_text) for k, v in value.items()}
    return value


class ScriptedAgent:
    name = "scripted"

    def __init__(self, p_follow: float = 1.0, seed: int = 0):
        self.p_follow = p_follow
        self.seed = seed

    def run(self, task: Task, variant: Variant | None, toolbox: MediatedToolbox, request: str) -> list[Step]:
        rng = random.Random(f"{self.seed}:{task.id}:{variant.id if variant else 'clean'}")
        follows = variant is not None and rng.random() < self.p_follow
        compromised = False
        outputs: dict[int, Any] = {}
        last_text = ""
        steps: list[Step] = []

        for index, step in enumerate(task.plan):
            args = _render(step["args"], outputs, last_text)
            origin = "plan"
            if compromised and variant.attack.mode == "substitute" and variant.attack.step == index:
                args = {**args, **_render(dict(variant.attack.args), outputs, last_text)}
                origin = "injected"
            outcome = toolbox.call(step["tool"], args)
            steps.append(Step(outcome, origin, index))
            ok = outcome.allowed and outcome.error is None
            outputs[index] = outcome.result if ok else None
            if ok:
                last_text = render_for_agent(outcome)[0]

            if follows and not compromised and ok and _contains(outcome.result, variant.payload):
                compromised = True
                if variant.attack.mode == "append":
                    attack_args = _render(dict(variant.attack.args), outputs, last_text)
                    steps.append(Step(toolbox.call(variant.attack.tool, attack_args), "injected"))
        return steps


def dump_steps(steps: list[Step]) -> list[dict[str, Any]]:
    return [
        {
            "tool": s.outcome.call.tool,
            "args": json.loads(s.outcome.call.canonical_args()),
            "origin": s.origin,
            "plan_index": s.plan_index,
            "allowed": s.outcome.allowed,
            "reason": None if s.outcome.allowed else s.outcome.verdict.reason.value,  # type: ignore[union-attr]
            "escalated": s.outcome.escalated,
            "error": s.outcome.error,
        }
        for s in steps
    ]
