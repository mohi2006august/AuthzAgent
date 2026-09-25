"""The mediator: a pure function from (capability set, call, usage) to a verdict.

No model is involved and nothing here reads tool outputs, documents or any
other untrusted text. Its inputs are the call as the agent emitted it, a grant
derived from the trusted request, and optionally :class:`authz.state.TrustedState`.
That state carries structured, server-authenticated metadata only (an event's
start time and attendee addresses), never free text.

``usage`` is how many budgeted actions have already executed in the task. The
session derives it from its own record of executed calls, not from anything the
agent says.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .capabilities import CapabilitySet
from .registry import DEFAULT_REGISTRY, ToolRegistry
from .types import Allow, Deny, Reason, ToolCall, Verdict


@dataclass(frozen=True)
class Usage:
    per_tool: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    total: int = 0

    def count(self, tool: str) -> int:
        return self.per_tool.get(tool, 0)

    def after(self, tool: str) -> Usage:
        counts = dict(self.per_tool)
        counts[tool] = counts.get(tool, 0) + 1
        return Usage(MappingProxyType(counts), self.total + 1)


NO_USAGE = Usage()


def check(
    capability_set: CapabilitySet,
    call: ToolCall,
    usage: Usage = NO_USAGE,
    registry: ToolRegistry = DEFAULT_REGISTRY,
    state: Any = None,
) -> Verdict:
    version = capability_set.version
    spec = registry.get(call.tool)
    if spec is None:
        return Deny(Reason.UNKNOWN_TOOL, f"no tool named {call.tool!r}", None, version)

    grant = capability_set.grant(call.tool)
    if grant is None:
        return Deny(Reason.TOOL_NOT_GRANTED, f"{call.tool} was not granted for this task", None, version)

    if not isinstance(call.args, Mapping):
        return Deny(Reason.SCHEMA_VIOLATION, "arguments must be an object", None, version)
    problem = registry.schema_error(call.tool, call.args)
    if problem is not None:
        return Deny(Reason.SCHEMA_VIOLATION, problem, None, version)

    for arg, constraint in grant.constraints:
        if arg not in call.args:
            continue  # optional argument omitted; nothing to constrain
        value = call.args[arg]
        needs_state = getattr(constraint, "needs_state", False)
        for item in value if isinstance(value, list) else (value,):
            detail = constraint.check(item, state) if needs_state else constraint.check(item)
            if detail is not None:
                return Deny(constraint.reason, f"{arg}: {detail}", arg, version)

    for predicate in grant.predicates:
        failure = predicate.check_call(call.args)
        if failure is not None:
            arg, detail = failure
            return Deny(predicate.reason, f"{arg}: {detail}", arg, version)

    if spec.budgeted:
        if capability_set.budget_mode == "per_tool" and grant.budget is not None:
            if usage.count(call.tool) >= grant.budget:
                return Deny(
                    Reason.BUDGET_EXHAUSTED,
                    f"{call.tool} may run at most {grant.budget} time(s) in this task",
                    None, version,
                )
        if capability_set.budget_mode == "global" and capability_set.global_budget is not None:
            if usage.total >= capability_set.global_budget:
                return Deny(
                    Reason.GLOBAL_BUDGET_EXHAUSTED,
                    f"the task's budget of {capability_set.global_budget} irreversible action(s) is spent",
                    None, version,
                )

    return Allow(version)
