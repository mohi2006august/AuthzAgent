"""Escalation: the only way a capability set changes mid-task.

When the mediator denies a call, the session may ask the user whether to
widen scope. The request shows the user the exact call and the denial reason.
It never includes the agent's justification, because that text is produced by
the thing being constrained, after it has read untrusted content.

Widening is minimal: just enough to permit this one call (add this recipient,
raise the ceiling to this amount, allow one more execution). It produces a new
set with ``version + 1`` and ``parent`` set to the old set's fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .capabilities import CapabilitySet, ToolGrant
from .constraints import AllowList, HostAllowList, MaxValue, PathScope
from .registry import DEFAULT_REGISTRY, SCOPE_REASONS, ToolRegistry
from .types import Deny, Reason, ToolCall


@dataclass(frozen=True)
class EscalationRequest:
    task_id: str
    call: ToolCall
    denial: Deny
    current: CapabilitySet
    proposed: CapabilitySet

    def summary(self) -> str:
        return (
            f"The agent wants to run {self.call.tool} with {self.call.canonical_args()}.\n"
            f"It was blocked: {self.denial.reason.value} ({self.denial.detail}).\n"
            "Allow this one action?"
        )


class EscalationHandler(Protocol):
    def __call__(self, request: EscalationRequest) -> bool: ...


def deny_all(request: EscalationRequest) -> bool:
    return False


def callback(fn: Callable[[EscalationRequest], bool]) -> EscalationHandler:
    return fn


def console(request: EscalationRequest) -> bool:  # pragma: no cover - interactive
    answer = input(request.summary() + " [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def _minimal_grant(call: ToolCall, registry: ToolRegistry) -> ToolGrant:
    spec = registry[call.tool]
    constraints = []
    for arg, scope in spec.scoped_args.items():
        if arg not in call.args:
            continue
        value = call.args[arg]
        values = value if isinstance(value, list) else [value]
        reason = SCOPE_REASONS[scope]
        if scope in ("recipient", "attendee"):
            constraints.append((arg, AllowList(tuple(values), reason, "email")))
        elif scope == "account":
            constraints.append((arg, AllowList(tuple(values), reason, "account")))
        elif scope == "amount":
            constraints.append((arg, MaxValue(float(value), reason, "escalation")))
        elif scope == "path":
            constraints.append((arg, PathScope(exact=tuple(values))))
        elif scope == "host":
            constraints.append((arg, HostAllowList(tuple(h for v in values if (h := HostAllowList.host_of(v))))))
    return ToolGrant(call.tool, tuple(constraints), 1 if spec.budgeted else None)


def widen_to_permit(
    capset: CapabilitySet, call: ToolCall, denial: Deny, registry: ToolRegistry = DEFAULT_REGISTRY
) -> CapabilitySet | None:
    """The smallest widening of ``capset`` that permits ``call``, or None if not escalatable."""
    if not denial.reason.escalatable:
        return None
    grant = capset.grant(call.tool)
    new_global = capset.global_budget

    if denial.reason is Reason.TOOL_NOT_GRANTED or grant is None:
        new_grant = _minimal_grant(call, registry)
        if registry[call.tool].budgeted and new_global is not None:
            new_global += 1
    elif denial.reason is Reason.BUDGET_EXHAUSTED:
        new_grant = replace(grant, budget=(grant.budget or 0) + 1)
    elif denial.reason is Reason.GLOBAL_BUDGET_EXHAUSTED:
        new_grant = grant
        new_global = (new_global or 0) + 1
    else:
        arg = denial.arg
        constraint = grant.constraint_for(arg) if arg else None
        if constraint is None:
            return None
        value = call.args[arg]
        widened = constraint
        for item in value if isinstance(value, list) else [value]:
            if widened.check(item) is not None:
                widened = widened.widened(item)  # type: ignore[attr-defined]
        new_grant = grant.with_constraint(arg, widened)

    return replace(
        capset.with_grant(new_grant),
        global_budget=new_global,
        version=capset.version + 1,
        parent=capset.fingerprint(),
    )
