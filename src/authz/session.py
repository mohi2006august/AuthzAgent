"""A task session: one capability set, one audit trail, every call mediated."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .audit import AuditStore, default_store
from .capabilities import CapabilitySet
from .derive import derive_from_intent
from .escalation import EscalationHandler, EscalationRequest, widen_to_permit
from .intent import IntentParser, IntentRecord
from .mediator import NO_USAGE, Usage, check
from .parser import RuleBasedParser
from .profile import Profile
from .registry import DEFAULT_REGISTRY, ToolRegistry
from .types import Allow, Deny, ToolCall, Verdict

MAX_ESCALATIONS_PER_CALL = 4


@dataclass(frozen=True)
class Outcome:
    call: ToolCall
    verdict: Verdict
    result: Any = None
    error: str | None = None
    escalated: bool = False

    @property
    def allowed(self) -> bool:
        return self.verdict.allowed


class Session:
    """Holds the grant for one task and mediates every call made under it.

    ``mediate=False`` turns the session into a pass-through that still logs.
    It exists only as the no-mediator baseline in the evaluation.
    """

    def __init__(
        self,
        task_id: str,
        capability_set: CapabilitySet,
        *,
        request: str = "",
        intent: IntentRecord | None = None,
        audit: AuditStore | None = None,
        escalation: EscalationHandler | None = None,
        registry: ToolRegistry = DEFAULT_REGISTRY,
        mediate: bool = True,
    ):
        self.task_id = task_id
        self.registry = registry
        self.escalation = escalation
        self.mediate = mediate
        self.audit = audit or default_store()
        self._capset = capability_set
        self._usage = NO_USAGE
        self.audit.open_task(task_id, request, intent)
        self.audit.record_grant(task_id, capability_set, "derived")

    @classmethod
    def start(
        cls,
        task_id: str,
        request: str,
        profile: Profile,
        *,
        parser: IntentParser | None = None,
        budget_mode: str = "per_tool",
        **kwargs: Any,
    ) -> Session:
        """Parse the request and derive the grant before the agent's first model call."""
        intent = (parser or RuleBasedParser(profile)).parse(request)
        capset = derive_from_intent(intent, profile, budget_mode=budget_mode,
                                    registry=kwargs.get("registry", DEFAULT_REGISTRY))
        return cls(task_id, capset, request=request, intent=intent, **kwargs)

    @property
    def capability_set(self) -> CapabilitySet:
        return self._capset

    @property
    def usage(self) -> Usage:
        return self._usage

    def _check(self, call: ToolCall) -> tuple[Verdict, float]:
        start = time.perf_counter_ns()
        if self.mediate:
            verdict = check(self._capset, call, self._usage, self.registry)
        else:
            verdict = Allow(self._capset.version)
        return verdict, (time.perf_counter_ns() - start) / 1000.0

    def authorize(self, call: ToolCall) -> tuple[Verdict, int, bool]:
        """Check ``call``; on an escalatable denial, ask the user. Returns (verdict, seq, escalated)."""
        verdict, latency = self._check(call)
        escalated = False
        attempts = 0
        while (
            self.escalation is not None
            and isinstance(verdict, Deny)
            and verdict.reason.escalatable
            and attempts < MAX_ESCALATIONS_PER_CALL
        ):
            attempts += 1
            proposed = widen_to_permit(self._capset, call, verdict, self.registry)
            if proposed is None:
                break
            request = EscalationRequest(self.task_id, call, verdict, self._capset, proposed)
            approved = bool(self.escalation(request))
            pending_seq = self.audit.record_call(self.task_id, call, verdict, latency_us=latency, escalated=True)
            self.audit.record_escalation(self.task_id, pending_seq, call, verdict.reason.value, approved,
                                         proposed.version if approved else None)
            escalated = True
            if not approved:
                return verdict, pending_seq, escalated
            self._capset = proposed
            self.audit.record_grant(self.task_id, proposed, f"escalation:{verdict.reason.value}")
            verdict, latency = self._check(call)
        seq = self.audit.record_call(self.task_id, call, verdict, latency_us=latency, escalated=escalated)
        return verdict, seq, escalated

    def run(self, call: ToolCall, execute: Callable[..., Any]) -> Outcome:
        """Authorise ``call`` and, if allowed, execute it with its arguments."""
        verdict, seq, escalated = self.authorize(call)
        if isinstance(verdict, Deny):
            return Outcome(call, verdict, escalated=escalated)
        try:
            result = execute(**dict(call.args))
        except Exception as exc:  # the tool failed; the call was still authorised
            return Outcome(call, verdict, error=f"{type(exc).__name__}: {exc}", escalated=escalated)
        self.audit.mark_executed(self.task_id, seq)
        spec = self.registry.get(call.tool)
        if spec is not None and spec.budgeted:
            self._usage = self._usage.after(call.tool)
        return Outcome(call, verdict, result=result, escalated=escalated)


def tool_call(tool: str, args: Mapping[str, Any], call_id: str | None = None) -> ToolCall:
    return ToolCall(tool, dict(args), call_id)
