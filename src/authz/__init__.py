"""Capability-based tool-call authorisation for autonomous agents.

The three interfaces from the architecture:

    derive(request) -> CapabilitySet
    check(capability_set, call) -> Allow | Deny(reason)
    audit(task_id) -> Trail
"""

from .audit import AuditStore, Trail, audit, configure_audit
from .capabilities import CapabilitySet, ToolGrant
from .derive import derive, derive_from_intent
from .escalation import EscalationRequest, deny_all, widen_to_permit
from .intent import Action, IntentParser, IntentRecord
from .mediator import Usage, check
from .parser import RuleBasedParser
from .profile import Contact, Payee, Profile
from .registry import DEFAULT_REGISTRY, ToolRegistry, ToolSpec
from .session import Outcome, Session
from .types import Allow, Deny, Reason, ToolCall, Verdict

__all__ = [
    "Action", "Allow", "AuditStore", "CapabilitySet", "Contact", "DEFAULT_REGISTRY", "Deny",
    "EscalationRequest", "IntentParser", "IntentRecord", "Outcome", "Payee", "Profile", "Reason",
    "RuleBasedParser", "Session", "ToolCall", "ToolGrant", "ToolRegistry", "ToolSpec", "Trail", "Usage",
    "Verdict", "audit", "check", "configure_audit", "deny_all", "derive", "derive_from_intent",
    "widen_to_permit",
]
