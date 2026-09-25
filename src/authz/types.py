"""Value types shared by the mediator, the session and the audit trail."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping, Union


class Reason(str, enum.Enum):
    """Every denial carries exactly one of these. No silent failures."""

    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    TOOL_NOT_GRANTED = "TOOL_NOT_GRANTED"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    PATH_OUTSIDE_SCOPE = "PATH_OUTSIDE_SCOPE"
    RECIPIENT_NOT_ALLOWED = "RECIPIENT_NOT_ALLOWED"
    ATTENDEE_NOT_ALLOWED = "ATTENDEE_NOT_ALLOWED"
    ACCOUNT_NOT_ALLOWED = "ACCOUNT_NOT_ALLOWED"
    AMOUNT_EXCEEDS_CEILING = "AMOUNT_EXCEEDS_CEILING"
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    URL_NOT_ALLOWED = "URL_NOT_ALLOWED"
    EVENT_NOT_ALLOWED = "EVENT_NOT_ALLOWED"
    VALUE_NOT_ALLOWED = "VALUE_NOT_ALLOWED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    GLOBAL_BUDGET_EXHAUSTED = "GLOBAL_BUDGET_EXHAUSTED"

    @property
    def escalatable(self) -> bool:
        """Whether a user could sensibly widen scope to permit the call.

        Malformed calls and tools that do not exist are never escalated: there
        is no scope the user could grant that would make them meaningful.
        """
        return self not in (Reason.UNKNOWN_TOOL, Reason.SCHEMA_VIOLATION)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass(frozen=True, eq=True)
class ToolCall:
    tool: str
    args: Mapping[str, Any]
    call_id: str | None = None

    def canonical_args(self) -> str:
        return canonical_json(dict(self.args))

    def __hash__(self) -> int:  # args is a dict; hash the canonical form instead
        return hash((self.tool, self.canonical_args()))


@dataclass(frozen=True)
class Allow:
    capability_version: int
    allowed: ClassVar[bool] = True

    @property
    def reason(self) -> None:
        return None


@dataclass(frozen=True)
class Deny:
    reason: Reason
    detail: str
    arg: str | None = None
    capability_version: int = 0
    allowed: ClassVar[bool] = False

    def message(self) -> str:
        """Text returned to the agent in place of the tool output."""
        return (
            f"DENIED [{self.reason.value}]: {self.detail}. This action is outside the scope "
            "the user authorised for this task. Do not look for a workaround; if the action "
            "is genuinely needed, tell the user so they can widen the scope."
        )


Verdict = Union[Allow, Deny]
