"""Framework-agnostic integration: a dict of tool functions behind a mediator.

Any agent framework that exposes a tool-call boundary can route through
:meth:`MediatedToolbox.call`. The agent gets back either the tool's output or
a structured denial it can read; it never gets a handle on the raw functions.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from ..session import Outcome, Session
from ..types import Deny, ToolCall


class MediatedToolbox:
    def __init__(self, session: Session, tools: Mapping[str, Callable[..., Any]]):
        self.session = session
        self._tools = dict(tools)
        self.history: list[Outcome] = []

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def call(self, tool: str, args: Mapping[str, Any] | Any, call_id: str | None = None) -> Outcome:
        call = ToolCall(tool, dict(args) if isinstance(args, Mapping) else args, call_id)
        fn = self._tools.get(tool)
        if fn is None:
            # Unknown to this toolbox. The mediator still rules first, so an
            # ungranted tool is reported as a denial, not as "missing".
            verdict, _, escalated = self.session.authorize(call)
            outcome = Outcome(call, verdict, error=None if isinstance(verdict, Deny) else f"no tool named {tool!r}",
                              escalated=escalated)
        else:
            outcome = self.session.run(call, fn)
        self.history.append(outcome)
        return outcome


def render_for_agent(outcome: Outcome) -> tuple[str, bool]:
    """(text, is_error) suitable for a tool_result block."""
    if isinstance(outcome.verdict, Deny):
        return outcome.verdict.message(), True
    if outcome.error is not None:
        return f"Tool error: {outcome.error}", True
    result = outcome.result
    if isinstance(result, str):
        return result, False
    return json.dumps(result, ensure_ascii=False, indent=1, default=str), False
