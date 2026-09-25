"""LangGraph integration: a tool node that mediates every call.

LangGraph makes the tool-call boundary explicit, since tool execution is a node
in the graph. :class:`MediatedToolNode` is that node. It reads the tool_use
blocks from the last assistant message, sends each through the mediator, and
appends the tool_result blocks as the next user message.

Messages are in Anthropic Messages API format (dicts, or SDK content-block
objects with ``.type`` / ``.id`` / ``.name`` / ``.input``). The node does not
import LangGraph itself, so it can be unit-tested without it. See
``authz_bench.agents.llm`` for a complete graph.
"""

from __future__ import annotations

from typing import Any, Mapping

from .generic import MediatedToolbox, render_for_agent


def _field(block: Any, name: str) -> Any:
    return block.get(name) if isinstance(block, Mapping) else getattr(block, name, None)


class MediatedToolNode:
    def __init__(self, toolbox: MediatedToolbox, messages_key: str = "messages"):
        self.toolbox = toolbox
        self.messages_key = messages_key

    def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        messages = list(state[self.messages_key])
        last = messages[-1] if messages else None
        if last is None or _field(last, "role") != "assistant":
            return {self.messages_key: messages}
        content = _field(last, "content") or []
        results = []
        for block in content if isinstance(content, list) else []:
            if _field(block, "type") != "tool_use":
                continue
            args = _field(block, "input")
            outcome = self.toolbox.call(_field(block, "name"), args if args is not None else {}, _field(block, "id"))
            text, is_error = render_for_agent(outcome)
            result: dict[str, Any] = {"type": "tool_result", "tool_use_id": _field(block, "id"), "content": text}
            if is_error:
                result["is_error"] = True
            results.append(result)
        if results:
            messages.append({"role": "user", "content": results})
        return {self.messages_key: messages}


def has_pending_tool_calls(state: Mapping[str, Any], messages_key: str = "messages") -> bool:
    """Router for ``add_conditional_edges``: True if the last assistant turn requested tools."""
    messages = state[messages_key]
    if not messages or _field(messages[-1], "role") != "assistant":
        return False
    content = _field(messages[-1], "content") or []
    return any(_field(b, "type") == "tool_use" for b in content) if isinstance(content, list) else False
