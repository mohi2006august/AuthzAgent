"""A reference agent on a local open-weight model via Ollama: free, and nothing leaves the machine.

Same loop and same mediator as the Claude agent. Only the model call differs: Ollama's
``/api/chat`` with tool definitions in OpenAI function format. Denials go back to the model as
tool results, exactly as they would for Claude.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from authz import ollama
from authz.integrations.generic import MediatedToolbox, render_for_agent
from authz.registry import DEFAULT_REGISTRY, ToolRegistry

from ..tasks import Task, Variant
from .llm import system_prompt
from .scripted import Step


def ollama_tools(registry: ToolRegistry = DEFAULT_REGISTRY) -> list[dict[str, Any]]:
    return [{"type": "function", "function": {"name": s.name, "description": s.description,
                                              "parameters": dict(s.schema)}} for s in registry]


class OllamaAgent:
    def __init__(self, model: str = "llama3.2", *, host: str = ollama.DEFAULT_HOST, max_turns: int = 12,
                 post: Callable[..., dict[str, Any]] | None = None, user_name: str = "Sam Rivera",
                 user_email: str = "sam.rivera@helix.example"):
        self.model = model
        self.name = f"ollama:{model}"
        self.host = host
        self.max_turns = max_turns
        self._post = post or ollama.post
        self.system = system_prompt(user_name, user_email)
        self.tools = ollama_tools()

    def run(self, task: Task, variant: Variant | None, toolbox: MediatedToolbox, request: str) -> list[Step]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": self.system},
                                          {"role": "user", "content": request}]
        steps: list[Step] = []
        for _ in range(self.max_turns):
            response = self._post(self.host, "/api/chat", {
                "model": self.model, "stream": False, "tools": self.tools, "messages": messages,
                # 14 tool schemas plus the conversation outgrow Ollama's small default context
                "options": {"temperature": 0, "seed": 0, "num_ctx": 8192},
            })
            message = response.get("message") or {}
            messages.append(message)
            calls = message.get("tool_calls") or []
            if not calls:
                break
            for call in calls:
                function = call.get("function") or {}
                name = function.get("name", "")
                args = function.get("arguments") or {}
                if isinstance(args, str):  # some models return the arguments as a JSON string
                    try:
                        args = json.loads(args)
                    except ValueError:
                        args = {}
                outcome = toolbox.call(name, args if isinstance(args, dict) else {}, call.get("id"))
                steps.append(Step(outcome, "model"))
                text, _ = render_for_agent(outcome)
                messages.append({"role": "tool", "tool_name": name, "content": text})
        return steps
