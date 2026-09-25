from .scripted import ScriptedAgent, Step, dump_steps

__all__ = ["ScriptedAgent", "Step", "dump_steps", "make_agent"]


def make_agent(name: str, **kwargs):
    if name == "scripted":
        return ScriptedAgent(**kwargs)
    if name == "claude":
        from .llm import ClaudeAgent

        return ClaudeAgent(**kwargs)
    if name == "langgraph":
        from .llm import LangGraphClaudeAgent

        return LangGraphClaudeAgent(**kwargs)
    raise ValueError(f"unknown agent {name!r}")
