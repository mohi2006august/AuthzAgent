"""Mediator configurations evaluated. Each is one point on the frontier plot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Config:
    name: str
    label: str
    parser: str = "rule"  # "rule" (rule-based v2), "gold" (hand-labelled) or "model" (grounded Claude parser)
    request_source: str = "original"  # "original", "paraphrase" or "heldout" (see scripts/author_suite.py)
    mediate: bool = True
    constraints: bool = True
    budgets: bool = True
    budget_mode: str = "per_tool"
    reads_only: bool = False
    escalation: str = "none"  # "none", "attentive", "attentive-nohist" or "rubber_stamp"
    derivation: str = "v2"  # "v1": host-level URLs, unbound cancellations, one ceiling per tool
    confirm_unstated_amounts: bool = False
    frontier: bool = True  # plotted on the main frontier
    needs_model: bool = False  # needs Anthropic credentials; excluded unless --with-model

    def derive_options(self) -> dict[str, Any]:
        if self.derivation == "v1":
            return {"url_policy": "host", "bind_events": False, "pair_ceilings": False}
        return {"confirm_unstated_amounts": self.confirm_unstated_amounts}


CONFIGS: tuple[Config, ...] = (
    Config("no-mediator", "No mediator", mediate=False),
    Config("tools-only", "Tool allow-list only", constraints=False, budgets=False),
    Config("tools+args", "Tools + arg constraints", budgets=False),
    Config("full", "Full (per-tool budget)"),
    Config("full-v1-derivation", "Full, v1 derivation", derivation="v1", frontier=False),
    Config("full-global", "Full (global budget)", budget_mode="global", frontier=False),
    Config("full+esc-attentive", "Full + escalation, attentive user", escalation="attentive"),
    Config("full+esc-attentive-nohist", "Full + escalation, attentive user, no history",
           escalation="attentive-nohist", frontier=False),
    Config("full+esc-rubber", "Full + escalation, rubber-stamp user", escalation="rubber_stamp"),
    Config("full+confirm-amounts", "Full + confirm unstated amounts (attentive user)",
           escalation="attentive", confirm_unstated_amounts=True),
    Config("read-only", "Deny all irreversible", reads_only=True),
    Config("oracle-intent", "Full, hand-labelled intent", parser="gold"),
    Config("paraphrased", "Full, paraphrases", request_source="paraphrase"),
    Config("heldout", "Full, held-out requests", request_source="heldout"),
    Config("model", "Full, grounded model parser", parser="model", needs_model=True),
    Config("model-heldout", "Full, grounded model parser, held-out", parser="model", request_source="heldout",
           needs_model=True),
)

BY_NAME = {c.name: c for c in CONFIGS}
DEFAULT_CONFIGS = tuple(c for c in CONFIGS if not c.needs_model)
