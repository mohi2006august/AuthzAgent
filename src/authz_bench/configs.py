"""Mediator configurations evaluated. Each is one point on the frontier plot."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    name: str
    label: str
    intent_source: str = "parsed"  # "parsed" (rule-based parser) or "gold" (hand-labelled)
    request_source: str = "original"  # "original", "paraphrase" or "heldout" (see scripts/author_suite.py)
    mediate: bool = True
    constraints: bool = True
    budgets: bool = True
    budget_mode: str = "per_tool"
    reads_only: bool = False
    escalation: str = "none"  # "none", "attentive" or "rubber_stamp"
    frontier: bool = True  # plotted on the main frontier


CONFIGS: tuple[Config, ...] = (
    Config("no-mediator", "No mediator", mediate=False),
    Config("tools-only", "Tool allow-list only", constraints=False, budgets=False),
    Config("tools+args", "Tools + arg constraints", budgets=False),
    Config("full", "Full (per-tool budget)"),
    Config("full-global", "Full (global budget)", budget_mode="global"),
    Config("full+esc-attentive", "Full + escalation, attentive user", escalation="attentive"),
    Config("full+esc-rubber", "Full + escalation, rubber-stamp user", escalation="rubber_stamp"),
    Config("read-only", "Deny all irreversible", reads_only=True),
    Config("oracle-intent", "Full, hand-labelled intent", intent_source="gold"),
    Config("paraphrased", "Full, held-out paraphrases", request_source="paraphrase"),
    Config("heldout", "Full, second held-out set", request_source="heldout"),
)

BY_NAME = {c.name: c for c in CONFIGS}
