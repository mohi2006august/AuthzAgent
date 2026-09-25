"""The capability set: the immutable grant a task runs under."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .constraints import Constraint, PairedCeiling, constraint_from_json, predicate_from_json
from .types import canonical_json

BUDGET_MODES = ("per_tool", "global", "none")


@dataclass(frozen=True)
class ToolGrant:
    """Permission to call one tool, subject to per-argument constraints.

    ``predicates`` constrain several arguments together (e.g. a ceiling per
    payee). ``budget`` caps how many times a budgeted (mutating) tool may
    execute in the task. ``None`` means uncapped, which derivation only ever
    uses for read and egress tools.
    """

    tool: str
    constraints: tuple[tuple[str, Constraint], ...] = ()
    budget: int | None = None
    predicates: tuple[PairedCeiling, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraints", tuple(sorted(self.constraints, key=lambda c: c[0])))

    def constraint_for(self, arg: str) -> Constraint | None:
        for name, constraint in self.constraints:
            if name == arg:
                return constraint
        return None

    def with_constraint(self, arg: str, constraint: Constraint) -> ToolGrant:
        others = tuple(c for c in self.constraints if c[0] != arg)
        return replace(self, constraints=others + ((arg, constraint),))

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": self.tool,
            "budget": self.budget,
            "constraints": {name: c.to_json() for name, c in self.constraints},
        }
        if self.predicates:
            out["predicates"] = [p.to_json() for p in self.predicates]
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> ToolGrant:
        return cls(
            data["tool"],
            tuple((name, constraint_from_json(c)) for name, c in data.get("constraints", {}).items()),
            data.get("budget"),
            tuple(predicate_from_json(p) for p in data.get("predicates", ())),
        )


@dataclass(frozen=True)
class CapabilitySet:
    """Immutable for the task's duration.

    The only way to obtain a different set mid-task is
    :func:`authz.escalation.widen_to_permit`, which the session calls only after
    the user approves. That returns a new set with ``version`` incremented and
    ``parent`` pointing at the fingerprint of the set it replaced.
    """

    grants: tuple[ToolGrant, ...]
    budget_mode: str = "per_tool"
    global_budget: int | None = None
    version: int = 1
    parent: str | None = None
    provenance: str = ""  # digest of the intent record this set was derived from
    _index: Mapping[str, ToolGrant] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.budget_mode not in BUDGET_MODES:
            raise ValueError(f"budget_mode must be one of {BUDGET_MODES}")
        grants = tuple(sorted(self.grants, key=lambda g: g.tool))
        if len({g.tool for g in grants}) != len(grants):
            raise ValueError("duplicate grants for one tool")
        object.__setattr__(self, "grants", grants)
        object.__setattr__(self, "_index", MappingProxyType({g.tool: g for g in grants}))

    def grant(self, tool: str) -> ToolGrant | None:
        return self._index.get(tool)

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(self._index)

    def with_grant(self, grant: ToolGrant) -> CapabilitySet:
        """A copy with ``grant`` added or replaced. Same version; callers bump it."""
        others = tuple(g for g in self.grants if g.tool != grant.tool)
        return replace(self, grants=others + (grant,))

    def _content(self) -> dict[str, Any]:
        return {
            "grants": [g.to_json() for g in self.grants],
            "budget_mode": self.budget_mode,
            "global_budget": self.global_budget,
            "provenance": self.provenance,
        }

    def fingerprint(self) -> str:
        """Stable digest of what the set permits (independent of its version history)."""
        return hashlib.sha256(canonical_json(self._content()).encode()).hexdigest()[:16]

    def to_json(self) -> dict[str, Any]:
        return {**self._content(), "version": self.version, "parent": self.parent, "fingerprint": self.fingerprint()}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> CapabilitySet:
        return cls(
            tuple(ToolGrant.from_json(g) for g in data["grants"]),
            data.get("budget_mode", "per_tool"),
            data.get("global_budget"),
            data.get("version", 1),
            data.get("parent"),
            data.get("provenance", ""),
        )

    @classmethod
    def empty(cls) -> CapabilitySet:
        return cls(())


def strip(capset: CapabilitySet, *, constraints: bool = False, budgets: bool = False,
          keep_tools: Iterable[str] | None = None) -> CapabilitySet:
    """Ablations used in evaluation: drop constraints, budgets, or whole grants."""
    keep = None if keep_tools is None else set(keep_tools)
    grants = []
    for g in capset.grants:
        if keep is not None and g.tool not in keep:
            continue
        grants.append(ToolGrant(g.tool, () if constraints else g.constraints, None if budgets else g.budget,
                                () if constraints else g.predicates))
    return replace(
        capset,
        grants=tuple(grants),
        budget_mode="none" if budgets else capset.budget_mode,
        global_budget=None if budgets else capset.global_budget,
    )
