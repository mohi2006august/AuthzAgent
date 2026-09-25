"""Intent record -> capability set.

Derivation is a pure function of the intent record, the profile and the tool
registry. Least privilege: a tool is granted only if the intent implies it,
and every scoped argument of a granted tool is constrained by the targets in
the intent.
"""

from __future__ import annotations

from collections import defaultdict

from .capabilities import CapabilitySet, ToolGrant
from .constraints import AllowList, HostAllowList, MaxValue, PathScope
from .intent import IntentParser, IntentRecord
from .parser import RuleBasedParser
from .profile import Profile
from .registry import DEFAULT_REGISTRY, SCOPE_REASONS, ToolRegistry
from .types import Reason

_IMPLIED_DOMAIN = {
    "transfer": "payments",
    "create_event": "calendar",
    "cancel_event": "calendar",
    "write_file": "fs",
    "delete_file": "fs",
}


def derive(
    request: str,
    *,
    profile: Profile | None = None,
    parser: IntentParser | None = None,
    budget_mode: str = "per_tool",
    registry: ToolRegistry = DEFAULT_REGISTRY,
) -> CapabilitySet:
    """``derive(request) -> CapabilitySet`` from the architecture's interface list."""
    profile = profile or Profile()
    parser = parser or RuleBasedParser(profile)
    return derive_from_intent(parser.parse(request), profile, budget_mode=budget_mode, registry=registry)


def derive_from_intent(
    intent: IntentRecord,
    profile: Profile,
    *,
    budget_mode: str = "per_tool",
    registry: ToolRegistry = DEFAULT_REGISTRY,
) -> CapabilitySet:
    grants: dict[str, ToolGrant] = {}
    domains = set(intent.read_domains)
    for action in intent.actions:
        if action.kind in _IMPLIED_DOMAIN:
            domains.add(_IMPLIED_DOMAIN[action.kind])
    if intent.fetch_hosts:
        domains.add("web")

    # -- reads ------------------------------------------------------------------
    if "fs" in domains:
        roots = set(intent.read_paths)
        for action in intent.actions:
            if action.kind in ("write_file", "delete_file"):
                roots.update(action.targets)
                roots.update(d for d, _ in action.globs)
        if not roots:
            roots.add(profile.home)
        exclude = tuple(profile.sensitive_paths)
        grants["read_file"] = ToolGrant("read_file", (("path", PathScope(prefixes=tuple(roots), exclude=exclude)),))
        grants["list_dir"] = ToolGrant(
            "list_dir", (("path", PathScope(prefixes=tuple(roots), exclude=exclude, allow_parents=True)),)
        )
    for domain in ("email", "payments", "calendar"):
        if domain in domains:
            for tool in registry.tools_for(domain, "read"):
                grants[tool] = ToolGrant(tool)
    if "web" in domains:
        grants["fetch_url"] = ToolGrant("fetch_url", (("url", HostAllowList(tuple(intent.fetch_hosts))),))

    # -- irreversible actions ------------------------------------------------------
    by_kind: dict[str, list] = defaultdict(list)
    for action in intent.actions:
        by_kind[action.kind].append(action)

    for kind, actions in by_kind.items():
        spec = registry[kind]
        budget = sum(a.count for a in actions)
        targets = tuple(t for a in actions for t in a.targets)
        constraints = []
        if kind == "send_email":
            allow = AllowList(targets, Reason.RECIPIENT_NOT_ALLOWED, "email")
            constraints = [("to", allow), ("cc", allow)]
        elif kind == "create_event":
            constraints = [("attendees", AllowList(targets + (profile.user_email,), Reason.ATTENDEE_NOT_ALLOWED, "email"))]
        elif kind == "transfer":
            ceilings = [a for a in actions if a.amount_ceiling is not None]
            constraints = [("to_account", AllowList(targets, Reason.ACCOUNT_NOT_ALLOWED, "account"))]
            if ceilings:
                top = max(ceilings, key=lambda a: a.amount_ceiling)
                constraints.append(("amount", MaxValue(float(top.amount_ceiling), source=top.ceiling_source or "request")))
            else:
                constraints.append(("amount", MaxValue(profile.default_amount_ceiling, source="policy")))
        elif kind in ("write_file", "delete_file"):
            globs = tuple(g for a in actions for g in a.globs)
            constraints = [("path", PathScope(exact=targets, globs=globs, exclude=tuple(profile.sensitive_paths)))]
        elif kind == "cancel_event":
            constraints = []  # event ids come from calendar data, so they cannot be pinned in advance
        for arg, _ in constraints:
            assert arg in spec.scoped_args, f"{kind}.{arg} is not a scoped argument"
            assert SCOPE_REASONS[spec.scoped_args[arg]] is not None
        grants[kind] = ToolGrant(kind, tuple(constraints), budget if spec.budgeted else None)

    budgeted = [g.budget for g in grants.values() if registry[g.tool].budgeted and g.budget is not None]
    return CapabilitySet(
        tuple(grants.values()),
        budget_mode=budget_mode,
        global_budget=sum(budgeted),
        provenance=intent.digest(),
    )
