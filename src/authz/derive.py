"""Intent record -> capability set.

Derivation is a pure function of the intent record, the profile and the tool
registry. Least privilege: a tool is granted only if the intent implies it,
and every scoped argument of a granted tool is constrained by the targets in
the intent.

The keyword options exist for ablations. The defaults are the v2 system.
``url_policy="host"``, ``bind_events=False`` and ``pair_ceilings=False``
reproduce v1's derivation.
"""

from __future__ import annotations

from collections import defaultdict

from .capabilities import CapabilitySet, ToolGrant
from .constraints import AllowList, EventMatch, HostAllowList, MaxValue, PairedCeiling, PathScope, UrlScope
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
    **options: object,
) -> CapabilitySet:
    """``derive(request) -> CapabilitySet`` from the architecture's interface list."""
    profile = profile or Profile()
    parser = parser or RuleBasedParser(profile)
    return derive_from_intent(parser.parse(request), profile, budget_mode=budget_mode, registry=registry,
                              **options)  # type: ignore[arg-type]


def derive_from_intent(
    intent: IntentRecord,
    profile: Profile,
    *,
    budget_mode: str = "per_tool",
    registry: ToolRegistry = DEFAULT_REGISTRY,
    url_policy: str = "exact",
    bind_events: bool = True,
    pair_ceilings: bool = True,
    confirm_unstated_amounts: bool = False,
) -> CapabilitySet:
    """Build the grant.

    url_policy               "exact": the URLs named in the request, plus query-free
                             pages on their hosts (F3). "host": any URL on a named host (v1).
    bind_events              bind cancel_event to the date and attendees named (F2).
    pair_ceilings            give each payee its own ceiling, not the largest one.
    confirm_unstated_amounts an amount the user did not state gets a zero ceiling,
                             so any such transfer needs the user's approval (F1).
    """
    grants: dict[str, ToolGrant] = {}
    domains = set(intent.read_domains)
    for action in intent.actions:
        if action.kind in _IMPLIED_DOMAIN:
            domains.add(_IMPLIED_DOMAIN[action.kind])
    if intent.fetch_hosts or intent.fetch_urls:
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
        hosts = set(intent.fetch_hosts) | {h for u in intent.fetch_urls if (h := HostAllowList.host_of(u))}
        if url_policy == "exact" and intent.fetch_urls:
            constraint = UrlScope(tuple(intent.fetch_urls), tuple(hosts))
        else:
            constraint = HostAllowList(tuple(hosts))
        grants["fetch_url"] = ToolGrant("fetch_url", (("url", constraint),))

    # -- irreversible actions ------------------------------------------------------
    by_kind: dict[str, list] = defaultdict(list)
    for action in intent.actions:
        by_kind[action.kind].append(action)

    for kind, actions in by_kind.items():
        spec = registry[kind]
        budget = sum(a.count for a in actions)
        targets = tuple(t for a in actions for t in a.targets)
        constraints = []
        predicates: tuple[PairedCeiling, ...] = ()
        if kind == "send_email":
            allow = AllowList(targets, Reason.RECIPIENT_NOT_ALLOWED, "email")
            constraints = [("to", allow), ("cc", allow)]
        elif kind == "create_event":
            constraints = [("attendees", AllowList(targets + (profile.user_email,), Reason.ATTENDEE_NOT_ALLOWED, "email"))]
        elif kind == "transfer":
            ceilings = []
            for a in actions:
                ceiling = a.amount_ceiling if a.amount_ceiling is not None else profile.default_amount_ceiling
                source = a.ceiling_source or ("request" if a.amount_ceiling is not None else "policy")
                if confirm_unstated_amounts and source == "policy":
                    ceiling, source = 0.0, "confirm"
                ceilings.append((a, float(ceiling), source))
            top = max(ceilings, key=lambda c: c[1]) if ceilings else None
            constraints = [
                ("to_account", AllowList(targets, Reason.ACCOUNT_NOT_ALLOWED, "account")),
                ("amount", MaxValue(top[1], source=top[2]) if top else MaxValue(profile.default_amount_ceiling,
                                                                                  source="policy")),
            ]
            pairs = tuple((t, c) for a, c, _ in ceilings for t in a.targets)
            if pair_ceilings and len({c for _, c in pairs}) > 1:
                predicates = (PairedCeiling(pairs),)
        elif kind in ("write_file", "delete_file"):
            globs = tuple(g for a in actions for g in a.globs)
            constraints = [("path", PathScope(exact=targets, globs=globs, exclude=tuple(profile.sensitive_paths)))]
        elif kind == "cancel_event":
            # Event ids come from calendar data, so they cannot be named in advance. With binding,
            # the id must belong to an event on the requested day with the requested attendees,
            # checked against trusted calendar metadata (authz.state).
            qualified = [a for a in actions if a.date or a.targets]
            if bind_events and len(actions) == 1 and qualified:
                a = qualified[0]
                constraints = [("event_id", EventMatch(a.date, a.targets))]
        for arg, _ in constraints:
            assert arg in spec.scoped_args, f"{kind}.{arg} is not a scoped argument"
            assert SCOPE_REASONS[spec.scoped_args[arg]] is not None
        grants[kind] = ToolGrant(kind, tuple(constraints), budget if spec.budgeted else None, predicates)

    budgeted = [g.budget for g in grants.values() if registry[g.tool].budgeted and g.budget is not None]
    return CapabilitySet(
        tuple(grants.values()),
        budget_mode=budget_mode,
        global_budget=sum(budgeted),
        provenance=intent.digest(),
    )
