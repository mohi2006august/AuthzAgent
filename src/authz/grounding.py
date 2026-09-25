"""Grounding: turn a model's reading of the request into an intent record, fail-closed.

A model-based parser reads only the trusted request, so it cannot be injected.
It can still be *wrong*, for instance by inventing a recipient or misreading an
amount. Grounding bounds the damage deterministically:

* Every reference, path, URL, amount and date must appear verbatim in the
  request. Anything else is dropped and noted.
* References are resolved to identifiers only through the trusted profile, or
  as literal e-mail addresses in the request.
* Anything that does not resolve becomes *unresolved*, which grants nothing.

So the most a model error can do is pick the wrong one of the things the user
actually named. It can never introduce a new recipient, payee, file or host.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .constraints import HostAllowList, canonical_path
from .dates import resolve_dates
from .intent import ACTION_KINDS, Action, IntentRecord
from .profile import Profile

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_NUMBER = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?")
_PATTERN = re.compile(r"^\*(?:\.[A-Za-z0-9]{1,8})?$")
_DOMAINS = ("fs", "email", "payments", "calendar", "web")
_PRONOUNS = {"him", "her", "them", "they", "he", "she", "me", "us"}
_DROP_PREFIXES = ("the ", "my ", "our ")


def _squash(text: str) -> str:
    return " ".join(text.replace("’", "'").lower().split())


def appears(fragment: str, request: str) -> bool:
    fragment = _squash(fragment)
    return bool(fragment) and fragment in _squash(request)


def _alias_table(profile: Profile) -> tuple[dict[str, str], dict[str, str]]:
    contacts, payees = {}, {}
    for c in profile.contacts:
        for alias in (c.name, *c.aliases):
            contacts[_squash(alias)] = c.email
    for p in profile.payees:
        for alias in (p.name, *p.aliases):
            payees[_squash(alias)] = p.account
    return contacts, payees


def _variants(ref: str) -> list[str]:
    ref = _squash(ref)
    out = [ref]
    if ref.endswith("'s"):
        out.append(ref[:-2])
    for prefix in _DROP_PREFIXES:
        for r in list(out):
            if r.startswith(prefix):
                out.append(r[len(prefix):])
    return out


def resolve_person(ref: str, profile: Profile) -> str | None:
    if _EMAIL.match(ref.strip()):
        return ref.strip().lower()
    contacts, _ = _alias_table(profile)
    return next((contacts[v] for v in _variants(ref) if v in contacts), None)


def resolve_payee(ref: str, profile: Profile) -> str | None:
    _, payees = _alias_table(profile)
    return next((payees[v] for v in _variants(ref) if v in payees), None)


def resolve_path(ref: str, profile: Profile) -> str | None:
    value = ref.strip().rstrip(".,;:")
    if value.startswith("~"):
        value = profile.home + value[1:]
    if len(value) > 1:
        value = value.rstrip("/")
    return canonical_path(value)


def ground(raw: Mapping[str, Any], request: str, profile: Profile, parser: str) -> IntentRecord:
    notes: list[str] = []

    def verbatim(kind: str, value: str) -> bool:
        if appears(value, request):
            return True
        notes.append(f"dropped {kind} {value!r}: not in the request")
        return False

    paths = []
    for p in raw.get("paths", []):
        if isinstance(p, str) and verbatim("path", p) and (c := resolve_path(p, profile)):
            paths.append(c)
    urls = [u for u in raw.get("urls", []) if isinstance(u, str) and verbatim("url", u) and HostAllowList.host_of(u)]
    domains = {d for d in raw.get("read_domains", []) if d in _DOMAINS}
    if paths:
        domains.add("fs")
    if urls:
        domains.add("web")

    actions: list[Action] = []
    for a in raw.get("actions", []):
        kind = a.get("kind")
        refs = [r for r in a.get("references", []) if isinstance(r, str) and r.strip()]
        refs = [r for r in refs if _squash(r) in _PRONOUNS or verbatim("reference", r)]
        amounts = []
        for text in a.get("amounts", []):
            if isinstance(text, str) and verbatim("amount", text):
                amounts += [float(n.replace(",", "")) for n in _NUMBER.findall(text)]
        date_text = a.get("date") or ""
        dates = resolve_dates(date_text, profile.today) if date_text and verbatim("date", date_text) else []
        bulk = bool(a.get("all_matching"))

        if kind in ("send_email", "create_event"):
            resolved = [resolve_person(r, profile) for r in refs]
            targets = tuple(sorted({t for t in resolved if t}))
            unresolved = tuple(r for r, t in zip(refs, resolved) if not t)
            count = max(1, len(targets)) if a.get("separately") and kind == "send_email" else 1
            if kind == "send_email" and not targets and not unresolved:
                unresolved = ("(no recipient named)",)
            actions.append(Action(kind, targets, count=count, unresolved=() if targets else unresolved))
        elif kind == "transfer":
            accounts = [(r, resolve_payee(r, profile)) for r in refs]
            resolved = [acct for _, acct in accounts if acct]
            unresolved = tuple(r for r, acct in accounts if not acct)
            if len(resolved) > 1 and len(resolved) == len(amounts):
                actions += [Action("transfer", (acct,), amount_ceiling=amt, ceiling_source="request")
                            for acct, amt in zip(resolved, amounts)]
                continue
            if amounts:
                ceiling, source = max(amounts), "request"
            else:
                ceiling, source = profile.default_amount_ceiling, "policy"
            actions.append(Action("transfer", tuple(sorted(set(resolved))), amount_ceiling=ceiling,
                                  ceiling_source=source, count=max(1, len(set(resolved))),
                                  unresolved=() if resolved else (unresolved or ("(no payee named)",))))
        elif kind in ("write_file", "delete_file", "move_file"):
            targets = [c for r in refs if (c := resolve_path(r, profile))]
            if kind == "move_file":
                if len(targets) >= 2:
                    actions.append(Action("write_file", (targets[-1],)))
                    actions.append(Action("delete_file", (targets[0],)))
                else:
                    notes.append("move without source and destination ignored")
                continue
            pattern = a.get("file_pattern") or ""
            if kind == "delete_file" and bulk and targets:
                ext = pattern[2:] if pattern.startswith("*.") else ""
                if not _PATTERN.match(pattern) or (ext and not appears(ext, request)):
                    notes.append(f"file pattern {pattern!r} not grounded; using *")
                    pattern = "*"
                actions.append(Action("delete_file", globs=tuple((t, pattern) for t in targets),
                                      count=profile.bulk_limit))
            elif targets:
                actions.append(Action(kind, tuple(sorted(set(targets))), count=len(set(targets))))
            else:
                notes.append(f"{kind} without a grounded path ignored")
        elif kind == "cancel_event":
            attendees = tuple(sorted({t for r in refs if (t := resolve_person(r, profile))}))
            actions.append(Action("cancel_event", attendees, count=profile.bulk_limit if bulk else 1,
                                  date=dates[0] if dates else None))
        elif kind is not None:
            notes.append(f"unknown action kind {kind!r} ignored")

    for action in actions:
        assert action.kind in ACTION_KINDS
    return IntentRecord(
        request=request,
        read_domains=tuple(sorted(domains)),
        read_paths=tuple(sorted(set(paths))),
        fetch_hosts=tuple(sorted({h for u in urls if (h := HostAllowList.host_of(u))})),
        fetch_urls=tuple(sorted(set(urls))),
        actions=tuple(actions),
        parser=parser,
        notes=tuple(notes),
    )
