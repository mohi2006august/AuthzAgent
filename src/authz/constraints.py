"""Per-argument predicates that make up a tool grant.

Each constraint is a small, deterministic predicate over a single argument
value. ``check`` returns ``None`` when the value is permitted and a
human-readable detail string when it is not. List-valued arguments are checked
element by element by the mediator, so constraints only ever see scalars.
"""

from __future__ import annotations

import fnmatch
import math
import posixpath
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .types import Reason


class Constraint(Protocol):
    kind: str

    @property
    def reason(self) -> Reason: ...

    def check(self, value: Any) -> str | None: ...

    def to_json(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# normalisation helpers


def normalise_email(value: str) -> str:
    return value.strip().lower()


def normalise_account(value: str) -> str:
    return "".join(value.split()).upper()


_NORMALISERS = {"email": normalise_email, "account": normalise_account, "exact": lambda v: v}


def canonical_path(value: Any) -> str | None:
    """Return ``value`` if it is an absolute, canonical POSIX path, else None.

    Canonical means ``posixpath.normpath`` leaves it unchanged: no ``..`` or
    ``.`` segments, no doubled or trailing slashes. Rejecting non-canonical
    paths outright (rather than normalising them) means the mediator and the
    tool server can never disagree about which file a path names.
    """
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or "\\" in value:
        return None
    if posixpath.normpath(value) != value or value.startswith("//"):
        return None
    return value


def path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


# ---------------------------------------------------------------------------
# constraints


@dataclass(frozen=True)
class AllowList:
    values: tuple[str, ...]
    reason: Reason = Reason.VALUE_NOT_ALLOWED
    normalise: str = "exact"
    kind: str = "allow_list"

    def __post_init__(self) -> None:
        norm = _NORMALISERS[self.normalise]
        object.__setattr__(self, "values", tuple(sorted({norm(v) for v in self.values})))

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return f"{value!r} is not a string"
        if _NORMALISERS[self.normalise](value) in self.values:
            return None
        if not self.values:
            return f"{value!r} is not permitted (the request named no permitted values)"
        return f"{value!r} is not one of the permitted values {list(self.values)}"

    def widened(self, value: str) -> AllowList:
        return AllowList(self.values + (value,), self.reason, self.normalise)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "values": list(self.values), "reason": self.reason.value, "normalise": self.normalise}


@dataclass(frozen=True)
class MaxValue:
    ceiling: float
    reason: Reason = Reason.AMOUNT_EXCEEDS_CEILING
    source: str = "request"  # "request" if stated by the user, "policy" if a default
    kind: str = "max_value"

    def check(self, value: Any) -> str | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return f"{value!r} is not a finite number"
        if value > self.ceiling + 1e-9:
            return f"{value} exceeds the ceiling of {self.ceiling} (from {self.source})"
        return None

    def widened(self, value: float) -> MaxValue:
        return MaxValue(max(self.ceiling, float(value)), self.reason, "escalation")

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "ceiling": self.ceiling, "reason": self.reason.value, "source": self.source}


@dataclass(frozen=True)
class PathScope:
    exact: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    globs: tuple[tuple[str, str], ...] = ()  # (directory, basename pattern), recursive under directory
    exclude: tuple[str, ...] = ()
    allow_parents: bool = False  # permit ancestors of granted paths (directory listings only)
    reason: Reason = Reason.PATH_OUTSIDE_SCOPE
    kind: str = "path_scope"

    def __post_init__(self) -> None:
        object.__setattr__(self, "exact", tuple(sorted(set(self.exact))))
        object.__setattr__(self, "prefixes", tuple(sorted(set(self.prefixes))))
        object.__setattr__(self, "globs", tuple(sorted({tuple(g) for g in self.globs})))
        object.__setattr__(self, "exclude", tuple(sorted(set(self.exclude))))

    def _roots(self) -> tuple[str, ...]:
        return self.exact + self.prefixes + tuple(d for d, _ in self.globs)

    def check(self, value: Any) -> str | None:
        path = canonical_path(value)
        if path is None:
            return f"{value!r} is not an absolute canonical path"
        if path in self.exact:
            return None
        if any(path_within(path, e) for e in self.exclude):
            return f"{path} is in a protected location and was not named in the request"
        if any(path_within(path, p) for p in self.prefixes):
            return None
        for directory, pattern in self.globs:
            if path_within(path, directory) and path != directory and fnmatch.fnmatchcase(posixpath.basename(path), pattern):
                return None
        if self.allow_parents and any(path_within(root, path) for root in self._roots()):
            return None
        return f"{path} is outside the granted paths"

    def widened(self, value: str) -> PathScope:
        return PathScope(self.exact + (value,), self.prefixes, self.globs, self.exclude, self.allow_parents, self.reason)

    def to_json(self) -> dict[str, Any]:
        return {
            "type": self.kind,
            "exact": list(self.exact),
            "prefixes": list(self.prefixes),
            "globs": [list(g) for g in self.globs],
            "exclude": list(self.exclude),
            "allow_parents": self.allow_parents,
            "reason": self.reason.value,
        }


@dataclass(frozen=True)
class HostAllowList:
    hosts: tuple[str, ...]
    reason: Reason = Reason.HOST_NOT_ALLOWED
    kind: str = "host_allow_list"

    def __post_init__(self) -> None:
        object.__setattr__(self, "hosts", tuple(sorted({h.lower() for h in self.hosts})))

    @staticmethod
    def host_of(url: Any) -> str | None:
        """Hostname of an http(s) URL without credentials or a custom port, else None."""
        if not isinstance(url, str):
            return None
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or parts.username or parts.password:
            return None
        if port not in (None, 80, 443):
            return None
        return parts.hostname

    def check(self, value: Any) -> str | None:
        host = self.host_of(value)
        if host is None:
            return f"{value!r} is not a plain http(s) URL"
        if host in self.hosts:
            return None
        return f"host {host!r} is not one of {list(self.hosts)}"

    def widened(self, value: str) -> HostAllowList:
        host = self.host_of(value)
        return HostAllowList(self.hosts + ((host,) if host else ()), self.reason)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "hosts": list(self.hosts), "reason": self.reason.value}


def normalise_url(url: str) -> str:
    """Lower-case scheme and host, drop the fragment (never sent to the server)."""
    parts = urlsplit(url)
    netloc = parts.netloc.lower()
    return f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


@dataclass(frozen=True)
class UrlScope:
    """The URLs the request named, plus query-free navigation on their hosts.

    Stricter than :class:`HostAllowList`: a granted host cannot be used as an
    exfiltration channel through query strings. (Data encoded in the *path* of
    a same-host URL still gets through; see the report, F3.)
    """

    urls: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    reason: Reason = Reason.URL_NOT_ALLOWED
    kind: str = "url_scope"

    def __post_init__(self) -> None:
        object.__setattr__(self, "urls", tuple(sorted({normalise_url(u) for u in self.urls})))
        object.__setattr__(self, "hosts", tuple(sorted({h.lower() for h in self.hosts})))

    def check(self, value: Any) -> str | None:
        host = HostAllowList.host_of(value)
        if host is None:
            return f"{value!r} is not a plain http(s) URL"
        if normalise_url(value) in self.urls:
            return None
        if host in self.hosts and not urlsplit(value).query:
            return None
        if host in self.hosts:
            return f"{value!r} adds a query string to a granted host; only the URLs named in the request may carry one"
        return f"host {host!r} is not one of {list(self.hosts)}"

    def widened(self, value: str) -> UrlScope:
        return UrlScope(self.urls + (value,), self.hosts, self.reason)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "urls": list(self.urls), "hosts": list(self.hosts), "reason": self.reason.value}


@dataclass(frozen=True)
class EventMatch:
    """An event id is allowed if trusted calendar metadata matches the request.

    Needs :class:`authz.state.TrustedState`. The mediator passes it in, and
    without it every id not approved explicitly is denied.
    """

    date: str | None = None
    attendees: tuple[str, ...] = ()
    ids: tuple[str, ...] = ()  # approved individually through escalation
    reason: Reason = Reason.EVENT_NOT_ALLOWED
    kind: str = "event_match"
    needs_state: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "attendees", tuple(sorted({normalise_email(a) for a in self.attendees})))
        object.__setattr__(self, "ids", tuple(sorted(set(self.ids))))

    def check(self, value: Any, state: Any = None) -> str | None:
        if not isinstance(value, str):
            return f"{value!r} is not an event id"
        if value in self.ids:
            return None
        if state is None:
            return "no trusted calendar metadata is available to verify this event"
        facts = state.event(value)
        if facts is None:
            return f"no event {value!r}"
        if self.date and not facts.start.startswith(self.date):
            return f"event {value!r} is on {facts.start[:10]}, not {self.date} as requested"
        present = {normalise_email(a) for a in facts.attendees}
        missing = [a for a in self.attendees if a not in present]
        if missing:
            return f"event {value!r} does not include {missing}"
        return None

    def widened(self, value: str) -> EventMatch:
        return EventMatch(self.date, self.attendees, self.ids + (value,), self.reason)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "date": self.date, "attendees": list(self.attendees), "ids": list(self.ids),
                "reason": self.reason.value}


@dataclass(frozen=True)
class PairedCeiling:
    """A grant-level predicate: each payee has its own ceiling.

    A per-argument ceiling cannot express "£120 to Northwind *and* £75 to Acme".
    This checks the pair (account, amount) together.
    """

    ceilings: tuple[tuple[str, float], ...]
    key_arg: str = "to_account"
    value_arg: str = "amount"
    reason: Reason = Reason.AMOUNT_EXCEEDS_CEILING
    kind: str = "paired_ceiling"

    def __post_init__(self) -> None:
        merged: dict[str, float] = {}
        for account, ceiling in self.ceilings:
            key = normalise_account(account)
            merged[key] = max(merged.get(key, 0.0), float(ceiling))
        object.__setattr__(self, "ceilings", tuple(sorted(merged.items())))

    def check_call(self, args: Mapping[str, Any]) -> tuple[str, str] | None:
        account, amount = args.get(self.key_arg), args.get(self.value_arg)
        if not isinstance(account, str) or not isinstance(amount, (int, float)):
            return None  # the per-argument constraints and the schema handle malformed calls
        limit = dict(self.ceilings).get(normalise_account(account))
        if limit is None or amount <= limit + 1e-9:
            return None
        return self.value_arg, f"{amount} exceeds the ceiling of {limit} for this payee"

    def widened_for(self, args: Mapping[str, Any]) -> PairedCeiling:
        return PairedCeiling(self.ceilings + ((args[self.key_arg], float(args[self.value_arg])),),
                             self.key_arg, self.value_arg, self.reason)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.kind, "ceilings": [list(c) for c in self.ceilings], "key_arg": self.key_arg,
                "value_arg": self.value_arg, "reason": self.reason.value}


def predicate_from_json(data: Mapping[str, Any]) -> PairedCeiling:
    if data["type"] != "paired_ceiling":
        raise ValueError(f"unknown predicate type {data['type']!r}")
    return PairedCeiling(tuple((a, float(c)) for a, c in data["ceilings"]), data.get("key_arg", "to_account"),
                         data.get("value_arg", "amount"), Reason(data["reason"]))


def constraint_from_json(data: Mapping[str, Any]) -> Constraint:
    kind = data["type"]
    reason = Reason(data["reason"])
    if kind == "allow_list":
        return AllowList(tuple(data["values"]), reason, data.get("normalise", "exact"))
    if kind == "max_value":
        return MaxValue(float(data["ceiling"]), reason, data.get("source", "request"))
    if kind == "path_scope":
        return PathScope(
            tuple(data.get("exact", ())),
            tuple(data.get("prefixes", ())),
            tuple(tuple(g) for g in data.get("globs", ())),
            tuple(data.get("exclude", ())),
            bool(data.get("allow_parents", False)),
            reason,
        )
    if kind == "host_allow_list":
        return HostAllowList(tuple(data["hosts"]), reason)
    if kind == "url_scope":
        return UrlScope(tuple(data.get("urls", ())), tuple(data.get("hosts", ())), reason)
    if kind == "event_match":
        return EventMatch(data.get("date"), tuple(data.get("attendees", ())), tuple(data.get("ids", ())), reason)
    raise ValueError(f"unknown constraint type {kind!r}")
