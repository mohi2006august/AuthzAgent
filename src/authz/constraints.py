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
    raise ValueError(f"unknown constraint type {kind!r}")
