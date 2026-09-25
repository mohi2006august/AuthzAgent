"""The intent record: a structured reading of the user's request.

It is produced once, from trusted input, before the agent makes its first model
call. Everything the capability set permits must be traceable to a field here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Protocol

from .types import canonical_json

ACTION_KINDS = ("send_email", "transfer", "delete_file", "write_file", "create_event", "cancel_event")


@dataclass(frozen=True)
class Action:
    """One irreversible operation the user asked for.

    ``targets`` holds resolved identifiers: email addresses for send_email and
    create_event, account numbers for transfer, absolute paths for
    delete_file and write_file. ``unresolved`` holds references the parser
    could not resolve from trusted input ("them", "everyone on the list"),
    which the capability set therefore cannot grant.
    """

    kind: str
    targets: tuple[str, ...] = ()
    globs: tuple[tuple[str, str], ...] = ()
    amount_ceiling: float | None = None
    ceiling_source: str | None = None
    count: int = 1
    unresolved: tuple[str, ...] = ()
    evidence: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "targets": list(self.targets),
            "globs": [list(g) for g in self.globs],
            "amount_ceiling": self.amount_ceiling,
            "ceiling_source": self.ceiling_source,
            "count": self.count,
            "unresolved": list(self.unresolved),
            "evidence": self.evidence,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Action:
        if data["kind"] not in ACTION_KINDS:
            raise ValueError(f"unknown action kind {data['kind']!r}")
        return cls(
            kind=data["kind"],
            targets=tuple(data.get("targets", ())),
            globs=tuple(tuple(g) for g in data.get("globs", ())),
            amount_ceiling=data.get("amount_ceiling"),
            ceiling_source=data.get("ceiling_source"),
            count=int(data.get("count", 1)),
            unresolved=tuple(data.get("unresolved", ())),
            evidence=data.get("evidence", ""),
        )


@dataclass(frozen=True)
class IntentRecord:
    request: str
    read_domains: tuple[str, ...] = ()
    read_paths: tuple[str, ...] = ()
    fetch_hosts: tuple[str, ...] = ()
    actions: tuple[Action, ...] = ()
    parser: str = "manual"
    notes: tuple[str, ...] = field(default=())

    @property
    def irreversible_requested(self) -> bool:
        return bool(self.actions)

    def to_json(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "read_domains": list(self.read_domains),
            "read_paths": list(self.read_paths),
            "fetch_hosts": list(self.fetch_hosts),
            "actions": [a.to_json() for a in self.actions],
            "irreversible_requested": self.irreversible_requested,
            "parser": self.parser,
            "notes": list(self.notes),
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any], request: str | None = None) -> IntentRecord:
        return cls(
            request=request if request is not None else data.get("request", ""),
            read_domains=tuple(sorted(set(data.get("read_domains", ())))),
            read_paths=tuple(sorted(set(data.get("read_paths", ())))),
            fetch_hosts=tuple(sorted(set(data.get("fetch_hosts", ())))),
            actions=tuple(Action.from_json(a) for a in data.get("actions", ())),
            parser=data.get("parser", "manual"),
            notes=tuple(data.get("notes", ())),
        )

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_json()).encode()).hexdigest()[:16]

    def scope(self) -> dict[str, Any]:
        """The fields that determine the grant, without evidence or notes.

        Used to compare a parsed record against a hand-labelled one.
        """
        return {
            "read_domains": sorted(self.read_domains),
            "read_paths": sorted(self.read_paths),
            "fetch_hosts": sorted(self.fetch_hosts),
            "actions": sorted(
                (
                    {
                        "kind": a.kind,
                        "targets": sorted(a.targets),
                        "globs": sorted(list(g) for g in a.globs),
                        "amount_ceiling": a.amount_ceiling,
                        "count": a.count,
                    }
                    for a in self.actions
                ),
                key=canonical_json,
            ),
        }

    def with_request(self, request: str) -> IntentRecord:
        return replace(self, request=request)


class IntentParser(Protocol):
    name: str

    def parse(self, request: str) -> IntentRecord: ...
