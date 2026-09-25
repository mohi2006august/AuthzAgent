"""The user's trusted profile: who they are, who they know, whom they pay.

This is configuration the user controls, never content retrieved during a task,
so the intent parser may resolve names against it. A name in a request that is
not in the profile stays unresolved. It does not get looked up in, say, the
inbox, because that would make the grant depend on untrusted data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class Contact:
    name: str
    email: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Payee:
    name: str
    account: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Profile:
    user_name: str = "User"
    user_email: str = "user@example.invalid"
    home: str = "/home/user"
    contacts: tuple[Contact, ...] = ()
    payees: tuple[Payee, ...] = ()
    default_amount_ceiling: float = 0.0
    bulk_limit: int = 20
    sensitive_paths: tuple[str, ...] = field(default=())
    today: str | None = None  # trusted context: the date relative words ("Friday") resolve against

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Profile:
        user = data.get("user", {})
        policy = data.get("policy", {})
        return cls(
            user_name=user.get("name", "User"),
            user_email=user.get("email", "user@example.invalid"),
            home=user.get("home", "/home/user"),
            contacts=tuple(Contact(c["name"], c["email"], tuple(c.get("aliases", ()))) for c in data.get("contacts", ())),
            payees=tuple(Payee(p["name"], p["account"], tuple(p.get("aliases", ()))) for p in data.get("payees", ())),
            default_amount_ceiling=float(policy.get("default_amount_ceiling", 0.0)),
            bulk_limit=int(policy.get("bulk_limit", 20)),
            sensitive_paths=tuple(policy.get("sensitive_paths", ())),
            today=data.get("context", {}).get("today"),
        )

    @classmethod
    def load(cls, path: str | Path) -> Profile:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))
