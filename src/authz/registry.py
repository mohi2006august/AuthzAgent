"""Static description of the tools the mediator knows about.

The registry is trusted configuration, written by the integrator. For each tool
it records the argument schema, the effect class (which drives budgeting), and
which arguments are *scoped*, meaning the capability set may constrain them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

from jsonschema import Draft202012Validator

from .types import Reason

READ = "read"      # observes state; no effect outside the agent's context
EGRESS = "egress"  # sends information out (irreversible for confidentiality)
MUTATE = "mutate"  # changes state; counted against the irreversible-action budget

# Scope kinds: how a scoped argument is constrained, and the denial it produces.
SCOPE_REASONS: Mapping[str, Reason] = {
    "path": Reason.PATH_OUTSIDE_SCOPE,
    "recipient": Reason.RECIPIENT_NOT_ALLOWED,
    "attendee": Reason.ATTENDEE_NOT_ALLOWED,
    "account": Reason.ACCOUNT_NOT_ALLOWED,
    "amount": Reason.AMOUNT_EXCEEDS_CEILING,
    "host": Reason.HOST_NOT_ALLOWED,
    "event": Reason.EVENT_NOT_ALLOWED,
}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    domain: str
    effect: str
    description: str
    schema: Mapping[str, Any]
    scoped_args: Mapping[str, str] = field(default_factory=dict)
    identity_args: tuple[str, ...] = ()

    @property
    def irreversible(self) -> bool:
        return self.effect != READ

    @property
    def budgeted(self) -> bool:
        return self.effect == MUTATE


class ToolRegistry:
    def __init__(self, specs: Iterable[ToolSpec]):
        self._specs = {s.name: s for s in specs}
        self._validators = {name: Draft202012Validator(s.schema) for name, s in self._specs.items()}

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def __getitem__(self, name: str) -> ToolSpec:
        return self._specs[name]

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __iter__(self) -> Iterator[ToolSpec]:
        return iter(self._specs.values())

    def names(self) -> tuple[str, ...]:
        return tuple(self._specs)

    def tools_for(self, domain: str, effect: str | None = None) -> tuple[str, ...]:
        return tuple(
            s.name for s in self._specs.values() if s.domain == domain and (effect is None or s.effect == effect)
        )

    def schema_error(self, name: str, args: Mapping[str, Any]) -> str | None:
        """First schema violation for ``args``, or None if they validate."""
        error = next(iter(self._validators[name].iter_errors(dict(args))), None)
        if error is None:
            return None
        where = "/".join(str(p) for p in error.absolute_path) or "(root)"
        return f"{where}: {error.message}"


_EMAIL = {"type": "string", "pattern": r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$", "maxLength": 254}
_PATH = {"type": "string", "pattern": r"^/[^\x00\\]*$", "maxLength": 1024}


def _obj(properties: Mapping[str, Any], required: Iterable[str] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(required),
        "additionalProperties": False,
    }


DEFAULT_TOOLS: tuple[ToolSpec, ...] = (
    # --- filesystem -------------------------------------------------------
    ToolSpec(
        "list_dir", "fs", READ, "List the entries of a directory.",
        _obj({"path": _PATH}, ["path"]), {"path": "path"}, ("path",),
    ),
    ToolSpec(
        "read_file", "fs", READ, "Read a text file.",
        _obj({"path": _PATH}, ["path"]), {"path": "path"}, ("path",),
    ),
    ToolSpec(
        "write_file", "fs", MUTATE, "Create or overwrite a file with the given content.",
        _obj({"path": _PATH, "content": {"type": "string"}}, ["path", "content"]),
        {"path": "path"}, ("path",),
    ),
    ToolSpec(
        "delete_file", "fs", MUTATE, "Permanently delete a file.",
        _obj({"path": _PATH}, ["path"]), {"path": "path"}, ("path",),
    ),
    # --- email ------------------------------------------------------------
    ToolSpec(
        "search_email", "email", READ, "Search the user's inbox; returns message ids, senders and subjects.",
        _obj({"query": {"type": "string", "maxLength": 500}}, ["query"]),
    ),
    ToolSpec(
        "read_email", "email", READ, "Read one email by id.",
        _obj({"id": {"type": "string", "maxLength": 100}}, ["id"]),
    ),
    ToolSpec(
        "send_email", "email", MUTATE, "Send an email from the user's account.",
        _obj(
            {
                "to": {"type": "array", "items": _EMAIL, "minItems": 1, "maxItems": 50},
                "cc": {"type": "array", "items": _EMAIL, "maxItems": 50},
                "subject": {"type": "string", "maxLength": 500},
                "body": {"type": "string"},
            },
            ["to", "subject", "body"],
        ),
        {"to": "recipient", "cc": "recipient"}, ("to", "cc"),
    ),
    # --- payments ---------------------------------------------------------
    ToolSpec(
        "list_invoices", "payments", READ, "List invoices with payee, account, amount, status and notes.",
        _obj({"status": {"enum": ["open", "paid", "all"]}}),
    ),
    ToolSpec("get_balance", "payments", READ, "Get the current account balance.", _obj({})),
    ToolSpec(
        "transfer", "payments", MUTATE, "Transfer money from the user's account to another account.",
        _obj(
            {
                "to_account": {"type": "string", "minLength": 4, "maxLength": 64},
                "amount": {"type": "number", "exclusiveMinimum": 0},
                "memo": {"type": "string", "maxLength": 200},
            },
            ["to_account", "amount"],
        ),
        {"to_account": "account", "amount": "amount"}, ("to_account", "amount"),
    ),
    # --- calendar ---------------------------------------------------------
    ToolSpec(
        "list_events", "calendar", READ, "List calendar events, optionally for one date (YYYY-MM-DD).",
        _obj({"date": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"}}),
    ),
    ToolSpec(
        "create_event", "calendar", MUTATE, "Create a calendar event and send invitations to the attendees.",
        _obj(
            {
                "title": {"type": "string", "maxLength": 200},
                "start": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$"},
                "attendees": {"type": "array", "items": _EMAIL, "maxItems": 50},
            },
            ["title", "start", "attendees"],
        ),
        {"attendees": "attendee"}, ("attendees", "start"),
    ),
    ToolSpec(
        "cancel_event", "calendar", MUTATE, "Cancel a calendar event and notify its attendees.",
        _obj({"event_id": {"type": "string", "maxLength": 100}}, ["event_id"]),
        {"event_id": "event"}, ("event_id",),
    ),
    # --- web --------------------------------------------------------------
    ToolSpec(
        "fetch_url", "web", EGRESS, "Fetch a web page over HTTP(S).",
        _obj({"url": {"type": "string", "pattern": r"^https?://", "maxLength": 2048}}, ["url"]),
        {"url": "host"}, ("url",),
    ),
)

DEFAULT_REGISTRY = ToolRegistry(DEFAULT_TOOLS)
