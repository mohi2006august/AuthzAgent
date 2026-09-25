"""A model-based intent parser that stays inside the security argument.

The model (Claude, through the Anthropic SDK) reads only the trusted request,
never retrieved content, so injection cannot reach it. It returns *verbatim
spans* in a fixed JSON schema: who, what, which files, how much, when. It
never returns resolved addresses or accounts. :func:`authz.grounding.ground`
then resolves those spans against the trusted profile and drops anything that
is not in the request. The capability set is therefore still a function of
trusted input only. The model can make the parse *wrong*, but never *wider*
than what the user named.

Reproducibility: every raw model output is cached, keyed on the prompt version,
model, request and profile. A cached parse re-grounds identically, which is
what the "same request, same capabilities" requirement needs. The first parse
of a new request is a model call, so it is not bit-for-bit reproducible across
model versions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .grounding import ground
from .intent import IntentRecord
from .profile import Profile
from .types import canonical_json

PROMPT_VERSION = "grounded-1"
MODEL = "claude-opus-5"

SYSTEM = """You turn a user's request to their assistant into a structured list of the actions it asks for.

Rules:
- Copy every reference exactly as it is written in the request (a substring of the request). Never resolve a
  name to an address, never invent a recipient, payee, file, URL or amount, and never add actions the user did
  not ask for. If the user says "her" or "them", give the name(s) from the request they refer to, copied exactly.
- kinds: send_email (includes forward, reply, notify, share), transfer (pay, refund, reimburse, move money),
  delete_file, write_file (create, save, edit, append), move_file (references: source then destination),
  create_event (schedule, invite, book), cancel_event.
- Do not include actions the user explicitly says not to do ("don't send it").
- "Tell me", "let me know" and "summarise" are answers to the user, not actions.
- amounts: the amount text exactly as written, e.g. "£86.50". date: the date expression exactly as written.
- all_matching: true when the request covers every matching item ("all .tmp files", "everything on Friday").
  file_pattern: "*.ext" for such file requests, else "".
- separately: true when the user wants one message per recipient.
- read_domains: the data the task needs to read: fs, email, payments, calendar, web.
- paths and urls: every file path and URL in the request, copied exactly."""

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "read_domains": {"type": "array", "items": {"enum": ["fs", "email", "payments", "calendar", "web"]}},
        "paths": {"type": "array", "items": {"type": "string"}},
        "urls": {"type": "array", "items": {"type": "string"}},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"enum": ["send_email", "transfer", "delete_file", "write_file", "move_file",
                                      "create_event", "cancel_event"]},
                    "references": {"type": "array", "items": {"type": "string"}},
                    "amounts": {"type": "array", "items": {"type": "string"}},
                    "date": {"type": "string"},
                    "all_matching": {"type": "boolean"},
                    "file_pattern": {"type": "string"},
                    "separately": {"type": "boolean"},
                },
                "required": ["kind", "references", "amounts", "date", "all_matching", "file_pattern", "separately"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["read_domains", "paths", "urls", "actions"],
    "additionalProperties": False,
}


class ModelParseError(RuntimeError):
    pass


class ParseCache:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._data: dict[str, Any] = {}
        if self.path and self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))

    def get(self, key: str) -> Any:
        return self._data.get(key)

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8")


class GroundedModelParser:
    def __init__(self, profile: Profile, *, model: str = MODEL, client: Any = None,
                 cache_path: str | Path | None = None, use_fallbacks: bool = True, effort: str = "medium"):
        self.profile = profile
        self.model = model
        self._client = client
        self.cache = ParseCache(cache_path)
        self.use_fallbacks = use_fallbacks
        self.effort = effort
        self.name = f"model:{model}/{PROMPT_VERSION}"
        self._profile_digest = hashlib.sha256(canonical_json({
            "contacts": [(c.name, c.email, c.aliases) for c in profile.contacts],
            "payees": [(p.name, p.account, p.aliases) for p in profile.payees],
            "home": profile.home, "today": profile.today,
        }).encode()).hexdigest()[:16]

    def _key(self, request: str) -> str:
        return hashlib.sha256(f"{PROMPT_VERSION}|{self.model}|{self._profile_digest}|{request}".encode()).hexdigest()

    def client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic()
        return self._client

    def _call(self, request: str) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4000,
            "system": SYSTEM,
            "messages": [{"role": "user", "content": request}],
            "output_config": {"effort": self.effort, "format": {"type": "json_schema", "schema": SCHEMA}},
        }
        if self.use_fallbacks:
            response = self.client().beta.messages.create(
                **kwargs, betas=["server-side-fallback-2026-07-01"], fallbacks="default"
            )
        else:
            response = self.client().messages.create(**kwargs)
        if response.stop_reason in ("refusal", "max_tokens"):
            raise ModelParseError(f"model stopped with {response.stop_reason}")
        text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise ModelParseError("no text block in the model response")
        return {"raw": json.loads(text), "model": getattr(response, "model", self.model)}

    def parse(self, request: str) -> IntentRecord:
        key = self._key(request)
        entry = self.cache.get(key)
        if entry is None:
            try:
                entry = self._call(request)
            except ModelParseError as exc:
                # Fail closed: a request we cannot parse grants nothing irreversible.
                return IntentRecord(request=request, parser=self.name, notes=(f"model parse failed: {exc}",))
            self.cache.put(key, entry)
        return ground(entry["raw"], request, self.profile, self.name)
