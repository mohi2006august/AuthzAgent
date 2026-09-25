"""Local mock tool servers over a fixture-backed world.

Nothing leaves the process. "Irreversible" actions are simulated: they mutate
the in-memory world and append to ``effects``, which the evaluator compares
against the task's expected effects.
"""

from __future__ import annotations

import copy
import itertools
import posixpath
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


def merge_fixtures(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Overlay task fixtures onto the shared base world.

    Dict-valued sections (files, web) merge by key; list-valued sections
    (inbox, invoices, events) merge by ``id``; scalars are replaced.
    """
    out = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = {**out[key], **copy.deepcopy(value)}
        elif isinstance(value, list) and isinstance(out.get(key), list):
            by_id = {item["id"]: item for item in out[key]}
            for item in value:
                by_id[item["id"]] = copy.deepcopy(item)
            out[key] = list(by_id.values())
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass
class Effect:
    tool: str
    args: dict[str, Any]


@dataclass
class World:
    files: dict[str, str] = field(default_factory=dict)
    inbox: list[dict[str, Any]] = field(default_factory=list)
    invoices: list[dict[str, Any]] = field(default_factory=list)
    balance: float = 0.0
    events: list[dict[str, Any]] = field(default_factory=list)
    web: dict[str, str] = field(default_factory=dict)
    effects: list[Effect] = field(default_factory=list)
    _ids: Any = field(default_factory=lambda: itertools.count(1), repr=False)

    @classmethod
    def from_fixtures(cls, fixtures: Mapping[str, Any]) -> World:
        f = copy.deepcopy(dict(fixtures))
        return cls(
            files=f.get("files", {}),
            inbox=f.get("inbox", []),
            invoices=f.get("invoices", []),
            balance=float(f.get("balance", 0.0)),
            events=f.get("events", []),
            web=f.get("web", {}),
        )

    def tools(self) -> dict[str, Callable[..., Any]]:
        return {
            "list_dir": self.list_dir, "read_file": self.read_file, "write_file": self.write_file,
            "delete_file": self.delete_file, "search_email": self.search_email, "read_email": self.read_email,
            "send_email": self.send_email, "list_invoices": self.list_invoices, "get_balance": self.get_balance,
            "transfer": self.transfer, "list_events": self.list_events, "create_event": self.create_event,
            "cancel_event": self.cancel_event, "fetch_url": self.fetch_url,
        }

    def _record(self, tool: str, **args: Any) -> None:
        self.effects.append(Effect(tool, copy.deepcopy(args)))

    # -- filesystem --------------------------------------------------------------

    @staticmethod
    def _path(path: str) -> str:
        # Like a real filesystem, resolve "." and ".." rather than refusing them.
        # (The mediator is stricter: it only accepts canonical paths.)
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"invalid path {path!r}")
        return posixpath.normpath(path)

    def list_dir(self, path: str) -> dict[str, Any]:
        root = self._path(path).rstrip("/") or "/"
        prefix = root if root == "/" else root + "/"
        entries = set()
        for name in self.files:
            if name.startswith(prefix):
                rest = name[len(prefix):]
                entries.add(rest.split("/", 1)[0] + ("/" if "/" in rest else ""))
        if not entries:
            return {"error": f"no such directory: {root}"}
        return {"path": root, "entries": sorted(entries)}

    def read_file(self, path: str) -> dict[str, Any]:
        p = self._path(path)
        if p not in self.files:
            return {"error": f"no such file: {p}"}
        return {"path": p, "content": self.files[p]}

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        p = self._path(path)
        self.files[p] = content
        self._record("write_file", path=p)
        return {"written": p, "bytes": len(content.encode())}

    def delete_file(self, path: str) -> dict[str, Any]:
        p = self._path(path)
        if p not in self.files:
            return {"error": f"no such file: {p}"}
        del self.files[p]
        self._record("delete_file", path=p)
        return {"deleted": p}

    # -- email ---------------------------------------------------------------------

    def search_email(self, query: str) -> list[dict[str, Any]]:
        words = [w for w in query.lower().split() if w]
        hits = []
        for m in sorted(self.inbox, key=lambda m: m.get("date", ""), reverse=True):
            text = f"{m.get('subject', '')} {m.get('body', '')} {m.get('from', '')}".lower()
            if all(w in text for w in words):
                hits.append({"id": m["id"], "from": m.get("from"), "subject": m.get("subject"), "date": m.get("date")})
        return hits

    def read_email(self, id: str) -> dict[str, Any]:  # noqa: A002 - matches the tool schema
        for m in self.inbox:
            if m["id"] == id:
                return copy.deepcopy(m)
        return {"error": f"no such message: {id}"}

    def send_email(self, to: list[str], subject: str, body: str, cc: list[str] | None = None) -> dict[str, Any]:
        cc = cc or []
        self._record("send_email", to=sorted(a.lower() for a in to), cc=sorted(a.lower() for a in cc), subject=subject)
        return {"status": "sent", "message_id": f"out-{next(self._ids)}"}

    # -- payments --------------------------------------------------------------------

    def list_invoices(self, status: str = "all") -> list[dict[str, Any]]:
        return [copy.deepcopy(i) for i in self.invoices if status == "all" or i.get("status") == status]

    def get_balance(self) -> dict[str, Any]:
        return {"balance": round(self.balance, 2), "currency": "GBP"}

    def transfer(self, to_account: str, amount: float, memo: str = "") -> dict[str, Any]:
        if amount > self.balance:
            return {"error": "insufficient funds"}
        self.balance -= amount
        account = "".join(to_account.split()).upper()
        self._record("transfer", to_account=account, amount=round(float(amount), 2), memo=memo)
        return {"status": "completed", "reference": f"TX-{next(self._ids):05d}"}

    # -- calendar -------------------------------------------------------------------

    def list_events(self, date: str | None = None) -> list[dict[str, Any]]:
        return [copy.deepcopy(e) for e in self.events if date is None or e.get("start", "").startswith(date)]

    def create_event(self, title: str, start: str, attendees: list[str]) -> dict[str, Any]:
        event_id = f"evt-new-{next(self._ids)}"
        self.events.append({"id": event_id, "title": title, "start": start, "attendees": attendees})
        self._record("create_event", title=title, start=start, attendees=sorted(a.lower() for a in attendees))
        return {"created": event_id, "invitations_sent": len(attendees)}

    def cancel_event(self, event_id: str) -> dict[str, Any]:
        for e in self.events:
            if e["id"] == event_id and e.get("status") != "cancelled":
                e["status"] = "cancelled"
                self._record("cancel_event", event_id=event_id)
                return {"cancelled": event_id}
        return {"error": f"no such event: {event_id}"}

    # -- web -------------------------------------------------------------------------

    def fetch_url(self, url: str) -> dict[str, Any]:
        self._record("fetch_url", url=url)
        page = self.web.get(url)
        if page is None:
            return {"url": url, "status": 404, "body": ""}
        return {"url": url, "status": 200, "body": page}
