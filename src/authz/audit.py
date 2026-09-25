"""Per-task audit trail: intent, granted capabilities, every call and its verdict.

Stored in SQLite (one file, or ``:memory:``) and exportable as JSON. Only the
session writes to it; the agent has no handle on it.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .capabilities import CapabilitySet
from .intent import IntentRecord
from .types import ToolCall, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    request TEXT NOT NULL,
    intent_json TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    task_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    parent TEXT,
    cause TEXT NOT NULL,
    capset_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (task_id, version)
);
CREATE TABLE IF NOT EXISTS calls (
    task_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT,
    detail TEXT,
    capability_version INTEGER NOT NULL,
    escalated INTEGER NOT NULL DEFAULT 0,
    executed INTEGER NOT NULL DEFAULT 0,
    latency_us REAL NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (task_id, seq)
);
CREATE TABLE IF NOT EXISTS escalations (
    task_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    call_seq INTEGER NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL,
    denial_reason TEXT NOT NULL,
    approved INTEGER NOT NULL,
    new_version INTEGER,
    created_at REAL NOT NULL,
    PRIMARY KEY (task_id, seq)
);
"""


@dataclass
class Trail:
    task_id: str
    request: str
    intent: dict[str, Any] | None
    grants: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def denied(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["verdict"] == "deny"]

    def to_json(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "request": self.request,
            "intent": self.intent,
            "grants": self.grants,
            "calls": self.calls,
            "escalations": self.escalations,
            "summary": {
                "calls_attempted": len(self.calls),
                "calls_denied": len(self.denied),
                "escalations": len(self.escalations),
                "escalations_approved": sum(1 for e in self.escalations if e["approved"]),
            },
        }


class AuditStore:
    def __init__(self, path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self._seq: dict[str, int] = {}

    def close(self) -> None:
        self._conn.close()

    # -- writes (session only) ------------------------------------------------------

    def open_task(self, task_id: str, request: str, intent: IntentRecord | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO tasks VALUES (?, ?, ?, ?)",
                (task_id, request, json.dumps(intent.to_json()) if intent else None, time.time()),
            )

    def record_grant(self, task_id: str, capset: CapabilitySet, cause: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, ?)",
                (task_id, capset.version, capset.fingerprint(), capset.parent, cause,
                 json.dumps(capset.to_json()), time.time()),
            )

    def record_call(self, task_id: str, call: ToolCall, verdict: Verdict, *, latency_us: float,
                    escalated: bool = False) -> int:
        with self._lock, self._conn:
            seq = self._seq.get(task_id, 0)
            self._seq[task_id] = seq + 1
            self._conn.execute(
                "INSERT INTO calls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                (
                    task_id, seq, call.tool, call.canonical_args(),
                    "allow" if verdict.allowed else "deny",
                    None if verdict.allowed else verdict.reason.value,  # type: ignore[union-attr]
                    None if verdict.allowed else verdict.detail,  # type: ignore[union-attr]
                    verdict.capability_version, int(escalated), latency_us, time.time(),
                ),
            )
            return seq

    def mark_executed(self, task_id: str, seq: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE calls SET executed = 1 WHERE task_id = ? AND seq = ?", (task_id, seq))

    def record_escalation(self, task_id: str, call_seq: int, call: ToolCall, denial_reason: str,
                          approved: bool, new_version: int | None) -> None:
        with self._lock, self._conn:
            seq = self._conn.execute(
                "SELECT COUNT(*) FROM escalations WHERE task_id = ?", (task_id,)
            ).fetchone()[0]
            self._conn.execute(
                "INSERT INTO escalations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (task_id, seq, call_seq, call.tool, call.canonical_args(), denial_reason, int(approved),
                 new_version, time.time()),
            )

    # -- reads ---------------------------------------------------------------------------

    def trail(self, task_id: str) -> Trail:
        row = self._conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        trail = Trail(task_id, row["request"], json.loads(row["intent_json"]) if row["intent_json"] else None)
        for g in self._conn.execute("SELECT * FROM grants WHERE task_id = ? ORDER BY version", (task_id,)):
            trail.grants.append({
                "version": g["version"], "fingerprint": g["fingerprint"], "parent": g["parent"],
                "cause": g["cause"], "capability_set": json.loads(g["capset_json"]),
            })
        for c in self._conn.execute("SELECT * FROM calls WHERE task_id = ? ORDER BY seq", (task_id,)):
            trail.calls.append({
                "seq": c["seq"], "tool": c["tool"], "args": json.loads(c["args_json"]),
                "verdict": c["verdict"], "reason": c["reason"], "detail": c["detail"],
                "capability_version": c["capability_version"], "escalated": bool(c["escalated"]),
                "executed": bool(c["executed"]), "latency_us": c["latency_us"],
            })
        for e in self._conn.execute("SELECT * FROM escalations WHERE task_id = ? ORDER BY seq", (task_id,)):
            trail.escalations.append({
                "seq": e["seq"], "call_seq": e["call_seq"], "tool": e["tool"], "args": json.loads(e["args_json"]),
                "denial_reason": e["denial_reason"], "approved": bool(e["approved"]), "new_version": e["new_version"],
            })
        return trail

    def task_ids(self) -> list[str]:
        return [r[0] for r in self._conn.execute("SELECT task_id FROM tasks ORDER BY created_at")]

    def export_json(self, path: str | Path, task_ids: list[str] | None = None) -> None:
        ids = task_ids if task_ids is not None else self.task_ids()
        Path(path).write_text(json.dumps([self.trail(t).to_json() for t in ids], indent=2), encoding="utf-8")


_default_store: AuditStore | None = None


def default_store() -> AuditStore:
    global _default_store
    if _default_store is None:
        _default_store = AuditStore()
    return _default_store


def configure_audit(path: str | Path) -> AuditStore:
    global _default_store
    _default_store = AuditStore(path)
    return _default_store


def audit(task_id: str, store: AuditStore | None = None) -> Trail:
    """``audit(task_id) -> Trail`` from the architecture's interface list."""
    return (store or default_store()).trail(task_id)
