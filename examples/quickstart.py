"""The three interfaces end to end, with no agent and no model.

    python examples/quickstart.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz import AuditStore, Profile, Session, ToolCall, audit, check, derive  # noqa: E402

profile = Profile.load(ROOT / "tasks" / "_profile.json")
request = "Pay Northwind Supplies £340 for invoice INV-2207."

# 1. derive(request) -> CapabilitySet, before the agent sees anything untrusted
capset = derive(request, profile=profile)
print("granted tools:", capset.tools)

# 2. check(capability_set, call) -> Allow | Deny(reason)
legit = ToolCall("transfer", {"to_account": "GB82 WEST 1234 5698 7654 32", "amount": 340.0, "memo": "INV-2207"})
bec = ToolCall("transfer", {"to_account": "GB47 MIDL 4015 2237 8811 04", "amount": 340.0, "memo": "INV-2207"})
print("legit :", check(capset, legit))
print("attack:", check(capset, bec))

# 3. a session mediates and records every call; audit(task_id) -> Trail
store = AuditStore()
session = Session.start("demo-1", request, profile, audit=store)
session.run(legit, lambda **kw: {"status": "completed"})
session.run(bec, lambda **kw: {"status": "completed"})
session.run(legit, lambda **kw: {"status": "completed"})  # a second payment: budget exhausted
trail = audit("demo-1", store)
print(json.dumps([{k: c[k] for k in ("tool", "verdict", "reason")} for c in trail.calls], indent=1))
