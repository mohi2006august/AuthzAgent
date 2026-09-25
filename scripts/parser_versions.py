"""Compare parser versions on each data split and write results/parser_versions.json.

v1 is loaded from the git tag ``v1-expanded``, so its numbers come from the code as frozen,
not from a re-implementation. Splits:

  dev-v1     original requests t01–t25 (v1 was written against these)
  new        original requests t26–t40 (written after v1 was frozen)
  para       first paraphrase set, t01–t40 (v1: held out for t01–t25; v2: development data)
  heldout    second held-out set, one per task (written before v2; not used to develop it)

    python scripts/parser_versions.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz.parser import RuleBasedParser  # noqa: E402
from authz_bench.tasks import load_suite  # noqa: E402


def load_v1_parser():
    source = subprocess.run(["git", "show", "v1-expanded:src/authz/parser.py"], cwd=ROOT, check=True,
                            capture_output=True, text=True, encoding="utf-8").stdout
    path = Path(tempfile.mkdtemp()) / "parser_v1.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("authz._parser_v1", path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "authz"  # resolve its relative imports against the current package
    sys.modules[spec.name] = module  # dataclasses look their module up while being created
    spec.loader.exec_module(module)
    return module.RuleBasedParser


def v1_scope(record, gold):
    """v1 records predate cancellation dates and URL lists; compare on the fields v1 knew about."""
    scope = record.scope()
    gold_scope = gold.scope()
    for s in (scope, gold_scope):
        s.pop("fetch_urls", None)
        for a in s["actions"]:
            a.pop("date", None)
            if a["kind"] == "cancel_event":
                a["targets"] = []
    return scope, gold_scope


def main() -> None:
    suite = load_suite(ROOT / "tasks")
    parsers = {"v1": load_v1_parser()(suite.profile), "v2": RuleBasedParser(suite.profile)}
    splits = {"dev-v1": [], "new": [], "para": [], "heldout": []}
    for task in suite.tasks:
        number = int(task.id[1:3])
        splits["dev-v1" if number <= 25 else "new"].append((task, task.request))
        splits["para"] += [(task, p) for p in task.paraphrases]
        splits["heldout"] += [(task, h) for h in task.heldout]

    out: dict[str, dict] = {}
    for version, parser in parsers.items():
        out[version] = {}
        for split, items in splits.items():
            exact = actions = 0
            for task, request in items:
                gold = task.gold(request)
                record = parser.parse(request)
                if version == "v1":
                    scope, gold_scope = v1_scope(record, gold)
                else:
                    scope, gold_scope = record.scope(), gold.scope()
                exact += scope == gold_scope
                actions += scope["actions"] == gold_scope["actions"]
            out[version][split] = {"n": len(items), "exact": exact, "actions": actions}
    path = ROOT / "results" / "parser_versions.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    for version, rows in out.items():
        print(version, {k: f"{v['exact']}/{v['n']} exact, {v['actions']}/{v['n']} actions" for k, v in rows.items()})


if __name__ == "__main__":
    main()
