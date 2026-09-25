"""Command line: generate poisoned variants, run the suite, build the results."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .agents import make_agent
from .configs import BY_NAME, DEFAULT_CONFIGS
from .poison import generate
from .runner import read_records, run_suite, write_records
from .tasks import DEFAULT_SUITE, load_suite

DEFAULT_OUT = DEFAULT_SUITE.parent / "results"

NO_CREDENTIALS = """No Anthropic credentials found, so nothing was run.

This command calls Claude. Set an API key in this terminal, then run it again:

  PowerShell:  $env:ANTHROPIC_API_KEY = "<your key>"
  bash:        export ANTHROPIC_API_KEY="<your key>"

(Or run `ant auth login` once if you use the Anthropic CLI.) Keys are created at console.anthropic.com.
The scripted-agent evaluation needs no credentials: python -m authz_bench all"""


def _selected_configs(args: argparse.Namespace) -> list:
    configs = [BY_NAME[c] for c in args.configs] if args.configs else list(DEFAULT_CONFIGS)
    if args.with_model and not args.configs:
        configs += [c for c in BY_NAME.values() if c.needs_model]
    return configs


def _preflight(args: argparse.Namespace, configs: list) -> None:
    """Fail fast, before any paid call, if a Claude-backed run has no working credentials."""
    if args.agent == "scripted" and not any(c.needs_model for c in configs):
        return
    try:
        import anthropic
    except ImportError:
        sys.exit('This needs the Anthropic SDK: pip install -e ".[agents]" (or use .venv/Scripts/python).')
    try:
        anthropic.Anthropic().models.list(limit=1)  # free: lists models, generates no tokens
    except TypeError as exc:
        if "authentication method" not in str(exc):
            raise
        sys.exit(NO_CREDENTIALS)
    except anthropic.AuthenticationError:
        sys.exit("Anthropic rejected the credentials (401). Check that ANTHROPIC_API_KEY is a valid, active key.")
    except anthropic.PermissionDeniedError:
        sys.exit("The credentials are valid but not permitted to use the API (403). Check the key's workspace.")
    except anthropic.APIConnectionError:
        sys.exit("Could not reach the Anthropic API. Check the network connection or proxy settings.")


def _run(args: argparse.Namespace) -> list:
    suite = load_suite(args.suite)
    configs = _selected_configs(args)
    _preflight(args, configs)
    agent_kwargs = {"p_follow": args.p_follow, "seed": args.seed} if args.agent == "scripted" else {}
    agent = make_agent(args.agent, **agent_kwargs)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    start = time.time()
    records = run_suite(suite, configs, agent, tasks=args.tasks, audit_path=out / "audit.sqlite"
                        if args.keep_audit else ":memory:")
    write_records(records, out / "runs.jsonl")
    print(f"{len(records)} runs in {time.time() - start:.1f}s -> {out / 'runs.jsonl'}")
    return records


def _report(args: argparse.Namespace, records: list | None = None) -> None:
    from .metrics import summarise
    from .plot import breakdown, frontier
    from .report import build

    suite = load_suite(args.suite)
    out = Path(args.out)
    records = records if records is not None else read_records(out / "runs.jsonl")
    metrics = summarise(records)
    v1_full = None
    v1_summary = out / "v1" / "summary.json"
    if v1_summary.exists():
        import json

        full = next((c for c in json.loads(v1_summary.read_text(encoding="utf-8"))["configs"] if c["config"] == "full"), None)
        if full:
            v1_full = (full["over_restriction_rate"]["rate"], full["unauthorised_action_rate"]["rate"])
    figures = frontier(metrics, out, v1_full) + [breakdown(metrics, out)]
    path = build(records, suite, out, agent=args.agent, figures=figures)
    print(f"wrote {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authz_bench")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--suite", default=str(DEFAULT_SUITE))
        p.add_argument("--out", default=str(DEFAULT_OUT))
        p.add_argument("--agent", default="scripted", choices=["scripted", "claude", "langgraph"])

    g = sub.add_parser("generate", help="write poisoned variants into tasks/*/poisoned")
    g.add_argument("--suite", default=str(DEFAULT_SUITE))
    g.add_argument("--seed", type=int, default=7)

    for name in ("run", "all"):
        p = sub.add_parser(name, help="run the suite" if name == "run" else "generate, run and report")
        common(p)
        p.add_argument("--configs", nargs="*", choices=list(BY_NAME))
        p.add_argument("--tasks", nargs="*")
        p.add_argument("--p-follow", type=float, default=1.0, help="scripted agent: probability of obeying an injection")
        p.add_argument("--seed", type=int, default=0)
        p.add_argument("--poison-seed", type=int, default=7)
        p.add_argument("--keep-audit", action="store_true", help="write the SQLite audit trail to --out")
        p.add_argument("--with-model", action="store_true",
                       help="also run the grounded model-parser configurations (needs Anthropic credentials)")

    r = sub.add_parser("report", help="rebuild results.md and figures from runs.jsonl")
    common(r)

    args = parser.parse_args(argv)
    if args.command == "generate":
        print(f"wrote {generate(args.suite, seed=args.seed)} poisoned variants")
    elif args.command == "run":
        _run(args)
    elif args.command == "report":
        _report(args)
    elif args.command == "all":
        _preflight(args, _selected_configs(args))
        print(f"wrote {generate(args.suite, seed=args.poison_seed)} poisoned variants")
        _report(args, _run(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
