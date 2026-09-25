"""Command line: generate poisoned variants, run the suite, build the results."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .agents import make_agent
from .configs import BY_NAME, CONFIGS
from .poison import generate
from .runner import read_records, run_suite, write_records
from .tasks import DEFAULT_SUITE, load_suite

DEFAULT_OUT = DEFAULT_SUITE.parent / "results"


def _run(args: argparse.Namespace) -> list:
    suite = load_suite(args.suite)
    configs = [BY_NAME[c] for c in args.configs] if args.configs else list(CONFIGS)
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
    figures = frontier(metrics, out) + [breakdown(metrics, out)]
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
        print(f"wrote {generate(args.suite, seed=args.poison_seed)} poisoned variants")
        _report(args, _run(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
