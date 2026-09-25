# Tool-call authorisation for autonomous agents

Least privilege for agent tool calls. A capability set is derived once from the user's trusted request and
enforced on every call by a mediator that contains no model and never reads untrusted text. Instructions
that arrive later in the context cannot widen what the agent may do.

* [prd.md](prd.md): requirements · [systemarchitecture.md](systemarchitecture.md): design ·
  [brain.md](brain.md): decisions and state (read first)
* [report/report.md](report/report.md): technical report · [results/results.md](results/results.md): every table

**Headline** (scripted worst-case agent, 25 tasks, 171 poisoned variants): the unauthorised action rate falls from
100% to 4.1% at 8% over-restriction. Every remaining miss stays inside the granted scope. Mediation takes 23 µs
per call at the median.

![frontier](results/frontier.png)

## Quick start

```
pip install -e ".[eval,dev]"
python examples/quickstart.py        # derive / check / audit without an agent
python -m authz_bench all            # generate poisoned variants, run all configurations, write results/
python -m pytest                     # 76 tests
```

Without installing, prefix commands with `PYTHONPATH=src`.

```python
from authz import Profile, derive, check, ToolCall

profile = Profile.load("tasks/_profile.json")
capset = derive("Pay Northwind Supplies £340 for invoice INV-2207.", profile=profile)
check(capset, ToolCall("transfer", {"to_account": "GB47 MIDL 4015 2237 8811 04", "amount": 340}))
# Deny(reason=ACCOUNT_NOT_ALLOWED, ...)
```

## Layout

```
src/authz/                 the library
  parser.py                rule-based intent parser (trusted input only, fails closed)
  intent.py                intent record
  derive.py                intent record -> capability set
  capabilities.py          immutable capability set, tool grants
  constraints.py           path scopes, allow-lists, ceilings, host allow-lists
  mediator.py              check(): the pure enforcement function
  session.py               per-task mediation, budget usage, escalation loop
  escalation.py            minimal, versioned widening on user approval
  audit.py                 SQLite audit trail + JSON export
  registry.py              tool schemas, effect classes, scoped arguments
  integrations/            framework-agnostic toolbox, LangGraph tool node
src/authz_bench/           the evaluation harness
  world.py                 local mock tool servers over fixtures
  tasks.py                 suite loader, effect matching
  poison.py                poisoning generator
  agents/                  scripted worst-case agent; Claude (Anthropic SDK) and LangGraph agents
  configs.py runner.py     configurations and the run loop
  metrics.py plot.py report.py
tasks/                     the suite: <id>/task.json, clean/, poisoned/  (authored by scripts/author_suite.py)
results/                   runs.jsonl, summary.json, results.md, figures
report/                    technical report
examples/                  quickstart; LangGraph + Claude reference agent
tests/
```

## Running with Claude

```
pip install -e ".[agents]"
python -m authz_bench run --agent claude --configs full no-mediator --tasks t06_pay_invoice
python examples/langgraph_reference_agent.py t06_pay_invoice bank-details-change
```

Needs Anthropic credentials. The agents use `claude-opus-5` with adaptive thinking and server-side refusal
fallbacks enabled (`fallbacks="default"`). Pass `use_fallbacks=False` to `ClaudeAgent` if you want every turn
answered by the same model during an evaluation. Tools are local fixtures; nothing but model calls leaves the
machine.

## Scope and ethics

Poisoned content is authored here and used only against our own agent and mock tool servers. No live
third-party APIs are targeted, and irreversible actions are simulated against local fixtures. All addresses,
accounts and hosts use reserved `.example` domains or fictional identifiers.
