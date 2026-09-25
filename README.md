# Tool-call authorisation for autonomous agents

Least privilege for agent tool calls. A capability set is derived once from the user's trusted request and
enforced on every call by a mediator that contains no model and never reads untrusted text. Instructions
that arrive later in the context cannot widen what the agent may do.

* [prd.md](prd.md): requirements · [systemarchitecture.md](systemarchitecture.md): design ·
  [brain.md](brain.md): decisions and state (read first)
* [report/report.md](report/report.md): technical report ·
  [report/supervisor-brief.md](report/supervisor-brief.md): open decisions ·
  [results/results.md](results/results.md): every table · [results/v1/](results/v1/results.md): v1 baseline

**Headline** (v2; scripted worst-case agent; 40 tasks; 266 poisoned variants): the unauthorised action rate
falls from 100% to 1.5% at 7.5% over-restriction. On held-out requests the figures are 1.9% and 10.0%. Every
remaining miss stays inside the granted scope. Mediation takes 23 µs per call at the median.

![frontier](results/frontier.png)

## Quick start

```
pip install -e ".[eval,dev]"
python examples/quickstart.py        # derive / check / audit without an agent
python -m authz_bench all            # generate poisoned variants, run 14 configurations, write results/
python scripts/parser_versions.py    # parser v1 (from git tag) vs v2 accuracy by data split
python -m pytest                     # 108 tests
```

Without installing, prefix commands with `PYTHONPATH=src`. A ready environment with every extra
(including `anthropic` and `langgraph`) is in `.venv`.

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
  parser.py                rule-based intent parser v2 (trusted input only, fails closed)
  model_parser.py          grounded model parser: Claude extracts verbatim spans; cached
  grounding.py             spans -> intent record, only via the request and the profile
  intent.py                intent record
  derive.py                intent record -> capability set (ablation switches for v1 behaviour)
  capabilities.py          immutable capability set, tool grants, grant-level predicates
  constraints.py           path scopes, allow-lists, ceilings, URL scopes, event bindings, per-payee ceilings
  state.py                 trusted structured state (event metadata; no free text)
  dates.py                 resolving "Friday" against the trusted current date
  mediator.py              check(): the pure enforcement function
  session.py               per-task mediation, budget usage, execution history, escalation loop
  escalation.py            minimal, versioned widening on user approval; prompt shows history
  audit.py                 SQLite audit trail + JSON export
  registry.py              tool schemas, effect classes, scoped arguments
  integrations/            framework-agnostic toolbox, LangGraph tool node
src/authz_bench/           the evaluation harness
  world.py                 local mock tool servers over fixtures (+ trusted calendar metadata)
  tasks.py                 suite loader, effect matching
  poison.py                poisoning generator
  agents/                  scripted worst-case agent; Claude (Anthropic SDK) and LangGraph agents
  configs.py runner.py     configurations and the run loop
  metrics.py plot.py report.py
tasks/                     40 tasks: <id>/task.json, clean/, poisoned/  (authored by scripts/author_suite.py)
results/                   runs.jsonl, summary.json, results.md, figures; v1/ baseline
report/                    technical report, supervisor brief
examples/                  quickstart; LangGraph + Claude reference agent
tests/
```

## Running free with a local model (Ollama)

No API key and no cost: the model runs on your own machine through [Ollama](https://ollama.com), and nothing
leaves localhost. The commands check that Ollama is running and the model is downloaded before starting.

```
ollama pull llama3.2        # 2 GB, once (already present on the development machine)

# grounded model parser on a local model (80 requests, parsed once each and cached)
.venv/Scripts/python -m authz_bench all --with-model --parser-backend ollama

# reference agent on a local model: start with two tasks, then the full suite
.venv/Scripts/python -m authz_bench run --agent ollama --configs full no-mediator --tasks t06_pay_invoice t16_cancel_1on1 --out results/ollama-smoke
.venv/Scripts/python -m authz_bench run --agent ollama --configs full no-mediator --out results/ollama
.venv/Scripts/python -m authz_bench report --agent ollama --out results/ollama
```

`--model` / `--parser-model` pick another local model (e.g. `qwen3:8b` after `ollama pull qwen3:8b`). On a
laptop CPU, each agent run takes tens of seconds, so the full suite takes hours. A small local model is much
weaker than Claude at tool use: the results measure *that* model's susceptibility and utility, which is a
different claim from a result on Claude.

## Running with Claude

Needs an Anthropic API key in the terminal you run from (keys are created at console.anthropic.com):

```
$env:ANTHROPIC_API_KEY = "<your key>"      # PowerShell; bash: export ANTHROPIC_API_KEY="<your key>"
```

The commands check the key first (a free model-list call) and stop with a message if it is missing or
rejected, so nothing is spent on a bad key. These calls cost money, so go cheapest first:

```
# 1. grounded model parser on originals + held-out requests: ~80 short calls, roughly $1-2, then cached
.venv/Scripts/python -m authz_bench all --with-model

# 2. Claude agent smoke test on two tasks (~34 runs, a few dollars)
.venv/Scripts/python -m authz_bench run --agent claude --configs full no-mediator --tasks t06_pay_invoice t16_cancel_1on1 --out results/claude-smoke

# 3. full Claude agent run: 612 runs; a rough estimate is on the order of $100 (depends on thinking length)
.venv/Scripts/python -m authz_bench run --agent claude --configs full no-mediator --out results/claude
.venv/Scripts/python -m authz_bench report --agent claude --out results/claude
```

The agents and the model parser use `claude-opus-5` with server-side refusal fallbacks (`fallbacks="default"`)
and record which model answered. Pass `use_fallbacks=False` if you need every turn answered by the same model
during an evaluation. Tools are local fixtures; nothing but model calls leaves the machine.
`examples/langgraph_reference_agent.py t06_pay_invoice bank-details-change` runs one task through the LangGraph agent.

## Versions

| Tag | What |
|---|---|
| `v1` | first version, 25 tasks |
| `v1-expanded` | v1 code on the 40-task suite (the baseline in `results/v1/`) |
| `v2` | current: failure-mode fixes, parser v2, escalation history, grounded model parser |

## Scope and ethics

Poisoned content is authored here and used only against our own agent and mock tool servers. No live
third-party APIs are targeted, and irreversible actions are simulated against local fixtures. All addresses,
accounts and hosts use reserved `.example` domains or fictional identifiers.
