# brain.md — Tool-Call Authorisation

Read first in any new session. Update on every decision.

## What this project is

Least-privilege for agents. The contribution is applying capability security to
agent tool calls, not detecting injection.

## The one-line argument

Anything that reads untrusted text can be persuaded by untrusted text. So the
enforcement point must not read untrusted text. Keep returning to this — it is what
makes the design defensible under questioning.

## Decisions made

| Decision | Reason |
| --- | --- |
| Mediator contains no model | Otherwise it inherits the vulnerability |
| Capability set immutable per task | Mid-task widening is the attack surface |
| Escalation requires the user, not the agent | The agent is the thing being constrained |
| Intent parser is rule-based for the evaluated system (2026-09-25) | Reproducible (75/75 identical fingerprints); fails closed (1 over-grant in 342 poisoned runs). Cost: 66% exact on held-out paraphrases. `IntentParser` protocol leaves room for a model-based parser |
| Irreversible-action budget is per tool (2026-09-25) | Global let one more attack through (t23 duplicate payment) with no gain in over-restriction; per-tool budgets summing to the global are never looser |
| Mediator accepts only canonical paths (rejects `..`, not normalise) | Mediator and tool server can never disagree on which file a path names |
| Hosts match exactly, no subdomain wildcard | Blocks `docs.x.example.evil.example` and `api.docs.x.example` tricks |
| Escalation prompt shows the call + reason code, never the agent's justification | Justification is written after reading untrusted content |
| Escalation widens minimally and versions the grant (`parent` = old fingerprint) | Audit trail shows exactly what the user added |
| Non-canonical paths and schema violations are not escalatable | No scope the user grants makes them meaningful |

## Decisions still open

- Model-based intent parser on trusted input, with a grounding check (every target must appear in the request
  or resolve via the profile), cached per request hash for reproducibility. Main lever on over-restriction.
- F2: binding data-dependent objects (event ids) to trusted attributes. Needs the mediator to read trusted
  metadata, which is a design extension. Decide whether it is in scope.
- F3: egress to exact URLs named in the request, rather than to hosts.

## Conventions

- Every denial has a reason code; no silent failures.
- Task suite lives in `tasks/`, each task a directory with `clean/` and `poisoned/`.
  `task.json` + `clean/` are written by `scripts/author_suite.py` (edit there, re-run);
  `poisoned/` is written by `python -m authz_bench generate` (seed 7, manifest hash in `tasks/_poison_manifest.json`).
- Over-restriction rate is reported in every results table, never omitted.
- Paraphrases in `task.json` are held out: never tune the parser on them. Report both columns.
- Rates are reported with k/n and 95% Wilson intervals.

## Known gotchas

- It is easy to build a mediator that scores perfectly by being maximally
  restrictive. The frontier plot is the defence against fooling yourself.
- Poisoned tool outputs must be realistic. Obvious injections produce a flattering
  result that will not survive a viva question.
- Intent parsing failures look like mediator failures in the logs. Tag them
  separately from the start. (Done: `intent_parse_failure` vs `policy_limit` vs `ablation`.)
- The headline unauthorised rate is a property of the attack mix (8/171 attacks are in scope). Always
  show the breakdown by relation to the grant, and near-miss vs generic attacks separately.
- The scripted agent's task utility is an upper bound: it knows plan arguments even when the read was denied.
- The budget stops the second action, not the wrong first one (F4). An injected duplicate can spend the budget
  and then an attentive user approves the legitimate call → double payment.
- OneDrive locks directories: the generator replaces files in `poisoned/` rather than deleting the directory.

## Current state

2026-09-25. Everything in the PRD's deliverables list exists: library (`src/authz`), reference agent
integration (LangGraph node + Claude agents), task suite (25 tasks, 171 poisoned variants) and generator,
results with frontier plot and failure modes (`results/`), and the technical report draft (`report/report.md`).
76 tests pass. Headline: 4.1% unauthorised at 8% over-restriction; 36% over-restriction on paraphrases.

Next action: run `--agent claude` and `--agent langgraph` on the suite (needs credentials) to replace the
worst-case compliance assumption with measured compliance, then implement the model-based parser.

## Questions for the supervisor

- Is a rule-based intent parser acceptable as a scoped simplification, given it fails closed but reaches
  only 66% exact match on held-out paraphrases? Or should the model-based parser be in scope?
- Preference between a library-first or agent-first framing in the write-up?
- Is F2 (binding event ids via trusted calendar metadata) in scope, or reported as a limitation?
- Should paraphrases come from third parties to remove the single-author threat to validity?
