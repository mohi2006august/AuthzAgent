# brain.md — Tool-Call Authorisation

Read first in any new session. Update on every decision.

## What this project is

Least-privilege for agents. The contribution is applying capability security to
agent tool calls, not detecting injection.

## The one-line argument

Anything that reads untrusted text can be persuaded by untrusted text. So the
enforcement point must not read untrusted text. Keep returning to this — it is what
makes the design defensible under questioning.

Extension (v2): the mediator may read *trusted structured state*, meaning server-authenticated,
owner-set fields such as an event's start time and attendees, but never free text such as titles
or bodies. A model may help *parse* the request, because the request is trusted, but its output is
grounded: spans must appear verbatim and are resolved only through the profile.

## Decisions made

| Decision | Reason |
| --- | --- |
| Mediator contains no model | Otherwise it inherits the vulnerability |
| Capability set immutable per task | Mid-task widening is the attack surface |
| Escalation requires the user, not the agent | The agent is the thing being constrained |
| Rule-based parser is the default; grounded model parser is available behind the same protocol (2026-09-25) | Rule v2: reproducible, fails closed, 90% exact on held-out requests. Model parser keeps the argument (trusted input, verbatim spans, profile-only resolution, cached) but is unmeasured |
| Irreversible-action budget is per tool (2026-09-25) | Global let the t23 duplicate payment through, with no gain in over-restriction |
| Canonical paths only (reject `..`, do not normalise) | Mediator and tool server can never disagree on which file a path names |
| Egress = exact URLs named, plus query-free same-host navigation (v2) | Closed query-string exfiltration (t12, t18, t36). Path-encoded data still passes |
| cancel_event bound to date + attendees via trusted calendar metadata (v2) | Closed wrong-event cancellations (t16, t35). Fails closed without state |
| Ceiling per payee when several are named (v2) | Closed cross-payee amount (t27) |
| Escalation prompt shows call, reason code and irreversible actions already executed; never the agent's justification | History closes F4 (budget race). Justification is written after reading untrusted content |
| Escalation widens minimally and versions the grant (`parent` = old fingerprint) | Audit trail shows exactly what the user added |
| Non-canonical paths and schema violations are not escalatable | No scope the user grants makes them meaningful |
| "Confirm unstated amounts" is an option, not the default | Removes in-scope amount inflation (F1) at 0.08 extra prompts per clean task; the user should choose |

## Decisions still open

- Whether "confirm unstated amounts" should be on by default (see the results: 1.5% → 0.4% unauthorised).
- F3 residue: path-encoded exfiltration to a granted host. Exact-URL-only mode for sensitive tasks?
- F8: data-dependent filters ("older than a week") cannot be expressed. Accept as a limitation, or add trusted file metadata (mtime) like events?
- Content is unconstrained (who/where/how much, not what). Out of scope, or future work?

## Conventions

- Every denial has a reason code; no silent failures.
- Task suite lives in `tasks/`, each task a directory with `clean/` and `poisoned/`.
  `task.json` + `clean/` are written by `scripts/author_suite.py` (edit there, re-run);
  `poisoned/` is written by `python -m authz_bench generate` (seed 7, manifest hash in `tasks/_poison_manifest.json`).
- Over-restriction rate is reported in every results table, never omitted.
- **Data splits.** Originals t01–t25 are v1 development data. Paraphrases and originals t26–t40 are v2
  development data. The `heldout` requests (one per task) were written before v2 and must not be used to
  change the parser; diagnose them, don't fix. A v3 parser needs a *new* held-out set written first.
- Rates are reported with k/n and 95% Wilson intervals.
- Versions are git tags: `v1` (25 tasks), `v1-expanded` (v1 code on 40 tasks, the baseline), `v2`.
- Run everything that needs `anthropic`/`langgraph` from `.venv` (`.venv/Scripts/python`).

## Known gotchas

- It is easy to build a mediator that scores perfectly by being maximally
  restrictive. The frontier plot is the defence against fooling yourself.
- Poisoned tool outputs must be realistic. Obvious injections produce a flattering
  result that will not survive a viva question.
- Intent parsing failures look like mediator failures in the logs. Tag them
  separately from the start. (Done: `intent_parse_failure` vs `policy_limit` vs `ablation`.)
- The headline unauthorised rate is a property of the attack mix (5/266 attacks are in scope). Always
  show the breakdown by relation to the grant, and near-miss vs generic attacks separately.
- The scripted agent's task utility is an upper bound: it knows plan arguments even when the read was denied.
- The budget stops the second action, not the wrong first one (F4). Show history on escalation.
- Parser rules interact: v2's earlier-payee rule caused the held-out t08 over-grant (F6b). Test rule
  combinations, not just single rules.
- Tokenisation splits ISO dates ("2026 - 10 - 02"); rejoin before resolving (fixed in v2).
- OneDrive locks directories: generators overwrite files rather than deleting directories.

## Current state

2026-09-25: v2 complete and tagged. 40 tasks, 266 poisoned variants, 14 configurations.
Full: 1.5% unauthorised at 7.5% over-restriction (v1: 4.1% / 22.5%); held-out: 1.9% / 10.0%.
All remaining misses are in scope (amounts under a policy ceiling, a bulk-delete pattern).
107 tests pass (LangGraph graph executes; Claude loop and model parser tested with fake clients).

Blocked on credentials (there is no ANTHROPIC_API_KEY and no `ant` profile on this machine):
- `python -m authz_bench run --agent claude` / `--agent langgraph`: measured injection compliance
- `python -m authz_bench all --with-model`: grounded model parser accuracy on the held-out split

Next action: get credentials, run the two commands above, then fix F6b.

## Questions for the supervisor

See `report/supervisor-brief.md` for evidence and a recommended answer to each.
- Is a rule-based intent parser acceptable as the default, with the grounded model parser as the measured alternative?
- Library-first or agent-first framing in the write-up?
- Is reading trusted structured state (event metadata) in the mediator an acceptable extension of the core argument?
- Should "confirm unstated amounts" be on by default?
- Should held-out requests come from third parties to remove the single-author threat?
