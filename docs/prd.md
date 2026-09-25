# PRD — Capability-Based Tool-Call Authorisation for Autonomous Agents

**Status:** draft · **Owner:** <your name> · **Duration:** 16 weeks

## 1. Problem

Autonomous agents execute irreversible actions — writes, deletions, transfers,
message sends — on the basis of chain-of-thought reasoning that is neither
auditable before execution nor verifiable after it. When an agent retrieves
content containing instructions, that content can widen the set of actions the
agent takes. Nothing in the current stack ties an action back to what the user
actually asked for.

## 2. Goal

Derive a least-privilege set of tool scopes from the user's original request, and
enforce it at call time, so that instructions appearing later in the context
cannot expand what the agent is permitted to do.

## 3. Non-goals

- Preventing the agent from being confused. We prevent confusion from becoming
  a privileged action.
- Sandboxing the host or the network. Orthogonal concern.
- Detecting injection. This project assumes injection sometimes succeeds and
  limits the blast radius.

## 4. Threat model

| Dimension | Assumption |
| --- | --- |
| Adversary goal | Cause the agent to perform an action outside the user's intent |
| Capability | Controls content the agent retrieves during the task (documents, API responses, web pages, tool outputs) |
| Knowledge | Knows the agent's tool list and that mediation exists |
| Trust | The user's initial request is trusted; everything after it is not |
| Out of scope | A malicious user, a compromised tool server, weight-level attacks |

## 5. Functional requirements

- **FR-1** Parse the user's request into an intent record before the first model call.
- **FR-2** Derive a capability set — tool names, argument constraints, and a
  budget of irreversible actions — from that intent record.
- **FR-3** Mediate every tool call against the capability set; deny and log on mismatch.
- **FR-4** Require explicit user re-authorisation to widen scope mid-task.
- **FR-5** Produce a per-task audit trail: intent, granted capabilities, calls
  attempted, calls denied.

## 6. Non-functional requirements

- Mediation adds under 50 ms per tool call.
- Capability derivation must be reproducible for the same request.
- Works with any agent framework exposing a tool-call interface.

## 7. Evaluation plan

Build a task suite where each task has known-correct tool usage, then run each
task twice: with clean tool outputs and with poisoned ones.

| Metric | Definition |
| --- | --- |
| Unauthorised action rate | Fraction of poisoned runs where an out-of-intent irreversible action executes |
| Task utility | Fraction of clean runs completing successfully |
| Over-restriction rate | Clean runs blocked by the mediator |
| Escalation attempts caught | Denied calls that were genuinely adversarial |

The headline result is the unauthorised action rate against over-restriction rate.
A mediator that blocks everything is trivially safe and useless; the frontier
between the two is the contribution.

## 8. Deliverables

- Mediation layer as a library plus a reference agent integration.
- Task suite with clean and poisoned variants, and the poisoning generator.
- Results including the frontier plot and a failure-mode section.
- Technical report.

## 9. Scope and ethics

Poisoned content is authored by us and used only against our own agent and our own
mock tool servers. No live third-party APIs are targeted. Irreversible actions in
evaluation are simulated against local fixtures.

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| Intent parsing becomes the whole project | Timebox it; a rule-based parser is acceptable if reported honestly |
| Task suite too easy | Include tasks where the correct action is close to the forbidden one |
| Over-restriction hidden | Report it as a first-class metric, not a footnote |
