# Supervisor brief: decisions needing a view

Five questions, each with the evidence behind it and the answer I recommend. Numbers are from
[`results/results.md`](../results/results.md) (40 tasks, 266 poisoned variants, worst-case scripted agent).

## 1. Is a rule-based intent parser acceptable as the default?

**Evidence.**
- *Accuracy.* On held-out requests (written before v2, not used to develop it), the rule-based parser
  matches the hand-labelled intent exactly 90% of the time (36/40), up from 78% for v1, and gets the
  irreversible actions right in 37/40.
- *Failure direction.* It fails closed. Of the four held-out tasks it blocked, only one was a parser error;
  the rest are policy limits no parser could avoid. It over-granted once in 266 poisoned runs.
- *Reproducibility.* It is fully reproducible (120/120 identical fingerprints).
- *The alternative.* A grounded model parser is implemented behind the same interface. The model only
  extracts verbatim spans, which are then resolved deterministically. Its safety property is structural:
  it can never grant anything not named in the request. Its accuracy is unmeasured because no API
  credentials were available.

**Recommendation.** Yes, as the default and reported honestly as a scoped simplification. Measure the model
parser on the held-out split as soon as credentials are available, and report both.

## 2. Library-first or agent-first framing?

**Evidence.** The contribution is the enforcement point and its evaluation, not an agent. The mediator is
framework-agnostic (a generic toolbox, a LangGraph node, and an Anthropic SDK loop all use it unchanged), and
the headline results use an agent that is deliberately not a real model.

**Recommendation.** Library-first. Keep the agent as the reference integration and the source of the
(pending) real-model compliance numbers.

## 3. Is reading trusted structured state in the mediator acceptable?

**Evidence.** v1 could not tell "cancel my 1:1 with Bob on Friday" from "cancel the board meeting": event
ids come from data, so three cancellation attacks succeeded. v2 lets the mediator check an event's start date
and attendee addresses against server-authenticated metadata. It never reads titles or descriptions. That
closed all five wrong-event cancellations, and bound calls fail closed without state. The argument
holds because the tool server is already trusted (compromise is out of scope), and the fields used are set by
the event's organiser. An attacker who organises their own matching event can only cancel that event.

**Recommendation.** Yes, stated explicitly as an extension of the argument: the mediator reads no *free text*,
and only structured, owner-set metadata. The same pattern could close F8 (file modification times for "older
than a week").

## 4. Should "confirm unstated amounts" be on by default?

**Evidence.** When the user states no amount ("pay the outstanding Acme invoice"), the ceiling is a £1,000
policy default, and three in-scope inflation attacks succeed. Setting the ceiling to zero for unstated amounts
(so the user confirms each such payment) cuts unauthorised actions from 1.5% to 0.4%. With an attentive user
the cost is 0.20 prompts per clean task instead of 0.12, and over-restriction stays at 0%.

**Recommendation.** On by default for payments. The prompt load is small, and the prompt shows the exact amount
and payee.

## 5. Should held-out requests come from third parties?

**Evidence.** One author wrote the tasks, the labels, the parser and all three request sets. The protocol
limits the bias (each held-out set was written before the parser version it evaluates), but the author knew
v1's vocabulary when writing the v2 held-out set.

**Recommendation.** Yes. Collect 40–80 requests from two or three people who have not seen the parser, and
use them as the final held-out set. It is cheap, and it removes the strongest threat to validity.
