# ADR 0004 — Building-block rules do not alert on their own

- **Status:** accepted
- **Date:** 2026/11/14

## Context

"Five failed SSH logins in five minutes" needs a rule matching one failed
login. That base rule is far too noisy to alert on: an internet-exposed host
produces thousands of them a day.

Two ways to express this were considered. Fold the threshold into one rule, or
keep a noisy base rule and correlate it.

Folding it in means the base matcher cannot be reused or tested independently,
and every new threshold duplicates the matching logic. Keeping them separate
means the base rule exists in the rule set and, naively, alerts on every event.

## Decision

Keep base and correlation separate. The engine suppresses standalone alerts
from any detection rule referenced by a correlation rule's `rules` list, and
such rules are tagged `level: informational` to make the intent explicit in the
rule file itself.

## Consequences

**Good.** The base matcher is written and tested once and reused by any number
of correlations. Thresholds change without touching matching logic. The
severity in the rule file honestly reflects how it is used.

**Bad.** A rule's effective behaviour now depends on whether some *other* rule
references it, which is non-local and can surprise. Mitigated by the
`informational` convention and by `test_building_block_rule_is_suppressed_when_a_correlation_consumes_it`,
which pins the behaviour.

Deleting a correlation rule silently un-mutes its base rule. A future
improvement is an explicit `building_block: true` field so the intent lives in
the rule rather than being inferred from references.
