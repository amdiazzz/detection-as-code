# ADR 0003 — Labelled test cases are the merge gate

- **Status:** accepted
- **Date:** 2026/11/14

## Context

The characteristic failure of a detection rule set is not a crash. It is a rule
that looks reasonable, passes review, and matches nothing — or matches
everything and gets muted. Either way the dashboard shows coverage that does
not exist, which is worse than an acknowledged gap because it stops anyone
looking.

Code review alone cannot catch this. Reading a Sigma rule and predicting
whether it fires on a particular log line is exactly the kind of mental
execution humans are bad at.

## Decision

Every rule must ship with a `tests/cases/<name>.yml` file containing at least
one **true positive** and one **true negative**. Correlation rules must have at
least one scenario that fires and one that stays silent. CI fails if any rule
lacks a case file, and `test_every_rule_has_a_test_case` enforces it
structurally rather than by convention.

## Consequences

**Good.** A rule that matches nothing cannot merge. A rule narrowed later
breaks its own true positives. Near-miss negatives (`zipfile.example.com`
against a `.zip` TLD rule) pin specificity, not just sensitivity. Each labelled
line is its own parametrised test, so a regression report names the exact line
that changed behaviour.

**Bad.** Authoring a rule costs more. This is the intended trade: the cost is
paid once by the author instead of repeatedly by whoever is on call.

Test cases can be wrong. A true positive asserting a line the parser does not
even recognise would be a vacuous test, so the harness fails explicitly when a
parser rejects a true-positive line rather than passing silently. Likewise a
negative-fixture test asserts the fixture parsed to a non-zero event count,
because a fixture that parses to nothing proves nothing.

## Note

This decision has already paid for itself. An accidentally malformed fixture
(`08:00:70` as a timestamp) exposed a crash in correlation sorting that would
have let a single corrupt log line abort a production scan. The fixture was
kept deliberately, as `tests/fixtures/sshd/malformed-timestamps.log`.
