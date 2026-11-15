# ADR 0002 — Correlation over a materialised event list

- **Status:** accepted
- **Date:** 2026/11/14

## Context

Correlation rules aggregate matches of detection rules over a time window.
Detection matching is per event and streams naturally; correlation needs the
matched events of its base rules, time-ordered, before it can count.

Log timestamps are not reliably monotonic. Syslog has second granularity, hosts
disagree about the clock, and journal exports interleave sources — so a
correlation that assumes input order is already sorted will miscount.

## Decision

`scan()` evaluates detection rules in one pass, collects matched events per
rule, then sorts and correlates per correlation rule. The event stream is
materialised in memory.

## Consequences

**Good.** Correct under out-of-order input because sorting is explicit. The
correlation engine is simple enough to unit test exhaustively. Events whose
timestamp failed to parse are dropped before sorting and counted in
`undatable_events`, so corrupt input degrades the result instead of aborting it.

**Bad.** Memory scales with the number of *matched* events, not with the log
size — acceptable here because base rules match a small fraction of lines, but
not acceptable for a rule matching most events at real volume.

## When to revisit

Revisit when scanning logs that do not fit in memory, or when moving to a live
tail. The streaming design would be a bounded reorder buffer — admit events
delayed by less than a watermark, drop or side-channel the rest — which trades
exactness for constant memory. That complexity is not justified while the
largest corpus here is a few hundred lines.
