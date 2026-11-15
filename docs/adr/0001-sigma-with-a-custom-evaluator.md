# ADR 0001 — Sigma format with a first-party evaluator

- **Status:** accepted
- **Date:** 2026/11/14

## Context

Rules need a storage format and something that evaluates them against log
events. Three options were considered.

1. **Bespoke YAML plus bespoke matcher.** Total freedom, zero transferability.
2. **Sigma plus pySigma.** Sigma is the de facto open standard for detection
   content, with a large public rule corpus and MITRE ATT&CK conventions
   baked into its tagging.
3. **Raw regular expressions in code.** Fast to start, unreviewable later.

The decisive constraint is that this repository's purpose is *testing rules
against labelled log lines*. pySigma is a conversion library: it compiles a
Sigma rule into a backend query for Splunk, Elasticsearch, and similar. It
deliberately does not evaluate a rule against an in-memory event, because in
its model the SIEM does the matching.

## Decision

Store rules in **Sigma format**, and implement a **small first-party
evaluator** for the subset of Sigma this repository uses.

## Consequences

**Good.** Rules stay portable: they can be fed to pySigma later to target a
real SIEM without rewriting the content. Tags follow ATT&CK conventions, so
coverage is expressible in a standard vocabulary. The test harness can evaluate
a rule directly against a log line, with no SIEM in the loop — which is the
entire point. Field names and modifiers are a documented standard rather than
local invention.

**Bad.** The evaluator is a reimplementation, so it can disagree with pySigma's
semantics. Mitigated by documenting the implemented subset in the README and by
unit-testing the semantics explicitly (case-insensitivity, null-means-absent,
`all` modifier, wildcard escaping) rather than assuming them.

Only a subset is supported. Unsupported constructs must fail validation loudly;
silently matching nothing is the failure mode this whole repository exists to
prevent.

## Alternatives rejected

Bespoke YAML was rejected because the format is the most durable artefact here
— a Sigma rule outlives this tooling. Raw regexes were rejected because a
detection needs reviewable structure, metadata, and severity, not just a
pattern.
