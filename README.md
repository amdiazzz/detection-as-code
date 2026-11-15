# detection-as-code

Sigma detection rules for a real segmented homelab, with a test harness that
refuses to let an untested rule reach `main`.

A detection rule nobody tested is worse than no rule at all: it creates the
appearance of coverage while silently matching nothing. This repository treats
detections the way a software team treats code — every rule ships with labelled
log lines that must trigger it and near-miss lines that must not, and CI fails
the pull request if either expectation breaks.

```
          raw log lines                  structured events              alerts
  ┌──────────────────────┐        ┌────────────────────────┐    ┌──────────────────┐
  │ auth.log  (sshd)     │        │ timestamp  src_ip      │    │ detection rules  │
  │ pihole.log (dnsmasq) │ ─────▶ │ user       uri_path    │──▶ │  (per event)     │
  │ access.log (JSON)    │ parser │ status_code  tld  ...  │    │ correlations     │
  └──────────────────────┘        └────────────────────────┘    │  (sliding window)│
                                                                └──────────────────┘
                                                                         │
                                        text / JSON / Markdown report ◀──┘
```

Parsers are the only component that knows about text formats. Rules only ever
see normalised events, so one rule covers several log sources.

## Quickstart

```bash
make venv install      # this box has no system pip; the target bootstraps one
make ci                # validate rules, lint, then run the full corpus
```

Scan a log file:

```bash
.venv/bin/dac scan /var/log/auth.log -p sshd
.venv/bin/dac scan tests/fixtures/sshd/bruteforce-single-source.log -p sshd
```

```
[HIGH] SSH Password Brute Force (src_ip=203.0.113.37) x5 @ 2026-11-14T03:12:31

1 alert(s) from 8 event(s) across 6 rule(s); by level: high=1
```

Other commands:

```bash
dac validate                            # schema-validate every rule
dac rules                               # list rules with severity and MITRE tags
dac scan app.log -p weblog -f json      # machine-readable output
dac scan app.log -p sshd --fail-on high # non-zero exit for pipeline gating
cat x.log | dac scan - -p sshd          # read stdin
```

## What is in here

| Path | Contents |
|---|---|
| `detections/` | Sigma rules evaluated one event at a time |
| `correlations/` | Sigma correlation rules aggregating over a time window |
| `tests/cases/` | Labelled true positives and true negatives, one file per rule |
| `tests/fixtures/` | Log corpora, each labelled captured or synthetic |
| `src/dac/` | Rule loader, condition evaluator, correlation engine, parsers, CLI |
| `docs/adr/` | Architecture decision records |
| `docs/THREAT_MODEL.md` | Threat model of the detection pipeline itself |

## Rules

| Rule | Level | Technique |
|---|---|---|
| SSH Password Authentication Failure | informational | T1110.001 |
| SSH Password Brute Force | high | T1110.001 |
| SSH Login Accepted From Untrusted Network | high | T1078 |
| DNS Query to High-Risk TLD | medium | T1071.004 |
| HTTP Request to Suspicious Admin or Secret Path | medium | T1595.003 |
| HTTP Path Enumeration From Single Source | medium | T1595.003 |

The informational SSH failure rule is a deliberate building block: it is far
too noisy to alert on, and the engine suppresses standalone alerts from any
rule a correlation consumes. See
[ADR 0004](docs/adr/0004-building-block-rules.md).

## Sigma support

Implemented: field modifiers `contains`, `startswith`, `endswith`, `re`,
`cidr`, `all`, `exists`, `lt`/`lte`/`gt`/`gte`; case-insensitive comparison;
`*` and `?` wildcards with backslash escaping; null-means-absent; unkeyed
keyword search; conditions with `and`/`or`/`not`, parentheses, and the
`1 of`/`any of`/`all of`/`them` quantifiers; `event_count` and `value_count`
correlations with `group-by` and `timespan`.

Not implemented: `base64`/`base64offset`/`utf16` encoding modifiers, field
references, rule collections, and the deprecated aggregation syntax
(`| count() by x > 5`) — correlation rules replace it. Unsupported constructs
fail validation loudly rather than matching nothing silently.

## Why a custom evaluator

pySigma converts rules into backend queries for Splunk, Elastic, and similar;
it does not evaluate a rule against an in-memory event. Testing a rule against
labelled log lines needs exactly that, so the evaluator here is deliberately
first-party and deliberately small. See
[ADR 0001](docs/adr/0001-sigma-with-a-custom-evaluator.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the rule-authoring workflow and the
checks CI enforces. The short version: one rule per pull request, with at least
one true positive and one true negative, or CI will reject it.

## License

MIT — see [LICENSE](LICENSE).
