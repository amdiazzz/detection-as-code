# Threat model: the detection pipeline itself

Detection tooling is defensive, which makes it easy to forget it is also an
attack surface. This document models threats against *this pipeline*, not
against the hosts it monitors.

## Assets

| Asset | Why an attacker cares |
|---|---|
| Rule set (`detections/`, `correlations/`) | Disabling or narrowing a rule creates a blind spot that looks like coverage. |
| Test corpus (`tests/`) | Weakening a test case lets a narrowed rule pass CI. |
| Alert output | Suppressed or flooded alerts delay response. |
| Captured fixtures | May leak internal topology if sanitisation fails. |
| CI credentials | Write access to the repository, and whatever the workflow token can reach. |

## Trust boundaries

1. **Log content is untrusted.** Usernames, URI paths, and DNS queries are
   partly attacker-controlled. Everything crossing this boundary is parsed
   defensively.
2. **Rule files are semi-trusted.** They are reviewed, but a rule is executable
   logic: a `re` modifier is a regular expression this engine will run.
3. **Pull requests from forks are untrusted.** They may modify rules, tests,
   and workflow files in the same change.

## Threats

### T1 — Blinding by rule narrowing

An attacker (or a careless contributor) narrows a rule so it no longer matches
real activity while still passing CI.

*Mitigation:* every rule needs true positives that must fire; narrowing a rule
breaks them. Rules are proven quiet against whole captured log files rather
than hand-picked lines, so a rule cannot be trivially rewritten to match
nothing. `CODEOWNERS` requires review on every rule change.

*Residual risk:* a change that edits the rule and its test case consistently
will pass. Review of the diff is the only control, which is exactly why one
rule per pull request is a hard convention here.

### T2 — Log injection

A log field under attacker control contains a newline plus a forged log line,
so one write becomes two events — one of them claiming a benign `src_ip`, or
claiming a successful login that never happened.

*Mitigation:* parsers anchor on the syslog envelope with `^`, so a forged line
lacking a valid envelope is dropped. The JSON parser takes the last
brace-delimited object on the line rather than concatenating fragments.

*Residual risk:* a log source that writes a genuine, well-formed envelope
around attacker-supplied text can still forge an event. This is a property of
the log source, not of the parser. Do not treat a single event as proof of
anything; correlation across independent sources is the defence.

### T3 — Regular-expression denial of service

A rule's `re` modifier, or a parser pattern, exhibits catastrophic
backtracking on a crafted line, stalling the scan.

*Mitigation:* parser patterns are anchored and avoid nested unbounded
quantifiers. Rule `re` modifiers are reviewed.

*Residual risk:* real. Python's `re` has no backtracking limit and no timeout.
A rule author can still introduce a vulnerable pattern. Prefer `contains` and
`startswith` over `re` where they express the same thing; they compile to
linear-time matching here.

### T4 — Crash-based blinding

A malformed log line raises an exception, aborting the scan so nothing after it
is evaluated. An attacker who can emit one bad line disables monitoring for
everything that follows.

*Mitigation:* parsers return `None` instead of raising. Correlation drops
events whose timestamp failed to parse instead of sorting a mixed-type list —
this was a real bug in this codebase, found by an accidentally malformed
fixture, and `tests/fixtures/sshd/malformed-timestamps.log` exists to keep it
fixed.

*Residual risk:* `undatable_events` is counted but nothing yet alerts on a
sudden rise in it, which would itself be a tampering signal.

### T5 — Supply chain

A compromised dependency or GitHub Action executes in CI with repository
credentials.

*Mitigation:* a single runtime dependency (`PyYAML`). `yaml.safe_load` is used
everywhere, never `yaml.load`. Dependabot watches pip and Actions. Workflows
declare least-privilege `permissions`. Actions are referenced by major version
from verified publishers.

*Residual risk:* major-version Action tags are mutable. Pinning to commit SHAs
is stricter and is a reasonable hardening step for a repository holding real
credentials.

### T6 — Alert flooding

An attacker generates noise to bury a real alert, or to train the operator to
ignore the channel.

*Mitigation:* correlations fire once per group per window, not once per event.
Building-block rules never alert standalone.

*Residual risk:* no rate limiting across groups. An attacker using many source
addresses still produces one alert per address.

### T7 — Fixture disclosure

A captured fixture leaks internal hostnames, public addresses, tokens, or
usernames.

*Mitigation:* fixtures are labelled by provenance; synthetic hostile addresses
come from the RFC 5737 documentation ranges; the contributor guide requires
sanitisation. GitHub secret scanning is enabled.

*Residual risk:* sanitisation is manual. An automated pre-commit check for
public IP addresses and token-shaped strings in fixtures would be a genuine
improvement.

## Explicitly out of scope

- Integrity of the log sources themselves. An attacker with root on a monitored
  host can edit its logs before shipping. Remote log shipping and append-only
  storage address that, and belong to the infrastructure, not to this repo.
- Clock integrity. Correlation trusts timestamps; NTP tampering breaks windowing.
- Confidentiality of alert output.
