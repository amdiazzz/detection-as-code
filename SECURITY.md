# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Please do not open a public issue for anything exploitable.

Expect an acknowledgement within 7 days.

## Scope

This project parses untrusted input: log lines are written, in part, by whoever
is attacking the monitored system. Findings of particular interest:

- **Parser crashes or hangs** on malformed log lines. A parser that raises on
  bad input hands an attacker a way to blind the pipeline — see
  [the threat model](docs/THREAT_MODEL.md).
- **Regular-expression denial of service** reachable through a rule's `re`
  modifier or a parser pattern.
- **Log injection** that causes one log line to be parsed as several events, or
  that forges fields such as `src_ip`.
- **Rule evaluation errors** causing a rule to silently match nothing.

## Out of scope

- Detection gaps and false negatives in the rule content itself. These are
  ordinary issues — please file one.
- False positives. Use the *False positive* issue template.

## Handling of captured logs

Fixtures in this repository are published deliberately and are either synthetic
or sanitised. Addresses in synthetic fixtures use the RFC 5737 documentation
ranges; internal addresses are RFC 1918 or Tailscale CGNAT. If you believe a
fixture leaks something it should not, report it privately.
