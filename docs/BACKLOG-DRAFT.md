# Proposed issue backlog (draft — not yet filed)

Each item is sized to be one pull request. Several come directly from residual
risks named in `docs/THREAT_MODEL.md` or from consequences recorded in the
ADRs, which is the intended way for those documents to generate work.

## Milestone: v0.2.0 — Real log ingestion

| # | Title | Labels | Why | Size |
|---|---|---|---|---|
| 1 | `feat(parsers): add a Proxmox pvedaemon auth parser` | parser, detection | CS101/CS102 web-UI logins are currently unmonitored. Closest thing to a real SSH-equivalent surface on the estate. | M |
| 2 | `feat(detections): alert on Proxmox web login failure bursts` | detection, correlation | Pairs with #1; reuses the event_count correlation already built. | S |
| 3 | `feat(cli): add a Discord webhook alert sink` | engine | Alerts currently only print. Discord is the existing homelab alert channel. | M |
| 4 | `feat(ci): nightly scheduled scan of shipped logs` | ci | Turns the repo from a rule library into a running detector. Opens an issue on a new high/critical. | L |

## Milestone: v0.3.0 — Hardening the pipeline

| # | Title | Labels | Why | Size |
|---|---|---|---|---|
| 5 | `feat(ci): fail CI when a fixture contains a public IP or token-shaped string` | ci, security | Threat model T7 residual risk: fixture sanitisation is manual today. | M |
| 6 | `feat(engine): reject rule regexes vulnerable to catastrophic backtracking` | engine, security | Threat model T3 residual risk. Python `re` has no timeout, so a bad `re` modifier can stall a scan. | L |
| 7 | `feat(engine): alert on a rise in undatable_events` | engine, security | Threat model T4 residual risk. A spike in unparseable timestamps is itself a tampering signal; it is counted but nothing watches it. | S |
| 8 | `feat(engine): add an explicit building_block field` | engine | ADR 0004 residual risk: suppression is inferred from correlation references, so deleting a correlation silently un-mutes its base rule. | S |

## Milestone: v0.4.0 — Coverage and breadth

| # | Title | Labels | Why | Size |
|---|---|---|---|---|
| 9 | `feat(docs): generate an ATT&CK coverage matrix from rule tags` | docs | Makes coverage and gaps legible at a glance. Strong portfolio artefact. | M |
| 10 | `feat(engine): support base64 and utf16 field modifiers` | engine | Named as unimplemented in the README; needed for encoded-command detections. | M |
| 11 | `feat(parsers): add a Cloudflare tunnel access log parser` | parser, detection | The tunnel is the only genuinely internet-exposed surface on the estate. | M |
| 12 | `feat(detections): flag tunnel auth from an unexpected ASN` | detection | Needs #11 plus ASN enrichment. The original third rule from the project plan. | L |
| 13 | `docs: add a worked rule-authoring walkthrough` | docs, good first issue | CONTRIBUTING describes the rules; a narrated end-to-end example lowers the barrier. | S |

## Deliberately not proposed yet

- **Live tailing / streaming correlation.** ADR 0002 says revisit only when the
  corpus stops fitting in memory. Not yet true.
- **A SIEM backend via pySigma.** Interesting, but it converts rules rather than
  running them, so it adds no detection coverage.
- **More TLD/path indicator lists.** Padding the existing rules' value lists is
  not new detection capability and inflates the diff for no review value.
