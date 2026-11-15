# Test fixtures

Every fixture is labelled by provenance, because a detection corpus that mixes
real and invented traffic without saying which is which cannot be reasoned
about. "Synthetic" means the lines were written by hand to exercise a rule;
"captured" means they came off a live host.

| Fixture | Provenance | Notes |
|---|---|---|
| `weblog/webui-benign-real.log` | **Captured** | 150 real request lines from the Hermes WebUI on the homelab LXC, sources `10.0.20.235` and `10.0.20.1`. Includes genuine `404`s, which is what makes it a strong true-negative corpus: the rules must stay quiet on real failing requests. |
| `weblog/scanner-path-enumeration.log` | Synthetic | Six distinct scanner paths from one source inside a minute. |
| `weblog/scanner-below-threshold.log` | Synthetic | Three paths only; must stay below the enumeration threshold. |
| `sshd/bruteforce-single-source.log` | Synthetic | Six failed passwords from one source inside five minutes, usernames rotating. |
| `sshd/bruteforce-below-threshold.log` | Synthetic | Three failures; below threshold. |
| `sshd/bruteforce-slow-outside-window.log` | Synthetic | Six failures spread over 35 minutes; tests that the sliding window expires. |
| `sshd/malformed-timestamps.log` | Synthetic | Five failures from one source, two carrying impossible timestamps (`08:00:70`, `Nov 32`). Regression fixture for a crash where unparseable timestamps aborted the whole scan. |
| `sshd/benign-admin-activity.log` | Synthetic | Normal admin sessions, including one mistyped password, from trusted ranges. |
| `dnsmasq/queries-mixed.log` | Synthetic | Mostly ordinary resolution with two high-risk TLD lookups. |

## Address ranges

Synthetic fixtures use the documentation ranges reserved by RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for hostile sources, so no
fixture ever implicates a real network. Internal addresses are RFC 1918 or the
Tailscale CGNAT range and are safe to publish.

## Adding captured logs

Sanitise before committing: strip real public IPs, hostnames that leak
infrastructure detail, session tokens, and usernames other than your own.
Captured fixtures are more valuable than synthetic ones precisely because they
contain the awkward real-world lines nobody thinks to invent, so prefer them
where sanitising is practical.
