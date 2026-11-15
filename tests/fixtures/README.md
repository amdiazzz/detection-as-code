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
| `pvedaemon/auth-mixed.log` | Synthetic (format-verified) | Ordinary Proxmox web-UI activity: successes, a couple of credential failures, a cluster-lock fault, and the neighbouring `IPCC.xs` pam line that accompanies every failure. |
| `pvedaemon/bruteforce-single-source.log` | Synthetic (format-verified) | Six credential failures from one public source inside 90 seconds, usernames and realms rotating. |
| `pvedaemon/stale-ticket-renewals.log` | Synthetic (format-verified) | The benign failure-then-success pair a browser produces when it wakes with an expired ticket. The most likely real false positive for any Proxmox auth rule. |
| `dnsmasq/queries-mixed.log` | Synthetic | Mostly ordinary resolution with two high-risk TLD lookups. |

## "Format-verified" synthetic fixtures

A fixture marked *format-verified* is synthetic, but its line formats were
taken from published real Proxmox output rather than guessed. Getting this
wrong is not a theoretical concern — three details of the real `pvedaemon`
format are counter-intuitive and would each have produced a rule that silently
never fires:

- `rhost` is normally an IPv4-mapped IPv6 address (`::ffff:10.0.1.26`), so a
  CIDR test against `10.0.0.0/8` fails against the raw value.
- `msg=` also carries server-side faults such as
  `cfs-lock 'authkey' error: got lock request timeout`, which share the
  `authentication failure` prefix but are not attacks.
- Successful authentications log **no** source address at all.

Sources:

- <https://pve.proxmox.com/wiki/Fail2ban> (the official `pvedaemon` failregex)
- <https://forum.proxmox.com/threads/successfull-access-log-without-ip-address.148857/>
  (success line format; absence of `rhost`)
- <https://forum.proxmox.com/threads/unexpected-authentication-failure-in-syslog.133011/>
  (stale-ticket renewal producing a benign failure)
- <https://forum.proxmox.com/threads/proxmox-ve-web-gui-authentication-will-fail-until-a-reboot.143000>
  (`cfs-lock` failure reason)

These should still be replaced with a sanitised capture from CS101 when one is
available; see issue #23.

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
