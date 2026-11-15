r"""Parse Proxmox VE ``pvedaemon`` authentication events from the journal.

Proxmox logs web-UI and API authentication through ``pvedaemon``. Three details
of the real format drive this implementation, and all three are easy to get
wrong by guessing:

**``rhost`` is normally an IPv4-mapped IPv6 address.** Real lines carry
``rhost=::ffff:192.168.1.10``, not ``rhost=192.168.1.10``. Left as-is, the
Sigma ``cidr`` modifier never matches an RFC 1918 range, so a rule excluding
trusted networks would silently fail open. The address is unwrapped to its
IPv4 form here, and the original is preserved as ``src_ip_raw``.

**``msg=`` is not always a credential failure.** Proxmox reuses the
``authentication failure`` prefix for server-side faults such as
``msg=cfs-lock 'authkey' error: got lock request timeout``, which indicates
cluster lock contention rather than an attacker. The reason is exposed as
``msg`` and classified into ``failure_reason`` so rules can distinguish a
credential attack from a broken hypervisor.

**Successful authentications carry no source address.** The success line is
``<root@pam> successful auth for user 'alex@pve'`` with no ``rhost``, so
``src_ip`` is absent on success. A "successful login from an untrusted
network" detection is therefore *not* expressible from this log source alone;
``/var/log/pveproxy/access.log`` is where that address lives.

Normalised fields: ``timestamp``, ``host``, ``program``, ``pid``, ``message``,
``auth_result``, ``src_ip``, ``src_ip_raw``, ``user``, ``user_name``,
``realm``, ``msg``, ``failure_reason``, ``acting_user``, ``product``,
``service``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ._syslog import parse_syslog_timestamp, split_syslog

_FAILURE_RE = re.compile(
    r"^authentication failure;\s+rhost=(?P<rhost>\S+)\s+user=(?P<user>\S+)\s+msg=(?P<msg>.*)$"
)
_SUCCESS_RE = re.compile(r"^<(?P<acting>[^>]+)>\s+successful auth for user\s+'(?P<user>[^']+)'")

#: Failure reasons that indicate a credential problem rather than a broken host.
_CREDENTIAL_REASONS = ("authentication failure", "no such user", "invalid credentials")


def _unwrap_ip(raw: str) -> str | None:
    """Return the plain address for ``rhost``, unwrapping IPv4-mapped IPv6.

    Proxmox binds a dual-stack socket, so an IPv4 client is reported as
    ``::ffff:10.0.1.26``. Returning that verbatim breaks CIDR matching, which
    is the kind of failure that makes a rule quietly useless rather than
    noisily broken.
    """
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else str(address)


def _classify(msg: str) -> str:
    """Bucket a failure reason as ``credentials`` or ``server_error``."""
    lowered = msg.strip().lower()
    if lowered.startswith(_CREDENTIAL_REASONS):
        return "credentials"
    return "server_error"


def _split_user(user: str) -> tuple[str, str | None]:
    """Split ``alex@pve`` into its name and realm."""
    if "@" in user:
        name, _, realm = user.rpartition("@")
        return name, realm or None
    return user, None


def parse_pvedaemon(line: str, *, year: int | None = None) -> dict[str, Any] | None:
    """Parse one pvedaemon line, or return None if it is not an auth event."""
    parts = split_syslog(line)
    if not parts or not parts["program"].startswith("pvedaemon"):
        return None

    message = parts["message"]
    event: dict[str, Any] = {
        "timestamp": parse_syslog_timestamp(parts["ts"], year=year),
        "host": parts["host"],
        "program": parts["program"],
        "pid": int(parts["pid"]) if parts["pid"] else None,
        "message": message,
        "product": "proxmox",
        "service": "pvedaemon",
    }

    if match := _FAILURE_RE.match(message):
        user = match["user"]
        name, realm = _split_user(user)
        msg = match["msg"].strip()
        event.update(
            auth_result="failure",
            src_ip_raw=match["rhost"],
            src_ip=_unwrap_ip(match["rhost"]),
            user=user,
            user_name=name,
            realm=realm,
            msg=msg,
            failure_reason=_classify(msg),
        )
        return event

    if match := _SUCCESS_RE.match(message):
        user = match["user"]
        name, realm = _split_user(user)
        event.update(
            auth_result="success",
            user=user,
            user_name=name,
            realm=realm,
            acting_user=match["acting"],
        )
        return event

    # Any other pvedaemon chatter (task start/end, quorum notices) is not an
    # authentication event. Dropping it keeps the event stream meaningful.
    return None
