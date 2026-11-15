"""Parse OpenSSH ``sshd`` authentication lines out of syslog/auth.log.

Normalised fields: ``timestamp``, ``host``, ``program``, ``pid``, ``message``,
``src_ip``, ``src_port``, ``user``, ``auth_method``, ``auth_result``,
``invalid_user``, ``dst_port``, ``product``, ``service``.
"""

from __future__ import annotations

import re
from typing import Any

from ._syslog import parse_syslog_timestamp, split_syslog

_FAILED_RE = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")
_CONNECTION_RE = re.compile(
    r"^Connection (?:from|closed by) (?:authenticating user (?P<user>\S+) )?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) port (?P<port>\d+)"
    r"(?: on (?P<local_ip>\S+) port (?P<local_port>\d+))?"
)
_LISTEN_RE = re.compile(r"^Server listening on (?P<local_ip>\S+) port (?P<local_port>\d+)")


def parse_sshd(line: str, *, year: int | None = None) -> dict[str, Any] | None:
    """Parse one sshd log line, or return None if it is not an sshd event."""
    parts = split_syslog(line)
    if not parts or not parts["program"].startswith("sshd"):
        return None

    message = parts["message"]
    event: dict[str, Any] = {
        "timestamp": parse_syslog_timestamp(parts["ts"], year=year),
        "host": parts["host"],
        "program": parts["program"],
        "pid": int(parts["pid"]) if parts["pid"] else None,
        "message": message,
        "product": "linux",
        "service": "sshd",
    }

    if match := _FAILED_RE.match(message):
        event.update(
            auth_result="failure",
            auth_method=match["method"],
            user=match["user"],
            invalid_user=bool(match["invalid"]),
            src_ip=match["ip"],
            src_port=int(match["port"]),
        )
    elif match := _ACCEPTED_RE.match(message):
        event.update(
            auth_result="success",
            auth_method=match["method"],
            user=match["user"],
            invalid_user=False,
            src_ip=match["ip"],
            src_port=int(match["port"]),
        )
    elif match := _INVALID_USER_RE.match(message):
        event.update(
            auth_result="failure",
            user=match["user"],
            invalid_user=True,
            src_ip=match["ip"],
            src_port=int(match["port"]),
        )
    elif match := _CONNECTION_RE.match(message):
        event.update(src_ip=match["ip"], src_port=int(match["port"]))
        if match["user"]:
            event["user"] = match["user"]
        if match["local_port"]:
            event["dst_ip"] = match["local_ip"]
            event["dst_port"] = int(match["local_port"])
    elif match := _LISTEN_RE.match(message):
        event.update(dst_ip=match["local_ip"], dst_port=int(match["local_port"]))

    return event
