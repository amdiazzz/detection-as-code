"""Parse dnsmasq / Pi-hole query log lines.

Normalised fields: ``timestamp``, ``host``, ``query_type``, ``query``,
``src_ip``, ``answer``, ``action``, ``tld``, ``product``, ``service``.
"""

from __future__ import annotations

import re
from typing import Any

from ._syslog import parse_syslog_timestamp, split_syslog

_QUERY_RE = re.compile(r"^query\[(?P<qtype>[A-Z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<ip>\S+)")
_REPLY_RE = re.compile(r"^(?P<action>reply|cached)\s+(?P<name>\S+)\s+is\s+(?P<answer>\S+)")
_BLOCK_RE = re.compile(r"^(?:blocked|gravity blocked)\s+(?P<name>\S+)\s+is\s+(?P<answer>\S+)")


def _tld(name: str) -> str | None:
    name = name.rstrip(".")
    return name.rsplit(".", 1)[-1].lower() if "." in name else None


def parse_dnsmasq(line: str, *, year: int | None = None) -> dict[str, Any] | None:
    """Parse one dnsmasq log line, or return None if it is not a DNS event."""
    parts = split_syslog(line)
    if not parts or not parts["program"].startswith(("dnsmasq", "pihole")):
        return None

    message = parts["message"]
    event: dict[str, Any] = {
        "timestamp": parse_syslog_timestamp(parts["ts"], year=year),
        "host": parts["host"],
        "program": parts["program"],
        "message": message,
        "product": "linux",
        "service": "dnsmasq",
        "category": "dns",
    }

    if match := _QUERY_RE.match(message):
        name = match["name"]
        event.update(
            action="query",
            query_type=match["qtype"],
            query=name,
            tld=_tld(name),
            src_ip=match["ip"],
        )
    elif match := _BLOCK_RE.match(message):
        name = match["name"]
        event.update(action="blocked", query=name, tld=_tld(name), answer=match["answer"])
    elif match := _REPLY_RE.match(message):
        name = match["name"]
        event.update(action=match["action"], query=name, tld=_tld(name), answer=match["answer"])
    else:
        return None

    return event
