"""Parse JSON HTTP access logs (the shape the Hermes WebUI emits).

Example line::

    {"ts": "2026-11-15T03:54:06Z", "remote": "10.0.20.235", "method": "GET",
     "path": "/api/approval/pending", "status": 200, "ms": 0.5}

A ``[webui] `` prefix and a surrounding syslog envelope are both tolerated, so
the same parser works on a raw file and on ``journalctl`` output.

Normalised fields: ``timestamp``, ``src_ip``, ``http_method``, ``uri``,
``uri_path``, ``status_code``, ``duration_ms``, ``user_agent``, ``category``.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

_JSON_START_RE = re.compile(r"\{.*\}\s*$")

_FIELD_ALIASES = {
    "src_ip": ("remote", "remote_addr", "client_ip", "src_ip", "ip"),
    "http_method": ("method", "http_method", "verb"),
    "uri": ("path", "uri", "request_uri", "url"),
    "status_code": ("status", "status_code", "response_code"),
    "duration_ms": ("ms", "duration_ms", "latency_ms"),
    "user_agent": ("user_agent", "ua", "http_user_agent"),
    "host": ("host", "server_name", "hostname"),
}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def parse_weblog(line: str) -> dict[str, Any] | None:
    """Parse one JSON access-log line, or return None when it is not JSON."""
    match = _JSON_START_RE.search(line)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    event: dict[str, Any] = {
        "timestamp": _parse_timestamp(
            payload.get("ts") or payload.get("time") or payload.get("timestamp")
        ),
        "product": "web",
        "service": "http",
        "category": "webserver",
        "raw": payload,
    }

    for canonical, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in payload:
                event[canonical] = payload[alias]
                break

    if isinstance(event.get("status_code"), str) and event["status_code"].isdigit():
        event["status_code"] = int(event["status_code"])

    if uri := event.get("uri"):
        split = urlsplit(str(uri))
        event["uri_path"] = split.path
        event["uri_query"] = split.query

    return event
