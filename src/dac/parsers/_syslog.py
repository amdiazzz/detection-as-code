"""Shared helpers for RFC 3164 style syslog lines."""

from __future__ import annotations

import re
from datetime import UTC, datetime

#: ``Nov 14 21:54:06 host program[1234]: message``
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[\w\-./]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


def parse_syslog_timestamp(text: str, *, year: int | None = None) -> datetime | None:
    """Parse a syslog timestamp, which omits the year.

    Syslog's missing year is a real correlation hazard: defaulting to the
    current year silently reorders events across a New Year boundary. The
    caller may pin ``year`` explicitly; fixtures do exactly that so the test
    corpus does not change behaviour on 1 January.
    """
    resolved = year or datetime.now(tz=UTC).year
    try:
        # The year is injected into the input rather than patched on afterwards:
        # strptime without a year is deprecated from Python 3.15 and cannot
        # represent 29 February at all.
        return datetime.strptime(f"{resolved} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def split_syslog(line: str) -> dict[str, str] | None:
    match = SYSLOG_RE.match(line)
    return match.groupdict() if match else None
