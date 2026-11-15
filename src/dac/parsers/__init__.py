"""Log parsers: turn a raw log line into a flat event dict.

A parser is a callable taking a line and returning a dict, or ``None`` when the
line is not of interest. Parsers normalise onto shared field names
(``src_ip``, ``user``, ``dst_port``, ...) so one rule can cover several log
formats, and they are the only place in the codebase that knows about text
formats -- rules see structured events only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from ..errors import ParserError
from .dnsmasq import parse_dnsmasq
from .sshd import parse_sshd
from .weblog import parse_weblog

Parser = Callable[[str], dict[str, Any] | None]

#: Registry of parser name -> callable, used by the CLI and the test harness.
PARSERS: dict[str, Parser] = {
    "sshd": parse_sshd,
    "dnsmasq": parse_dnsmasq,
    "weblog": parse_weblog,
}


def get_parser(name: str) -> Parser:
    """Look up a parser by name, with a helpful error listing valid names."""
    try:
        return PARSERS[name]
    except KeyError:
        raise ParserError(
            f"unknown parser {name!r}; available: {', '.join(sorted(PARSERS))}"
        ) from None


def parse_lines(name: str, lines: Iterable[str]) -> Iterator[Mapping[str, Any]]:
    """Parse an iterable of lines, skipping blanks and unrecognised entries."""
    parser = get_parser(name)
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        event = parser(line)
        if event is not None:
            yield event


__all__ = [
    "PARSERS",
    "Parser",
    "get_parser",
    "parse_dnsmasq",
    "parse_lines",
    "parse_sshd",
    "parse_weblog",
]
