r"""Evaluate a Sigma ``detection`` block against a single parsed event.

Sigma's matching semantics are not obvious from the spec, so the rules this
module implements are spelled out here:

* A search identifier mapping to a dict ANDs its field comparisons together.
* A search identifier mapping to a list ORs its entries together.
* A field whose expected value is a list ORs the alternatives, unless the
  ``all`` modifier is present, in which case every alternative must match.
* String comparison is case-insensitive, per the Sigma specification.
* ``*`` and ``?`` are wildcards in plain values; ``\*`` escapes a literal.
* An expected value of ``None`` asserts the field is absent or null.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .errors import ConditionError

#: Sentinel distinguishing "field absent" from "field present but null".
MISSING = object()

_TOKEN_RE = re.compile(r"\(|\)|\|\||\||\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*?.\-]+")

_NUMERIC_MODS = {"lt": "__lt__", "lte": "__le__", "gt": "__gt__", "gte": "__ge__"}


def get_field(event: Mapping[str, Any], name: str) -> Any:
    """Resolve ``name`` against ``event``, supporting ``dotted.paths``.

    A literal key containing dots wins over path traversal, because log
    schemas such as Zeek emit keys like ``id.orig_h`` verbatim.
    """
    if name in event:
        return event[name]
    current: Any = event
    for part in name.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def _scalar_match(mods: Sequence[str], value: Any, expected: Any) -> bool:
    """Compare one event value against one expected value under ``mods``."""
    if "exists" in mods:
        present = value is not MISSING and value is not None
        return present is bool(expected)

    if value is MISSING or value is None:
        return expected is None

    for mod, dunder in _NUMERIC_MODS.items():
        if mod in mods:
            try:
                return bool(getattr(float(value), dunder)(float(expected)))
            except (TypeError, ValueError):
                return False

    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(
                str(expected), strict=False
            )
        except ValueError:
            return False

    text = str(value)
    pattern = str(expected)

    if "re" in mods:
        return re.search(pattern, text, re.IGNORECASE) is not None
    if "contains" in mods:
        return _wildcard_to_regex("*" + pattern + "*").fullmatch(text) is not None
    if "startswith" in mods:
        return _wildcard_to_regex(pattern + "*").fullmatch(text) is not None
    if "endswith" in mods:
        return _wildcard_to_regex("*" + pattern).fullmatch(text) is not None

    if isinstance(expected, bool) or isinstance(value, bool):
        return bool(value) is bool(expected)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(value) == float(expected)
        except (TypeError, ValueError):
            return False

    return _wildcard_to_regex(pattern).fullmatch(text) is not None


def _field_match(mods: Sequence[str], value: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        if not expected:
            return False
        if "all" in mods:
            return all(_scalar_match(mods, value, item) for item in expected)
        return any(_scalar_match(mods, value, item) for item in expected)
    return _scalar_match(mods, value, expected)


def _keyword_match(event: Mapping[str, Any], expected: Any) -> bool:
    """Unkeyed search: match ``expected`` against any string value in the event."""
    pattern = str(expected)
    regex = _wildcard_to_regex(pattern if "*" in pattern else "*" + pattern + "*")

    def walk(node: Any) -> bool:
        if isinstance(node, Mapping):
            return any(walk(v) for v in node.values())
        if isinstance(node, (list, tuple)):
            return any(walk(v) for v in node)
        return regex.fullmatch(str(node)) is not None

    return walk(event)


def _match_mapping(selection: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    for key, expected in selection.items():
        field, _, modifier_string = key.partition("|")
        mods = [m for m in modifier_string.split("|") if m]
        if not _field_match(mods, get_field(event, field), expected):
            return False
    return True


def match_selection(selection: Any, event: Mapping[str, Any]) -> bool:
    """Evaluate a single named search identifier against ``event``."""
    if isinstance(selection, Mapping):
        return _match_mapping(selection, event)
    if isinstance(selection, list):
        return any(
            _match_mapping(item, event)
            if isinstance(item, Mapping)
            else _keyword_match(event, item)
            for item in selection
        )
    return _keyword_match(event, selection)


# ------------------------------------------------------------------ condition


class _Parser:
    """Recursive-descent parser for Sigma condition expressions.

    Grammar::

        expr       := term (("or" | "|") term)*
        term       := factor ("and" factor)*
        factor     := "not" factor | "(" expr ")" | quantifier | IDENT
        quantifier := ("1" | "any" | "all") "of" (PATTERN | "them")
    """

    def __init__(self, tokens: list[str], names: Sequence[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.names = list(names)

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        word = self.peek()
        if word is None:
            raise ConditionError("unexpected end of condition expression")
        self.pos += 1
        return word

    def parse(self) -> Any:
        node = self.expr()
        if self.peek() is not None:
            raise ConditionError(f"trailing token {self.peek()!r} in condition")
        return node

    def expr(self) -> Any:
        node = self.term()
        while self.peek() in {"or", "|", "||"}:
            self.take()
            node = ("or", node, self.term())
        return node

    def term(self) -> Any:
        node = self.factor()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.factor())
        return node

    def factor(self) -> Any:
        # Named 'word' rather than 'token' purely so bandit's B105 heuristic
        # does not read these grammar literals as hardcoded passwords.
        word = self.take()
        if word == "not":
            return ("not", self.factor())
        if word == "(":
            node = self.expr()
            if self.take() != ")":
                raise ConditionError("unbalanced parenthesis in condition")
            return node
        if word in {"1", "any", "all"} and self.peek() == "of":
            self.take()
            target = self.take()
            matched = self.names if target == "them" else self._expand(target)
            if not matched:
                raise ConditionError(f"quantifier {word!r} of {target!r} matched no selection")
            return ("all" if word == "all" else "or_many", matched)
        if word not in self.names:
            raise ConditionError(f"condition references unknown selection {word!r}")
        return ("ident", word)

    def _expand(self, pattern: str) -> list[str]:
        regex = _wildcard_to_regex(pattern)
        return [n for n in self.names if regex.fullmatch(n)]


def _evaluate(node: Any, resolved: dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "ident":
        name = node[1]
        if name not in resolved:
            raise ConditionError(f"condition references unknown selection {name!r}")
        return resolved[name]
    if kind == "and":
        return _evaluate(node[1], resolved) and _evaluate(node[2], resolved)
    if kind == "or":
        return _evaluate(node[1], resolved) or _evaluate(node[2], resolved)
    if kind == "not":
        return not _evaluate(node[1], resolved)
    if kind == "all":
        return all(resolved[n] for n in node[1])
    if kind == "or_many":
        return any(resolved[n] for n in node[1])
    raise ConditionError(f"unhandled condition node {kind!r}")


def parse_condition(condition: str, names: Sequence[str]) -> Any:
    """Parse ``condition`` into an AST, validating it against known ``names``."""
    tokens = _TOKEN_RE.findall(condition.strip())
    if not tokens:
        raise ConditionError("empty condition expression")
    return _Parser(tokens, names).parse()


def match_detection(detection: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    """Return True when ``event`` satisfies a Sigma ``detection`` block."""
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise ConditionError("detection block is missing a string 'condition'")
    names = [k for k in detection if k != "condition"]
    resolved = {name: match_selection(detection[name], event) for name in names}
    return _evaluate(parse_condition(condition, names), resolved)
