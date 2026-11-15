"""Load and validate Sigma rules, including the invariants this repo enforces.

Two rule kinds are supported:

``detection``
    A classic Sigma rule with a ``logsource`` and a ``detection`` block. It is
    evaluated against one event at a time.

``correlation``
    A Sigma correlation rule that aggregates the output of one or more
    detection rules over a time window. See :mod:`dac.correlation`.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import RuleError
from .matcher import match_detection, parse_condition

#: Rule severities, ordered least to most urgent.
LEVELS = ("informational", "low", "medium", "high", "critical")

#: Sigma lifecycle states. ``deprecated`` rules are skipped when scanning.
STATUSES = ("experimental", "test", "stable", "deprecated", "unsupported")

_REQUIRED = ("title", "id", "status", "description", "author", "date", "level", "logsource")

_DATE_RE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z0-9_\-]+)$")


@dataclass(frozen=True)
class Rule:
    """A validated Sigma rule."""

    path: Path
    raw: Mapping[str, Any]

    id: str = field(init=False)
    title: str = field(init=False)
    level: str = field(init=False)
    status: str = field(init=False)
    kind: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.raw.get("id", "")))
        object.__setattr__(self, "title", str(self.raw.get("title", "")))
        object.__setattr__(self, "level", str(self.raw.get("level", "")))
        object.__setattr__(self, "status", str(self.raw.get("status", "")))
        object.__setattr__(
            self, "kind", "correlation" if "correlation" in self.raw else "detection"
        )

    @property
    def detection(self) -> Mapping[str, Any]:
        return self.raw.get("detection", {})

    @property
    def logsource(self) -> Mapping[str, Any]:
        return self.raw.get("logsource", {})

    @property
    def tags(self) -> list[str]:
        return list(self.raw.get("tags", []) or [])

    @property
    def is_deprecated(self) -> bool:
        return self.status == "deprecated"

    def matches(self, event: Mapping[str, Any]) -> bool:
        """Evaluate this rule's detection block against a single event."""
        if self.kind != "detection":
            raise RuleError(f"{self.path}: correlation rules cannot match a single event")
        return match_detection(self.detection, event)

    def applies_to(self, event: Mapping[str, Any]) -> bool:
        """Return True when the event's log source is in scope for this rule.

        A rule's ``logsource`` keys are matched against the event only when the
        event actually carries that key. Parsers are not obliged to populate
        every Sigma log source field, and a missing key must not silently
        suppress a detection -- that failure mode is invisible in production.
        """
        for key, expected in self.logsource.items():
            if key in {"definition"}:
                continue
            actual = event.get(key)
            if actual is not None and str(actual).lower() != str(expected).lower():
                return False
        return True


def _validate_common(data: Mapping[str, Any], path: Path) -> list[str]:
    problems: list[str] = []
    for key in _REQUIRED:
        if key == "logsource" and "correlation" in data:
            continue
        if not data.get(key):
            problems.append(f"missing required field '{key}'")

    rule_id = data.get("id")
    if rule_id:
        try:
            uuid.UUID(str(rule_id))
        except (ValueError, AttributeError, TypeError):
            problems.append(f"id {rule_id!r} is not a UUID")

    if (level := data.get("level")) and level not in LEVELS:
        problems.append(f"level {level!r} not one of {LEVELS}")
    if (status := data.get("status")) and status not in STATUSES:
        problems.append(f"status {status!r} not one of {STATUSES}")
    if (date := data.get("date")) and not _DATE_RE.match(str(date)):
        problems.append(f"date {date!r} is not YYYY/MM/DD")

    tags = data.get("tags") or []
    if not isinstance(tags, list):
        problems.append("tags must be a list")
    else:
        attack_tags = [t for t in tags if str(t).startswith("attack.")]
        if not attack_tags:
            problems.append("at least one 'attack.*' MITRE tag is required")
        problems.extend(
            f"malformed MITRE tag {t!r}" for t in attack_tags if not _ATTACK_TAG_RE.match(str(t))
        )

    fps = data.get("falsepositives")
    if not fps or not isinstance(fps, list):
        problems.append("falsepositives must be a non-empty list (write 'Unknown' if truly none)")

    return problems


def _validate_detection(data: Mapping[str, Any], path: Path) -> list[str]:
    problems: list[str] = []
    detection = data.get("detection")
    if not isinstance(detection, Mapping):
        return ["detection block is missing or not a mapping"]

    condition = detection.get("condition")
    if not isinstance(condition, str):
        return ["detection block needs a string 'condition'"]

    names = [k for k in detection if k != "condition"]
    if not names:
        problems.append("detection block defines no search identifiers")
    try:
        parse_condition(condition, names)
    except Exception as exc:
        problems.append(f"unparseable condition: {exc}")
    return problems


def _validate_correlation(data: Mapping[str, Any], path: Path) -> list[str]:
    problems: list[str] = []
    corr = data.get("correlation")
    if not isinstance(corr, Mapping):
        return ["correlation block is not a mapping"]

    ctype = corr.get("type")
    if ctype not in {"event_count", "value_count"}:
        problems.append(f"correlation type {ctype!r} must be 'event_count' or 'value_count'")
    if not corr.get("rules"):
        problems.append("correlation needs a non-empty 'rules' list")
    if not corr.get("group-by"):
        problems.append("correlation needs a non-empty 'group-by' list")
    if not corr.get("timespan"):
        problems.append("correlation needs a 'timespan' (e.g. 5m, 1h)")
    cond = corr.get("condition")
    if not isinstance(cond, Mapping) or not cond:
        problems.append("correlation needs a condition mapping such as {gte: 5}")
    elif not set(cond) & {"gt", "gte", "lt", "lte", "eq"}:
        problems.append("correlation condition needs one of gt/gte/lt/lte/eq")
    if ctype == "value_count" and not corr.get("field"):
        problems.append("value_count correlation needs a 'field' to count distinct values of")
    return problems


def validate(data: Mapping[str, Any], path: Path) -> list[str]:
    """Return a list of human-readable problems; empty means the rule is valid."""
    if not isinstance(data, Mapping):
        return ["file does not contain a YAML mapping"]
    problems = _validate_common(data, path)
    if "correlation" in data:
        problems.extend(_validate_correlation(data, path))
    else:
        problems.extend(_validate_detection(data, path))
    return problems


def load_rule(path: str | Path) -> Rule:
    """Load and validate a single rule file, raising :class:`RuleError` on problems."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc

    problems = validate(data, path)
    if problems:
        bullets = "\n".join(f"  - {p}" for p in problems)
        raise RuleError(f"{path}: invalid rule:\n{bullets}")
    return Rule(path=path, raw=data)


def iter_rule_paths(roots: Iterable[str | Path]) -> list[Path]:
    """Collect every ``.yml``/``.yaml`` rule path beneath ``roots``, sorted."""
    found: list[Path] = []
    for root in roots:
        root = Path(root)
        if root.is_file():
            found.append(root)
            continue
        for pattern in ("**/*.yml", "**/*.yaml"):
            found.extend(p for p in root.glob(pattern) if not p.name.startswith("_"))
    return sorted(set(found))


def load_rules(roots: Iterable[str | Path]) -> tuple[list[Rule], dict[Path, list[str]]]:
    """Load every rule under ``roots``, returning valid rules and per-path problems."""
    rules: list[Rule] = []
    errors: dict[Path, list[str]] = {}
    for path in iter_rule_paths(roots):
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors[path] = [f"invalid YAML: {exc}"]
            continue
        problems = validate(data, path)
        if problems:
            errors[path] = problems
        else:
            rules.append(Rule(path=path, raw=data))

    seen: dict[str, Path] = {}
    for rule in rules:
        if rule.id in seen:
            errors.setdefault(rule.path, []).append(
                f"duplicate rule id {rule.id} (also used by {seen[rule.id]})"
            )
        else:
            seen[rule.id] = rule.path
    return rules, errors
