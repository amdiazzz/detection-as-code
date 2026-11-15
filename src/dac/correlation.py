"""Sliding-window correlation over the output of detection rules.

Implements the two Sigma correlation types that matter for log-based alerting:

``event_count``
    Fire when the number of matching events in a window crosses a threshold.
    This is how brute-force detection works.

``value_count``
    Fire when the number of *distinct* values of a field crosses a threshold.
    This is how password spraying and port scanning are detected -- many
    distinct targets rather than many attempts at one.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .errors import RuleError
from .rule import Rule

_TIMESPAN_RE = re.compile(r"^(\d+)([smhdw])$")

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_COMPARATORS = {
    "gt": lambda value, bound: value > bound,
    "gte": lambda value, bound: value >= bound,
    "lt": lambda value, bound: value < bound,
    "lte": lambda value, bound: value <= bound,
    "eq": lambda value, bound: value == bound,
}


def parse_timespan(text: str) -> timedelta:
    """Convert a Sigma timespan such as ``5m`` or ``1h`` to a timedelta."""
    match = _TIMESPAN_RE.match(str(text).strip())
    if not match:
        raise RuleError(f"invalid timespan {text!r}; expected forms like 30s, 5m, 1h, 7d")
    amount, unit = match.groups()
    return timedelta(seconds=int(amount) * _UNIT_SECONDS[unit])


@dataclass(frozen=True)
class Alert:
    """A fired detection or correlation, ready to be reported."""

    rule_id: str
    rule_title: str
    level: str
    timestamp: datetime | None
    group: dict[str, Any]
    count: int
    evidence: list[Mapping[str, Any]]

    def summary(self) -> str:
        group = ", ".join(f"{k}={v}" for k, v in self.group.items()) or "-"
        when = self.timestamp.isoformat() if self.timestamp else "unknown-time"
        return f"[{self.level.upper()}] {self.rule_title} ({group}) x{self.count} @ {when}"


def _group_key(event: Mapping[str, Any], fields: Sequence[str]) -> tuple | None:
    """Build a grouping key, or None when a required field is absent.

    An event missing a group-by field cannot be attributed to an actor, so it
    is dropped rather than bucketed under a shared ``None`` key -- otherwise
    unrelated events accumulate into a single phantom group and fire a
    false alert.
    """
    key: list[Any] = []
    for name in fields:
        value = event.get(name)
        if value is None:
            return None
        key.append(value)
    return tuple(key)


def correlate(
    rule: Rule,
    events: Iterable[Mapping[str, Any]],
    *,
    timestamp_field: str = "timestamp",
) -> list[Alert]:
    """Apply a correlation rule to an ordered stream of already-matched events."""
    corr = rule.raw["correlation"]
    group_fields: list[str] = list(corr["group-by"])
    window = parse_timespan(corr["timespan"])
    ctype = corr["type"]
    value_field = corr.get("field")

    condition: Mapping[str, Any] = corr["condition"]
    comparator_name = next(k for k in condition if k in _COMPARATORS)
    bound = condition[comparator_name]
    comparator = _COMPARATORS[comparator_name]

    buckets: dict[tuple, deque[tuple[datetime, Mapping[str, Any]]]] = defaultdict(deque)
    fired: set[tuple] = set()
    alerts: list[Alert] = []

    for event in events:
        when = event.get(timestamp_field)
        if not isinstance(when, datetime):
            continue
        key = _group_key(event, group_fields)
        if key is None:
            continue

        bucket = buckets[key]
        bucket.append((when, event))
        while bucket and when - bucket[0][0] > window:
            bucket.popleft()

        if ctype == "value_count":
            observed = len(
                {e.get(value_field) for _, e in bucket if e.get(value_field) is not None}
            )
        else:
            observed = len(bucket)

        if comparator(observed, bound):
            if key in fired:
                continue
            fired.add(key)
            alerts.append(
                Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    timestamp=when,
                    group=dict(zip(group_fields, key, strict=True)),
                    count=observed,
                    evidence=[e for _, e in bucket],
                )
            )
        else:
            fired.discard(key)

    return alerts
