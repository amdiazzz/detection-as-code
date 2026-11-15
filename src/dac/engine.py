"""Run a rule set over a stream of events and collect alerts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from .correlation import Alert, correlate
from .rule import Rule


@dataclass
class ScanResult:
    """Everything a scan produced, ready for reporting."""

    alerts: list[Alert] = field(default_factory=list)
    events_seen: int = 0
    rules_evaluated: int = 0
    skipped_deprecated: list[str] = field(default_factory=list)
    undatable_events: int = 0

    @property
    def by_level(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.level] = counts.get(alert.level, 0) + 1
        return counts


def _base_rule_ids(rule: Rule) -> list[str]:
    return [str(r) for r in rule.raw["correlation"]["rules"]]


def scan(rules: Sequence[Rule], events: Iterable[Mapping[str, object]]) -> ScanResult:
    """Evaluate detection rules per event, then feed matches into correlations.

    Events are materialised because correlation needs a second pass. That is a
    deliberate memory-for-simplicity trade; see docs/adr/0002 for the streaming
    design this would need at real log volume.
    """
    result = ScanResult()

    active = [r for r in rules if not r.is_deprecated]
    result.skipped_deprecated = [r.id for r in rules if r.is_deprecated]

    detections = [r for r in active if r.kind == "detection"]
    correlations = [r for r in active if r.kind == "correlation"]
    result.rules_evaluated = len(active)

    by_id = {r.id: r for r in detections}
    by_title = {r.title: r for r in detections}
    matches: dict[str, list[Mapping[str, object]]] = {r.id: [] for r in detections}

    correlated_ids = {rid for c in correlations for rid in _base_rule_ids(c)}

    for event in events:
        result.events_seen += 1
        for rule in detections:
            if not rule.applies_to(event):
                continue
            if not rule.matches(event):
                continue
            matches[rule.id].append(event)
            # A rule that only exists to feed a correlation should not alert on
            # its own; that is what makes a noisy building block usable.
            if rule.id in correlated_ids:
                continue
            timestamp = event.get("timestamp")
            # A rule's `fields` list names the evidence an analyst needs in
            # order to triage it, so surface exactly those on the alert rather
            # than making them go and read the raw event.
            highlights = {
                name: event[name]
                for name in rule.raw.get("fields") or []
                if event.get(name) is not None
            }
            result.alerts.append(
                Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    timestamp=timestamp if hasattr(timestamp, "isoformat") else None,
                    group=highlights,
                    count=1,
                    evidence=[event],
                )
            )

    for rule in correlations:
        stream: list[Mapping[str, object]] = []
        for ref in _base_rule_ids(rule):
            target = by_id.get(ref) or by_title.get(ref)
            if target is None:
                continue
            stream.extend(matches.get(target.id, []))
        # Correlation is time-ordered, so an event whose timestamp failed to
        # parse cannot participate. Dropping it before the sort is deliberate:
        # mixing None (or a 0 sentinel) with datetimes raises TypeError and
        # would let one corrupt log line abort the entire scan.
        datable = [e for e in stream if isinstance(e.get("timestamp"), datetime)]
        result.undatable_events += len(stream) - len(datable)
        datable.sort(key=lambda e: e["timestamp"])  # type: ignore[index,return-value]
        result.alerts.extend(correlate(rule, datable))

    return result
