"""Render scan results as text, JSON, or Markdown."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .engine import ScanResult

_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _sorted_alerts(result: ScanResult) -> list[Any]:
    return sorted(result.alerts, key=lambda a: (_LEVEL_ORDER.get(a.level, 9), a.rule_title))


def as_text(result: ScanResult) -> str:
    lines = [a.summary() for a in _sorted_alerts(result)]
    if not lines:
        lines = ["no alerts"]
    counts = ", ".join(f"{k}={v}" for k, v in sorted(result.by_level.items())) or "none"
    lines.append("")
    lines.append(
        f"{len(result.alerts)} alert(s) from {result.events_seen} event(s) "
        f"across {result.rules_evaluated} rule(s); by level: {counts}"
    )
    return "\n".join(lines)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def as_json(result: ScanResult, *, max_evidence: int = 3) -> str:
    payload = {
        "summary": {
            "alerts": len(result.alerts),
            "events_seen": result.events_seen,
            "rules_evaluated": result.rules_evaluated,
            "by_level": result.by_level,
            "skipped_deprecated": result.skipped_deprecated,
        },
        "alerts": [
            {
                "rule_id": a.rule_id,
                "rule_title": a.rule_title,
                "level": a.level,
                "timestamp": _jsonable(a.timestamp),
                "group": _jsonable(a.group),
                "count": a.count,
                "evidence": [_jsonable(e) for e in a.evidence[:max_evidence]],
            }
            for a in _sorted_alerts(result)
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def as_markdown(result: ScanResult) -> str:
    rows = [
        "# Detection scan report",
        "",
        f"- Events examined: **{result.events_seen}**",
        f"- Rules evaluated: **{result.rules_evaluated}**",
        f"- Alerts: **{len(result.alerts)}**",
        "",
    ]
    if not result.alerts:
        rows.append("No alerts fired.")
        return "\n".join(rows)

    rows += ["| Level | Rule | Group | Count | First seen |", "|---|---|---|---|---|"]
    for alert in _sorted_alerts(result):
        group = ", ".join(f"`{k}={v}`" for k, v in alert.group.items()) or "-"
        when = alert.timestamp.isoformat() if alert.timestamp else "-"
        rows.append(f"| {alert.level} | {alert.rule_title} | {group} | {alert.count} | {when} |")
    return "\n".join(rows)


RENDERERS = {"text": as_text, "json": as_json, "markdown": as_markdown}
