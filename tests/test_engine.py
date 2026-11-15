"""Tests for the scan orchestration layer."""

from __future__ import annotations

from datetime import datetime

from dac.engine import scan
from dac.report import as_json, as_markdown, as_text
from dac.rule import load_rule, load_rules

from .conftest import RULE_DIRS

ALL_RULES, _ = load_rules(RULE_DIRS)


def _rule(title: str):
    return next(r for r in ALL_RULES if r.title == title)


def test_building_block_rule_is_suppressed_when_a_correlation_consumes_it() -> None:
    """The noisy base rule must not alert on its own once correlated."""
    events = [
        {
            "timestamp": datetime(2026, 11, 14, 3, 0, 0),
            "service": "sshd",
            "product": "linux",
            "auth_result": "failure",
            "auth_method": "password",
            "src_ip": "203.0.113.5",
        }
    ]
    result = scan(ALL_RULES, events)
    assert result.alerts == []
    assert result.events_seen == 1


def test_standalone_rule_alerts_without_a_correlation() -> None:
    events = [
        {
            "timestamp": datetime(2026, 11, 14, 3, 0, 0),
            "service": "sshd",
            "product": "linux",
            "auth_result": "success",
            "src_ip": "203.0.113.5",
        }
    ]
    result = scan(ALL_RULES, events)
    assert [a.rule_title for a in result.alerts] == ["SSH Login Accepted From Untrusted Network"]


def test_deprecated_rules_are_skipped(tmp_path) -> None:
    path = tmp_path / "dep.yml"
    path.write_text(
        "title: Dead\nid: 22222222-2222-3333-4444-555555555555\nstatus: deprecated\n"
        "description: x\nauthor: a\ndate: 2026/11/14\ntags:\n  - attack.discovery\n"
        "logsource:\n  service: sshd\ndetection:\n  selection:\n    a: 1\n  condition: selection\n"
        "falsepositives:\n  - Unknown\nlevel: low\n"
    )
    rule = load_rule(path)
    result = scan([rule], [{"a": 1, "service": "sshd"}])
    assert result.alerts == []
    assert result.skipped_deprecated == [rule.id]


def test_by_level_counts_alerts() -> None:
    events = [
        {
            "timestamp": datetime(2026, 11, 14, 3, 0, 0),
            "service": "sshd",
            "product": "linux",
            "auth_result": "success",
            "src_ip": "203.0.113.5",
        },
        {
            "timestamp": datetime(2026, 11, 14, 3, 0, 1),
            "service": "dnsmasq",
            "product": "linux",
            "category": "dns",
            "action": "query",
            "tld": "zip",
            "query": "x.zip",
        },
    ]
    result = scan(ALL_RULES, events)
    assert result.by_level == {"high": 1, "medium": 1}


class TestReporting:
    def test_text_report_says_no_alerts_when_clean(self) -> None:
        assert "no alerts" in as_text(scan(ALL_RULES, []))

    def test_markdown_report_says_nothing_fired_when_clean(self) -> None:
        assert "No alerts fired." in as_markdown(scan(ALL_RULES, []))

    def test_json_report_is_stable_when_clean(self) -> None:
        import json

        payload = json.loads(as_json(scan(ALL_RULES, [])))
        assert payload["summary"]["alerts"] == 0
        assert payload["alerts"] == []

    def test_json_evidence_is_capped(self) -> None:
        import json

        events = [
            {
                "timestamp": datetime(2026, 11, 14, 3, 0, i),
                "service": "sshd",
                "product": "linux",
                "auth_result": "failure",
                "auth_method": "password",
                "src_ip": "203.0.113.5",
            }
            for i in range(10)
        ]
        payload = json.loads(as_json(scan(ALL_RULES, events), max_evidence=2))
        assert len(payload["alerts"][0]["evidence"]) == 2


def test_unparseable_timestamps_do_not_abort_the_scan() -> None:
    """Regression: mixing None and datetime in the correlation sort key raised
    TypeError, so one corrupt log line aborted the whole scan."""
    from dac.parsers import parse_lines

    from .conftest import fixture_lines

    events = list(parse_lines("sshd", fixture_lines("sshd/malformed-timestamps.log")))
    assert len(events) == 5, "all five lines should still parse into events"
    assert sum(1 for e in events if e["timestamp"] is None) == 2

    result = scan(ALL_RULES, events)
    assert result.undatable_events == 2
    assert result.alerts == [], "three datable failures must stay below the threshold of five"


def test_standalone_alert_surfaces_the_rules_declared_fields() -> None:
    """An alert should carry the evidence its rule declares in `fields`."""
    events = [
        {
            "timestamp": datetime(2026, 11, 14, 7, 0, 4),
            "service": "dnsmasq",
            "product": "linux",
            "category": "dns",
            "action": "query",
            "query": "invoice-update.zip",
            "tld": "zip",
            "src_ip": "10.0.1.26",
        }
    ]
    alert = scan(ALL_RULES, events).alerts[0]
    assert alert.group == {
        "src_ip": "10.0.1.26",
        "query": "invoice-update.zip",
        "tld": "zip",
    }
    assert "query=invoice-update.zip" in alert.summary()
