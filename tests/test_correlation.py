"""Unit tests for the sliding-window correlation engine."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from dac.correlation import correlate, parse_timespan
from dac.errors import RuleError
from dac.rule import Rule


def make_rule(**overrides) -> Rule:
    correlation = {
        "type": "event_count",
        "rules": ["base"],
        "group-by": ["src_ip"],
        "timespan": "5m",
        "condition": {"gte": 3},
    }
    correlation.update(overrides)
    return Rule(
        path=__import__("pathlib").Path("virtual.yml"),
        raw={
            "title": "T",
            "id": "00000000-0000-0000-0000-000000000000",
            "level": "high",
            "status": "test",
            "correlation": correlation,
        },
    )


def events(count: int, *, ip="1.1.1.1", step_seconds=10, field_values=None):
    base = datetime(2026, 11, 14, 3, 0, 0)
    out = []
    for i in range(count):
        event = {"timestamp": base + timedelta(seconds=i * step_seconds), "src_ip": ip}
        if field_values:
            event["uri_path"] = field_values[i % len(field_values)]
        out.append(event)
    return out


class TestTimespan:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400), ("1w", 604800)],
    )
    def test_valid_timespans(self, text, seconds) -> None:
        assert parse_timespan(text) == timedelta(seconds=seconds)

    @pytest.mark.parametrize("text", ["", "5", "m", "5y", "-5m", "5 m"])
    def test_invalid_timespans_raise(self, text) -> None:
        with pytest.raises(RuleError):
            parse_timespan(text)


class TestEventCount:
    def test_fires_at_threshold(self) -> None:
        alerts = correlate(make_rule(), events(3))
        assert len(alerts) == 1
        assert alerts[0].count == 3
        assert alerts[0].group == {"src_ip": "1.1.1.1"}

    def test_stays_quiet_below_threshold(self) -> None:
        assert correlate(make_rule(), events(2)) == []

    def test_fires_only_once_per_group(self) -> None:
        assert len(correlate(make_rule(), events(10))) == 1

    def test_events_outside_the_window_do_not_accumulate(self) -> None:
        assert correlate(make_rule(), events(5, step_seconds=600)) == []

    def test_groups_are_independent(self) -> None:
        stream = sorted(
            events(3, ip="1.1.1.1") + events(2, ip="2.2.2.2"),
            key=lambda e: e["timestamp"],
        )
        alerts = correlate(make_rule(), stream)
        assert [a.group["src_ip"] for a in alerts] == ["1.1.1.1"]

    def test_events_missing_the_group_field_are_dropped(self) -> None:
        stream = [{"timestamp": datetime(2026, 11, 14, 3, 0, i)} for i in range(5)]
        assert correlate(make_rule(), stream) == []

    def test_events_without_a_timestamp_are_dropped(self) -> None:
        assert correlate(make_rule(), [{"src_ip": "1.1.1.1"}] * 5) == []


class TestValueCount:
    def _rule(self):
        return make_rule(type="value_count", field="uri_path", condition={"gte": 3})

    def test_counts_distinct_values(self) -> None:
        stream = events(3, field_values=["/a", "/b", "/c"])
        assert len(correlate(self._rule(), stream)) == 1

    def test_repeated_single_value_never_fires(self) -> None:
        stream = events(10, field_values=["/a"])
        assert correlate(self._rule(), stream) == []


class TestAlertRendering:
    def test_summary_includes_level_group_and_count(self) -> None:
        alert = correlate(make_rule(), events(3))[0]
        summary = alert.summary()
        assert "HIGH" in summary
        assert "src_ip=1.1.1.1" in summary
        assert "x3" in summary
