"""Run every rule against its labelled corpus.

Each true positive and true negative becomes its own test, so a regression
report names the exact log line that changed behaviour rather than just the
rule.
"""

from __future__ import annotations

import pytest

from dac.engine import scan
from dac.parsers import get_parser, parse_lines
from dac.rule import load_rule

from .conftest import CASES, fixture_lines


def _detection_cases():
    for case in CASES:
        if case.scenarios:
            continue
        for example in case.true_positives:
            yield pytest.param(case, example, True, id=f"{case}-tp-{example.name}")
        for example in case.true_negatives:
            yield pytest.param(case, example, False, id=f"{case}-tn-{example.name}")


@pytest.mark.parametrize(("case", "example", "should_match"), list(_detection_cases()))
def test_detection_example(case, example, should_match) -> None:
    rule = load_rule(case.rule_path)
    event = get_parser(case.parser)(example.line)

    if event is None:
        assert not should_match, (
            f"{rule.title}: parser {case.parser!r} rejected a true-positive line: {example.line!r}"
        )
        return

    matched = rule.applies_to(event) and rule.matches(event)
    if should_match:
        assert matched, f"{rule.title} did NOT fire on true positive {example.name!r}"
    else:
        assert not matched, f"{rule.title} wrongly fired on true negative {example.name!r}"


def _negative_fixture_cases():
    for case in CASES:
        for name in case.true_negative_fixtures:
            yield pytest.param(case, name, id=f"{case}-tnfix-{name}")


@pytest.mark.parametrize(("case", "fixture_name"), list(_negative_fixture_cases()))
def test_rule_is_quiet_on_negative_fixture(case, fixture_name) -> None:
    """A whole known-clean log file must produce no alerts from this rule."""
    rule = load_rule(case.rule_path)
    events = list(parse_lines(case.parser, fixture_lines(fixture_name)))
    assert events, f"fixture {fixture_name} parsed to zero events; the test proves nothing"

    fired = [e for e in events if rule.applies_to(e) and rule.matches(e)]
    assert not fired, (
        f"{rule.title} fired {len(fired)} time(s) on clean fixture {fixture_name}; "
        f"first offending event: {fired[0]!r}"
    )


def _scenario_cases():
    for case in CASES:
        for scenario in case.scenarios:
            yield pytest.param(case, scenario, id=f"{case}-{scenario.name}")


@pytest.mark.parametrize(("case", "scenario"), list(_scenario_cases()))
def test_correlation_scenario(case, scenario) -> None:
    rule = load_rule(case.rule_path)
    rules = [rule] + [load_rule(p) for p in case.supporting_rules]
    events = list(parse_lines(case.parser, fixture_lines(scenario.fixture)))

    result = scan(rules, events)
    fired = [a for a in result.alerts if a.rule_id == rule.id]

    assert len(fired) == scenario.expect_alerts, (
        f"{rule.title} on {scenario.fixture}: expected {scenario.expect_alerts} alert(s), "
        f"got {len(fired)} -> {[a.summary() for a in fired]}"
    )
