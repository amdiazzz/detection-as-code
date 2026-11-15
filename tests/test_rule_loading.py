"""Unit tests for rule loading and validation."""

from __future__ import annotations

import textwrap

import pytest

from dac.errors import RuleError
from dac.rule import load_rule, load_rules, validate

VALID = textwrap.dedent(
    """
    title: Example
    id: 11111111-2222-3333-4444-555555555555
    status: experimental
    description: An example rule.
    author: Alex Diaz
    date: 2026/11/14
    tags:
      - attack.credential_access
      - attack.t1110.001
    logsource:
      product: linux
      service: sshd
    detection:
      selection:
        auth_result: failure
      condition: selection
    falsepositives:
      - Unknown
    level: low
    """
)


def write(tmp_path, text, name="rule.yml"):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_valid_rule_loads(tmp_path) -> None:
    rule = load_rule(write(tmp_path, VALID))
    assert rule.title == "Example"
    assert rule.kind == "detection"
    assert rule.level == "low"
    assert not rule.is_deprecated


@pytest.mark.parametrize(
    ("replace", "with_", "expected"),
    [
        ("id: 11111111-2222-3333-4444-555555555555", "id: not-a-uuid", "not a UUID"),
        ("level: low", "level: urgent", "level"),
        ("status: experimental", "status: brandnew", "status"),
        ("date: 2026/11/14", "date: 14-11-2026", "YYYY/MM/DD"),
        ("  - attack.credential_access\n  - attack.t1110.001", "  - hygiene", "MITRE tag"),
        ("  - attack.t1110.001", "  - attack.T1110.001.extra", "malformed MITRE tag"),
        ("falsepositives:\n  - Unknown", "falsepositives: []", "falsepositives"),
        ("  condition: selection", "  condition: missing_sel", "unparseable condition"),
        ("title: Example", "title: ''", "missing required field 'title'"),
    ],
)
def test_invalid_rules_are_rejected(tmp_path, replace, with_, expected) -> None:
    mutated = VALID.replace(replace, with_)
    assert mutated != VALID, f"mutation {replace!r} did not apply; the test proves nothing"
    path = write(tmp_path, mutated)
    with pytest.raises(RuleError, match=expected):
        load_rule(path)


def test_malformed_yaml_is_reported(tmp_path) -> None:
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rule(write(tmp_path, "title: [unclosed"))


def test_detection_without_search_identifiers_is_rejected(tmp_path) -> None:
    text = VALID.replace("  selection:\n    auth_result: failure\n", "")
    assert "selection:" not in text, "fixture edit did not apply; check indentation"
    with pytest.raises(RuleError):
        load_rule(write(tmp_path, text))


def test_duplicate_ids_are_reported_across_files(tmp_path) -> None:
    write(tmp_path, VALID, "a.yml")
    write(tmp_path, VALID, "b.yml")
    _, errors = load_rules([tmp_path])
    assert any("duplicate rule id" in p for problems in errors.values() for p in problems)


def test_underscore_prefixed_files_are_skipped(tmp_path) -> None:
    write(tmp_path, "title: template", "_template.yml")
    rules, errors = load_rules([tmp_path])
    assert not rules and not errors


class TestCorrelationValidation:
    BASE = textwrap.dedent(
        """
        title: Corr
        id: 99999999-2222-3333-4444-555555555555
        status: experimental
        description: A correlation.
        author: Alex Diaz
        date: 2026/11/14
        tags:
          - attack.credential_access
        correlation:
          type: event_count
          rules:
            - 11111111-2222-3333-4444-555555555555
          group-by:
            - src_ip
          timespan: 5m
          condition:
            gte: 5
        falsepositives:
          - Unknown
        level: high
        """
    )

    def test_valid_correlation_loads(self, tmp_path) -> None:
        rule = load_rule(write(tmp_path, self.BASE))
        assert rule.kind == "correlation"

    def test_correlation_cannot_match_a_single_event(self, tmp_path) -> None:
        rule = load_rule(write(tmp_path, self.BASE))
        with pytest.raises(RuleError, match="cannot match a single event"):
            rule.matches({"src_ip": "1.1.1.1"})

    @pytest.mark.parametrize(
        ("replace", "with_", "expected"),
        [
            ("type: event_count", "type: magic", "correlation type"),
            ("  timespan: 5m\n", "", "timespan"),
            ("    gte: 5", "    roughly: 5", "gt/gte/lt/lte/eq"),
            ("type: event_count", "type: value_count", "needs a 'field'"),
        ],
    )
    def test_invalid_correlations_are_rejected(self, tmp_path, replace, with_, expected) -> None:
        mutated = self.BASE.replace(replace, with_)
        assert mutated != self.BASE, f"mutation {replace!r} did not apply"
        with pytest.raises(RuleError, match=expected):
            load_rule(write(tmp_path, mutated))


class TestLogsourceScoping:
    def test_applies_to_ignores_fields_the_parser_does_not_emit(self, tmp_path) -> None:
        rule = load_rule(write(tmp_path, VALID))
        assert rule.applies_to({"service": "sshd"}) is True

    def test_applies_to_rejects_a_conflicting_value(self, tmp_path) -> None:
        rule = load_rule(write(tmp_path, VALID))
        assert rule.applies_to({"service": "nginx", "product": "linux"}) is False

    def test_validate_returns_problems_for_non_mapping(self, tmp_path) -> None:
        assert validate(["a", "list"], tmp_path / "x.yml")
