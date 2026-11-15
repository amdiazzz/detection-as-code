"""Repository invariants. These are the gates that keep the rule set trustworthy.

A detection rule nobody tested is worse than no rule: it creates the
appearance of coverage. These tests make that failure mode impossible to merge.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dac.rule import iter_rule_paths, load_rules

from .conftest import CASES, FIXTURES_DIR, RULE_DIRS


def test_every_rule_file_is_valid() -> None:
    _, errors = load_rules(RULE_DIRS)
    assert not errors, "invalid rules:\n" + "\n".join(
        f"{path}: {'; '.join(problems)}" for path, problems in errors.items()
    )


def test_rule_ids_are_unique() -> None:
    rules, _ = load_rules(RULE_DIRS)
    seen: dict[str, Path] = {}
    duplicates = []
    for rule in rules:
        if rule.id in seen:
            duplicates.append(f"{rule.id}: {rule.path} and {seen[rule.id]}")
        seen[rule.id] = rule.path
    assert not duplicates, "duplicate rule ids:\n" + "\n".join(duplicates)


def test_every_rule_has_a_test_case() -> None:
    covered = {case.rule_path.resolve() for case in CASES}
    missing = [p for p in iter_rule_paths(RULE_DIRS) if p.resolve() not in covered]
    assert not missing, "rules with no test case in tests/cases:\n" + "\n".join(
        str(p) for p in missing
    )


@pytest.mark.parametrize("case", CASES, ids=str)
def test_case_references_an_existing_rule(case) -> None:
    assert case.rule_path.exists(), f"{case.path} points at missing rule {case.rule_path}"


@pytest.mark.parametrize("case", [c for c in CASES if not c.scenarios], ids=str)
def test_detection_cases_have_both_polarities(case) -> None:
    """A rule proven only to fire has not been shown to be specific."""
    assert case.true_positives, f"{case.path}: needs at least one true positive"
    assert case.true_negatives, f"{case.path}: needs at least one true negative"


@pytest.mark.parametrize("case", [c for c in CASES if c.scenarios], ids=str)
def test_correlation_cases_cover_firing_and_quiet(case) -> None:
    """A threshold rule must be shown to fire AND to stay below the threshold."""
    counts = {s.expect_alerts for s in case.scenarios}
    assert any(c > 0 for c in counts), f"{case.path}: no scenario expects an alert"
    assert 0 in counts, f"{case.path}: no scenario expects silence"


@pytest.mark.parametrize("case", CASES, ids=str)
def test_referenced_fixtures_exist(case) -> None:
    names = [s.fixture for s in case.scenarios] + list(case.true_negative_fixtures)
    missing = [n for n in names if not (FIXTURES_DIR / n).exists()]
    assert not missing, f"{case.path} references missing fixtures: {missing}"
