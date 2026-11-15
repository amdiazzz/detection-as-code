"""Shared fixtures and the loader for the YAML test-case corpus."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "tests" / "cases"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
RULE_DIRS = (REPO_ROOT / "detections", REPO_ROOT / "correlations")


@dataclass(frozen=True)
class Example:
    """One labelled log line."""

    name: str
    line: str


@dataclass(frozen=True)
class Scenario:
    """One correlation scenario: a fixture file and the alert count it must produce."""

    name: str
    fixture: str
    expect_alerts: int


@dataclass(frozen=True)
class Case:
    """A parsed test-case file describing how one rule must behave."""

    path: Path
    rule_path: Path
    parser: str
    true_positives: list[Example] = field(default_factory=list)
    true_negatives: list[Example] = field(default_factory=list)
    true_negative_fixtures: list[str] = field(default_factory=list)
    supporting_rules: list[Path] = field(default_factory=list)
    scenarios: list[Scenario] = field(default_factory=list)

    @property
    def is_correlation(self) -> bool:
        return bool(self.scenarios)

    def __str__(self) -> str:
        return self.path.stem


def _examples(raw: Any, label: str, case_path: Path) -> list[Example]:
    out: list[Example] = []
    for index, item in enumerate(raw or []):
        if isinstance(item, str):
            out.append(Example(name=f"{label}[{index}]", line=item))
        elif isinstance(item, dict) and "line" in item:
            out.append(Example(name=str(item.get("name", f"{label}[{index}]")), line=item["line"]))
        else:
            raise ValueError(f"{case_path}: {label}[{index}] must be a string or have a 'line' key")
    return out


def load_cases() -> list[Case]:
    """Parse every case file under ``tests/cases``."""
    cases: list[Case] = []
    for path in sorted(CASES_DIR.glob("*.yml")):
        data = yaml.safe_load(path.read_text())
        cases.append(
            Case(
                path=path,
                rule_path=REPO_ROOT / data["rule"],
                parser=data["parser"],
                true_positives=_examples(data.get("true_positives"), "true_positives", path),
                true_negatives=_examples(data.get("true_negatives"), "true_negatives", path),
                true_negative_fixtures=list(data.get("true_negative_fixtures") or []),
                supporting_rules=[REPO_ROOT / p for p in data.get("supporting_rules") or []],
                scenarios=[
                    Scenario(
                        name=str(s.get("name", s["fixture"])),
                        fixture=s["fixture"],
                        expect_alerts=int(s["expect_alerts"]),
                    )
                    for s in data.get("scenarios") or []
                ],
            )
        )
    return cases


CASES = load_cases()


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def cases() -> list[Case]:
    return CASES


def fixture_lines(name: str) -> list[str]:
    """Read a fixture log file by its path relative to ``tests/fixtures``."""
    path = FIXTURES_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"fixture {name!r} not found at {path}")
    return path.read_text().splitlines()
