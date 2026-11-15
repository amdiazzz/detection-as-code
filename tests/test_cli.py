"""End-to-end tests for the CLI surface."""

from __future__ import annotations

import json

import pytest

from dac.cli import main

from .conftest import FIXTURES_DIR, REPO_ROOT

RULE_ARGS = ["-r", str(REPO_ROOT / "detections"), "-r", str(REPO_ROOT / "correlations")]


def test_validate_passes_on_the_repo_rule_set(capsys) -> None:
    assert main([*RULE_ARGS, "validate"]) == 0
    assert "invalid" in capsys.readouterr().out


def test_rules_lists_every_rule(capsys) -> None:
    assert main([*RULE_ARGS, "rules"]) == 0
    out = capsys.readouterr().out
    assert "SSH Password Brute Force" in out
    assert "correlation" in out


def test_scan_reports_the_bruteforce_alert(capsys) -> None:
    code = main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "sshd/bruteforce-single-source.log"),
            "-p",
            "sshd",
        ]
    )
    out = capsys.readouterr().out
    assert "SSH Password Brute Force" in out
    assert code == 0


def test_scan_json_output_is_valid_json(capsys) -> None:
    main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "sshd/bruteforce-single-source.log"),
            "-p",
            "sshd",
            "-f",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["alerts"] >= 1
    assert payload["alerts"][0]["group"]["src_ip"] == "203.0.113.37"


def test_scan_markdown_output_has_a_table(capsys) -> None:
    main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "weblog/scanner-path-enumeration.log"),
            "-p",
            "weblog",
            "-f",
            "markdown",
        ]
    )
    out = capsys.readouterr().out
    assert "| Level | Rule |" in out


def test_fail_on_sets_a_nonzero_exit_code(capsys) -> None:
    code = main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "sshd/bruteforce-single-source.log"),
            "-p",
            "sshd",
            "--fail-on",
            "high",
        ]
    )
    capsys.readouterr()
    assert code == 1


def test_fail_on_ignores_lower_severity_than_threshold(capsys) -> None:
    code = main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "dnsmasq/queries-mixed.log"),
            "-p",
            "dnsmasq",
            "--fail-on",
            "critical",
        ]
    )
    capsys.readouterr()
    assert code == 0


def test_real_weblog_fixture_produces_no_alerts(capsys) -> None:
    """The captured production traffic must be clean, 404s and all."""
    main(
        [
            *RULE_ARGS,
            "scan",
            str(FIXTURES_DIR / "weblog/webui-benign-real.log"),
            "-p",
            "weblog",
            "-f",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["alerts"] == 0, (
        f"real traffic produced false positives: {payload['alerts']}"
    )
    assert payload["summary"]["events_seen"] == 150


def test_scan_reads_stdin(monkeypatch, capsys) -> None:
    import io

    line = (
        "Nov 14 03:11:11 cs101 sshd[2211]: Accepted password for root "
        "from 203.0.113.37 port 51200 ssh2"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(line))
    main([*RULE_ARGS, "scan", "-", "-p", "sshd"])
    assert "Untrusted Network" in capsys.readouterr().out


def test_unknown_parser_is_rejected_by_argparse() -> None:
    with pytest.raises(SystemExit):
        main([*RULE_ARGS, "scan", "x.log", "-p", "nope"])
