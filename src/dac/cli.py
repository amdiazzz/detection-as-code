"""Command line interface: ``dac validate``, ``dac scan``, ``dac rules``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .engine import scan
from .parsers import PARSERS, parse_lines
from .report import RENDERERS
from .rule import load_rules

DEFAULT_RULE_DIRS = ("detections", "correlations")


def _rule_roots(values: Sequence[str] | None) -> list[str]:
    if values:
        return list(values)
    return [d for d in DEFAULT_RULE_DIRS if Path(d).exists()]


def cmd_validate(args: argparse.Namespace) -> int:
    rules, errors = load_rules(_rule_roots(args.rules))
    for path, problems in sorted(errors.items()):
        print(f"FAIL {path}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
    print(f"{len(rules)} rule(s) valid, {len(errors)} invalid")
    return 1 if errors else 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules, errors = load_rules(_rule_roots(args.rules))
    for rule in sorted(rules, key=lambda r: (r.kind, r.level, r.title)):
        tags = ",".join(t for t in rule.tags if t.startswith("attack.")) or "-"
        print(f"{rule.kind:11} {rule.level:13} {rule.title}  [{tags}]")
    if errors:
        print(f"({len(errors)} invalid rule file(s); run 'dac validate')", file=sys.stderr)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    rules, errors = load_rules(_rule_roots(args.rules))
    if errors and args.strict:
        print(f"refusing to scan: {len(errors)} invalid rule(s)", file=sys.stderr)
        return 2

    lines: list[str] = []
    for source in args.log:
        if source == "-":
            lines.extend(sys.stdin.read().splitlines())
        else:
            lines.extend(Path(source).read_text(errors="replace").splitlines())

    events = list(parse_lines(args.parser, lines))
    result = scan(rules, events)
    print(RENDERERS[args.format](result))

    if args.fail_on and result.alerts:
        from .report import _LEVEL_ORDER

        threshold = _LEVEL_ORDER[args.fail_on]
        if any(_LEVEL_ORDER.get(a.level, 9) <= threshold for a in result.alerts):
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dac", description="Detection-as-code toolkit")
    parser.add_argument(
        "-r",
        "--rules",
        action="append",
        metavar="PATH",
        help="rule file or directory (repeatable; defaults to detections/ and correlations/)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="schema-validate every rule")
    validate.set_defaults(func=cmd_validate)

    rules_cmd = sub.add_parser("rules", help="list loaded rules")
    rules_cmd.set_defaults(func=cmd_rules)

    scan_cmd = sub.add_parser("scan", help="run rules against a log file")
    scan_cmd.add_argument("log", nargs="+", help="log file(s), or - for stdin")
    scan_cmd.add_argument(
        "-p", "--parser", required=True, choices=sorted(PARSERS), help="log format"
    )
    scan_cmd.add_argument(
        "-f", "--format", default="text", choices=sorted(RENDERERS), help="output format"
    )
    scan_cmd.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "informational"],
        help="exit non-zero when an alert at or above this level fires",
    )
    scan_cmd.add_argument(
        "--strict", action="store_true", help="refuse to scan when any rule is invalid"
    )
    scan_cmd.set_defaults(func=cmd_scan)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
