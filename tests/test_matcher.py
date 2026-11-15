"""Unit tests for Sigma matching semantics."""

from __future__ import annotations

import pytest

from dac.errors import ConditionError
from dac.matcher import MISSING, get_field, match_detection, match_selection, parse_condition


class TestFieldResolution:
    def test_literal_key_wins_over_path_traversal(self) -> None:
        event = {"id.orig_h": "1.2.3.4", "id": {"orig_h": "9.9.9.9"}}
        assert get_field(event, "id.orig_h") == "1.2.3.4"

    def test_dotted_path_traversal(self) -> None:
        assert get_field({"raw": {"status": 404}}, "raw.status") == 404

    def test_absent_field_returns_sentinel(self) -> None:
        assert get_field({"a": 1}, "b") is MISSING


class TestScalarSemantics:
    @pytest.mark.parametrize(
        ("expected", "value", "want"),
        [
            ("ROOT", "root", True),
            ("root", "root", True),
            ("root", "rooted", False),
            ("ro*", "root", True),
            ("r??t", "root", True),
            ("r?t", "root", False),
        ],
    )
    def test_case_insensitive_and_wildcards(self, expected, value, want) -> None:
        assert match_selection({"user": expected}, {"user": value}) is want

    def test_escaped_wildcard_is_literal(self) -> None:
        assert match_selection({"q": r"a\*b"}, {"q": "a*b"}) is True
        assert match_selection({"q": r"a\*b"}, {"q": "axxb"}) is False

    def test_numeric_equality_crosses_string_boundary(self) -> None:
        assert match_selection({"status_code": 404}, {"status_code": "404"}) is True

    def test_list_value_is_or(self) -> None:
        sel = {"tld": ["zip", "mov"]}
        assert match_selection(sel, {"tld": "mov"}) is True
        assert match_selection(sel, {"tld": "com"}) is False

    def test_empty_list_never_matches(self) -> None:
        assert match_selection({"tld": []}, {"tld": "zip"}) is False

    def test_all_modifier_requires_every_value(self) -> None:
        sel = {"message|all|contains": ["Failed", "password"]}
        assert match_selection(sel, {"message": "Failed password for root"}) is True
        assert match_selection(sel, {"message": "Failed publickey for root"}) is False

    def test_null_expected_asserts_absence(self) -> None:
        assert match_selection({"user": None}, {"src_ip": "1.1.1.1"}) is True
        assert match_selection({"user": None}, {"user": "root"}) is False

    def test_exists_modifier(self) -> None:
        assert match_selection({"user|exists": True}, {"user": "root"}) is True
        assert match_selection({"user|exists": False}, {"src_ip": "1.1.1.1"}) is True


class TestModifiers:
    @pytest.mark.parametrize(
        ("key", "expected", "value", "want"),
        [
            ("p|contains", "admin", "/wp-admin/x", True),
            ("p|contains", "admin", "/api/models", False),
            ("p|startswith", "/api", "/api/models", True),
            ("p|startswith", "/api", "/x/api", False),
            ("p|endswith", ".env", "/.env", True),
            ("p|endswith", ".env", "/.environment", False),
            ("p|re", r"^/wp-(login|admin)", "/wp-login.php", True),
            ("p|re", r"^/wp-(login|admin)", "/api", False),
        ],
    )
    def test_string_modifiers(self, key, expected, value, want) -> None:
        assert match_selection({key: expected}, {"p": value}) is want

    @pytest.mark.parametrize(
        ("network", "ip", "want"),
        [
            ("10.0.0.0/8", "10.0.1.26", True),
            ("10.0.0.0/8", "203.0.113.1", False),
            ("100.64.0.0/10", "100.96.14.7", True),
            ("192.168.0.0/16", "192.168.8.1", True),
        ],
    )
    def test_cidr_modifier(self, network, ip, want) -> None:
        assert match_selection({"src_ip|cidr": network}, {"src_ip": ip}) is want

    def test_cidr_on_garbage_value_is_false_not_an_exception(self) -> None:
        assert match_selection({"src_ip|cidr": "10.0.0.0/8"}, {"src_ip": "not-an-ip"}) is False

    @pytest.mark.parametrize(
        ("key", "bound", "value", "want"),
        [
            ("n|gt", 5, 6, True),
            ("n|gt", 5, 5, False),
            ("n|gte", 5, 5, True),
            ("n|lt", 5, 4, True),
            ("n|lte", 5, 5, True),
        ],
    )
    def test_numeric_modifiers(self, key, bound, value, want) -> None:
        assert match_selection({key: bound}, {"n": value}) is want


class TestKeywordSearch:
    def test_bare_value_searches_all_fields(self) -> None:
        event = {"message": "Failed password for root", "src_ip": "1.2.3.4"}
        assert match_selection(["password"], event) is True
        assert match_selection(["publickey"], event) is False

    def test_keyword_search_descends_into_nested_values(self) -> None:
        assert match_selection(["404"], {"raw": {"status": 404}}) is True


class TestConditions:
    def _detection(self, condition: str) -> dict:
        return {
            "sel_a": {"x": 1},
            "sel_b": {"y": 2},
            "other": {"z": 3},
            "condition": condition,
        }

    @pytest.mark.parametrize(
        ("condition", "event", "want"),
        [
            ("sel_a", {"x": 1}, True),
            ("sel_a and sel_b", {"x": 1, "y": 2}, True),
            ("sel_a and sel_b", {"x": 1}, False),
            ("sel_a or sel_b", {"y": 2}, True),
            ("sel_a and not sel_b", {"x": 1}, True),
            ("sel_a and not sel_b", {"x": 1, "y": 2}, False),
            ("(sel_a or sel_b) and not other", {"x": 1}, True),
            ("(sel_a or sel_b) and not other", {"x": 1, "z": 3}, False),
            ("1 of sel_*", {"y": 2}, True),
            ("any of sel_*", {"y": 2}, True),
            ("all of sel_*", {"x": 1, "y": 2}, True),
            ("all of sel_*", {"x": 1}, False),
            ("all of them", {"x": 1, "y": 2, "z": 3}, True),
        ],
    )
    def test_condition_logic(self, condition, event, want) -> None:
        assert match_detection(self._detection(condition), event) is want

    def test_unknown_selection_is_an_error(self) -> None:
        with pytest.raises(ConditionError, match="unknown selection"):
            match_detection({"sel_a": {"x": 1}, "condition": "nope"}, {"x": 1})

    def test_empty_condition_is_an_error(self) -> None:
        with pytest.raises(ConditionError):
            parse_condition("   ", ["sel_a"])

    def test_unbalanced_parenthesis_is_an_error(self) -> None:
        with pytest.raises(ConditionError):
            parse_condition("(sel_a", ["sel_a"])

    def test_quantifier_matching_nothing_is_an_error(self) -> None:
        with pytest.raises(ConditionError, match="matched no selection"):
            parse_condition("all of missing_*", ["sel_a"])

    def test_missing_condition_key_is_an_error(self) -> None:
        with pytest.raises(ConditionError, match="missing a string"):
            match_detection({"sel_a": {"x": 1}}, {"x": 1})

    def test_selection_named_with_or_prefix_is_not_an_operator(self) -> None:
        """A selection called 'origin' must not be tokenised as 'or'."""
        detection = {"origin": {"x": 1}, "condition": "origin"}
        assert match_detection(detection, {"x": 1}) is True
