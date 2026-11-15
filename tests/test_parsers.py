"""Unit tests for the log parsers."""

from __future__ import annotations

from datetime import datetime

import pytest

from dac.errors import ParserError
from dac.parsers import get_parser, parse_dnsmasq, parse_lines, parse_sshd, parse_weblog


class TestSshd:
    def test_failed_password_fields(self) -> None:
        event = parse_sshd(
            "Nov 14 03:11:11 cs101 sshd[2211]: Failed password for root "
            "from 203.0.113.37 port 51200 ssh2",
            year=2026,
        )
        assert event is not None
        assert event["auth_result"] == "failure"
        assert event["auth_method"] == "password"
        assert event["user"] == "root"
        assert event["invalid_user"] is False
        assert event["src_ip"] == "203.0.113.37"
        assert event["src_port"] == 51200
        assert event["service"] == "sshd"
        assert event["timestamp"] == datetime(2026, 11, 14, 3, 11, 11)

    def test_invalid_user_flag(self) -> None:
        event = parse_sshd(
            "Nov 14 03:11:31 cs101 sshd[2212]: Failed password for invalid user oracle "
            "from 203.0.113.37 port 51201 ssh2"
        )
        assert event["invalid_user"] is True
        assert event["user"] == "oracle"

    def test_accepted_publickey(self) -> None:
        event = parse_sshd(
            "Nov 14 06:01:12 cs101 sshd[5501]: Accepted publickey for alexdiaz "
            "from 10.0.1.26 port 49600 ssh2"
        )
        assert event["auth_result"] == "success"
        assert event["auth_method"] == "publickey"

    def test_server_listening_captures_destination_port(self) -> None:
        event = parse_sshd("Nov 14 03:10:58 cs101 sshd[2200]: Server listening on 0.0.0.0 port 22.")
        assert event["dst_port"] == 22

    def test_non_sshd_line_is_ignored(self) -> None:
        assert parse_sshd("Nov 14 06:12:33 cs101 systemd[1]: Started Session 42.") is None

    def test_unparseable_line_is_ignored(self) -> None:
        assert parse_sshd("total garbage") is None

    def test_sshd_line_without_known_message_still_yields_an_event(self) -> None:
        event = parse_sshd("Nov 14 03:11:00 cs101 sshd[2211]: Received disconnect from 1.2.3.4")
        assert event is not None
        assert "auth_result" not in event


class TestDnsmasq:
    def test_query_fields(self) -> None:
        event = parse_dnsmasq(
            "Nov 14 07:00:04 pihole dnsmasq[912]: query[A] invoice-update.zip from 10.0.1.26"
        )
        assert event["action"] == "query"
        assert event["query"] == "invoice-update.zip"
        assert event["tld"] == "zip"
        assert event["query_type"] == "A"
        assert event["src_ip"] == "10.0.1.26"
        assert event["category"] == "dns"

    def test_subdomain_tld_extraction(self) -> None:
        event = parse_dnsmasq(
            "Nov 14 07:00:15 pihole dnsmasq[912]: query[A] a.b.example.xyz from 10.0.1.26"
        )
        assert event["tld"] == "xyz"

    def test_blocked_action(self) -> None:
        event = parse_dnsmasq(
            "Nov 14 07:00:16 pihole dnsmasq[912]: gravity blocked doubleclick.net is 0.0.0.0"
        )
        assert event["action"] == "blocked"

    def test_reply_action(self) -> None:
        event = parse_dnsmasq(
            "Nov 14 07:00:04 pihole dnsmasq[912]: reply github.com is 140.82.113.3"
        )
        assert event["action"] == "reply"
        assert event["answer"] == "140.82.113.3"

    def test_uninteresting_dnsmasq_line_is_dropped(self) -> None:
        assert parse_dnsmasq("Nov 14 07:00:00 pihole dnsmasq[912]: started, version 2.90") is None

    def test_non_dns_program_is_ignored(self) -> None:
        assert parse_dnsmasq("Nov 14 07:00:00 cs101 sshd[1]: Failed password") is None


class TestWeblog:
    def test_json_fields_are_normalised(self) -> None:
        event = parse_weblog(
            '{"ts": "2026-11-15T04:10:03Z", "remote": "198.51.100.22", "method": "GET", '
            '"path": "/wp-login.php?redirect=1", "status": 404, "ms": 0.4}'
        )
        assert event["src_ip"] == "198.51.100.22"
        assert event["http_method"] == "GET"
        assert event["uri_path"] == "/wp-login.php"
        assert event["uri_query"] == "redirect=1"
        assert event["status_code"] == 404
        assert event["timestamp"].year == 2026
        assert event["category"] == "webserver"

    def test_syslog_wrapped_json_is_tolerated(self) -> None:
        line = (
            "Nov 14 21:54:06 hermesagent start.sh[186]: [webui] "
            '{"ts": "2026-11-15T03:54:06Z", "remote": "10.0.20.235", "method": "GET", '
            '"path": "/api/models", "status": 200, "ms": 0.5}'
        )
        event = parse_weblog(line)
        assert event["uri_path"] == "/api/models"

    def test_nginx_style_aliases(self) -> None:
        event = parse_weblog(
            '{"time": "2026-11-15T04:10:03Z", "remote_addr": "203.0.113.9", '
            '"verb": "POST", "request_uri": "/.env", "status": "403"}'
        )
        assert event["src_ip"] == "203.0.113.9"
        assert event["http_method"] == "POST"
        assert event["status_code"] == 403

    def test_non_json_returns_none(self) -> None:
        assert parse_weblog("this is not json at all") is None

    def test_malformed_json_returns_none(self) -> None:
        assert parse_weblog('{"ts": "x", broken}') is None

    def test_json_scalar_is_not_an_event(self) -> None:
        assert parse_weblog("[1, 2, 3]") is None

    def test_bad_timestamp_yields_none_timestamp_not_a_crash(self) -> None:
        event = parse_weblog('{"ts": "not-a-date", "remote": "1.2.3.4", "path": "/"}')
        assert event["timestamp"] is None


class TestRegistry:
    def test_unknown_parser_name_lists_valid_options(self) -> None:
        with pytest.raises(ParserError, match="available: dnsmasq, sshd, weblog"):
            get_parser("nope")

    def test_parse_lines_skips_blanks_and_unmatched(self) -> None:
        lines = [
            "",
            "   ",
            "garbage",
            "Nov 14 03:11:11 c sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        assert len(list(parse_lines("sshd", lines))) == 1
