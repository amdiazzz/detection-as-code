"""Unit tests for the log parsers."""

from __future__ import annotations

from datetime import datetime

import pytest

from dac.errors import ParserError
from dac.parsers import (
    get_parser,
    parse_dnsmasq,
    parse_lines,
    parse_pvedaemon,
    parse_sshd,
    parse_weblog,
)


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
        with pytest.raises(ParserError, match="available: dnsmasq, pvedaemon, sshd, weblog"):
            get_parser("nope")

    def test_parse_lines_skips_blanks_and_unmatched(self) -> None:
        lines = [
            "",
            "   ",
            "garbage",
            "Nov 14 03:11:11 c sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        assert len(list(parse_lines("sshd", lines))) == 1


class TestPvedaemon:
    """Line formats here are taken from published Proxmox output, not invented.

    Sources are listed in tests/fixtures/README.md.
    """

    def test_failure_fields(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[1885456]: authentication failure; "
            "rhost=::ffff:10.0.1.26 user=root@pam msg=Authentication failure",
            year=2026,
        )
        assert event is not None
        assert event["auth_result"] == "failure"
        assert event["user"] == "root@pam"
        assert event["user_name"] == "root"
        assert event["realm"] == "pam"
        assert event["msg"] == "Authentication failure"
        assert event["failure_reason"] == "credentials"
        assert event["service"] == "pvedaemon"
        assert event["product"] == "proxmox"
        assert event["timestamp"] == datetime(2026, 11, 14, 9, 12, 3)

    def test_ipv4_mapped_ipv6_rhost_is_unwrapped(self) -> None:
        """Without unwrapping, a cidr rule against 10.0.0.0/8 never matches."""
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=::ffff:10.0.1.26 user=root@pam msg=Authentication failure"
        )
        assert event["src_ip"] == "10.0.1.26"
        assert event["src_ip_raw"] == "::ffff:10.0.1.26"

    def test_plain_ipv4_rhost_is_preserved(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=203.0.113.9 user=root@pam msg=Authentication failure"
        )
        assert event["src_ip"] == "203.0.113.9"

    def test_genuine_ipv6_rhost_is_preserved(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=2001:db8::5 user=root@pam msg=Authentication failure"
        )
        assert event["src_ip"] == "2001:db8::5"

    def test_unparseable_rhost_yields_none_not_a_crash(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=garbage user=root@pam msg=Authentication failure"
        )
        assert event["src_ip"] is None
        assert event["src_ip_raw"] == "garbage"

    def test_no_such_user_is_a_credential_failure(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=::ffff:203.0.113.9 user=test@pam msg=no such user ('test@pam')"
        )
        assert event["failure_reason"] == "credentials"

    def test_cluster_lock_error_is_not_a_credential_failure(self) -> None:
        """Proxmox reuses the 'authentication failure' prefix for host faults.

        A brute-force rule keyed on the prefix alone would fire on cluster lock
        contention, which is an availability problem and not an attack.
        """
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=::ffff:10.0.1.26 user=root@pam "
            "msg=cfs-lock 'authkey' error: got lock request timeout"
        )
        assert event["auth_result"] == "failure"
        assert event["failure_reason"] == "server_error"

    def test_success_fields(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:15:40 cs101 pvedaemon[2832]: <root@pam> successful auth "
            "for user 'alexdiaz@pve'"
        )
        assert event["auth_result"] == "success"
        assert event["user"] == "alexdiaz@pve"
        assert event["realm"] == "pve"
        assert event["acting_user"] == "root@pam"

    def test_success_carries_no_source_address(self) -> None:
        """Documented limitation: the success line has no rhost field."""
        event = parse_pvedaemon(
            "Nov 14 09:15:40 cs101 pvedaemon[2832]: <root@pam> successful auth for user 'root@pam'"
        )
        assert "src_ip" not in event

    def test_user_without_a_realm(self) -> None:
        event = parse_pvedaemon(
            "Nov 14 09:12:03 cs101 pvedaemon[101]: authentication failure; "
            "rhost=::ffff:10.0.1.26 user=root msg=Authentication failure"
        )
        assert event["user_name"] == "root"
        assert event["realm"] is None

    def test_non_auth_pvedaemon_chatter_is_dropped(self) -> None:
        assert (
            parse_pvedaemon(
                "Nov 14 09:12:03 cs101 pvedaemon[101]: <root@pam> starting task "
                "UPID:cs101:0002F:15AA4:qmcreate:101:root@pam:"
            )
            is None
        )
        assert (
            parse_pvedaemon(
                "Nov 14 09:12:03 cs101 pvedaemon[101]: Cluster not quorate - "
                "extending auth key lifetime!"
            )
            is None
        )

    def test_neighbouring_pam_line_is_ignored(self) -> None:
        """IPCC.xs logs its own pam_unix failure for the same login attempt."""
        assert (
            parse_pvedaemon(
                "Nov 14 09:12:03 cs101 IPCC.xs[4160338]: pam_unix(proxmox-ve-auth:auth): "
                "authentication failure; logname= uid=0 euid=0 tty= ruser= "
                "rhost=::ffff:10.0.1.26  user=root"
            )
            is None
        )

    def test_sshd_line_is_ignored(self) -> None:
        assert (
            parse_pvedaemon(
                "Nov 14 03:11:11 cs101 sshd[2211]: Failed password for root "
                "from 203.0.113.37 port 51200 ssh2"
            )
            is None
        )

    def test_garbage_line_is_ignored(self) -> None:
        assert parse_pvedaemon("total garbage") is None
