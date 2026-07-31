"""Active response guard rails.

These are the tests that matter most in this repository: everything here is
protecting against the system firewalling its own operator out of their server.
"""

from __future__ import annotations

import json

import pytest

from sentinel.config import Settings
from sentinel.response import Responder


@pytest.fixture
def responder(settings) -> Responder:
    return Responder(settings)


class TestDryRunDefault:
    def test_default_mode_is_dry_run(self, settings):
        assert settings.response_mode == "dry-run"

    def test_dry_run_reports_the_command_without_running_it(self, responder):
        action = responder.block("203.0.113.45", score=95, reason="test")
        assert action.allowed is True
        assert action.executed is False
        assert action.command[:2] == ["ufw", "insert"]
        assert "203.0.113.45" in action.command

    def test_deny_rule_is_inserted_at_position_1(self, responder):
        # A deny appended after an existing allow for the same traffic never
        # matches, so position matters.
        action = responder.block("203.0.113.45", score=95, reason="test")
        assert action.command[1:3] == ["insert", "1"]


class TestAllowlist:
    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.42", "169.254.1.1", "::1"],
    )
    def test_allowlisted_ranges_are_refused(self, responder, address):
        action = responder.block(address, score=100, reason="test")
        assert action.allowed is False
        assert "allowlisted" in action.reason

    def test_public_address_is_not_allowlisted(self, responder):
        assert responder.is_allowlisted("203.0.113.45") is False

    def test_allowlist_beats_a_maximum_score(self, responder):
        action = responder.block("192.168.1.1", score=100, reason="model says critical")
        assert action.allowed is False

    def test_custom_allowlist_is_honoured(self, monkeypatch, settings):
        monkeypatch.setenv("SENTINEL_RESPONSE_ALLOWLIST", "203.0.113.0/24")
        custom = Settings()
        assert Responder(custom).block("203.0.113.45", score=100, reason="t").allowed is False

    def test_malformed_allowlist_entry_is_skipped_not_fatal(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_RESPONSE_ALLOWLIST", "not-a-cidr,10.0.0.0/8")
        responder = Responder(Settings())
        assert responder.is_allowlisted("10.0.0.1") is True
        assert responder.is_allowlisted("203.0.113.45") is False


class TestScoreThreshold:
    def test_below_threshold_is_refused(self, responder):
        action = responder.block("203.0.113.45", score=54, reason="one failed password")
        assert action.allowed is False
        assert "below threshold" in action.reason

    def test_at_threshold_is_allowed(self, responder, settings):
        action = responder.block("203.0.113.45", score=settings.response_min_score, reason="t")
        assert action.allowed is True

    def test_default_threshold_only_admits_correlated_incidents(self, settings):
        # A single failed password scores 54; only correlation reaches 90+.
        assert settings.response_min_score >= 90


class TestValidation:
    @pytest.mark.parametrize("bad", ["not-an-ip", "", "999.999.999.999", "203.0.113.45; rm -rf /"])
    def test_invalid_addresses_are_refused(self, responder, bad):
        action = responder.block(bad, score=100, reason="t")
        assert action.allowed is False
        assert action.executed is False

    def test_command_injection_never_reaches_a_command(self, responder):
        action = responder.block("203.0.113.45 && curl evil.example", score=100, reason="t")
        assert action.allowed is False
        assert action.command == []

    def test_multicast_is_refused(self, responder):
        assert responder.block("224.0.0.1", score=100, reason="t").allowed is False

    def test_disabled_mode_refuses_everything(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_RESPONSE_MODE", "disabled")
        action = Responder(Settings()).block("203.0.113.45", score=100, reason="t")
        assert action.allowed is False
        assert "disabled" in action.reason


class TestRateLimit:
    def test_dry_run_actions_do_not_consume_the_budget(self, responder):
        for _ in range(50):
            assert responder.block("203.0.113.45", score=95, reason="t").allowed is True

    def test_enforced_blocks_are_capped(self, settings):
        responder = Responder(settings, max_blocks_per_hour=3)
        responder._recent = [__import__("time").time()] * 3
        action = responder.block("203.0.113.45", score=95, reason="t")
        assert action.allowed is False
        assert "rate limit" in action.reason


class TestAudit:
    def test_allowed_actions_are_recorded(self, responder, settings):
        responder.block("203.0.113.45", score=95, reason="brute force incident")
        rows = [json.loads(line) for line in settings.audit_log.read_text(encoding="utf-8").splitlines()]
        assert rows and rows[-1]["target"] == "203.0.113.45"

    def test_refusals_are_recorded_too(self, responder, settings):
        # "The system decided not to act" is exactly what you need evidence of
        # during an incident review.
        responder.block("192.168.1.1", score=100, reason="t")
        rows = [json.loads(line) for line in settings.audit_log.read_text(encoding="utf-8").splitlines()]
        assert rows[-1]["allowed"] is False
        assert "allowlisted" in rows[-1]["reason"]

    def test_history_is_newest_first(self, responder):
        responder.block("203.0.113.1", score=95, reason="first")
        responder.block("203.0.113.2", score=95, reason="second")
        history = responder.history()
        assert history[0]["target"] == "203.0.113.2"

    def test_history_is_empty_before_any_action(self, responder):
        assert responder.history() == []


class TestStatus:
    def test_reports_the_guard_rails(self, responder):
        status = responder.status()
        assert status["mode"] == "dry-run"
        assert status["min_score"] >= 90
        assert "10.0.0.0/8" in status["allowlist"]
        assert "max_blocks_per_hour" in status


class TestUnblock:
    def test_unblock_is_not_gated_behind_enforce(self, responder):
        # Undoing a block is never the dangerous direction.
        action = responder.unblock("203.0.113.45")
        assert action.allowed is True

    def test_unblock_validates_the_address(self, responder):
        assert responder.unblock("nonsense").allowed is False
