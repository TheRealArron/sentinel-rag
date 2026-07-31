"""Pseudonymisation, the RAG chain, and its guard rails."""

from __future__ import annotations

import json

import pytest

from sentinel.analyst import Analyst
from sentinel.llm import LLMError, NoLLM, extract_json
from sentinel.privacy import Anonymizer
from sentinel.schemas import LogEvent


class StubLLM:
    """Drives the analyst through the same seam a real provider uses."""

    provider = "stub"
    model = "stub-1"
    available = True

    def __init__(self, response: str = "", raise_error: Exception | None = None) -> None:
        self.response = response
        self.raise_error = raise_error
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if self.raise_error:
            raise self.raise_error
        return self.response


def good_payload(**overrides) -> str:
    payload = {
        "severity": "critical",
        "confidence": 0.86,
        "title_en": "SSH brute force followed by successful login",
        "title_ja": "SSH総当たり攻撃の後にログイン成功",
        "summary_en": "Five failures then a success from 203.0.113.45 [S1].",
        "summary_ja": "203.0.113.45 から5回の認証失敗の後、認証に成功しました [S1]。",
        "attack_narrative": "Scan, spray, success, escalate.",
        "mitre": ["T1110.001", "T1078.003"],
        "recommended_actions": ["sudo ufw deny from 203.0.113.45 to any"],
        "citations": ["S1"],
        "notes": [],
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


class TestAnonymizer:
    def test_private_ips_are_masked_public_ones_are_not(self):
        anon = Anonymizer()
        out = anon.scrub("connection from 203.0.113.45 to 192.168.1.42")
        assert "203.0.113.45" in out, "the attacker's address is the actionable field"
        assert "192.168.1.42" not in out
        assert "IP_PRIVATE_1" in out

    def test_public_ips_masked_when_opted_in(self):
        out = Anonymizer(anonymize_public_ips=True).scrub("from 203.0.113.45")
        assert "203.0.113.45" not in out
        assert "IP_PUBLIC_1" in out

    def test_loopback_gets_its_own_class(self):
        assert "IP_LOOPBACK_1" in Anonymizer().scrub("bound to 127.0.0.1:8000")

    def test_hosts_and_users_learned_from_events(self, sample_events):
        anon = Anonymizer().learn(sample_events)
        out = anon.scrub("sentinel sshd: session opened for user arron")
        assert "sentinel" not in out
        assert "arron" not in out
        assert "HOST_1" in out and "USER_1" in out

    def test_generic_accounts_are_preserved(self, sample_events):
        # Masking "root" would make an escalation alert incomprehensible.
        anon = Anonymizer().learn(sample_events)
        assert "root" in anon.scrub("sudo to root by someone")

    def test_restore_is_an_exact_inverse(self, sample_events):
        anon = Anonymizer().learn(sample_events)
        original = "sentinel sshd: arron from 192.168.1.42 to admin@example.com"
        assert anon.restore(anon.scrub(original)) == original

    def test_longest_match_wins_so_prefixes_are_not_half_replaced(self):
        anon = Anonymizer().learn_terms(hosts=["sentinel", "sentinel-server"])
        out = anon.scrub("host sentinel-server reporting")
        assert "HOST_1-server" not in out
        assert anon.restore(out) == "host sentinel-server reporting"

    def test_usernames_are_word_bounded(self):
        anon = Anonymizer().learn_terms(users=["al"])
        assert "already" in anon.scrub("the job already finished")

    def test_placeholders_are_stable_for_repeated_values(self):
        anon = Anonymizer()
        first = anon.scrub("10.0.0.5 and 10.0.0.5 again")
        assert first.count("IP_PRIVATE_1") == 2

    def test_double_digit_placeholders_restore_correctly(self):
        # USER_1 must not be substituted inside USER_10.
        anon = Anonymizer().learn_terms(users=[f"user{i:02d}" for i in range(15)])
        original = " ".join(f"user{i:02d}" for i in range(15))
        assert anon.restore(anon.scrub(original)) == original

    def test_emails_masked_before_ips_chew_them_up(self):
        anon = Anonymizer()
        out = anon.scrub("alert sent to soc@example.co.jp")
        assert "soc@example.co.jp" not in out
        assert "EMAIL_1" in out

    def test_disabled_is_a_passthrough(self, sample_events):
        anon = Anonymizer(enabled=False).learn(sample_events)
        assert anon.scrub("sentinel 192.168.1.42") == "sentinel 192.168.1.42"

    def test_summary_reports_what_was_masked(self, sample_events):
        anon = Anonymizer().learn(sample_events)
        anon.scrub("sentinel 192.168.1.42")
        summary = anon.summary()
        assert summary["enabled"] is True
        assert summary["substitutions"] >= 2


class TestExtractJson:
    def test_plain_object(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_fenced_block(self):
        assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_leading_prose(self):
        assert extract_json('Here you go:\n{"a": 1}') == {"a": 1}

    def test_nested_objects(self):
        assert extract_json('{"a": {"b": {"c": 1}}}')["a"]["b"]["c"] == 1

    def test_braces_inside_strings_do_not_confuse_the_scanner(self):
        # A naive \{.*\} regex gets this wrong.
        assert extract_json('{"msg": "use } carefully", "n": 1}')["n"] == 1

    def test_escaped_quotes(self):
        assert extract_json(r'{"msg": "he said \"hi\""}')["msg"] == 'he said "hi"'

    def test_empty_response_raises(self):
        with pytest.raises(ValueError, match="empty"):
            extract_json("")

    def test_no_object_raises(self):
        with pytest.raises(ValueError, match="no JSON object"):
            extract_json("just prose, no object here")


class TestNoLLM:
    def test_reports_unavailable_rather_than_faking_output(self):
        llm = NoLLM("no key")
        assert llm.available is False
        with pytest.raises(LLMError):
            llm.complete("s", "u")


class TestAnalyst:
    def _analyst(self, engine, llm) -> Analyst:
        return Analyst(engine.settings, engine.retriever, llm)

    def _attack_events(self, sample_events) -> list[LogEvent]:
        return [e for e in sample_events if e.score >= 60]

    def test_produces_a_bilingual_cited_alert(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload())
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert alert.title_en and alert.title_ja
        assert alert.summary_en and alert.summary_ja
        assert alert.citations
        assert alert.degraded is False
        assert alert.provider == "stub"

    def test_prompt_fences_untrusted_log_data(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload())
        self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        _system, user = stub.calls[0]
        assert "<untrusted_log_data>" in user and "</untrusted_log_data>" in user
        assert "<retrieved_sources>" in user

    def test_system_prompt_states_the_injection_rule(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload())
        self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        system, _user = stub.calls[0]
        assert "never instructions" in system
        assert "hostile injection" in system

    def test_log_text_is_pseudonymised_before_it_reaches_the_model(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload())
        self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        _system, user = stub.calls[0]
        assert "sentinel" not in user, "the hostname reached the model unmasked"
        assert "HOST_1" in user

    def test_placeholders_are_restored_in_the_returned_alert(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload(summary_en="Compromise on HOST_1 by USER_1 [S1]."))
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert "HOST_1" not in alert.summary_en
        assert "sentinel" in alert.summary_en
        assert alert.anonymized is True

    def test_severity_cannot_jump_more_than_one_step_above_the_rules(self, indexed_engine, sample_events):
        quiet = [e for e in sample_events if e.severity == "info"]
        assert quiet
        stub = StubLLM(good_payload(severity="critical"))
        alert = self._analyst(indexed_engine, stub).analyze(events=quiet)
        # Observed severity is info, so the ceiling is notice.
        assert alert.severity == "notice"
        assert any("clamped" in n for n in alert.notes)

    def test_one_step_escalation_is_allowed(self, indexed_engine, sample_events):
        quiet = [e for e in sample_events if e.severity == "info"]
        alert = self._analyst(indexed_engine, StubLLM(good_payload(severity="notice"))).analyze(events=quiet)
        assert alert.severity == "notice"
        assert not any("clamped" in n for n in alert.notes)

    def test_unrecognised_severity_falls_back_to_the_deterministic_one(self, indexed_engine, sample_events):
        events = self._attack_events(sample_events)
        stub = StubLLM(good_payload(severity="apocalyptic"))
        alert = self._analyst(indexed_engine, stub).analyze(events=events)
        assert alert.severity == "critical"
        assert any("unrecognised severity" in n for n in alert.notes)

    def test_invented_citations_are_dropped(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload(citations=["S1", "S99", "the internet"]))
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert len(alert.citations) == 1
        assert any("do not match a retrieved source" in n for n in alert.notes)

    def test_ungrounded_output_has_its_confidence_capped(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload(citations=[], confidence=0.99))
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert alert.confidence <= 0.4
        assert any("confidence capped" in n for n in alert.notes)

    def test_malformed_model_output_falls_back_to_rules(self, indexed_engine, sample_events):
        stub = StubLLM("I am not JSON at all.")
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert alert.degraded is True
        assert any("rule-based" in n for n in alert.notes)

    def test_provider_failure_falls_back_to_rules(self, indexed_engine, sample_events):
        stub = StubLLM(raise_error=LLMError("429 rate limit"))
        alert = self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        assert alert.degraded is True
        assert any("429" in n for n in alert.notes)

    def test_alert_id_is_content_addressed(self, indexed_engine, sample_events):
        events = self._attack_events(sample_events)
        analyst = self._analyst(indexed_engine, StubLLM(good_payload()))
        assert analyst.analyze(events=events).alert_id == analyst.analyze(events=events).alert_id

    def test_deterministic_signals_are_given_to_the_model(self, indexed_engine, sample_events):
        stub = StubLLM(good_payload())
        self._analyst(indexed_engine, stub).analyze(events=self._attack_events(sample_events))
        _system, user = stub.calls[0]
        assert "DETERMINISTIC SIGNALS" in user
        assert "peak deterministic score" in user

    def test_requires_events_or_a_question(self, indexed_engine):
        with pytest.raises(ValueError, match="needs events"):
            self._analyst(indexed_engine, StubLLM(good_payload())).analyze()

    def test_question_only_path_works(self, indexed_engine):
        stub = StubLLM(good_payload())
        alert = self._analyst(indexed_engine, stub).analyze(question="How do I stop SSH brute force?")
        assert alert.citations
        assert stub.calls


class TestFallbackAnalyst:
    def test_marks_itself_degraded_and_names_the_reason(self, indexed_engine, sample_events):
        alert = indexed_engine.analyze_events([e for e in sample_events if e.score >= 60])
        assert alert.degraded is True
        assert alert.provider == "none"
        assert any("GEMINI_API_KEY" in n for n in alert.notes)

    def test_still_bilingual(self, indexed_engine, sample_events):
        alert = indexed_engine.analyze_events([e for e in sample_events if e.score >= 60])
        assert alert.title_ja and alert.summary_ja
        assert any(ord(ch) > 0x3000 for ch in alert.summary_ja)

    def test_still_retrieves_and_cites(self, indexed_engine, sample_events):
        alert = indexed_engine.analyze_events([e for e in sample_events if e.score >= 60])
        assert alert.citations, "retrieval must still run without an LLM"

    def test_severity_matches_the_deterministic_maximum(self, indexed_engine, sample_events):
        events = [e for e in sample_events if e.score >= 60]
        alert = indexed_engine.analyze_events(events)
        assert alert.severity == "critical"

    def test_actions_are_category_specific_and_bilingual(self, indexed_engine, sample_events):
        auth = [e for e in sample_events if e.category == "authentication"]
        alert = indexed_engine.analyze_events(auth)
        assert any("ufw deny" in a for a in alert.recommended_actions)
        assert any("ファイアウォール" in a for a in alert.recommended_actions)

    def test_source_ip_is_substituted_into_the_action(self, indexed_engine, sample_events):
        auth = [e for e in sample_events if e.category == "authentication" and e.source_ip]
        alert = indexed_engine.analyze_events(auth)
        assert any("203.0.113.45" in a for a in alert.recommended_actions)

    def test_indicators_are_populated(self, indexed_engine, sample_events):
        alert = indexed_engine.analyze_events([e for e in sample_events if e.score >= 60])
        assert "203.0.113.45" in alert.indicators["source_ips"]
        assert alert.indicators["peak_score"] >= 90

    def test_alert_serialises_to_json(self, indexed_engine, sample_events):
        alert = indexed_engine.analyze_events([e for e in sample_events if e.score >= 60])
        parsed = json.loads(alert.to_json())
        assert parsed["title"]["ja"]
        assert parsed["severity"] == "critical"
