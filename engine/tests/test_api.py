"""HTTP routes and the event buffer.

Routes are exercised through routes.Router directly — the same object both the
FastAPI app and the stdlib server delegate to — so these tests cover the real
request handling without needing either framework installed.
"""

from __future__ import annotations

import json

import pytest

from sentinel.config import Settings
from sentinel.engine import EventBuffer, SentinelEngine
from sentinel.routes import Request, Router


@pytest.fixture
def router(indexed_engine) -> Router:
    return Router(indexed_engine)


def get(router: Router, path: str, **query) -> tuple[int, dict]:
    response = router.dispatch(Request(method="GET", path=path, query={k: str(v) for k, v in query.items()}))
    return response.status, response.payload


def post(router: Router, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    response = router.dispatch(
        Request(method="POST", path=path, body=body or {}, headers=headers or {})
    )
    return response.status, response.payload


class TestDispatch:
    def test_unknown_path_is_404(self, router):
        status, payload = get(router, "/api/nope")
        assert status == 404
        assert "not found" in payload["error"]

    def test_wrong_method_is_405_not_404(self, router):
        # Telling the caller their URL was right saves real debugging time.
        status, payload = post(router, "/api/health")
        assert status == 405

    def test_trailing_slash_is_normalised(self, router):
        assert get(router, "/api/health/")[0] == 200

    def test_handler_errors_become_500_without_a_traceback(self, router, monkeypatch):
        monkeypatch.setattr(router.engine, "stats", lambda: 1 / 0)
        status, payload = get(router, "/api/stats")
        assert status == 500
        assert "ZeroDivisionError" in payload["error"]
        assert "Traceback" not in json.dumps(payload)
        assert "sentinel/engine.py" not in json.dumps(payload)


class TestReadEndpoints:
    def test_health_is_cheap_and_loads_no_model(self, engine):
        router = Router(engine)
        status, payload = get(router, "/api/health")
        assert status == 200
        assert payload["status"] == "ok"
        assert engine._embedder is None, "health check triggered a model load"

    def test_stats(self, router):
        status, payload = get(router, "/api/stats")
        assert status == 200
        assert payload["events"]["events"] == 25
        assert payload["events"]["incidents"] == 2
        assert payload["response"]["mode"] == "dry-run"

    def test_config_masks_secrets(self, monkeypatch, engine):
        monkeypatch.setenv("GEMINI_API_KEY", "super-secret-value")
        rebuilt = SentinelEngine(Settings())
        _status, payload = get(Router(rebuilt), "/api/config")
        assert "super-secret-value" not in json.dumps(payload)
        assert payload["gemini_api_key"].startswith("set (")

    def test_events_feed_is_newest_first(self, router):
        _status, payload = get(router, "/api/events", limit=10)
        timestamps = [e["timestamp"] for e in payload["events"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_events_filters(self, router):
        _s, by_sev = get(router, "/api/events", severity="critical", limit=100)
        # 5 from the intrusion narrative + 2 honeytoken hits.
        assert by_sev["count"] == 7
        assert all(e["severity"] == "critical" for e in by_sev["events"])

        _s, incidents = get(router, "/api/events", incidents_only=1, limit=100)
        assert incidents["count"] == 2

        _s, by_ip = get(router, "/api/events", source_ip="203.0.113.45", limit=100)
        assert by_ip["count"] >= 9

        _s, search = get(router, "/api/events", q="xmrig", limit=100)
        assert search["count"] == 1

    def test_events_min_score(self, router):
        _s, payload = get(router, "/api/events", min_score=90, limit=100)
        assert all(e["score"] >= 90 for e in payload["events"])

    def test_events_limit_is_clamped(self, router):
        assert get(router, "/api/events", limit=99999)[0] == 200

    def test_bad_integer_query_is_400(self, router):
        status, payload = get(router, "/api/events", limit="abc")
        assert status == 400
        assert "integer" in payload["error"]

    def test_dashboard_is_served_as_html(self, router):
        response = router.dispatch(Request(method="GET", path="/"))
        assert response.status == 200
        assert response.content_type.startswith("text/html")
        assert "Sentinel RAG" in response.body_text


class TestSearchEndpoint:
    def test_get_and_post_agree(self, router):
        _s, from_get = get(router, "/api/search", q="brute force")
        _s, from_post = post(router, "/api/search", {"query": "brute force"})
        assert [r["parent_id"] for r in from_get["results"]] == [r["parent_id"] for r in from_post["results"]]

    def test_empty_query_is_400(self, router):
        status, payload = post(router, "/api/search", {"query": "   "})
        assert status == 400
        assert "non-empty" in payload["error"]

    def test_unsupported_language_is_400(self, router):
        status, payload = post(router, "/api/search", {"query": "x", "languages": ["fr"]})
        assert status == 400
        assert "unsupported language" in payload["error"]

    def test_response_reports_the_language_mix_and_backend(self, router):
        _s, payload = post(router, "/api/search", {"query": "SSH brute force", "k": 6})
        assert payload["language_mix"].get("ja", 0) >= 1
        assert payload["embedder_semantic"] is False
        assert payload["vector_backend"] == "local"


class TestAnalyzeEndpoint:
    def test_empty_body_triages_recent_events(self, router):
        status, payload = post(router, "/api/analyze", {})
        assert status == 200
        assert payload["severity"] == "critical"
        assert payload["citations"]

    def test_question_only(self, router):
        _s, payload = post(router, "/api/analyze", {"question": "SSHの総当たり攻撃を止めるには"})
        assert payload["title"]["ja"]

    def test_specific_event_ids(self, router, sample_event_dicts):
        ids = [r["raw_sha256"] for r in sample_event_dicts if r["score"] >= 90]
        _s, payload = post(router, "/api/analyze", {"event_ids": ids})
        assert set(payload["event_ids"]) == set(ids)

    def test_unknown_event_ids_are_400(self, router):
        status, payload = post(router, "/api/analyze", {"event_ids": ["deadbeef"]})
        assert status == 400
        assert "event buffer" in payload["error"]


class TestResponseEndpoints:
    def test_status(self, router):
        _s, payload = get(router, "/api/response/status")
        assert payload["mode"] == "dry-run"

    def test_block_requires_a_score(self, router):
        status, payload = post(router, "/api/response/block", {"ip": "203.0.113.45"})
        assert status == 400
        assert "'score' is required" in payload["error"]

    def test_block_rejects_a_non_address(self, router):
        assert post(router, "/api/response/block", {"ip": "evil; rm -rf /", "score": 99})[0] == 400

    def test_allowlisted_block_is_403(self, router):
        status, payload = post(router, "/api/response/block", {"ip": "192.168.1.1", "score": 99})
        assert status == 403
        assert payload["allowed"] is False

    def test_dry_run_block_succeeds(self, router):
        status, payload = post(router, "/api/response/block", {"ip": "203.0.113.45", "score": 99})
        assert status == 200
        assert payload["executed"] is False

    def test_history_records_the_attempt(self, router):
        post(router, "/api/response/block", {"ip": "203.0.113.45", "score": 99})
        _s, payload = get(router, "/api/response/history")
        assert payload["actions"][0]["target"] == "203.0.113.45"


class TestAuth:
    @pytest.fixture
    def secured(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_TOKEN", "s3cret-token")
        return Router(SentinelEngine(Settings()))

    def test_reads_stay_open(self, secured):
        assert get(secured, "/api/health")[0] == 200
        assert get(secured, "/api/events")[0] == 200

    def test_protected_endpoint_without_a_token_is_401(self, secured):
        status, payload = post(secured, "/api/response/block", {"ip": "203.0.113.45", "score": 99})
        assert status == 401
        assert "SENTINEL_API_TOKEN" in payload["error"]

    def test_wrong_token_is_401(self, secured):
        status, _ = post(
            secured, "/api/response/block", {"ip": "203.0.113.45", "score": 99},
            headers={"authorization": "Bearer wrong"},
        )
        assert status == 401

    def test_correct_token_is_accepted(self, secured):
        status, _ = post(
            secured, "/api/response/block", {"ip": "203.0.113.45", "score": 99},
            headers={"authorization": "Bearer s3cret-token"},
        )
        assert status == 200

    def test_no_token_configured_means_no_auth(self, router):
        assert post(router, "/api/response/block", {"ip": "203.0.113.45", "score": 99})[0] == 200


class TestEventBuffer:
    def _write(self, path, events):
        with path.open("a", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def test_incremental_refresh_reads_only_new_lines(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.touch()
        buffer = EventBuffer(path, 100)
        self._write(path, [{"seq": 0, "raw_sha256": "a", "message": "one"}])
        assert buffer.refresh() == 1
        assert buffer.refresh() == 0
        self._write(path, [{"seq": 1, "raw_sha256": "b", "message": "two"}])
        assert buffer.refresh() == 1
        assert len(buffer.all()) == 2

    def test_partial_final_line_is_not_consumed(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.write_text('{"seq": 0, "raw_sha256": "a", "message": "complete"}\n{"seq": 1, "raw_', encoding="utf-8")
        buffer = EventBuffer(path, 100)
        assert buffer.refresh() == 1
        # Completing the line makes it readable on the next pass.
        with path.open("a", encoding="utf-8") as fh:
            fh.write('sha256": "b", "message": "now complete"}\n')
        assert buffer.refresh() == 1

    def test_duplicate_fingerprints_are_dropped(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.touch()
        buffer = EventBuffer(path, 100)
        row = {"seq": 0, "raw_sha256": "same", "message": "x"}
        self._write(path, [row, row])
        assert buffer.refresh() == 1

    def test_truncation_resets_the_offset(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.touch()
        buffer = EventBuffer(path, 100)
        self._write(path, [{"seq": i, "raw_sha256": f"h{i}", "message": "x"} for i in range(5)])
        buffer.refresh()
        path.write_text("", encoding="utf-8")  # logrotate copytruncate
        self._write(path, [{"seq": 99, "raw_sha256": "new", "message": "after rotation"}])
        buffer.refresh()
        assert [e.seq for e in buffer.all()] == [99]

    def test_multibyte_content_keeps_the_offset_aligned(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.touch()
        buffer = EventBuffer(path, 100)
        self._write(path, [{"seq": 0, "raw_sha256": "a", "message": "ブルートフォース攻撃を検知"}])
        assert buffer.refresh() == 1
        self._write(path, [{"seq": 1, "raw_sha256": "b", "message": "次のイベント"}])
        assert buffer.refresh() == 1
        assert buffer.all()[1].message == "次のイベント"

    def test_malformed_lines_are_skipped(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.write_text('not json\n{"seq": 1, "raw_sha256": "b", "message": "ok"}\n', encoding="utf-8")
        buffer = EventBuffer(path, 100)
        assert buffer.refresh() == 1

    def test_capacity_is_bounded(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.touch()
        buffer = EventBuffer(path, 10)
        self._write(path, [{"seq": i, "raw_sha256": f"h{i}", "message": "x"} for i in range(100)])
        buffer.refresh()
        assert len(buffer.all()) == 10

    def test_missing_file_is_not_an_error(self, tmp_path):
        assert EventBuffer(tmp_path / "absent.jsonl", 10).refresh() == 0


class TestEngineIntegration:
    def test_stats_does_not_force_a_model_load(self, engine):
        stats = engine.stats()
        assert stats["index"]["loaded"] is False

    def test_triage_selects_by_severity_then_restores_log_order(self, indexed_engine):
        alert = indexed_engine.triage_top(limit=10, min_score=60)
        assert alert.severity == "critical"
        assert alert.indicators["event_count"] <= 10

    def test_triage_with_no_qualifying_events_still_answers(self, indexed_engine):
        alert = indexed_engine.triage_top(limit=5, min_score=101)
        assert alert.alert_id

    def test_warm_reports_every_backend(self, engine):
        info = engine.warm()
        assert info["vector_backend"] == "local"
        assert info["llm_available"] is False
        assert info["embedder_semantic"] is False


class TestHoneytokensInTheFixture:
    """The demo data must actually exercise Phase 5.

    These assert on the Go ingestor's output as committed, so if the honeytoken
    config or detection logic regresses, the Python suite notices even though the
    detection itself lives in Go.
    """

    def _canaries(self, events):
        return [e for e in events if e.rule == "honeytoken_referenced"]

    def test_two_canary_events_are_present(self, engine):
        canaries = self._canaries(engine.events.all())
        assert len(canaries) == 2, [e.rule for e in engine.events.all()]

    def test_canaries_score_100_and_are_critical(self, engine):
        for event in self._canaries(engine.events.all()):
            assert event.score == 100
            assert event.severity == "critical"
            assert event.category == "deception"

    def test_both_token_kinds_are_demonstrated(self, engine):
        kinds = {e.fields.get("honeytoken_kind") for e in self._canaries(engine.events.all())}
        assert kinds == {"user", "path"}

    def test_the_triggering_rule_is_preserved(self, engine):
        # The alert must say *how* the canary was touched, not merely that it was.
        triggers = {e.fields.get("trigger_rule") for e in self._canaries(engine.events.all())}
        assert triggers == {"ssh_invalid_user", "sudo_command_executed"}

    def test_canary_tags_are_bilingual(self, engine):
        for event in self._canaries(engine.events.all()):
            assert "honeytoken" in event.tags
            assert "ハニートークン" in event.tags

    def test_a_single_canary_clears_the_firewall_threshold(self, engine):
        # The whole point of Phase 5: before it, only a correlated incident could
        # reach the response threshold. Now one event can.
        canary = next(e for e in self._canaries(engine.events.all()) if e.source_ip)
        action = engine.responder.block(canary.source_ip, score=canary.score, reason="honeytoken")
        assert action.allowed is True

        ordinary = next(e for e in engine.events.all() if e.rule == "ssh_failed_password")
        refused = engine.responder.block(ordinary.source_ip, score=ordinary.score, reason="ordinary")
        assert refused.allowed is False
        assert "below threshold" in refused.reason

    def test_canaries_did_not_disturb_the_brute_force_correlation(self, engine):
        # The canary lines were placed to avoid perturbing the 5-failure window
        # the rest of the fixture depends on.
        incident = next(e for e in engine.events.all() if e.rule == "correlated_brute_force")
        assert incident.fields["failure_count"] == "5"
        assert incident.fields["targeted_users"] == "admin, arron, oracle, root, test"
