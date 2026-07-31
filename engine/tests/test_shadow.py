"""Phase 6 — Shadow Search.

The properties worth testing here are mostly about restraint: that it refuses to
be confident on a thin baseline, that it does not re-report the same finding
nightly, and that it does not pad a five-item report with one incident described
five ways. An anomaly detector is easy to write and hard to make quiet.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.schemas import LogEvent
from sentinel.shadow import ALPHA, Anomaly, Baseline, ShadowSearch, ShadowState

BASE = datetime(2026, 7, 30, 6, 0, 0, tzinfo=timezone.utc)


def event(offset_hours: float, **kwargs) -> LogEvent:
    ts = BASE - timedelta(hours=offset_hours)
    defaults = {
        "raw_sha256": f"h{offset_hours}{kwargs.get('rule', '')}{kwargs.get('process', '')}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "process": "sshd",
        "rule": "ssh_failed_password",
        "category": "authentication",
        "severity": "warning",
        "score": 54,
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


@pytest.fixture
def historied_engine(settings):
    """An engine whose event log has a week of history before the intrusion.

    The committed demo fixture is five minutes of events with no "before", which
    makes every value novel and — correctly — yields zero surprise, since there is
    no basis for it. Advisory generation therefore cannot be exercised against it.
    This writes a boring baseline first, which is the condition Shadow Search is
    actually designed for.
    """
    import json as _json

    from sentinel.engine import SentinelEngine

    rows = []
    # ~10 days of routine sshd noise, well before the window. Deliberately over
    # the 200-event shadow_min_baseline so this fixture exercises the confident
    # path; the thin-baseline refusal has its own test.
    for hour in range(30, 260):
        rows.append({
            "raw_sha256": f"base{hour}",
            "timestamp": (BASE - timedelta(hours=hour)).isoformat().replace("+00:00", "Z"),
            "process": "sshd", "rule": "ssh_failed_password", "category": "authentication",
            "severity": "warning", "score": 54, "user": "admin",
            "source_ip": f"198.51.100.{hour % 200 + 1}", "message": "Failed password for invalid user admin",
        })
    # Inside the window: a miner and a credential dropper, neither ever seen.
    rows.append({
        "raw_sha256": "win-miner",
        "timestamp": (BASE - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        "process": "systemd", "rule": "cryptominer_indicator", "category": "impact",
        "severity": "critical", "score": 92, "message": "Started xmrig-proxy.service.",
    })
    rows.append({
        "raw_sha256": "win-persist",
        "timestamp": (BASE - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "process": "bash", "rule": "authorized_keys_modified", "category": "persistence",
        "severity": "high", "score": 78,
        "message": "echo 'ssh-ed25519 AAAA' >> /root/.ssh/authorized_keys",
    })

    settings.events_path.parent.mkdir(parents=True, exist_ok=True)
    with settings.events_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(_json.dumps(row) + "\n")

    built = SentinelEngine(settings)
    built.events.refresh()
    built.indexer.index_advisories()
    return built


class TestBaseline:
    def test_counts_every_dimension(self):
        baseline = Baseline.build([event(48, user="arron", source_ip="10.0.0.1")])
        assert baseline.counts["rule"]["ssh_failed_password"] == 1
        assert baseline.counts["user"]["arron"] == 1
        assert baseline.counts["source_ip"]["10.0.0.1"] == 1
        assert baseline.counts["hour"]  # derived from the timestamp

    def test_novel_value_has_finite_surprise(self):
        # p=0 would be infinite bits. Smoothing is what keeps a brand-new host
        # from declaring that everything is infinitely anomalous on day one.
        baseline = Baseline.build([event(48) for _ in range(50)])
        bits = baseline.surprise_bits("rule", "never_seen_rule")
        assert 0 < bits < 100
        assert bits == pytest.approx(-__import__("math").log2(ALPHA / (50 + ALPHA * 2)), rel=1e-6)

    def test_common_value_is_less_surprising_than_rare(self):
        events = [event(48) for _ in range(99)] + [event(47, rule="rare_rule")]
        baseline = Baseline.build(events)
        assert baseline.surprise_bits("rule", "ssh_failed_password") < baseline.surprise_bits("rule", "rare_rule")

    def test_empty_baseline_finds_nothing_surprising(self):
        # With no history there is no basis for surprise, and the smoothed
        # probability collapses to 1.0 -> 0 bits. That is the safe direction:
        # a host on its first boot reports nothing rather than everything.
        baseline = Baseline.build([])
        assert baseline.surprise_bits("rule", "anything") == 0.0
        assert baseline.rate_per_hour("rule", "anything") == 0.0


class TestSplit:
    def test_partitions_at_the_window_boundary(self, engine):
        shadow = ShadowSearch(engine)
        events = [event(1), event(5), event(30), event(100)]
        baseline, window = shadow.split(events, window_hours=24, now=BASE)
        assert len(window) == 2
        assert len(baseline) == 2

    def test_events_without_timestamps_are_dropped(self, engine):
        shadow = ShadowSearch(engine)
        broken = LogEvent(raw_sha256="x", timestamp="", ingested_at="")
        baseline, window = shadow.split([broken, event(1)], window_hours=24, now=BASE)
        assert len(baseline) + len(window) == 1


class TestAnomalyDetection:
    def _shadow(self, engine) -> ShadowSearch:
        return ShadowSearch(engine)

    def test_novel_process_is_found(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h, process="sshd") for h in range(30, 200)])
        # Keeps the known rule, so `process` is the only novel dimension and the
        # finding cannot be collapsed into an equally-novel sibling.
        window = [event(1, process="xmrig", raw_sha256="w1")]

        found = shadow.find_anomalies(baseline, window, limit=5, min_surprise=1.0, min_count=1)
        processes = [a for a in found if a.dimension == "process"]
        assert processes and processes[0].value == "xmrig"
        assert processes[0].kind == "novel"
        assert processes[0].baseline_count == 0

    def test_volume_spike_on_a_known_value_is_found(self, engine):
        shadow = self._shadow(engine)
        # One failure per hour for 200 hours, then 200 in the window.
        baseline = Baseline.build([event(h) for h in range(25, 225)])
        window = [event(1 + i / 100, raw_sha256=f"w{i}") for i in range(200)]

        found = shadow.find_anomalies(baseline, window, limit=10, min_surprise=0.5, min_count=5)
        spikes = [a for a in found if a.kind == "spike"]
        assert spikes, [(a.value, a.kind) for a in found]
        assert "usual rate" in spikes[0].reason_en

    def test_min_count_filters_singletons(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [event(1, process="oneoff", raw_sha256="w1")]

        assert shadow.find_anomalies(baseline, window, limit=5, min_surprise=1.0, min_count=2) == []

    def test_min_surprise_filters_the_mundane(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [event(1, raw_sha256=f"w{i}") for i in range(5)]

        # Everything in the window is exactly what the baseline predicts.
        assert shadow.find_anomalies(baseline, window, limit=5, min_surprise=6.0, min_count=1) == []

    def test_one_incident_is_not_reported_five_ways(self, engine):
        # A novel rule, category, and process can all be the same two events.
        # Reported separately they fill the whole report with one finding.
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [
            event(1, process="xmrig", rule="cryptominer_indicator", category="impact", raw_sha256="same1"),
            event(1, process="xmrig", rule="cryptominer_indicator", category="impact", raw_sha256="same2"),
        ]
        found = shadow.find_anomalies(baseline, window, limit=5, min_surprise=1.0, min_count=1)
        assert len(found) == 1, [(a.dimension, a.value) for a in found]

    def test_distinct_incidents_are_both_reported(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [
            event(1, process="xmrig", rule="cryptominer_indicator", raw_sha256="a1"),
            event(2, process="pkexec", rule="pkexec_polkit_abuse", raw_sha256="b1"),
        ]
        found = shadow.find_anomalies(baseline, window, limit=5, min_surprise=1.0, min_count=1)
        assert len({a.value for a in found}) >= 2

    def test_one_noisy_dimension_cannot_fill_the_report(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [event(1, source_ip=f"203.0.113.{i}", raw_sha256=f"w{i}") for i in range(20)]

        found = shadow.find_anomalies(baseline, window, limit=5, min_surprise=1.0, min_count=1)
        by_dimension = [a.dimension for a in found]
        assert by_dimension.count("source_ip") <= 2

    def test_results_are_ordered_by_surprise(self, engine):
        shadow = self._shadow(engine)
        baseline = Baseline.build([event(h) for h in range(30, 200)])
        window = [
            event(1, process="xmrig", raw_sha256="a"),
            event(2, process="pkexec", raw_sha256="b"),
            event(3, user="root", raw_sha256="c"),
        ]
        found = shadow.find_anomalies(baseline, window, limit=10, min_surprise=0.1, min_count=1)
        assert [a.surprise for a in found] == sorted((a.surprise for a in found), reverse=True)


class TestState:
    def test_suppresses_within_cooldown(self, tmp_path):
        state = ShadowState(tmp_path / "s.json")
        state.record(["rule=x"], BASE)
        assert state.is_suppressed("rule=x", BASE + timedelta(hours=1), 24) is True

    def test_allows_after_cooldown(self, tmp_path):
        state = ShadowState(tmp_path / "s.json")
        state.record(["rule=x"], BASE)
        assert state.is_suppressed("rule=x", BASE + timedelta(hours=25), 24) is False

    def test_unknown_key_is_never_suppressed(self, tmp_path):
        assert ShadowState(tmp_path / "s.json").is_suppressed("rule=new", BASE, 24) is False

    def test_persists_across_instances(self, tmp_path):
        ShadowState(tmp_path / "s.json").record(["rule=x"], BASE)
        assert ShadowState(tmp_path / "s.json").is_suppressed("rule=x", BASE, 24) is True

    def test_corrupt_state_degrades_to_empty(self, tmp_path):
        path = tmp_path / "s.json"
        path.write_text("{not json", encoding="utf-8")
        assert ShadowState(path).is_suppressed("rule=x", BASE, 24) is False


class TestRun:
    def test_thin_baseline_is_flagged_low_confidence(self, indexed_engine):
        # The fixture is ~5 minutes of events, far under the 200-event minimum.
        report = indexed_engine.shadow_search(window_hours=24 * 365, ignore_cooldown=True)
        assert report.low_confidence is True
        assert any("below the" in note for note in report.notes)

    def test_empty_window_says_so_rather_than_inventing_findings(self, indexed_engine):
        report = indexed_engine.shadow_search(window_hours=1, ignore_cooldown=True)
        assert report.window_events == 0
        assert report.anomalies == []
        assert any("nothing to analyse" in note for note in report.notes)

    def test_report_serialises(self, indexed_engine):
        report = indexed_engine.shadow_search(window_hours=24 * 365, ignore_cooldown=True)
        parsed = json.loads(report.to_json())
        assert "anomalies" in parsed and "advisories" in parsed
        assert parsed["window_hours"] == 24 * 365

    def test_advisories_cite_threat_intelligence_not_our_own_logs(self, historied_engine):
        # Retrieving log windows to explain log windows is circular, and it
        # crowds out the JPCERT/CVE documents that are the point.
        report = historied_engine.shadow_search(window_hours=24, ignore_cooldown=True, now=BASE)
        assert report.advisories, "expected at least one advisory from the fixture"
        for advisory in report.advisories:
            for citation in advisory.citations:
                assert "Log window" not in citation.title, citation.title

    def test_advisories_are_bilingual(self, historied_engine):
        report = historied_engine.shadow_search(window_hours=24, ignore_cooldown=True, now=BASE)
        assert report.advisories
        for advisory in report.advisories:
            assert advisory.title_ja and advisory.summary_ja
            assert any(ord(ch) > 0x3000 for ch in advisory.summary_ja)

    def test_cooldown_suppresses_a_second_run(self, historied_engine):
        first = historied_engine.shadow_search(window_hours=24, now=BASE)
        assert first.advisories
        second = historied_engine.shadow_search(window_hours=24, now=BASE)
        assert second.suppressed > 0
        assert not second.advisories
        assert any("suppressed" in note for note in second.notes)

    def test_ignore_cooldown_overrides_suppression(self, historied_engine):
        historied_engine.shadow_search(window_hours=24, now=BASE)
        again = historied_engine.shadow_search(window_hours=24, ignore_cooldown=True, now=BASE)
        assert again.advisories

    def test_as_of_replays_a_historical_window(self, indexed_engine):
        # The fixture is dated in the past, so the default "now" finds nothing.
        default = indexed_engine.shadow_search(window_hours=24, ignore_cooldown=True)
        assert default.window_events == 0

        replayed = indexed_engine.shadow_search(
            window_hours=24, ignore_cooldown=True,
            now=datetime(2026, 7, 30, 6, 0, tzinfo=timezone.utc),
        )
        assert replayed.window_events > 0

    def test_finds_the_planted_anomalies(self, historied_engine):
        report = historied_engine.shadow_search(window_hours=24, ignore_cooldown=True, now=BASE)
        assert report.low_confidence is False, report.notes
        values = {a.value for a in report.anomalies}
        assert "cryptominer_indicator" in values or "impact" in values
        assert "authorized_keys_modified" in values or "persistence" in values

    def test_report_is_persisted_for_the_dashboard(self, indexed_engine):
        indexed_engine.shadow_search(window_hours=24 * 365, ignore_cooldown=True)
        latest = indexed_engine.shadow_latest()
        assert latest["never_run"] is False
        assert "anomalies" in latest

    def test_latest_is_safe_before_any_run(self, engine):
        latest = engine.shadow_latest()
        assert latest["never_run"] is True
        assert latest["anomalies"] == []
        assert any("has not run yet" in note for note in latest["notes"])


class TestQueryConstruction:
    def test_query_uses_behaviour_not_just_the_bare_value(self, engine):
        # Searching an advisory corpus for "203.0.113.45" retrieves nothing;
        # searching for what it did retrieves the document that explains it.
        shadow = ShadowSearch(engine)
        anomaly = Anomaly(
            dimension="source_ip", value="203.0.113.45", count=9, baseline_count=0,
            surprise=10.0, kind="novel", reason_en="never seen", reason_ja="未出現",
            example="Failed password for root from 203.0.113.45 port 22 ssh2",
            peak_severity="high",
        )
        query = shadow.query_for(anomaly)
        assert "203.0.113.45" in query
        assert "Failed password" in query
        assert "source address" in query
