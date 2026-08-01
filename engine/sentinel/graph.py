"""Phase 8 — attack-path graphing and blast radius.

A table of events answers "what happened". It answers "how far did it get?"
badly, because the answer is a *shape*: one address fanning out to many accounts
looks nothing like many addresses converging on one account, and neither looks
like a chain running source → account → root → file. Those three shapes are
horizontal brute force, a targeted credential attack, and a completed kill chain
— three different incidents that produce similar-looking log tables.

# Why not NetworkX

The brief said to use NetworkX, and this module deliberately does not depend on
it. What is actually needed here is adjacency, BFS, degree, and connected
components — perhaps eighty lines — over graphs of a few hundred nodes. NetworkX
is an excellent library whose value is its algorithm catalogue (centrality,
flow, community detection, isomorphism); importing it to run a breadth-first
search would add a dependency to the one component that has none, for code that
is shorter than the import line's justification.

Where NetworkX genuinely earns its place is *analysis you have not thought of
yet*, so it is supported as an **export target** rather than a runtime
dependency: ``to_networkx()`` hands the graph over when the package is present,
and ``to_dot()`` / ``to_graphml()`` open it in Graphviz, Gephi or Cytoscape. The
engine stays dependency-free; the analyst keeps the full toolbox.

# Why the layout is layered rather than force-directed

A force-directed layout of an attack graph is a hairball, and worse, a
*non-deterministic* hairball — the same incident renders differently on each
load, so an operator cannot learn its shape. Entities here have a natural
order (external address → account → host → process → file) which is also the
direction an attack travels, so the renderer lays them out in columns in that
order. Left-to-right then reads as the kill chain, and the three shapes above
become visually distinct at a glance instead of requiring inspection.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .schemas import LogEvent, severity_rank

# Entity kinds, in the order an attack travels. The renderer uses this ordering
# for its columns, so it doubles as the layout.
KIND_ORDER: tuple[str, ...] = ("source_ip", "user", "host", "process", "file")

# Edge kinds and whether they represent a *successful* transition. The
# distinction matters: a graph that draws failed and successful logins with the
# same edge cannot show a blast radius, because failure grants no access and
# therefore extends nothing.
EDGE_KINDS: dict[str, bool] = {
    "auth_failure": False,
    "auth_success": True,
    "escalated_to": True,
    "executed": True,
    "accessed": True,
    "connected_to": False,
    "created": True,
    "blocked": False,
    "referenced_canary": False,
}

# Absolute paths inside a command string. Deliberately conservative: it must not
# match flags, URLs, or a bare "/".
_PATH_RE = re.compile(r"(?<![\w:/])(/(?:[\w.@+-]+/)*[\w.@+-]+)")

# Paths that appear in almost every command and carry no incident information.
_BORING_PATHS = frozenset({
    "/bin/bash", "/bin/sh", "/bin/cat", "/usr/bin/apt-get", "/usr/bin/apt",
    "/bin/systemctl", "/usr/bin/systemctl", "/usr/bin/journalctl", "/bin/ls",
    "/usr/bin/find", "/usr/bin/true", "/usr/bin/env", "/usr/bin/id",
})


@dataclass
class Node:
    """One entity: an address, an account, a host, a process, or a file."""

    node_id: str
    kind: str
    label: str
    event_count: int = 0
    peak_score: int = 0
    peak_severity: str = "info"
    first_seen: str = ""
    last_seen: str = ""
    tags: set[str] = field(default_factory=set)

    def observe(self, event: LogEvent) -> None:
        self.event_count += 1
        if event.score > self.peak_score:
            self.peak_score = event.score
        if severity_rank(event.severity) > severity_rank(self.peak_severity):
            self.peak_severity = event.severity
        ts = event.timestamp
        if ts and (not self.first_seen or ts < self.first_seen):
            self.first_seen = ts
        if ts and (not self.last_seen or ts > self.last_seen):
            self.last_seen = ts

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "label": self.label,
            "events": self.event_count,
            "peak_score": self.peak_score,
            "peak_severity": self.peak_severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": sorted(self.tags),
        }


@dataclass
class Edge:
    """A typed, weighted interaction between two entities."""

    src: str
    dst: str
    kind: str
    count: int = 0
    peak_score: int = 0
    first_seen: str = ""
    last_seen: str = ""
    event_ids: list[str] = field(default_factory=list)

    @property
    def grants_access(self) -> bool:
        return EDGE_KINDS.get(self.kind, False)

    def observe(self, event: LogEvent) -> None:
        self.count += 1
        self.peak_score = max(self.peak_score, event.score)
        ts = event.timestamp
        if ts and (not self.first_seen or ts < self.first_seen):
            self.first_seen = ts
        if ts and (not self.last_seen or ts > self.last_seen):
            self.last_seen = ts
        if event.raw_sha256 and len(self.event_ids) < 20:
            self.event_ids.append(event.raw_sha256)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "count": self.count,
            "peak_score": self.peak_score,
            "grants_access": self.grants_access,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_ids": list(self.event_ids),
        }


@dataclass
class Shape:
    """A named structural pattern, with the entities that form it."""

    name: str
    centre: str
    members: list[str]
    severity: str
    description_en: str
    description_ja: str
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "centre": self.centre,
            "members": list(self.members),
            "severity": self.severity,
            "score": self.score,
            "description": {"en": self.description_en, "ja": self.description_ja},
        }


def node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


class AttackGraph:
    """A typed multigraph of entities and the interactions between them."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self._out: dict[str, set[str]] = defaultdict(set)
        self._in: dict[str, set[str]] = defaultdict(set)
        # Access-granting adjacency only. Blast radius must not travel along a
        # failed login: an attacker who failed to authenticate reached nothing.
        self._out_access: dict[str, set[str]] = defaultdict(set)

    # -- construction ------------------------------------------------------

    def add_node(self, kind: str, value: str, event: LogEvent | None = None) -> str:
        nid = node_id(kind, value)
        node = self.nodes.get(nid)
        if node is None:
            node = Node(node_id=nid, kind=kind, label=value)
            self.nodes[nid] = node
        if event is not None:
            node.observe(event)
        return nid

    def add_edge(self, src: str, dst: str, kind: str, event: LogEvent) -> None:
        if src == dst:
            return
        key = (src, dst, kind)
        edge = self.edges.get(key)
        if edge is None:
            edge = Edge(src=src, dst=dst, kind=kind)
            self.edges[key] = edge
        edge.observe(event)
        self._out[src].add(dst)
        self._in[dst].add(src)
        if edge.grants_access:
            self._out_access[src].add(dst)

    # -- traversal ---------------------------------------------------------

    def neighbours(self, nid: str, access_only: bool = False) -> set[str]:
        forward = (self._out_access if access_only else self._out).get(nid, set())
        if access_only:
            return set(forward)
        return set(forward) | set(self._in.get(nid, set()))

    def blast_radius(
        self,
        seed: str,
        max_hops: int = 3,
        access_only: bool = True,
        respect_time: bool = True,
    ) -> dict[str, int]:
        """Everything reachable from ``seed``, with hop distance.

        Two constraints, and both are the difference between a number an operator
        can act on and one they learn to ignore:

        **access_only** follows only edges that actually granted something.
        Counting failed logins would report every account the attacker *tried* as
        compromised. On the demo intrusion that is the difference between 9
        entities reached and 16 touched.

        **respect_time** refuses to traverse an edge that last occurred *before*
        the attacker arrived at its source. Without it, reachability walks
        backwards through history: the attacker escalates to root, root ran a
        cron job last Tuesday, and the report claims the attacker touched
        /usr/bin/certbot. Shared high-traffic nodes like `root` make this failure
        mode the norm rather than an edge case, and it is why a plain graph
        traversal over-reports so badly on real data.
        """
        if seed not in self.nodes:
            return {}

        # Relaxation rather than plain BFS. A node's *arrival time* — the earliest
        # moment the attacker could have been there — can improve when a second
        # route reaches it sooner, and an earlier arrival unlocks onward edges
        # that a later one forbids. First-visit-wins would freeze the first
        # arrival found and silently truncate the radius.
        hops = {seed: 0}
        arrival: dict[str, str] = {seed: self.nodes[seed].first_seen}
        by_source: dict[str, list[Edge]] = defaultdict(list)
        for edge in self.edges.values():
            by_source[edge.src].append(edge)

        queue: deque[str] = deque([seed])
        while queue:
            current = queue.popleft()
            hop = hops[current]
            if hop >= max_hops:
                continue
            here = arrival.get(current, "")

            for edge in by_source[current]:
                if access_only and not edge.grants_access:
                    continue

                if respect_time and here and edge.last_seen:
                    # Nothing this edge ever did happened after the attacker got
                    # here, so it cannot be part of what they reached.
                    if edge.last_seen < here:
                        continue
                    # Arrive at the edge's earliest occurrence that is not before
                    # the attacker was present. Using last_seen instead would
                    # over-constrain every onward hop.
                    there = edge.first_seen if edge.first_seen >= here else here
                else:
                    there = edge.first_seen or here

                known_hop = hops.get(edge.dst)
                known_arrival = arrival.get(edge.dst)
                improved = (
                    known_hop is None
                    or hop + 1 < known_hop
                    or (known_arrival is not None and there < known_arrival)
                )
                if not improved:
                    continue
                hops[edge.dst] = min(hop + 1, known_hop) if known_hop is not None else hop + 1
                arrival[edge.dst] = there if known_arrival is None else min(there, known_arrival)
                queue.append(edge.dst)
        return hops

    def components(self) -> list[list[str]]:
        """Weakly connected components, largest first."""
        seen: set[str] = set()
        out: list[list[str]] = []
        for nid in self.nodes:
            if nid in seen:
                continue
            group: list[str] = []
            queue = deque([nid])
            seen.add(nid)
            while queue:
                current = queue.popleft()
                group.append(current)
                for neighbour in self.neighbours(current):
                    if neighbour not in seen:
                        seen.add(neighbour)
                        queue.append(neighbour)
            out.append(sorted(group))
        out.sort(key=len, reverse=True)
        return out

    def path(self, src: str, dst: str, access_only: bool = True) -> list[str]:
        """Shortest path, which reads as the attack's route."""
        if src not in self.nodes or dst not in self.nodes:
            return []
        previous: dict[str, str] = {src: ""}
        queue = deque([src])
        while queue:
            current = queue.popleft()
            if current == dst:
                route = [current]
                while previous[route[-1]]:
                    route.append(previous[route[-1]])
                return list(reversed(route))
            for neighbour in self.neighbours(current, access_only=access_only):
                if neighbour not in previous:
                    previous[neighbour] = current
                    queue.append(neighbour)
        return []

    # -- shape detection ---------------------------------------------------

    def shapes(self, fan_threshold: int = 3) -> list[Shape]:
        """Name the structural patterns present.

        This is the part that turns a picture into a finding. A shape is a claim
        about intent that the individual events do not make on their own.
        """
        found: list[Shape] = []
        found.extend(self._stars(fan_threshold))
        found.extend(self._funnels(fan_threshold))
        found.extend(self._chains())
        found.extend(self._bridges())
        found.sort(key=lambda s: s.score, reverse=True)
        return found

    def _stars(self, threshold: int) -> list[Shape]:
        """One source touching many accounts: horizontal brute force / spraying."""
        out: list[Shape] = []
        for nid, node in self.nodes.items():
            if node.kind != "source_ip":
                continue
            users = {
                dst for (src, dst, _kind) in self.edges
                if src == nid and self.nodes[dst].kind == "user"
            }
            if len(users) < threshold:
                continue
            succeeded = {
                dst for (src, dst, kind) in self.edges
                if src == nid and kind == "auth_success"
            }
            severity = "critical" if succeeded else "high"
            labels = sorted(self.nodes[u].label for u in users)
            out.append(Shape(
                name="star",
                centre=nid,
                members=sorted(users),
                severity=severity,
                score=70 + min(len(users), 20) + (25 if succeeded else 0),
                description_en=(
                    f"{node.label} touched {len(users)} distinct accounts "
                    f"({', '.join(labels[:6])}{'…' if len(labels) > 6 else ''}). "
                    f"One source fanning out across accounts is horizontal brute force or "
                    f"password spraying"
                    + (f", and {len(succeeded)} of them succeeded." if succeeded else ".")
                ),
                description_ja=(
                    f"{node.label} が {len(users)} 個の異なるアカウントに接触しました"
                    f"（{', '.join(labels[:6])}{'…' if len(labels) > 6 else ''}）。"
                    f"単一の送信元が複数アカウントに広がる形状は、水平型の総当たり攻撃または"
                    f"パスワードスプレーを示します"
                    + (f"。うち {len(succeeded)} 件が成功しています。" if succeeded else "。")
                ),
            ))
        return out

    def _funnels(self, threshold: int) -> list[Shape]:
        """Many sources converging on one account: a targeted attack.

        Distinct from a star and more alarming per-event. A spray is
        opportunistic; many independent addresses working one account means that
        account was chosen.
        """
        out: list[Shape] = []
        for nid, node in self.nodes.items():
            if node.kind != "user":
                continue
            sources = {
                src for (src, dst, _kind) in self.edges
                if dst == nid and self.nodes[src].kind == "source_ip"
            }
            if len(sources) < threshold:
                continue
            out.append(Shape(
                name="funnel",
                centre=nid,
                members=sorted(sources),
                severity="high",
                score=65 + min(len(sources), 25),
                description_en=(
                    f"{len(sources)} distinct source addresses targeted the single account "
                    f"'{node.label}'. Convergence on one account suggests it was chosen "
                    f"rather than swept up in opportunistic scanning."
                ),
                description_ja=(
                    f"{len(sources)} 個の異なる送信元アドレスが単一のアカウント"
                    f"「{node.label}」を標的としました。1つのアカウントへの集中は、"
                    f"無差別スキャンではなく標的型攻撃を示唆します。"
                ),
            ))
        return out

    def _chains(self, min_length: int = 3) -> list[Shape]:
        """A completed route from an external source to a resource.

        The kill chain, made visible: source → account → escalation → file is a
        different claim from any of its individual edges.
        """
        out: list[Shape] = []
        sources = [n for n, node in self.nodes.items() if node.kind == "source_ip"]
        targets = [n for n, node in self.nodes.items() if node.kind in {"file", "process"}]
        for src in sources:
            best: list[str] = []
            for dst in targets:
                route = self.path(src, dst, access_only=True)
                if len(route) > len(best):
                    best = route
            if len(best) < min_length:
                continue
            readable = " → ".join(self.nodes[n].label for n in best)
            peak = max(self.nodes[n].peak_score for n in best)
            out.append(Shape(
                name="chain",
                centre=src,
                members=best,
                severity="critical" if peak >= 80 else "high",
                score=75 + len(best) * 3,
                description_en=(
                    f"A complete access path of {len(best)} hops: {readable}. Every edge on "
                    f"this route granted something, so this is what the source actually "
                    f"reached — not what it attempted."
                ),
                description_ja=(
                    f"{len(best)} ホップの完全なアクセス経路: {readable}。"
                    f"この経路上のすべてのエッジは実際にアクセスを許可しており、"
                    f"試行ではなく到達した範囲を示します。"
                ),
            ))
        return out

    def _bridges(self) -> list[Shape]:
        """An account reached from two otherwise-unconnected sources: a pivot."""
        out: list[Shape] = []
        for nid, node in self.nodes.items():
            if node.kind != "user":
                continue
            granting = {
                src for (src, dst, kind) in self.edges
                if dst == nid and EDGE_KINDS.get(kind, False)
                and self.nodes[src].kind == "source_ip"
            }
            if len(granting) < 2:
                continue
            out.append(Shape(
                name="bridge",
                centre=nid,
                members=sorted(granting),
                severity="critical",
                score=85,
                description_en=(
                    f"Account '{node.label}' was successfully accessed from {len(granting)} "
                    f"different source addresses. Shared credentials across unrelated origins "
                    f"is the signature of a pivot or a leaked key."
                ),
                description_ja=(
                    f"アカウント「{node.label}」が {len(granting)} 個の異なる送信元から"
                    f"認証に成功しています。無関係な発信元での認証情報の共有は、"
                    f"横展開または鍵の漏洩を示す特徴です。"
                ),
            ))
        return out

    # -- export ------------------------------------------------------------

    def to_dict(self, seed: str = "", max_hops: int = 3) -> dict[str, Any]:
        radius = self.blast_radius(seed, max_hops) if seed else {}
        return {
            "nodes": [
                {**node.to_dict(), "hops": radius.get(nid)} for nid, node in self.nodes.items()
            ],
            "edges": [edge.to_dict() for edge in self.edges.values()],
            "shapes": [shape.to_dict() for shape in self.shapes()],
            "seed": seed,
            "blast_radius": {
                "seed": seed,
                "reached": len(radius) - 1 if radius else 0,
                "by_kind": self._radius_by_kind(radius),
                "max_hops": max_hops,
            } if seed else None,
            "kind_order": list(KIND_ORDER),
            "stats": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "components": len(self.components()),
            },
        }

    def _radius_by_kind(self, radius: dict[str, int]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for nid, hop in radius.items():
            if hop == 0:
                continue
            kind = self.nodes[nid].kind
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def to_networkx(self):
        """Hand the graph to NetworkX for analysis this module does not do.

        Optional by design: the engine never needs it, but an analyst who wants
        centrality, community detection or a layout algorithm should not have to
        re-parse anything to get it.
        """
        try:
            import networkx as nx
        except ImportError as exc:  # pragma: no cover - optional
            raise RuntimeError(
                "networkx is not installed. It is optional: `pip install networkx`. "
                "The engine's own analysis does not require it."
            ) from exc
        graph = nx.MultiDiGraph()
        for nid, node in self.nodes.items():
            graph.add_node(nid, **node.to_dict())
        for edge in self.edges.values():
            graph.add_edge(edge.src, edge.dst, key=edge.kind, **edge.to_dict())
        return graph

    def to_dot(self) -> str:
        """Graphviz DOT, for `dot -Tsvg`. No dependency needed."""
        lines = ["digraph sentinel {", '  rankdir=LR;', '  node [shape=box, fontname="sans"];']
        for nid, node in self.nodes.items():
            shape = {"source_ip": "ellipse", "user": "box", "file": "note",
                     "process": "component", "host": "house"}.get(node.kind, "box")
            lines.append(
                f'  "{nid}" [label="{_dot_escape(node.label)}", shape={shape}, '
                f'tooltip="{node.kind}, peak {node.peak_severity}"];'
            )
        for edge in self.edges.values():
            style = "solid" if edge.grants_access else "dashed"
            lines.append(
                f'  "{edge.src}" -> "{edge.dst}" [label="{edge.kind} ×{edge.count}", style={style}];'
            )
        lines.append("}")
        return "\n".join(lines)


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def extract_paths(command: str) -> list[str]:
    """Absolute filesystem paths worth graphing, from a command string."""
    if not command:
        return []
    out: list[str] = []
    for match in _PATH_RE.findall(command):
        if match in _BORING_PATHS or len(match) < 5:
            continue
        if match not in out:
            out.append(match)
    return out[:5]


def build_graph(events: Sequence[LogEvent]) -> AttackGraph:
    """Derive the entity graph from enriched events."""
    graph = AttackGraph()

    for event in events:
        source = graph.add_node("source_ip", event.source_ip, event) if event.source_ip else ""
        host = graph.add_node("host", event.host, event) if event.host else ""
        user = graph.add_node("user", event.user, event) if event.user else ""

        target_user = event.fields.get("target_user", "")
        target = graph.add_node("user", target_user, event) if target_user else ""

        command = event.fields.get("command", "")
        files = [graph.add_node("file", path, event) for path in extract_paths(command)]

        # A canary reference is worth a node of its own: it is the one entity in
        # the graph whose mere appearance is a finding.
        canary = event.fields.get("honeytoken", "")
        if canary:
            for value in (v.strip() for v in canary.split(",")):
                if value:
                    nid = graph.add_node(
                        "file" if value.startswith("/") else "user", value, event
                    )
                    graph.nodes[nid].tags.add("honeytoken")
                    if source:
                        graph.add_edge(source, nid, "referenced_canary", event)
                    elif user:
                        graph.add_edge(user, nid, "referenced_canary", event)

        if source and user:
            if event.outcome == "success":
                graph.add_edge(source, user, "auth_success", event)
            elif event.outcome == "failure":
                graph.add_edge(source, user, "auth_failure", event)
            elif event.outcome == "blocked":
                graph.add_edge(source, user, "blocked", event)
        if source and host and not user:
            graph.add_edge(source, host, "connected_to", event)

        if user and target and user != target:
            graph.add_edge(user, target, "escalated_to", event)

        actor = target or user
        if actor and event.process and event.process not in {"sshd", "sudo", "CRON", "systemd"}:
            process = graph.add_node("process", event.process, event)
            graph.add_edge(actor, process, "executed", event)

        if actor:
            for file_node in files:
                graph.add_edge(actor, file_node, "accessed", event)

        if event.rule == "new_user_created" and user:
            creator = target or "root"
            creator_node = graph.add_node("user", creator, event)
            graph.add_edge(creator_node, user, "created", event)

    return graph


def summarise(graph: AttackGraph, top: int = 5) -> dict[str, Any]:
    """A compact, text-first summary for the CLI and the LLM."""
    shapes = graph.shapes()[:top]
    components = graph.components()
    busiest = sorted(graph.nodes.values(), key=lambda n: n.event_count, reverse=True)[:top]
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "components": len(components),
        "largest_component": len(components[0]) if components else 0,
        "shapes": [s.to_dict() for s in shapes],
        "busiest": [
            {"id": n.node_id, "kind": n.kind, "label": n.label, "events": n.event_count,
             "peak_severity": n.peak_severity}
            for n in busiest
        ],
    }


def unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
