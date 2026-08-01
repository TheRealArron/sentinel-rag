"""The façade that wires the engine together.

Everything above this line is a component with one job; ``SentinelEngine`` is the
one place that knows how they fit. The CLI, the FastAPI app, and the stdlib server
all drive this object, so there is exactly one construction path and one place
where the backend-selection story lives.

Components are built lazily. Loading multilingual-e5 costs seconds and hundreds of
megabytes of RAM, so ``/api/events`` — which needs no model at all — must not pay
for it. The first search or analysis triggers the load.
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from . import corpus
from .analyst import Analyst
from .config import Settings, get_settings
from .embeddings import Embedder, get_embedder
from .indexer import Indexer, IndexStats
from .llm import LLM, get_llm
from .response import Responder
from .retriever import ParentDocumentRetriever
from .schemas import Alert, LogEvent, Retrieved, severity_rank
from .store import ParentStore, VectorStore, get_parent_store, get_vector_store


class EventBuffer:
    """A bounded, incrementally-refreshed view of the ingestor's JSONL output.

    Re-reading the whole file on every request would make the dashboard's refresh
    cost grow without bound as logs accumulate, so the buffer remembers its byte
    offset and reads only what is new. It also detects truncation and inode
    replacement, because logrotate will do both underneath a long-running process.
    """

    def __init__(self, path: Path, max_events: int) -> None:
        self.path = Path(path)
        self.max_events = max_events
        self._events: deque[LogEvent] = deque(maxlen=max_events)
        self._seen: set[str] = set()
        self._offset = 0
        self._inode: int | None = None
        self._lock = threading.RLock()

    def refresh(self) -> int:
        """Read newly appended events. Returns how many were added."""
        with self._lock:
            if not self.path.exists():
                return 0
            stat = self.path.stat()
            if self._inode is not None and (stat.st_ino != self._inode or stat.st_size < self._offset):
                # Rotated or truncated: the offset is meaningless, start over.
                self._offset = 0
                self._events.clear()
                self._seen.clear()
            self._inode = stat.st_ino
            if stat.st_size == self._offset:
                return 0

            added = 0
            # Binary mode so the byte offset is exact. In text mode a replacement
            # character has a different encoded length than the bytes it replaced,
            # which would desynchronise the offset and silently skip or re-read
            # lines forever.
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                for raw in fh:
                    if not raw.endswith(b"\n"):
                        # Partial final line: the ingestor flushes on a timer, so
                        # leave the offset before it and pick it up next refresh.
                        break
                    self._offset += len(raw)
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    event = _safe_event(line)
                    if event is None:
                        continue
                    if event.raw_sha256 and event.raw_sha256 in self._seen:
                        continue
                    if event.raw_sha256:
                        if len(self._seen) >= self.max_events * 2:
                            self._seen.clear()  # bounded: the deque already caps history
                        self._seen.add(event.raw_sha256)
                    self._events.append(event)
                    added += 1
            return added

    def all(self) -> list[LogEvent]:
        with self._lock:
            return list(self._events)

    def query(
        self,
        limit: int = 100,
        min_score: int = 0,
        severity: str = "",
        category: str = "",
        source_ip: str = "",
        rule: str = "",
        incidents_only: bool = False,
        search: str = "",
    ) -> list[LogEvent]:
        """Filter the buffer, newest first."""
        results: list[LogEvent] = []
        needle = search.lower()
        for event in reversed(self.all()):
            if event.score < min_score:
                continue
            if severity and event.severity != severity:
                continue
            if category and event.category != category:
                continue
            if source_ip and event.source_ip != source_ip:
                continue
            if rule and event.rule != rule:
                continue
            if incidents_only and not event.is_incident:
                continue
            if needle and needle not in event.message.lower() and needle not in event.rule.lower():
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return results

    def summary(self) -> dict[str, Any]:
        events = self.all()
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_source: dict[str, int] = {}
        incidents = 0
        sanitised = 0
        for event in events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_category[event.category] = by_category.get(event.category, 0) + 1
            if event.source_ip:
                by_source[event.source_ip] = by_source.get(event.source_ip, 0) + 1
            if event.is_incident:
                incidents += 1
            if event.sanitized:
                sanitised += 1
        top_sources = sorted(by_source.items(), key=lambda kv: kv[1], reverse=True)[:10]
        return {
            "events": len(events),
            "incidents": incidents,
            "sanitised_lines": sanitised,
            "by_severity": by_severity,
            "by_category": by_category,
            "top_sources": [{"source_ip": ip, "count": n} for ip, n in top_sources],
            "buffer_capacity": self.max_events,
            "events_path": str(self.path),
            "events_path_exists": self.path.exists(),
        }


def _safe_event(line: str) -> LogEvent | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    try:
        return LogEvent.from_dict(obj)
    except (TypeError, ValueError):
        return None


class SentinelEngine:
    """Lazily-constructed composition root."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.ensure_dirs()
        self.events = EventBuffer(self.settings.events_path, self.settings.max_events_in_memory)
        self.responder = Responder(self.settings)
        self._lock = threading.RLock()
        self._embedder: Embedder | None = None
        self._vectors: VectorStore | None = None
        self._parents: ParentStore | None = None
        self._retriever: ParentDocumentRetriever | None = None
        self._llm: LLM | None = None
        self._analyst: Analyst | None = None
        self._indexer: Indexer | None = None
        self._shadow: Any = None
        self.events.refresh()

    # -- lazy components ---------------------------------------------------

    @property
    def embedder(self) -> Embedder:
        with self._lock:
            if self._embedder is None:
                self._embedder = get_embedder(self.settings)
            return self._embedder

    @property
    def vectors(self) -> VectorStore:
        with self._lock:
            if self._vectors is None:
                self._vectors = get_vector_store(self.settings)
            return self._vectors

    @property
    def parents(self) -> ParentStore:
        with self._lock:
            if self._parents is None:
                self._parents = get_parent_store(self.settings)
            return self._parents

    @property
    def retriever(self) -> ParentDocumentRetriever:
        with self._lock:
            if self._retriever is None:
                self._retriever = ParentDocumentRetriever(
                    self.settings, self.embedder, self.vectors, self.parents
                )
            return self._retriever

    @property
    def llm(self) -> LLM:
        with self._lock:
            if self._llm is None:
                self._llm = get_llm(self.settings)
            return self._llm

    @property
    def analyst(self) -> Analyst:
        with self._lock:
            if self._analyst is None:
                self._analyst = Analyst(self.settings, self.retriever, self.llm)
            return self._analyst

    @property
    def indexer(self) -> Indexer:
        with self._lock:
            if self._indexer is None:
                self._indexer = Indexer(self.settings, self.embedder, self.vectors, self.parents)
            return self._indexer

    @property
    def shadow(self):
        """Phase 6 proactive correlation. Lazy: it pulls in the retriever."""
        with self._lock:
            if self._shadow is None:
                from .shadow import ShadowSearch

                self._shadow = ShadowSearch(self, self.settings)
            return self._shadow

    # -- operations --------------------------------------------------------

    def search(
        self,
        query: str,
        k: int | None = None,
        languages: Sequence[str] | None = None,
        doc_types: Sequence[str] | None = None,
    ) -> list[Retrieved]:
        return self.retriever.retrieve(query, k=k, languages=languages, doc_types=doc_types)

    def analyze_events(self, events: Sequence[LogEvent], question: str = "") -> Alert:
        return self.analyst.analyze(events=events, question=question)

    def analyze_question(self, question: str) -> Alert:
        return self.analyst.analyze(question=question)

    def triage_top(self, limit: int = 25, min_score: int = 60, question: str = "") -> Alert:
        """Analyse the most significant recent events.

        Selection is by deterministic score, not recency: the point of triage is to
        surface the important thing, and the important thing is rarely the newest
        line. Events are re-sorted into log order before analysis so the narrative
        the model sees is chronological.
        """
        self.events.refresh()
        candidates = sorted(
            self.events.query(limit=limit * 4, min_score=min_score),
            key=lambda e: (severity_rank(e.severity), e.score),
            reverse=True,
        )[:limit]
        candidates.sort(key=lambda e: (e.timestamp, e.seq))
        if not candidates:
            return self.analyst.analyze(
                question=question or "No events above the score threshold are present."
            )
        return self.analyst.analyze(events=candidates, question=question)

    def shadow_search(self, window_hours: int | None = None, limit: int | None = None,
                      ignore_cooldown: bool = False, now: Any = None):
        """Run one Shadow Search pass, persist the report, and return it.

        ``now`` overrides the window anchor, which is how a historical window is
        replayed — useful for incident review, and the only way to analyse an
        archived log whose events are older than the window.
        """
        report = self.shadow.run(window_hours=window_hours, limit=limit,
                                 ignore_cooldown=ignore_cooldown, now=now)
        self._write_shadow_report(report)
        return report

    def _write_shadow_report(self, report) -> None:
        """Persist atomically so a dashboard poll never reads a half-written file."""
        import tempfile

        path = self.settings.index_dir / "shadow_report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".shadow-report-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(report.to_json(indent=None))
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def shadow_latest(self) -> dict[str, Any]:
        """Last persisted report, or an empty shell if Shadow Search never ran.

        Deliberately does not trigger a run: the dashboard polls this, and a poll
        that silently rebuilt the baseline would be the most expensive request in
        the system.
        """
        path = self.settings.index_dir / "shadow_report.json"
        if not path.exists():
            return {
                "created_at": "",
                "never_run": True,
                "anomalies": [],
                "advisories": [],
                "notes": ["Shadow Search has not run yet. Try: python -m sentinel shadow"],
            }
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"created_at": "", "never_run": True, "anomalies": [], "advisories": [],
                    "notes": [f"Could not read the stored report: {exc}"]}
        data["never_run"] = False
        return data

    def attack_graph(self, limit: int = 5000, min_score: int = 0):
        """Build the entity graph from the buffered events.

        Rebuilt per request rather than cached: it is O(events) over a bounded
        buffer, and a stale graph on a security dashboard is worse than a slightly
        slower one.
        """
        from .graph import build_graph

        self.events.refresh()
        return build_graph(self.events.query(limit=limit, min_score=min_score))

    def index_all(self, rebuild: bool = False) -> IndexStats:
        if rebuild:
            return self.indexer.rebuild()
        stats = self.indexer.index_advisories()
        return stats.merge(self.indexer.index_event_file())

    def index_events_from_buffer(self) -> IndexStats:
        self.events.refresh()
        return self.indexer.index_events(self.events.all())

    # -- introspection -----------------------------------------------------

    def stats(self) -> dict[str, Any]:
        self.events.refresh()
        out: dict[str, Any] = {
            "events": self.events.summary(),
            "response": self.responder.status(),
            "corpus": corpus.corpus_stats(self.settings.advisory_dir),
        }
        # Index and model stats require building the components, which is
        # expensive. Report them only if something already triggered the load, so
        # a health check stays cheap.
        with self._lock:
            loaded = self._vectors is not None and self._embedder is not None
        if loaded:
            out["index"] = self.indexer.stats()
        else:
            out["index"] = {"loaded": False, "note": "index not loaded yet; call /api/search or /api/analyze"}
        out["llm"] = {
            "provider": self._llm.provider if self._llm else "not loaded",
            "model": self._llm.model if self._llm else "not loaded",
            "available": self._llm.available if self._llm else None,
            # Air-gap posture is reported whether or not the LLM has loaded: an
            # operator asking "is anything leaving this host?" must not have to
            # trigger a model load to find out.
            "air_gap": self.settings.air_gap,
            "local_backend": self.settings.local_backend,
            "cloud_fallback": self.settings.llm_fallback,
            "escalations": getattr(self._llm, "escalations", 0) if self._llm else 0,
        }
        out["config"] = {
            "embedding_backend": self.settings.embedding_backend,
            "embedding_model": self.settings.embedding_model,
            "vector_backend": self.settings.vector_backend,
            "child_tokens": self.settings.child_tokens,
            "parent_tokens": self.settings.parent_tokens,
            "top_k": self.settings.top_k,
            "per_language_floor": self.settings.per_language_floor,
            "anonymize": self.settings.anonymize,
        }
        return out

    def health(self) -> dict[str, Any]:
        """Cheap liveness probe: no model load, no index touch."""
        return {
            "status": "ok",
            "events_buffered": len(self.events.all()),
            "events_path_exists": self.settings.events_path.exists(),
            "advisories_dir_exists": self.settings.advisory_dir.exists(),
            "response_mode": self.settings.response_mode,
        }

    def warm(self) -> dict[str, Any]:
        """Force the lazy components to load. Used by the CLI and by tests."""
        return {
            "embedder": self.embedder.name,
            "embedder_semantic": self.embedder.semantic,
            "vector_backend": self.vectors.backend,
            "vectors": self.vectors.count(),
            "parents": self.parents.count(),
            "llm_provider": self.llm.provider,
            "llm_available": self.llm.available,
            "air_gap": self.settings.air_gap,
            "local": self.local_health(),
        }

    def local_health(self) -> dict[str, Any]:
        """Probe the local inference server without loading anything heavy.

        Preflight for air-gap deployments: the failure mode this catches is a
        host configured for local inference where the model was never pulled, so
        every alert silently degrades to rule-based.
        """
        if self.settings.local_backend in {"", "none"}:
            return {"enabled": False}
        from .local_llm import build_local_llm

        try:
            backend = build_local_llm(self.settings)
        except Exception as exc:  # noqa: BLE001
            return {"enabled": True, "error": str(exc)}
        if backend is None:
            return {"enabled": False}
        return {"enabled": True, **backend.health()}


def event_from_fingerprints(engine: SentinelEngine, fingerprints: Iterable[str]) -> list[LogEvent]:
    """Look up buffered events by their raw_sha256 fingerprints."""
    wanted = {f for f in fingerprints if f}
    if not wanted:
        return []
    return [e for e in engine.events.all() if e.raw_sha256 in wanted]
