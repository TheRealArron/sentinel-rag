"""Building the hierarchical index.

The indexer is the write path: documents in, parents to the parent store, child
vectors to the vector store. Two properties it guarantees:

*   **Idempotence.** Child ids are content-addressed (``chunking._stable_id`` over
    parent id, ordinal, and text), so re-indexing an unchanged corpus embeds
    nothing and writes nothing. This matters more than it sounds: embedding is by
    far the most expensive step, and a home server that re-indexes on every boot
    would spend minutes of CPU re-deriving vectors it already has.
*   **Batching.** Texts are embedded in batches, because per-text model calls on
    CPU are dominated by fixed overhead.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import corpus
from .chunking import build_hierarchy
from .config import Settings
from .embeddings import Embedder
from .schemas import Chunk, Document, LogEvent
from .store import ParentStore, VectorStore


@dataclass
class IndexStats:
    """What an indexing run did, for the CLI and ``/api/stats``."""

    documents: int = 0
    parents: int = 0
    children_total: int = 0
    children_embedded: int = 0
    children_skipped: int = 0
    by_language: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)

    def merge(self, other: IndexStats) -> IndexStats:
        merged = IndexStats(
            documents=self.documents + other.documents,
            parents=self.parents + other.parents,
            children_total=self.children_total + other.children_total,
            children_embedded=self.children_embedded + other.children_embedded,
            children_skipped=self.children_skipped + other.children_skipped,
            by_language=dict(self.by_language),
            by_type=dict(self.by_type),
        )
        for key, value in other.by_language.items():
            merged.by_language[key] = merged.by_language.get(key, 0) + value
        for key, value in other.by_type.items():
            merged.by_type[key] = merged.by_type.get(key, 0) + value
        return merged

    def to_dict(self) -> dict[str, object]:
        return {
            "documents": self.documents,
            "parents": self.parents,
            "children_total": self.children_total,
            "children_embedded": self.children_embedded,
            "children_skipped": self.children_skipped,
            "by_language": dict(self.by_language),
            "by_type": dict(self.by_type),
        }


class Indexer:
    def __init__(
        self,
        settings: Settings,
        embedder: Embedder,
        vectors: VectorStore,
        parents: ParentStore,
    ) -> None:
        self.settings = settings
        self.embedder = embedder
        self.vectors = vectors
        self.parents = parents

    # -- documents ---------------------------------------------------------

    def index_documents(self, docs: Sequence[Document]) -> IndexStats:
        stats = IndexStats()
        if not docs:
            return stats

        all_parents: list[Document] = []
        all_children: list[Chunk] = []
        for doc in docs:
            parents, children = build_hierarchy(
                doc,
                parent_tokens=self.settings.parent_tokens,
                child_tokens=self.settings.child_tokens,
                child_overlap=self.settings.child_overlap,
            )
            if not parents:
                continue
            stats.documents += 1
            stats.by_language[doc.lang] = stats.by_language.get(doc.lang, 0) + 1
            stats.by_type[doc.doc_type] = stats.by_type.get(doc.doc_type, 0) + 1
            all_parents.extend(parents)
            all_children.extend(children)

        stats.parents = len(all_parents)
        stats.children_total = len(all_children)

        # Parents are written first. If the process dies between the two writes,
        # an orphaned parent is harmless (nothing points at it) whereas an
        # orphaned child would retrieve and then fail to expand.
        self.parents.put_many(all_parents)

        already = self.vectors.existing_ids([c.chunk_id for c in all_children])
        todo = [c for c in all_children if c.chunk_id not in already]
        stats.children_skipped = len(all_children) - len(todo)

        for batch in _batches(todo, self.settings.embedding_batch_size):
            vectors = self.embedder.embed_documents([c.text for c in batch])
            self.vectors.add(batch, vectors)
            stats.children_embedded += len(batch)

        return stats

    # -- convenience entry points ------------------------------------------

    def index_advisories(self, advisory_dir: Path | None = None) -> IndexStats:
        docs = corpus.load_advisories(advisory_dir or self.settings.advisory_dir)
        return self.index_documents(docs)

    def index_events(self, events: Sequence[LogEvent], window_minutes: int = 10) -> IndexStats:
        docs = corpus.events_to_documents(events, window_minutes)
        return self.index_documents(docs)

    def index_event_file(self, events_path: Path | None = None, limit: int | None = None) -> IndexStats:
        events = corpus.load_events(events_path or self.settings.events_path, limit=limit)
        return self.index_events(events)

    def rebuild(self) -> IndexStats:
        """Drop the index and rebuild it from advisories plus the event log."""
        self.vectors.reset()
        self.parents.reset()
        stats = self.index_advisories()
        return stats.merge(self.index_event_file())

    def stats(self) -> dict[str, object]:
        return {
            "vectors": self.vectors.count(),
            "backend": self.vectors.backend,
            "embedder": self.embedder.name,
            "embedder_semantic": self.embedder.semantic,
            "embedding_dim": self.embedder.dim,
            **self.parents.stats(),
        }


def _batches(items: Sequence[Chunk], size: int) -> list[Sequence[Chunk]]:
    size = max(1, size)
    return [items[i : i + size] for i in range(0, len(items), size)]
