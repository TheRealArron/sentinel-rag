"""Vector storage and the parent document store.

Two backends behind one interface:

*   ``ChromaVectorStore`` — ChromaDB with a persistent HNSW index, configured for
    cosine space. This is the production path. HNSW gives approximate nearest
    neighbour in O(log n)-ish time, which is what lets the index keep answering in
    milliseconds as a home server accumulates months of logs.
*   ``LocalVectorStore`` — exact brute-force cosine over a JSONL file, no
    dependencies. It exists so the engine boots on a clean checkout, and it is
    genuinely correct (exact, not approximate) — just O(n) per query, so it is
    capped and warns past a size where that stops being acceptable.

The **parent store is separate from the vector store on purpose**. Only child
chunks are embedded and indexed; parents are looked up by id after retrieval.
Storing parents as vectors too would double the index for no benefit and would
let a parent out-rank its own child.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .config import Settings
from .embeddings import cosine
from .schemas import Chunk, Document

# Past this many vectors, exact brute-force search stops being a reasonable
# default and the operator should install ChromaDB.
LOCAL_BACKEND_SOFT_LIMIT = 50_000


@runtime_checkable
class VectorStore(Protocol):
    backend: str

    def add(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> int: ...

    def query(
        self, vector: Sequence[float], k: int, where: dict[str, Any] | None = None
    ) -> list[tuple[Chunk, float]]: ...

    def count(self) -> int: ...

    def reset(self) -> None: ...

    def existing_ids(self, ids: Sequence[str]) -> set[str]: ...


# --------------------------------------------------------------------------- #
# metadata helpers
# --------------------------------------------------------------------------- #

def _chunk_metadata(chunk: Chunk) -> dict[str, Any]:
    """Flatten a chunk into scalar-only metadata (Chroma rejects nested values)."""
    meta: dict[str, Any] = {
        "parent_id": chunk.parent_id,
        "lang": chunk.lang,
        "ordinal": int(chunk.ordinal),
    }
    for key, value in chunk.metadata.items():
        if isinstance(value, (bool, str, int, float)):
            meta[key] = value
    return meta


def _chunk_from_row(chunk_id: str, text: str, meta: dict[str, Any]) -> Chunk:
    meta = dict(meta or {})
    return Chunk(
        chunk_id=chunk_id,
        parent_id=str(meta.pop("parent_id", "")),
        text=text,
        lang=str(meta.pop("lang", "")),
        ordinal=int(meta.pop("ordinal", 0) or 0),
        metadata=meta,
    )


def matches_where(meta: dict[str, Any], where: dict[str, Any] | None) -> bool:
    """Evaluate the subset of Chroma's filter grammar the retriever uses.

    Supported: implicit equality, ``$eq``, ``$ne``, ``$in``, ``$nin``, and the
    boolean combinators ``$and`` / ``$or``. Anything else raises rather than
    silently matching everything — a filter that quietly stops filtering is how a
    "Japanese-only" search starts returning English.
    """
    if not where:
        return True
    for key, condition in where.items():
        if key == "$and":
            if not all(matches_where(meta, sub) for sub in condition):
                return False
            continue
        if key == "$or":
            if not any(matches_where(meta, sub) for sub in condition):
                return False
            continue
        actual = meta.get(key)
        if not isinstance(condition, dict):
            if actual != condition:
                return False
            continue
        for op, operand in condition.items():
            if op == "$eq":
                ok = actual == operand
            elif op == "$ne":
                ok = actual != operand
            elif op == "$in":
                ok = actual in operand
            elif op == "$nin":
                ok = actual not in operand
            else:
                raise ValueError(f"unsupported filter operator {op!r}")
            if not ok:
                return False
    return True


# --------------------------------------------------------------------------- #
# parent store
# --------------------------------------------------------------------------- #

class ParentStore:
    """Id-to-parent-document map, persisted as one JSON file.

    A single file is the right call at this scale: a home server's advisory corpus
    plus a rolling log window is thousands of documents, not millions, and one
    atomic rewrite is far easier to reason about than an embedded key-value store
    that has to be kept consistent with Chroma.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._docs: dict[str, Document] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if self.path.exists():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    # A truncated parent store must not brick the API; an empty
                    # store degrades retrieval to child-only, which is recoverable
                    # by re-indexing.
                    raw = {}
                for doc_id, payload in (raw or {}).items():
                    try:
                        self._docs[doc_id] = Document.from_dict(payload)
                    except (KeyError, TypeError):
                        continue
            self._loaded = True

    def put_many(self, docs: Sequence[Document]) -> None:
        self._load()
        with self._lock:
            for doc in docs:
                self._docs[doc.doc_id] = doc
            self._flush()

    def get(self, doc_id: str) -> Document | None:
        self._load()
        return self._docs.get(doc_id)

    def get_many(self, doc_ids: Sequence[str]) -> dict[str, Document]:
        self._load()
        return {i: self._docs[i] for i in doc_ids if i in self._docs}

    def all_ids(self) -> list[str]:
        self._load()
        return list(self._docs)

    def count(self) -> int:
        self._load()
        return len(self._docs)

    def stats(self) -> dict[str, Any]:
        self._load()
        by_lang: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for doc in self._docs.values():
            by_lang[doc.lang] = by_lang.get(doc.lang, 0) + 1
            by_type[doc.doc_type] = by_type.get(doc.doc_type, 0) + 1
        return {"parents": len(self._docs), "by_language": by_lang, "by_type": by_type}

    def reset(self) -> None:
        with self._lock:
            self._docs.clear()
            self._loaded = True
            self._flush()

    def _flush(self) -> None:
        """Atomic write: temp file in the same directory, then rename.

        Writing in place would leave a corrupt parent store if the process is
        killed mid-write, and the most likely time for that is during a large
        re-index — exactly when the file matters most.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {doc_id: doc.to_dict() for doc_id, doc in self._docs.items()}
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".parents-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


# --------------------------------------------------------------------------- #
# local (dependency-free) vector store
# --------------------------------------------------------------------------- #

class LocalVectorStore:
    """Exact cosine search over vectors persisted as JSONL."""

    backend = "local"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._chunks: dict[str, Chunk] = {}
        self._vectors: dict[str, list[float]] = {}
        self._loaded = False
        self.warning: str | None = None

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if self.path.exists():
                with self.path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                            chunk = _chunk_from_row(row["chunk_id"], row["text"], row.get("metadata", {}))
                            self._chunks[chunk.chunk_id] = chunk
                            self._vectors[chunk.chunk_id] = [float(x) for x in row["vector"]]
                        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                            continue
            self._loaded = True
            self._check_size()

    def _check_size(self) -> None:
        if len(self._vectors) > LOCAL_BACKEND_SOFT_LIMIT:
            self.warning = (
                f"{len(self._vectors)} vectors in the local brute-force index "
                f"(soft limit {LOCAL_BACKEND_SOFT_LIMIT}). Install chromadb and set "
                f"SENTINEL_VECTOR_BACKEND=chroma for HNSW-indexed search."
            )

    def add(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> int:
        if len(chunks) != len(vectors):
            raise ValueError(f"chunk/vector count mismatch: {len(chunks)} vs {len(vectors)}")
        self._load()
        added = 0
        with self._lock:
            for chunk, vector in zip(chunks, vectors, strict=True):
                if chunk.chunk_id not in self._chunks:
                    added += 1
                self._chunks[chunk.chunk_id] = chunk
                self._vectors[chunk.chunk_id] = [float(x) for x in vector]
            self._flush()
            self._check_size()
        return added

    def query(
        self, vector: Sequence[float], k: int, where: dict[str, Any] | None = None
    ) -> list[tuple[Chunk, float]]:
        self._load()
        scored: list[tuple[Chunk, float]] = []
        for chunk_id, candidate in self._vectors.items():
            chunk = self._chunks[chunk_id]
            if not matches_where(_chunk_metadata(chunk), where):
                continue
            scored.append((chunk, cosine(vector, candidate)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    def count(self) -> int:
        self._load()
        return len(self._vectors)

    def existing_ids(self, ids: Sequence[str]) -> set[str]:
        self._load()
        return {i for i in ids if i in self._vectors}

    def reset(self) -> None:
        with self._lock:
            self._chunks.clear()
            self._vectors.clear()
            self._loaded = True
            self.warning = None
            self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".vectors-", suffix=".jsonl")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for chunk_id, vector in self._vectors.items():
                    chunk = self._chunks[chunk_id]
                    fh.write(
                        json.dumps(
                            {
                                "chunk_id": chunk_id,
                                "text": chunk.text,
                                "metadata": _chunk_metadata(chunk),
                                "vector": vector,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


# --------------------------------------------------------------------------- #
# ChromaDB store
# --------------------------------------------------------------------------- #

class ChromaVectorStore:
    """Persistent ChromaDB collection with an HNSW cosine index."""

    backend = "chroma"

    def __init__(self, directory: Path, collection_name: str) -> None:
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError(
                "chromadb is not installed. Install engine/requirements.txt, or set "
                "SENTINEL_VECTOR_BACKEND=local to use the built-in index."
            ) from exc
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.warning = None
        self._client = chromadb.PersistentClient(
            path=str(directory),
            settings=ChromaSettings(anonymized_telemetry=False, allow_reset=True),
        )
        self._name = collection_name
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            # Cosine, not the L2 default: e5 vectors are unit-normalised, and
            # cosine keeps "similarity" comparable across chunk lengths.
            metadata={"hnsw:space": "cosine"},
        )

    def add(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> int:
        if len(chunks) != len(vectors):
            raise ValueError(f"chunk/vector count mismatch: {len(chunks)} vs {len(vectors)}")
        if not chunks:
            return 0
        before = self.count()
        # upsert, not add: re-running the indexer over an unchanged corpus should
        # be a no-op rather than a duplicate-id error.
        self._collection.upsert(
            ids=[c.chunk_id for c in chunks],
            documents=[c.text for c in chunks],
            metadatas=[_chunk_metadata(c) for c in chunks],
            embeddings=[list(map(float, v)) for v in vectors],
        )
        return max(0, self.count() - before)

    def query(
        self, vector: Sequence[float], k: int, where: dict[str, Any] | None = None
    ) -> list[tuple[Chunk, float]]:
        if self.count() == 0:
            return []
        result = self._collection.query(
            query_embeddings=[list(map(float, vector))],
            n_results=min(k, self.count()),
            where=where or None,
            include=["documents", "metadatas", "distances"],
        )
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]

        out: list[tuple[Chunk, float]] = []
        for i, chunk_id in enumerate(ids):
            text = docs[i] if i < len(docs) else ""
            meta = metas[i] if i < len(metas) else {}
            # Chroma reports cosine *distance*; the rest of the engine speaks
            # similarity, so convert once, here.
            distance = float(dists[i]) if i < len(dists) else 1.0
            out.append((_chunk_from_row(chunk_id, text or "", meta or {}), 1.0 - distance))
        return out

    def count(self) -> int:
        return int(self._collection.count())

    def existing_ids(self, ids: Sequence[str]) -> set[str]:
        if not ids:
            return set()
        found = self._collection.get(ids=list(ids), include=[])
        return set(found.get("ids") or [])

    def reset(self) -> None:
        self._client.delete_collection(self._name)
        self._collection = self._client.get_or_create_collection(
            name=self._name, metadata={"hnsw:space": "cosine"}
        )


def chromadb_available() -> bool:
    try:
        import chromadb  # noqa: F401
    except Exception:
        return False
    return True


def get_vector_store(settings: Settings) -> VectorStore:
    """Build the vector store named by settings (see get_embedder for the contract)."""
    backend = settings.vector_backend
    if backend == "local":
        return LocalVectorStore(settings.index_dir / "vectors.jsonl")
    if backend == "chroma":
        return ChromaVectorStore(settings.chroma_dir, settings.collection_name)
    if chromadb_available():
        try:
            return ChromaVectorStore(settings.chroma_dir, settings.collection_name)
        except Exception:
            return LocalVectorStore(settings.index_dir / "vectors.jsonl")
    return LocalVectorStore(settings.index_dir / "vectors.jsonl")


def get_parent_store(settings: Settings) -> ParentStore:
    return ParentStore(settings.index_dir / "parents.json")
