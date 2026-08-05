"""Embedding backends.

``E5Embedder`` is the real one: multilingual-e5 with the mandatory asymmetric
``query: ``/``passage: `` prefixes. ``HashingEmbedder`` is a zero-dependency
lexical fallback with **no cross-lingual ability**; ``Embedder.semantic`` reports
which regime you are in.

See docs/design/retrieval.md and docs/design/dependencies.md.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from .config import Settings

_WORD_RE = re.compile(r"[0-9a-zA-Z_.:/@-]+")


@runtime_checkable
class Embedder(Protocol):
    """Minimal embedding interface used by the store and retriever."""

    name: str
    dim: int
    semantic: bool

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


def l2_normalise(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return vec
    return [v / norm for v in vec]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity. Assumes nothing about normalisation."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b, strict=True):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / math.sqrt(na * nb)


class E5Embedder:
    """multilingual-e5 via sentence-transformers."""

    semantic = True

    def __init__(self, model_name: str, device: str = "cpu", batch_size: int = 16) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError(
                "sentence-transformers is not installed. Install engine/requirements.txt, "
                "or set SENTINEL_EMBEDDING_BACKEND=hashing to run without it."
            ) from exc
        self.name = model_name
        self.batch_size = batch_size
        self._model = SentenceTransformer(model_name, device=device)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def _encode(self, texts: Sequence[str], prefix: str) -> list[list[float]]:
        prefixed = [f"{prefix}{t}" for t in texts]
        vectors = self._model.encode(
            prefixed,
            batch_size=self.batch_size,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        return [[float(x) for x in row] for row in vectors]

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        return self._encode(texts, "passage: ")

    def embed_query(self, text: str) -> list[float]:
        return self._encode([text], "query: ")[0]


class HashingEmbedder:
    """Deterministic, dependency-free lexical vectoriser.

    Features are word unigrams plus character 3-grams. Character n-grams are what
    make it usable on Japanese at all (no whitespace to tokenise on) and on log
    text (``203.0.113.45`` shares n-grams with ``203.0.113.4``). Term frequencies
    are damped with ``1 + log(tf)`` so a line repeating one token does not
    dominate its own vector.
    """

    semantic = False

    def __init__(self, dim: int = 512) -> None:
        if dim <= 0:
            raise ValueError("hashing dim must be positive")
        self.name = f"hashing-{dim}"
        self.dim = dim

    def _features(self, text: str) -> dict[str, int]:
        text = text.lower()
        counts: dict[str, int] = {}
        for word in _WORD_RE.findall(text):
            counts[f"w:{word}"] = counts.get(f"w:{word}", 0) + 1
        squeezed = re.sub(r"\s+", " ", text)
        for i in range(len(squeezed) - 2):
            gram = squeezed[i : i + 3]
            if gram.strip():
                counts[f"g:{gram}"] = counts.get(f"g:{gram}", 0) + 1
        return counts

    def _bucket(self, feature: str) -> tuple[int, float]:
        # blake2b rather than Python's hash(): hash() is randomised per process by
        # PYTHONHASHSEED, which would make a persisted index unreadable after a
        # restart. The sign bit halves collision cancellation bias.
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        return value % self.dim, 1.0 if (value >> 63) & 1 else -1.0

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for feature, tf in self._features(text).items():
            idx, sign = self._bucket(feature)
            vec[idx] += sign * (1.0 + math.log(tf))
        return l2_normalise(vec)

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


def sentence_transformers_available() -> bool:
    try:
        import sentence_transformers  # noqa: F401
    except Exception:
        return False
    return True


def get_embedder(settings: Settings) -> Embedder:
    """Build the embedder named by settings, honouring the auto/explicit contract.

    ``auto`` prefers e5 and falls back silently; naming ``e5`` explicitly raises if
    it is unavailable, so a production deployment cannot quietly downgrade itself
    to the lexical fallback.
    """
    backend = settings.embedding_backend
    if backend == "hashing":
        return HashingEmbedder(settings.hashing_dim)
    if backend == "e5":
        return E5Embedder(settings.embedding_model, settings.embedding_device, settings.embedding_batch_size)
    if sentence_transformers_available():
        try:
            return E5Embedder(settings.embedding_model, settings.embedding_device, settings.embedding_batch_size)
        except Exception:
            # A missing model download or an out-of-memory load should degrade,
            # not take the API down.
            return HashingEmbedder(settings.hashing_dim)
    return HashingEmbedder(settings.hashing_dim)
