"""Bilingual parent-document retrieval.

The retrieval contract, in order:

1.  Embed the query with the ``query: `` prefix (asymmetric, see embeddings.py).
2.  Search ``candidate_k`` **child** chunks — small and precise.
3.  Enforce a per-language floor. This is the step that makes "bilingual" a
    property of the system rather than a property of the model. Even with a
    genuinely cross-lingual embedder, an English query against a corpus that is
    70% English will return an all-English top-k most of the time, and the
    Japanese JPCERT advisory that would have explained the attack never reaches
    the model. A targeted second query per language guarantees Japanese sources
    get a seat at the table.
4.  Collapse children to their **parents** — large and contextual — keeping each
    parent's best-scoring child as the reason it was retrieved.
5.  Cap at ``max_parents`` so the prompt stays inside the context budget.

Steps 3 and 4 are where hallucinations get designed out: the model sees full
advisory sections rather than fragments, and it sees both languages' account of
the same technique, so a claim unsupported by either is visibly unsupported.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .config import Settings
from .embeddings import Embedder
from .lang import LANG_EN, LANG_JA
from .schemas import Chunk, Citation, Document, Retrieved
from .store import ParentStore, VectorStore


class ParentDocumentRetriever:
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

    # -- public API --------------------------------------------------------

    def retrieve(
        self,
        query: str,
        k: int | None = None,
        where: dict[str, Any] | None = None,
        languages: Sequence[str] | None = None,
        doc_types: Sequence[str] | None = None,
    ) -> list[Retrieved]:
        """Retrieve parent documents relevant to ``query``.

        ``languages`` defaults to (en, ja) and drives the per-language floor.
        ``doc_types`` restricts to e.g. ``("advisory",)`` when you want threat
        intelligence only and not the log windows.
        """
        if not query.strip():
            return []
        k = k or self.settings.top_k
        languages = list(languages or (LANG_EN, LANG_JA))

        base_filter = dict(where or {})
        if doc_types:
            base_filter["doc_type"] = {"$in": list(doc_types)}

        vector = self.embedder.embed_query(query)
        hits = self._search(vector, self.settings.candidate_k, base_filter or None)
        hits = self._top_up_languages(vector, hits, languages, base_filter or None)
        hits = [(c, s) for c, s in hits if s >= self.settings.min_similarity]
        hits.sort(key=lambda pair: pair[1], reverse=True)

        # Collapse the *whole* candidate pool, then select. Truncating the pool
        # before selection would silently discard the language top-ups: they are
        # by definition lower-scoring than the hits that crowded them out, so a
        # score-ordered cut removes exactly the ones the floor just added.
        parents = self._collapse_to_parents(hits)
        return self._select_with_language_floor(parents, k, languages)

    def citations(self, retrieved: Sequence[Retrieved]) -> list[Citation]:
        out: list[Citation] = []
        for item in retrieved:
            parent = item.parent
            if parent is None:
                continue
            out.append(
                Citation(
                    doc_id=parent.doc_id,
                    title=parent.title,
                    source=parent.source or str(parent.metadata.get("path", "")),
                    lang=parent.lang,
                    similarity=item.score,
                )
            )
        return out

    def build_context(self, retrieved: Sequence[Retrieved], max_chars_per_parent: int = 6000) -> str:
        """Render retrieved parents as a numbered, citable context block.

        Sources are numbered ``[S1]``, ``[S2]`` … and the prompt instructs the
        model to cite those markers. Numbered citations are the cheapest available
        grounding check: an answer that cites nothing, or cites a marker that does
        not exist, is visibly ungrounded.
        """
        blocks: list[str] = []
        for i, item in enumerate(retrieved, start=1):
            parent = item.parent
            if parent is None:
                continue
            text = parent.text
            if len(text) > max_chars_per_parent:
                text = text[:max_chars_per_parent] + "\n…[truncated]"
            header = (
                f"[S{i}] title: {parent.title}\n"
                f"     type: {parent.doc_type} | language: {parent.lang} | "
                f"source: {parent.source or 'n/a'} | similarity: {item.score:.3f}"
            )
            excerpt = item.chunk.text.strip().replace("\n", " ")
            if len(excerpt) > 400:
                excerpt = excerpt[:400] + "…"
            blocks.append(f"{header}\n     matched on: {excerpt}\n---\n{text}")
        return "\n\n".join(blocks)

    def language_mix(self, retrieved: Sequence[Retrieved]) -> dict[str, int]:
        mix: dict[str, int] = {}
        for item in retrieved:
            lang = item.parent.lang if item.parent else item.chunk.lang
            mix[lang] = mix.get(lang, 0) + 1
        return mix

    # -- internals ---------------------------------------------------------

    def _search(
        self, vector: Sequence[float], k: int, where: dict[str, Any] | None
    ) -> list[tuple[Chunk, float]]:
        if self.vectors.count() == 0:
            return []
        return self.vectors.query(vector, k, where)

    def _top_up_languages(
        self,
        vector: Sequence[float],
        hits: list[tuple[Chunk, float]],
        languages: Sequence[str],
        base_filter: dict[str, Any] | None,
    ) -> list[tuple[Chunk, float]]:
        """Ensure the candidate pool contains hits from every language.

        Step one of two. A plain top-``candidate_k`` search against a corpus that
        leans one way can return zero candidates in the other language, in which
        case no amount of downstream selection can produce a bilingual result.
        This runs a targeted query per language so the candidates exist;
        ``_select_with_language_floor`` then guarantees they survive selection.
        """
        floor = self.settings.per_language_floor
        if floor <= 0:
            return hits

        seen_ids = {c.chunk_id for c, _ in hits}
        counts: dict[str, int] = {}
        for chunk, _score in hits:
            counts[chunk.lang] = counts.get(chunk.lang, 0) + 1

        topped_up = list(hits)
        for lang in languages:
            missing = floor - counts.get(lang, 0)
            if missing <= 0:
                continue
            lang_filter: dict[str, Any] = dict(base_filter or {})
            lang_filter["lang"] = lang
            # Ask for more than we need: some hits will already be in the list.
            for chunk, score in self._search(vector, missing * 3, lang_filter):
                if chunk.chunk_id in seen_ids:
                    continue
                seen_ids.add(chunk.chunk_id)
                topped_up.append((chunk, score))
                missing -= 1
                if missing <= 0:
                    break
        return topped_up

    def _select_with_language_floor(
        self, parents: list[Retrieved], k: int, languages: Sequence[str]
    ) -> list[Retrieved]:
        """Pick the final ``k`` parents, reserving slots for each language.

        Step two of two. Highest-scoring first, but each language named in
        ``languages`` is guaranteed up to ``per_language_floor`` slots before the
        remaining slots are filled purely by score. Without the reservation an
        English query against a mostly-English corpus returns an English-only
        result set essentially always, and the Japanese advisory that would have
        explained the attack never reaches the model.
        """
        limit = min(k, self.settings.max_parents)
        floor = self.settings.per_language_floor
        if limit <= 0:
            return []
        if floor <= 0 or len(languages) < 2:
            return parents[:limit]

        selected: list[Retrieved] = []
        taken: set[int] = set()

        def lang_of(item: Retrieved) -> str:
            return item.parent.lang if item.parent else item.chunk.lang

        # Reserved slots, allocated round-robin across languages rather than
        # language-by-language. Filling English's whole quota first would consume
        # every slot when k is small — at k=2 with a floor of 2 the result would
        # be English-only, which is precisely the failure the floor exists to
        # prevent. Round-robin degrades to "one of each" instead.
        for _round in range(floor):
            for lang in languages:
                if len(selected) >= limit:
                    break
                for i, item in enumerate(parents):
                    if i in taken or lang_of(item) != lang:
                        continue
                    taken.add(i)
                    selected.append(item)
                    break
            if len(selected) >= limit:
                break

        # Then fill what is left by score alone.
        for i, item in enumerate(parents):
            if len(selected) >= limit:
                break
            if i not in taken:
                taken.add(i)
                selected.append(item)

        selected.sort(key=lambda r: r.score, reverse=True)
        return selected

    def _collapse_to_parents(self, hits: Sequence[tuple[Chunk, float]]) -> list[Retrieved]:
        """Keep each parent once, represented by its best-scoring child."""
        best: dict[str, tuple[Chunk, float]] = {}
        order: list[str] = []
        for chunk, score in hits:
            parent_id = chunk.parent_id or chunk.chunk_id
            current = best.get(parent_id)
            if current is None:
                best[parent_id] = (chunk, score)
                order.append(parent_id)
            elif score > current[1]:
                best[parent_id] = (chunk, score)

        parent_docs = self.parents.get_many(order)
        results: list[Retrieved] = []
        for parent_id in order:
            chunk, score = best[parent_id]
            parent = parent_docs.get(parent_id)
            if parent is None:
                # The child survived a parent-store reset. Reconstruct a minimal
                # parent from the chunk so retrieval degrades to child-only rather
                # than dropping the hit entirely.
                parent = Document(
                    doc_id=parent_id,
                    title=str(chunk.metadata.get("title", parent_id)),
                    text=chunk.text,
                    source=str(chunk.metadata.get("source", "")),
                    lang=chunk.lang,
                    doc_type=str(chunk.metadata.get("doc_type", "unknown")),
                    metadata={"reconstructed": True},
                )
            results.append(Retrieved(chunk=chunk, score=score, parent=parent))

        results.sort(key=lambda r: r.score, reverse=True)
        return results
