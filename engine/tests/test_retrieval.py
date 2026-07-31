"""Embeddings, storage, indexing, and the bilingual parent-document retriever."""

from __future__ import annotations

import pytest

from sentinel.corpus import events_to_documents, group_events, load_advisories, parse_front_matter
from sentinel.embeddings import HashingEmbedder, cosine, l2_normalise
from sentinel.lang import LANG_EN, LANG_JA
from sentinel.schemas import Chunk, Document
from sentinel.store import LocalVectorStore, ParentStore, matches_where


class TestHashingEmbedder:
    def test_vectors_are_unit_length(self):
        emb = HashingEmbedder(128)
        for text in ["Failed password for root", "認証失敗が繰り返されています", "x"]:
            norm = sum(v * v for v in emb.embed_query(text)) ** 0.5
            assert norm == pytest.approx(1.0, abs=1e-9)

    def test_deterministic_across_instances(self):
        # Must not depend on PYTHONHASHSEED: a persisted index has to survive a
        # process restart.
        a = HashingEmbedder(128).embed_query("sshd brute force")
        b = HashingEmbedder(128).embed_query("sshd brute force")
        assert a == b

    def test_similar_text_scores_higher_than_unrelated(self):
        emb = HashingEmbedder(512)
        query = emb.embed_query("Failed password for root from 203.0.113.45")
        near = emb.embed_query("Failed password for admin from 203.0.113.44")
        far = emb.embed_query("Started Daily apt download activities")
        assert cosine(query, near) > cosine(query, far)

    def test_handles_japanese_without_whitespace_tokens(self):
        emb = HashingEmbedder(512)
        query = emb.embed_query("ブルートフォース攻撃の検知")
        near = emb.embed_query("ブルートフォース攻撃への対策")
        far = emb.embed_query("ディスク容量が不足しています")
        assert cosine(query, near) > cosine(query, far)

    def test_reports_itself_as_non_semantic(self):
        # The API surfaces this so a demo is never mistaken for a deployment.
        assert HashingEmbedder(64).semantic is False

    def test_batch_matches_single(self):
        emb = HashingEmbedder(64)
        assert emb.embed_documents(["a", "b"]) == [emb.embed_query("a"), emb.embed_query("b")]

    def test_rejects_zero_dimension(self):
        with pytest.raises(ValueError):
            HashingEmbedder(0)


class TestCosine:
    def test_orthogonal_is_zero(self):
        assert cosine([1, 0], [0, 1]) == 0.0

    def test_identical_is_one(self):
        assert cosine([3, 4], [3, 4]) == pytest.approx(1.0)

    def test_zero_vector_is_safe(self):
        assert cosine([0, 0], [1, 1]) == 0.0

    def test_length_mismatch_is_safe(self):
        assert cosine([1, 2, 3], [1, 2]) == 0.0

    def test_l2_normalise_of_zero_vector_is_unchanged(self):
        assert l2_normalise([0.0, 0.0]) == [0.0, 0.0]


class TestMatchesWhere:
    def test_none_matches_everything(self):
        assert matches_where({"lang": "ja"}, None)

    def test_implicit_equality(self):
        assert matches_where({"lang": "ja"}, {"lang": "ja"})
        assert not matches_where({"lang": "en"}, {"lang": "ja"})

    def test_operators(self):
        meta = {"lang": "ja", "doc_type": "advisory"}
        assert matches_where(meta, {"lang": {"$ne": "en"}})
        assert matches_where(meta, {"doc_type": {"$in": ["advisory", "log_window"]}})
        assert not matches_where(meta, {"doc_type": {"$nin": ["advisory"]}})

    def test_boolean_combinators(self):
        meta = {"lang": "ja", "doc_type": "advisory"}
        assert matches_where(meta, {"$and": [{"lang": "ja"}, {"doc_type": "advisory"}]})
        assert matches_where(meta, {"$or": [{"lang": "en"}, {"doc_type": "advisory"}]})
        assert not matches_where(meta, {"$or": [{"lang": "en"}, {"doc_type": "log_window"}]})

    def test_unknown_operator_raises_rather_than_matching_everything(self):
        # A filter that silently stops filtering is how a "Japanese-only" search
        # starts returning English.
        with pytest.raises(ValueError, match="unsupported filter operator"):
            matches_where({"lang": "ja"}, {"lang": {"$regex": ".*"}})


class TestLocalVectorStore:
    def _chunk(self, cid: str, lang: str = "en") -> Chunk:
        return Chunk(chunk_id=cid, parent_id="p1", text=f"text {cid}", lang=lang,
                     metadata={"doc_type": "advisory"})

    def test_add_and_query(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        store.add([self._chunk("a"), self._chunk("b")], [[1.0, 0.0], [0.0, 1.0]])
        results = store.query([1.0, 0.0], k=2)
        assert results[0][0].chunk_id == "a"
        assert results[0][1] == pytest.approx(1.0)

    def test_persists_across_instances(self, tmp_path):
        path = tmp_path / "v.jsonl"
        LocalVectorStore(path).add([self._chunk("a")], [[1.0, 0.0]])
        assert LocalVectorStore(path).count() == 1

    def test_upsert_is_idempotent(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        store.add([self._chunk("a")], [[1.0, 0.0]])
        store.add([self._chunk("a")], [[1.0, 0.0]])
        assert store.count() == 1

    def test_existing_ids(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        store.add([self._chunk("a")], [[1.0, 0.0]])
        assert store.existing_ids(["a", "zzz"]) == {"a"}

    def test_where_filter_applies(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        store.add([self._chunk("en1", "en"), self._chunk("ja1", "ja")], [[1.0, 0.0], [0.9, 0.1]])
        results = store.query([1.0, 0.0], k=5, where={"lang": "ja"})
        assert [c.chunk_id for c, _ in results] == ["ja1"]

    def test_count_mismatch_is_rejected(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        with pytest.raises(ValueError, match="mismatch"):
            store.add([self._chunk("a")], [[1.0], [2.0]])

    def test_reset_clears(self, tmp_path):
        store = LocalVectorStore(tmp_path / "v.jsonl")
        store.add([self._chunk("a")], [[1.0, 0.0]])
        store.reset()
        assert store.count() == 0

    def test_corrupt_lines_are_skipped_not_fatal(self, tmp_path):
        path = tmp_path / "v.jsonl"
        LocalVectorStore(path).add([self._chunk("a")], [[1.0, 0.0]])
        with path.open("a", encoding="utf-8") as fh:
            fh.write("{not json\n")
        assert LocalVectorStore(path).count() == 1


class TestParentStore:
    def test_roundtrip(self, tmp_path):
        store = ParentStore(tmp_path / "parents.json")
        store.put_many([Document(doc_id="d1", title="T", text="body", lang="en")])
        assert ParentStore(tmp_path / "parents.json").get("d1").title == "T"

    def test_missing_id_returns_none(self, tmp_path):
        assert ParentStore(tmp_path / "parents.json").get("nope") is None

    def test_stats_counts_by_language(self, tmp_path):
        store = ParentStore(tmp_path / "parents.json")
        store.put_many([
            Document(doc_id="a", title="A", text="english body", lang="en"),
            Document(doc_id="b", title="B", text="日本語の本文", lang="ja"),
        ])
        assert store.stats()["by_language"] == {"en": 1, "ja": 1}

    def test_truncated_file_degrades_instead_of_crashing(self, tmp_path):
        path = tmp_path / "parents.json"
        path.write_text('{"d1": {"doc_id": "d1", "title"', encoding="utf-8")
        assert ParentStore(path).count() == 0


class TestFrontMatter:
    def test_parses_scalars_and_lists(self):
        meta, body = parse_front_matter(
            '---\nid: x\ntitle: "A title"\nseverity: high\nmitre: [T1110, T1078]\n'
            "keywords:\n  - brute force\n  - ブルートフォース\n---\nBody here.\n"
        )
        assert meta["id"] == "x"
        assert meta["title"] == "A title"
        assert meta["mitre"] == ["T1110", "T1078"]
        assert meta["keywords"] == ["brute force", "ブルートフォース"]
        assert body.strip() == "Body here."

    def test_no_front_matter_returns_whole_text(self):
        meta, body = parse_front_matter("# Just markdown\n\ntext")
        assert meta == {}
        assert "Just markdown" in body

    def test_coerces_numbers_and_booleans(self):
        meta, _ = parse_front_matter("---\nport: 22\nratio: 1.5\nactive: true\n---\nbody")
        assert meta["port"] == 22
        assert meta["ratio"] == 1.5
        assert meta["active"] is True


class TestCorpusLoading:
    def test_loads_both_languages(self, settings):
        docs = load_advisories(settings.advisory_dir)
        langs = {d.lang for d in docs}
        assert LANG_EN in langs and LANG_JA in langs, f"expected both languages, got {langs}"
        assert len(docs) >= 8

    def test_keywords_are_folded_into_indexed_text(self, settings):
        docs = load_advisories(settings.advisory_dir)
        japanese = [d for d in docs if d.lang == LANG_JA]
        assert japanese
        # The EN/JA lexical bridge: a Japanese advisory carries English keywords
        # in its indexed body, which is what makes it retrievable from English
        # even when the embedder is non-semantic.
        assert any("brute force" in d.text for d in japanese)

    def test_readme_is_not_indexed_as_an_advisory(self, settings):
        assert not any(d.source.lower() == "readme.md" for d in load_advisories(settings.advisory_dir))

    def test_missing_directory_returns_empty(self, tmp_path):
        assert load_advisories(tmp_path / "nope") == []


class TestEventGrouping:
    def test_groups_by_source_and_time_window(self, sample_events):
        groups = group_events(sample_events, window_minutes=10)
        assert groups
        assert sum(len(g) for g in groups) == len(sample_events)

    def test_each_group_is_in_log_order(self, sample_events):
        for group in group_events(sample_events, window_minutes=10):
            assert [e.seq for e in group] == sorted(e.seq for e in group)

    def test_attacker_events_land_in_one_group(self, sample_events):
        groups = group_events(sample_events, window_minutes=60)
        attacker = [g for g in groups if g[0].source_ip == "203.0.113.45"]
        assert len(attacker) == 1
        # 5 failures + 1 success + 2 incidents + ufw block + publickey login
        assert len(attacker[0]) >= 9

    def test_window_document_title_summarises_the_window(self, sample_events):
        docs = events_to_documents(sample_events, window_minutes=60)
        attacker = [d for d in docs if "203.0.113.45" in d.title]
        assert attacker
        assert "peak critical" in attacker[0].title
        assert attacker[0].doc_type == "log_window"

    def test_zero_window_is_rejected(self, sample_events):
        with pytest.raises(ValueError):
            group_events(sample_events, window_minutes=0)


class TestIndexingAndRetrieval:
    def test_index_covers_advisories_and_log_windows(self, indexed_engine):
        stats = indexed_engine.indexer.stats()
        assert stats["vectors"] > 0
        assert stats["by_type"].get("advisory", 0) >= 8
        assert stats["by_type"].get("log_window", 0) >= 1

    def test_reindexing_embeds_nothing_new(self, indexed_engine):
        second = indexed_engine.index_all()
        assert second.children_embedded == 0
        assert second.children_skipped > 0

    def test_rebuild_repopulates(self, indexed_engine):
        before = indexed_engine.vectors.count()
        indexed_engine.index_all(rebuild=True)
        assert indexed_engine.vectors.count() == before

    def test_search_returns_parents_not_children(self, indexed_engine):
        results = indexed_engine.search("SSH brute force attack", k=5)
        assert results
        for item in results:
            assert item.parent is not None
            # The parent must be at least as large as the child that found it.
            assert len(item.parent.text) >= len(item.chunk.text) - 200

    @pytest.mark.parametrize("k", [2, 3, 4, 5, 6])
    def test_per_language_floor_holds_at_every_k(self, indexed_engine, k):
        # Regression: the floor's top-ups are by definition lower-scoring than
        # the hits that crowded them out, so any score-ordered truncation applied
        # after the top-up removes exactly the hits the floor just added. A small
        # k is where that shows.
        for query in ("SSH brute force from the internet", "SSH ブルートフォース 攻撃 対策"):
            results = indexed_engine.search(query, k=k)
            mix = indexed_engine.retriever.language_mix(results)
            assert len(results) <= k
            assert mix.get(LANG_EN, 0) >= 1, f"k={k} {query!r}: no English source: {mix}"
            assert mix.get(LANG_JA, 0) >= 1, f"k={k} {query!r}: no Japanese source: {mix}"

    def test_per_language_floor_surfaces_japanese_for_an_english_query(self, indexed_engine):
        results = indexed_engine.search("SSH brute force password guessing", k=6)
        mix = indexed_engine.retriever.language_mix(results)
        assert mix.get(LANG_JA, 0) >= 1, f"no Japanese source retrieved: {mix}"
        assert mix.get(LANG_EN, 0) >= 1, f"no English source retrieved: {mix}"

    def test_per_language_floor_surfaces_english_for_a_japanese_query(self, indexed_engine):
        results = indexed_engine.search("SSH ブルートフォース 攻撃 認証失敗 対策", k=6)
        mix = indexed_engine.retriever.language_mix(results)
        assert mix.get(LANG_EN, 0) >= 1, f"no English source retrieved: {mix}"
        assert mix.get(LANG_JA, 0) >= 1, f"no Japanese source retrieved: {mix}"

    def test_floor_can_be_disabled(self, indexed_engine):
        import dataclasses

        indexed_engine.retriever.settings = dataclasses.replace(
            indexed_engine.settings, per_language_floor=0
        )
        results = indexed_engine.search("SSH brute force from the internet", k=3)
        assert results  # still returns hits, just without the reservation
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_doc_type_filter_excludes_log_windows(self, indexed_engine):
        results = indexed_engine.search("brute force", k=6, doc_types=["advisory"])
        assert results
        assert all(r.parent.doc_type == "advisory" for r in results)

    def test_results_are_deduplicated_by_parent(self, indexed_engine):
        results = indexed_engine.search("persistence authorized_keys systemd cron", k=8)
        ids = [r.parent.doc_id for r in results]
        assert len(ids) == len(set(ids))

    def test_results_are_sorted_by_similarity(self, indexed_engine):
        results = indexed_engine.search("cryptomining xmrig", k=6)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_query_returns_nothing(self, indexed_engine):
        assert indexed_engine.search("   ") == []

    def test_context_block_is_numbered_and_citable(self, indexed_engine):
        results = indexed_engine.search("privilege escalation pkexec", k=3)
        context = indexed_engine.retriever.build_context(results)
        assert "[S1]" in context
        assert "matched on:" in context
        for i in range(1, len(results) + 1):
            assert f"[S{i}]" in context

    def test_result_lang_agrees_with_the_aggregate_language_mix(self, indexed_engine):
        # A child chunk's detected language can differ from its parent's (a log
        # window dense with Japanese bridge tags classifies as `ja` while the
        # parent is pinned `en`). The per-result `lang` must be the parent's, or
        # the API contradicts its own summary.
        results = indexed_engine.search("ブルートフォース攻撃の対策", k=4)
        mix = indexed_engine.retriever.language_mix(results)
        reported: dict[str, int] = {}
        for row in (r.to_dict() for r in results):
            reported[row["lang"]] = reported.get(row["lang"], 0) + 1
        assert reported == mix

    def test_citations_align_with_retrieved_order(self, indexed_engine):
        results = indexed_engine.search("SSH brute force", k=4)
        citations = indexed_engine.retriever.citations(results)
        assert len(citations) == len(results)
        assert [c.doc_id for c in citations] == [r.parent.doc_id for r in results]
