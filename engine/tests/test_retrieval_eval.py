"""The retrieval evaluation harness, and the floor it pins.

`make retrieval-report` is the readable form. This is the gate: it runs the same
47 pairs on the dependency-free backend and fails if quality drops, so a change
to chunking, the retriever, or the corpus cannot silently make retrieval worse.

The thresholds are set below the measured values with room for noise, and they
are floors rather than equalities — the point is to catch a regression, not to
freeze a number that a corpus refresh would legitimately move.
"""

from __future__ import annotations

import json

import pytest

from sentinel.retrieval_eval import (
    CaseResult,
    EvalCase,
    Metrics,
    document_languages,
    evaluate,
    load_cases,
    summarise,
)

EVAL_PATH = None  # resolved from the repo root in the fixture below


@pytest.fixture(scope="module")
def cases():
    from tests.conftest import REPO_ROOT

    return load_cases(REPO_ROOT / "data" / "eval" / "retrieval.jsonl")


def test_the_default_cases_path_does_not_depend_on_the_working_directory(tmp_path, monkeypatch):
    # `make retrieval-report` runs from engine/, so a cwd-relative default
    # resolved to engine/data/eval/ and the documented command failed. CI passes
    # an explicit --cases and never saw it.
    monkeypatch.chdir(tmp_path)
    assert len(load_cases()) >= 30


class TestTheEvalSetItself:
    def test_it_is_the_promised_size_and_shape(self, cases):
        assert 30 <= len(cases) <= 60, f"{len(cases)} pairs"
        langs = {c.lang for c in cases}
        assert langs == {"en", "ja"}, langs
        assert all(c.expected for c in cases), "every case needs an expected document"
        assert all(c.why for c in cases), "every case needs a stated reason"

    def test_ids_are_unique(self, cases):
        ids = [c.id for c in cases]
        assert len(ids) == len(set(ids))

    def test_every_expected_document_exists(self, cases, engine):
        known = set(document_languages(engine))
        for case in cases:
            unknown = [d for d in case.expected if d not in known]
            assert not unknown, f"{case.id} expects documents not in the corpus: {unknown}"

    def test_the_majority_are_event_derived(self, cases):
        # The methodological constraint, enforced. Queries written by reading a
        # document and inverting it measure nothing; `origin: event` marks the
        # ones written from the rule set and sample log before the corpus was
        # consulted. If that half ever becomes the minority, the set has drifted
        # into being a restatement of the corpus.
        event = sum(1 for c in cases if c.origin == "event")
        assert event > len(cases) / 2, f"only {event}/{len(cases)} are event-derived"

    def test_cross_lingual_coverage_is_substantial(self, cases, engine):
        langs = document_languages(engine)
        cross = [
            c for c in cases
            if any(langs.get(d) and langs[d] != c.lang for d in c.expected)
        ]
        assert len(cross) >= 20, (
            f"only {len(cross)} cases have an answer in the other language; the "
            f"cross-lingual figure would be measuring noise"
        )


class TestMetrics:
    """The arithmetic, exercised without retrieval so a failure is unambiguous."""

    def test_hit_and_mrr(self):
        m = Metrics("t")
        for rank in (1, 3, 0, 5):
            m.add(rank, (1, 3, 5))
        assert m.n == 4
        assert m.hit_at(1) == 0.25
        assert m.hit_at(3) == 0.5
        assert m.hit_at(5) == 0.75
        assert m.mrr() == pytest.approx((1 + 1 / 3 + 0 + 1 / 5) / 4)

    def test_a_miss_scores_zero_not_undefined(self):
        m = Metrics("t")
        m.add(0, (1, 5))
        assert m.hit_at(5) == 0.0 and m.mrr() == 0.0

    def test_first_hit_rank_respects_language_restriction(self):
        case = EvalCase(id="x", query="q", lang="en", origin="event",
                        expected=["doc-en", "doc-ja"], why="")
        result = CaseResult(case=case, ranked=["other", "doc-en", "doc-ja"],
                            ranked_langs=["en", "en", "ja"])
        assert result.first_hit_rank() == 2
        assert result.first_hit_rank(only_lang="ja") == 3
        assert result.first_hit_rank(only_lang="de") == 0

    def test_cross_lingual_only_counts_queries_that_can_be_answered(self):
        # A query whose expected documents are all in its own language must not
        # enter the cross-lingual denominator, or the figure is diluted by
        # queries that were never a cross-lingual test.
        langs = {"doc-en": "en"}
        case = EvalCase(id="x", query="q", lang="en", origin="event",
                        expected=["doc-en"], why="")
        result = CaseResult(case=case, ranked=["doc-en"], ranked_langs=["en"])
        report = summarise([result], langs, ks=(1,))
        assert report["cross_lingual"]["queries"] == 0


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    """One evaluation run on the fallback backend, shared by the assertions below.

    Module-scoped because indexing 47 documents and running 47 queries twice
    (floor on and off) is the expensive part, and every assertion reads the same
    numbers.
    """
    from sentinel.config import Settings
    from sentinel.engine import SentinelEngine
    from tests.conftest import ADVISORY_DIR, REPO_ROOT

    tmp = tmp_path_factory.mktemp("evalidx")
    monkey = pytest.MonkeyPatch()
    try:
        for key, value in {
            "SENTINEL_ADVISORY_DIR": str(ADVISORY_DIR),
            "SENTINEL_DATA_DIR": str(tmp / "data"),
            "SENTINEL_EVENTS_PATH": str(tmp / "data" / "events.jsonl"),
            "SENTINEL_INDEX_DIR": str(tmp / "index"),
            "SENTINEL_CHROMA_DIR": str(tmp / "chroma"),
            "SENTINEL_EMBEDDING_BACKEND": "hashing",
            "SENTINEL_VECTOR_BACKEND": "local",
            "SENTINEL_LLM_PROVIDER": "heuristic",
        }.items():
            monkey.setenv(key, value)
        engine = SentinelEngine(Settings())
        engine.index_all()
        return evaluate(engine, load_cases(REPO_ROOT / "data" / "eval" / "retrieval.jsonl"), k=5)
    finally:
        monkey.undo()


class TestBaselineOnTheFallbackBackend:
    """Floors on the dependency-free path, which is what CI runs."""

    def test_overall_recall_does_not_regress(self, report):
        # Measured 0.830 at hit@5 with the floor off. The floor is 0.70: below
        # that, something in chunking or ranking has broken.
        assert report["floor_off"]["overall"]["hit@5"] >= 0.70, json.dumps(
            report["floor_off"]["overall"], indent=2
        )
        assert report["floor_off"]["overall"]["hit@1"] >= 0.50

    def test_the_fallback_cannot_do_cross_lingual_retrieval(self, report):
        """The finding, pinned so it cannot be quietly overstated.

        Measured 0.188 at hit@5 with the floor off. This asserts an *upper*
        bound, which is unusual and deliberate: if a lexical hashing embedder
        ever scores well here, the eval set has sprung a leak — most likely a
        query that shares literal tokens with a document in the other language —
        and the number would be flattering the system rather than measuring it.
        """
        cross = report["floor_off"]["cross_lingual"]
        assert cross["queries"] >= 20
        assert cross["hit@5"] <= 0.40, (
            f"the non-semantic fallback scored {cross['hit@5']} on cross-lingual "
            f"retrieval. Either the embedder changed, or the eval set now leaks "
            f"shared tokens across languages: {json.dumps(cross)}"
        )

    def test_the_floor_is_what_produces_cross_lingual_hits_not_the_model(self, report):
        """hit@1 and hit@3 are identical with the floor on and off; hit@5 is not.

        That is the mechanism made visible. The floor reserves a slot near the
        bottom of the result set, so it can only change the figure at the k where
        the reservation lands — and it changes it a lot.
        """
        off = report["floor_off"]["cross_lingual"]
        on = report["floor_on"]["cross_lingual"]
        assert on["hit@1"] == off["hit@1"]
        assert on["hit@3"] == off["hit@3"]
        assert on["hit@5"] > off["hit@5"] + 0.2, (
            f"the per-language floor should dominate cross-lingual hit@5 on this "
            f"backend: floor off {off['hit@5']}, floor on {on['hit@5']}"
        )

    def test_event_derived_queries_are_reported_separately(self, report):
        origins = {e["label"]: e for e in report["floor_off"]["by_origin"]}
        assert "origin = event" in origins and "origin = software" in origins
        assert origins["origin = event"]["queries"] >= 25
