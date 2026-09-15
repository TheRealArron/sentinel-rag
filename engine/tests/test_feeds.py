"""The corpus fetchers, and the question the bilingual claim rests on.

The existing retrieval tests assert that an English query returns a Japanese
source. They pass. They have always passed, and they would pass with an embedder
that understood no language at all — because every Japanese document in the
hand-written corpus carries an English keyword list folded into its indexed text,
and because the per-language floor *reserves* a Japanese slot regardless of
score.

Both mechanisms are real and deliberate. Neither is cross-lingual understanding.

These tests separate the three things that were being conflated:

1. Does the floor guarantee a Japanese source? (yes, by construction)
2. Does the lexical keyword bridge work? (yes, when keywords are present)
3. Does the *embedding* connect an English query to Japanese prose that shares
   no English text at all? (that is the actual bilingual claim, and it depends
   entirely on which backend is loaded)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.feeds import (
    Advisory,
    FeedError,
    fetch_jvn,
    fetch_nvd,
    write_advisories,
)
from sentinel.lang import LANG_EN, LANG_JA

REPO_ROOT = Path(__file__).resolve().parents[2]
NVD_DIR = REPO_ROOT / "data" / "advisories" / "nvd"

# A Japanese advisory in the shape a *fetched* JVN document takes: real Japanese
# security prose, and no keyword list at all. Written here rather than copied
# from JVN, because JVN content is (c) JPCERT/CC and IPA and redistribution
# requires prior coordination — see sentinel/feeds.py. What matters for the test
# is the structural property, not the provenance: nothing in this document
# contains the English words an English query would use.
JA_NO_KEYWORDS = """\
---
id: test-ja-no-keywords
title: "SSHサーバへの辞書攻撃の増加について"
publisher: "テスト用文書"
published: 2026-08-01
lang: ja
severity: high
---

## 概要

インターネットに公開されたSSHサーバに対し、推測しやすい認証情報を用いた
機械的な試行が増加しています。攻撃元は短時間に多数の利用者名を試し、
成功するまで接続を繰り返します。

## 対策

公開鍵認証のみを許可し、パスワードによる認証を無効にしてください。
また、接続元の制限と試行回数の制限を導入することを推奨します。
"""


class TestNVDParsing:
    """The NVD side, exercised without touching the network."""

    def test_metrics_without_cvss_data_do_not_crash(self):
        # Real NVD records mix cvssMetricV31 with entries like ssvcV203 that
        # carry no cvssData at all. A naive metrics[k][0]["cvssData"] raises
        # KeyError on those, which is how the first version of this failed.
        from sentinel.feeds import _nvd_severity

        severity, score = _nvd_severity({
            "ssvcV203": [{"source": "nvd@nist.gov", "role": "CISA Coordinator"}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}],
        })
        assert severity == "HIGH" and score == 8.1

    def test_metrics_with_no_usable_entry_returns_empty(self):
        from sentinel.feeds import _nvd_severity

        assert _nvd_severity({"ssvcV203": [{"role": "x"}]}) == ("", None)

    def test_a_non_https_url_is_refused(self):
        # urllib will open file: and ftp: URLs. The fetcher must not.
        from sentinel.feeds import _get

        with pytest.raises(FeedError, match="non-HTTPS"):
            _get("file:///etc/passwd")

    def test_a_window_wider_than_the_api_allows_is_named(self):
        # NVD answers a >120-day window with a bare 404 and no body, which reads
        # as "endpoint gone". The error has to say what was actually wrong.
        with pytest.raises(FeedError, match="at most 120 days"):
            fetch_nvd(days=900, limit=1)

    def test_committed_sample_is_real_and_parses(self):
        assert NVD_DIR.is_dir(), "the committed NVD sample is missing"
        docs = sorted(NVD_DIR.glob("*.md"))
        assert len(docs) >= 20, f"only {len(docs)} NVD documents committed"

        from sentinel.corpus import parse_front_matter

        for path in docs:
            meta, body = parse_front_matter(path.read_text(encoding="utf-8"))
            assert meta.get("lang") == "en", path.name
            assert str(meta.get("cve", "")).startswith("CVE-"), path.name
            assert "nvd.nist.gov" in str(meta.get("source_url", "")), path.name
            assert len(body.strip()) > 120, f"{path.name} has almost no body"

    def test_fetched_documents_carry_no_invented_bilingual_keywords(self):
        # The whole point of fetching. If a fetched English document arrived with
        # Japanese keywords stapled on, cross-lingual retrieval would be
        # unmeasurable again — the answer would be inside the document.
        from sentinel.corpus import parse_front_matter

        for path in sorted(NVD_DIR.glob("*.md")):
            meta, _ = parse_front_matter(path.read_text(encoding="utf-8"))
            for keyword in meta.get("keywords", []) or []:
                assert keyword.isascii(), (
                    f"{path.name} carries a non-ASCII keyword {keyword!r}; fetched "
                    f"documents must not gain an invented bilingual bridge"
                )


class TestAdvisoryWriting:
    def test_round_trips_through_the_corpus_parser(self, tmp_path):
        from sentinel.corpus import parse_front_matter

        advisory = Advisory(
            id="cve-2024-6387", title='regreSSHion — "unauthenticated" RCE',
            publisher="NVD (public domain)", published="2024-07-01", lang="en",
            body="## Description\n\nA race condition in sshd.", severity="high",
            cve="CVE-2024-6387", source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
            keywords=["cwe-364"],
        )
        [path] = write_advisories([advisory], tmp_path)
        meta, body = parse_front_matter(path.read_text(encoding="utf-8"))

        assert meta["id"] == "cve-2024-6387"
        assert meta["cve"] == "CVE-2024-6387"
        assert meta["keywords"] == ["cwe-364"]
        assert "race condition" in body
        # A quote in the title must not terminate the front-matter string.
        assert meta["title"].startswith("regreSSHion")

    def test_filenames_are_filesystem_safe(self, tmp_path):
        # JVN ids look like "JVNVU#96149019". A '#' in a path is legal on Linux
        # and a nuisance everywhere else.
        advisory = Advisory(
            id="jvnvu#96149019", title="テスト", publisher="JVN", published="2026-09-03",
            lang="ja", body="## 概要\n\nテスト", source_url="https://jvn.jp/vu/JVNVU96149019/",
        )
        [path] = write_advisories([advisory], tmp_path)
        assert "#" not in path.name
        assert path.name.endswith(".md")


class TestJVNIsNotRedistributed:
    """The licensing constraint, enforced by a test rather than a comment."""

    def test_no_jvn_text_is_committed(self):
        advisories = REPO_ROOT / "data" / "advisories"
        offenders = [
            p for p in advisories.rglob("*.md")
            if "jvn.jp" in p.read_text(encoding="utf-8", errors="replace")
            and "sample-ja-" not in p.name
        ]
        assert not offenders, (
            "fetched JVN text is committed: "
            + ", ".join(str(p.relative_to(REPO_ROOT)) for p in offenders)
            + ". JVN content is (c) JPCERT/CC and IPA and redistribution requires "
              "prior coordination with office@jpcert.or.jp."
        )

    def test_the_fetch_target_is_gitignored(self):
        ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        assert "data/advisories/jvn-local/" in ignored

    def test_fetched_jvn_documents_carry_attribution(self, monkeypatch):
        rdf = b"""<?xml version="1.0"?><rdf:RDF>
        <item rdf:about="https://jvn.jp/vu/JVNVU96149019/">
          <title>Apache Tomcat\xe3\x81\xab\xe3\x81\x8a\xe3\x81\x91\xe3\x82\x8b\xe8\x84\x86\xe5\xbc\xb1\xe6\x80\xa7</title>
          <description>\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x90\xe3\x82\xa4\xe3\x82\xb6\xe3\x83\xaa\xe3\x81\x8c\xe5\x85\xac\xe9\x96\x8b\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xbe\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82</description>
          <dc:identifier>JVNVU#96149019</dc:identifier>
          <dc:date>2026-09-03T15:00:50+09:00</dc:date>
        </item></rdf:RDF>"""
        monkeypatch.setattr("sentinel.feeds._get", lambda url: rdf)

        [advisory] = fetch_jvn(limit=5)
        assert advisory.lang == "ja"
        assert advisory.source_url == "https://jvn.jp/vu/JVNVU96149019/"
        assert "jvn.jp" in advisory.body, "the citation URL must survive into the body"
        assert "office@jpcert.or.jp" in advisory.body
        # No invented bilingual bridge: JVN supplies no keywords and none are made up.
        assert advisory.keywords == []


class TestWhatMakesRetrievalBilingual:
    """Which mechanism is actually carrying the bilingual guarantee.

    These tests run on the hashing embedder — the zero-dependency fallback CI
    uses — and they record what it can and cannot do. That is the point: the
    README's cross-lingual claim is about `multilingual-e5-large`, and CI has
    never had it loaded.
    """

    @pytest.fixture
    def engine_with_unkeyworded_ja(self, settings, tmp_path, monkeypatch):
        from sentinel.engine import SentinelEngine

        corpus = tmp_path / "advisories"
        corpus.mkdir(parents=True, exist_ok=True)
        (corpus / "test-ja-no-keywords.md").write_text(JA_NO_KEYWORDS, encoding="utf-8")
        for path in sorted(NVD_DIR.glob("*.md"))[:12]:
            (corpus / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

        monkeypatch.setenv("SENTINEL_ADVISORY_DIR", str(corpus))
        from sentinel.config import Settings

        built = SentinelEngine(Settings())
        built.index_all()
        return built

    def test_the_floor_still_guarantees_a_japanese_source(self, engine_with_unkeyworded_ja):
        # This is the guarantee that actually holds without any cross-lingual
        # model: the retriever runs a targeted per-language query and reserves
        # slots. It would hold if the embedder were a random projection.
        results = engine_with_unkeyworded_ja.search("SSH brute force password guessing", k=6)
        mix = engine_with_unkeyworded_ja.retriever.language_mix(results)
        assert mix.get(LANG_JA, 0) >= 1, f"the per-language floor did not fire: {mix}"
        assert mix.get(LANG_EN, 0) >= 1, f"no English source: {mix}"

    def test_the_hashing_fallback_has_no_cross_lingual_signal(self, engine_with_unkeyworded_ja):
        """The measurement, not an aspiration.

        A hashing embedder maps tokens to buckets. An English query and Japanese
        prose about the same attack share no tokens, so their vectors are
        unrelated by construction — the similarity is noise. Pinning that here
        stops the suite from *appearing* to validate a bilingual claim it cannot
        reach, and it fails loudly if someone starts asserting otherwise.
        """
        engine = engine_with_unkeyworded_ja
        assert engine.embedder.semantic is False, (
            f"this test characterises the non-semantic fallback, got {engine.embedder.name!r}"
        )

        results = engine.search("SSH brute force password guessing", k=6)
        japanese = [r for r in results if r.chunk.lang == LANG_JA]
        assert japanese, "precondition: the floor should have supplied a Japanese hit"

        # The Japanese document is present because the floor put it there. Its
        # similarity score is the tell: with no shared tokens it sits near zero,
        # nothing like the score a genuine semantic match would earn.
        best = max(r.score for r in japanese)
        assert best < 0.25, (
            f"the hashing embedder scored a token-disjoint Japanese passage at {best:.3f}. "
            f"If that is real cross-lingual signal, this test should be replaced with one "
            f"that measures it properly rather than assuming it cannot happen."
        )

    def test_the_keyword_bridge_is_what_lifts_the_score(self, engine_with_unkeyworded_ja, tmp_path):
        """Adding the English keyword list back is what makes the score move.

        This isolates the lexical bridge from the semantic one, and shows how
        much of the existing corpus's apparent bilingualism it is responsible
        for: all of it, on this backend.
        """
        from sentinel.config import Settings
        from sentinel.engine import SentinelEngine

        bridged = JA_NO_KEYWORDS.replace(
            "severity: high\n",
            "severity: high\nkeywords:\n  - brute force\n  - password guessing\n"
            "  - ブルートフォース\n",
        )
        corpus = tmp_path / "bridged"
        corpus.mkdir(parents=True, exist_ok=True)
        (corpus / "test-ja-bridged.md").write_text(bridged, encoding="utf-8")
        for path in sorted(NVD_DIR.glob("*.md"))[:12]:
            (corpus / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

        import os

        os.environ["SENTINEL_ADVISORY_DIR"] = str(corpus)
        try:
            engine = SentinelEngine(Settings())
            engine.index_all()
            results = engine.search("SSH brute force password guessing", k=6)
        finally:
            os.environ["SENTINEL_ADVISORY_DIR"] = str(
                engine_with_unkeyworded_ja.settings.advisory_dir
            )

        japanese = [r for r in results if r.chunk.lang == LANG_JA]
        assert japanese, "the bridged Japanese document should be retrievable"
        assert max(r.score for r in japanese) > 0.25, (
            "the English keyword list is folded into the indexed text, so an English "
            "query should match it lexically"
        )


def test_feeds_cli_is_registered():
    from sentinel.cli import build_parser

    args = build_parser().parse_args(["feeds", "--source", "nvd", "--dry-run"])
    assert args.source == "nvd"
    assert callable(args.func)
    # --source is required rather than defaulting, because the two sources have
    # different redistribution terms.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["feeds"])


def test_jvn_notice_names_the_contact_and_the_terms():
    from sentinel.feeds import JPCERT_REDISTRIBUTION_NOTICE as notice

    assert "office@jpcert.or.jp" in notice
    assert "jpcert.or.jp/guide.html" in notice
    assert json.dumps(notice)  # printable, no control characters
