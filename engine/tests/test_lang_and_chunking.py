from __future__ import annotations

import pytest

from sentinel.chunking import apply_overlap, build_hierarchy, split_text
from sentinel.lang import LANG_EN, LANG_JA, detect_language, estimate_tokens
from sentinel.schemas import Document


class TestDetectLanguage:
    def test_plain_english(self):
        assert detect_language("Failed password for root from 203.0.113.45 port 22") == LANG_EN

    def test_plain_japanese(self):
        assert detect_language("SSHサーバに対するブルートフォース攻撃の増加について") == LANG_JA

    def test_japanese_advisory_heavy_with_ascii(self):
        # The realistic hard case: a Japanese advisory is mostly ASCII by
        # character count (CVE ids, commands, IPs). A prose-trained langid model
        # calls this English; the script-ratio classifier must not.
        text = (
            "sshd[4001]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2 "
            "というログが記録されている場合、認証情報の総当たり攻撃を受けています。"
            "PasswordAuthentication no を設定してください。"
        )
        assert detect_language(text) == LANG_JA

    def test_one_stray_kana_in_long_english_stays_english(self):
        text = ("The advisory uses the term ブ for brevity. " + "This document is written in English. " * 20)
        assert detect_language(text) == LANG_EN

    def test_empty_and_symbols_default_to_english(self):
        assert detect_language("") == LANG_EN
        assert detect_language("   \n\t ") == LANG_EN
        assert detect_language("192.168.1.1:22 -> 10.0.0.1:443") == LANG_EN


class TestEstimateTokens:
    def test_cjk_is_about_one_token_per_character(self):
        text = "認証失敗が繰り返されています"
        assert estimate_tokens(text) == len(text)

    def test_english_is_about_four_characters_per_token(self):
        text = "a" * 400
        assert 95 <= estimate_tokens(text) <= 105

    def test_japanese_costs_more_tokens_than_equal_length_english(self):
        # This is the whole reason the function exists: a character-count
        # splitter tuned for English overshoots Japanese by ~4x.
        japanese = "攻" * 100
        english = "a" * 100
        assert estimate_tokens(japanese) > 3 * estimate_tokens(english)

    def test_empty(self):
        assert estimate_tokens("") == 0


class TestSplitText:
    def test_short_text_is_one_chunk(self):
        assert split_text("one short line", 400) == ["one short line"]

    def test_every_chunk_respects_the_budget(self):
        text = "\n\n".join(f"Paragraph {i}. " + "word " * 60 for i in range(40))
        chunks = split_text(text, 100)
        assert len(chunks) > 1
        oversized = [c for c in chunks if estimate_tokens(c) > 100]
        assert not oversized, f"{len(oversized)} chunk(s) over budget"

    def test_japanese_splits_on_full_stops_and_respects_budget(self):
        text = "。".join(f"これは第{i}文であり攻撃の詳細を説明しています" for i in range(60)) + "。"
        chunks = split_text(text, 80)
        assert len(chunks) > 1
        assert all(estimate_tokens(c) <= 80 for c in chunks)
        # Separators stay attached, so pieces still read as sentences.
        assert sum(c.count("。") for c in chunks) == text.count("。")

    def test_no_content_is_lost(self):
        text = "\n".join(f"line {i} with some content" for i in range(200))
        rejoined = "".join(split_text(text, 50))
        for i in (0, 99, 199):
            assert f"line {i} with some content" in rejoined

    def test_single_unsplittable_run_is_hard_split(self):
        text = "x" * 5000  # no separator anywhere
        chunks = split_text(text, 50)
        assert len(chunks) > 1
        assert all(estimate_tokens(c) <= 51 for c in chunks)

    def test_small_pieces_are_merged_not_left_one_per_line(self):
        text = "\n".join(f"short {i}" for i in range(200))
        chunks = split_text(text, 100)
        # 200 tiny lines must not become 200 chunks.
        assert len(chunks) < 20


class TestOverlap:
    def test_overlap_prefixes_each_piece_with_its_predecessor_tail(self):
        pieces = ["first piece ends with alpha", "second piece begins here", "third piece"]
        out = apply_overlap(pieces, 4)
        assert out[0] == pieces[0]
        assert out[1].endswith(pieces[1])
        assert len(out[1]) > len(pieces[1])

    def test_zero_overlap_is_identity(self):
        pieces = ["a", "b", "c"]
        assert apply_overlap(pieces, 0) == pieces

    def test_single_piece_is_identity(self):
        assert apply_overlap(["only"], 50) == ["only"]


class TestBuildHierarchy:
    def _doc(self, text: str, lang: str = "en") -> Document:
        return Document(doc_id="doc-1", title="Test advisory", text=text, source="test.md", lang=lang)

    def test_short_document_is_one_parent_with_a_stable_id(self):
        parents, children = build_hierarchy(self._doc("A short advisory body."), 2000, 400, 60)
        assert len(parents) == 1
        assert parents[0].doc_id == "doc-1"  # id unchanged for the common case
        assert children
        assert all(c.parent_id == "doc-1" for c in children)

    def test_long_document_produces_multiple_parents(self):
        text = "\n\n".join(f"## Section {i}\n" + "word " * 400 for i in range(20))
        parents, children = build_hierarchy(self._doc(text), 500, 100, 20)
        assert len(parents) > 1
        assert all(p.doc_id.startswith("doc-1#p") for p in parents)
        assert {c.parent_id for c in children} == {p.doc_id for p in parents}

    def test_children_are_smaller_than_parents(self):
        text = "\n\n".join(f"Paragraph {i}. " + "word " * 100 for i in range(30))
        parents, children = build_hierarchy(self._doc(text), 1000, 150, 20)
        assert max(estimate_tokens(p.text) for p in parents) > max(
            estimate_tokens(c.text) for c in children
        )

    def test_child_text_carries_the_parent_title(self):
        parents, children = build_hierarchy(self._doc("Body text here."), 2000, 400, 60)
        assert all(c.text.startswith("Test advisory") for c in children)

    def test_ids_are_content_addressed_so_reindexing_is_a_noop(self):
        doc = self._doc("Stable body text for hashing.")
        first = {c.chunk_id for c in build_hierarchy(doc, 2000, 400, 60)[1]}
        second = {c.chunk_id for c in build_hierarchy(doc, 2000, 400, 60)[1]}
        assert first == second

    def test_changed_text_changes_ids(self):
        a = {c.chunk_id for c in build_hierarchy(self._doc("original"), 2000, 400, 60)[1]}
        b = {c.chunk_id for c in build_hierarchy(self._doc("modified"), 2000, 400, 60)[1]}
        assert a != b

    def test_child_larger_than_parent_is_rejected(self):
        with pytest.raises(ValueError, match="must be smaller"):
            build_hierarchy(self._doc("text"), parent_tokens=100, child_tokens=200)

    def test_japanese_document_children_stay_in_budget(self):
        text = "。".join("攻撃者はSSHの総当たり攻撃により認証情報を取得しました" for _ in range(80)) + "。"
        parents, children = build_hierarchy(self._doc(text, "ja"), 600, 120, 20)
        assert len(children) > 1
        # +len(title) tokens for the prepended title.
        assert all(estimate_tokens(c.text) <= 160 for c in children)
        assert all(c.lang == "ja" for c in children)
