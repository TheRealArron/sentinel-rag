"""Language detection and token estimation for the bilingual corpus.

Both are dependency-free and both are script-aware, because Japanese security
advisories are dense with ASCII (CVE ids, IPs, "sshd") and Japanese averages ~1
token per character against English's ~4.

See docs/design/retrieval.md.
"""

from __future__ import annotations

# Japanese-specific script ranges. Han is shared with Chinese, so Han alone is
# not evidence of Japanese; Hiragana and Katakana are.
_HIRAGANA = (0x3040, 0x309F)
_KATAKANA = (0x30A0, 0x30FF)
_KATAKANA_EXT = (0x31F0, 0x31FF)
_HAN = (0x4E00, 0x9FFF)
_HAN_EXT_A = (0x3400, 0x4DBF)
_CJK_PUNCT = (0x3000, 0x303F)
_FULLWIDTH = (0xFF00, 0xFFEF)

LANG_JA = "ja"
LANG_EN = "en"


def _in(code: int, span: tuple[int, int]) -> bool:
    return span[0] <= code <= span[1]


def is_cjk(ch: str) -> bool:
    """True for code points that count as one token in a CJK tokenizer."""
    code = ord(ch)
    return any(
        _in(code, span)
        for span in (_HIRAGANA, _KATAKANA, _KATAKANA_EXT, _HAN, _HAN_EXT_A, _CJK_PUNCT, _FULLWIDTH)
    )


def _is_kana(ch: str) -> bool:
    code = ord(ch)
    return _in(code, _HIRAGANA) or _in(code, _KATAKANA) or _in(code, _KATAKANA_EXT)


def detect_language(text: str) -> str:
    """Classify text as ``ja`` or ``en``.

    A single kana character is strong evidence of Japanese, but one stray
    character in a long English document is more likely a quotation than a
    language, so we require kana to make up at least 2% of the letters *or* the
    combined CJK share to exceed 15%.
    """
    if not text:
        return LANG_EN
    kana = 0
    cjk = 0
    letters = 0
    for ch in text:
        if ch.isspace():
            continue
        letters += 1
        if _is_kana(ch):
            kana += 1
            cjk += 1
        elif is_cjk(ch):
            cjk += 1
    if letters == 0:
        return LANG_EN
    if kana / letters >= 0.02 or cjk / letters >= 0.15:
        return LANG_JA
    return LANG_EN


def estimate_tokens(text: str) -> int:
    """Approximate the token count of ``text`` without a tokenizer.

    Three character classes, because multilingual-e5's SentencePiece vocabulary
    treats them differently:

    * CJK code points — one token each.
    * Letters and whitespace — about four characters per token, because the
      vocabulary merges those into multi-character word pieces.
    * Everything else: digits, punctuation, symbols — one token each. These are
      the pieces SentencePiece does *not* merge, and they are why an NVD record
      dense with ``CVE-2026-46279`` and ``mm/alloc_tag:`` tokenises far worse
      than prose of the same length.

    That third class is the correction. Counting it at four characters per token
    made this an underestimate exactly where it mattered: the worst child chunk
    in this corpus estimated 433 tokens and really held 788, a ratio of 1.82.
    The chunker's budget is only as good as this estimate, so nine of 93 child
    chunks were built past e5's 512-token input limit and truncated silently at
    embed time.

    Measured on this corpus after the change: real tokens ÷ this estimate has a
    maximum of 1.05, where it was 1.80, and the longest child chunk is 497 tokens
    against the 512-token limit — fifteen tokens of headroom, which is thin and
    empirical rather than guaranteed. `engine/tests/test_tokenizer_vectors.py`
    pins it against counts from the real tokenizer.

    Overestimating is the safe direction for a budget; underestimating is not.
    See "Script-aware chunking" in docs/design/retrieval.md.
    """
    if not text:
        return 0
    cjk = 0
    merged = 0
    discrete = 0
    for ch in text:
        if is_cjk(ch):
            cjk += 1
        elif ch.isalpha() or ch.isspace():
            merged += 1
        else:
            discrete += 1
    return cjk + (merged + 3) // 4 + discrete


def token_budget_to_chars(tokens: int, text: str) -> int:
    """Convert a token budget into a character budget calibrated on ``text``.

    Used by the chunker so the same 400-token target yields ~400 characters of
    Japanese but ~1600 characters of English.
    """
    if tokens <= 0:
        return 0
    est = estimate_tokens(text)
    if est == 0:
        return tokens * 4
    chars_per_token = max(1.0, len(text) / est)
    return max(1, int(tokens * chars_per_token))
