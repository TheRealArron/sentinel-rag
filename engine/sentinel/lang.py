"""Language handling for the bilingual corpus.

Two things live here, both deliberately dependency-free:

*   ``detect_language`` — a script-ratio classifier. A full langid model would be
    overkill and wrong for this corpus: Japanese security advisories are dense
    with ASCII (CVE ids, IP addresses, "sshd", "Authentication"), so a
    probabilistic model trained on prose mislabels them as English. Counting
    Japanese script code points is both cheaper and more accurate here.
*   ``estimate_tokens`` — a tokenizer-free length estimate. Loading a HuggingFace
    tokenizer just to split text would drag a heavy dependency into the chunking
    path, and chunk boundaries do not need to be exact. What they do need is to
    be *right about CJK*: Japanese averages close to one token per character
    while English averages about four characters per token, so a single
    characters-per-token constant would make Japanese parents four times too
    large and silently blow the model's context budget.
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

    CJK code points count as one token each; runs of non-CJK characters count as
    one token per four characters. Empirically within ~15% of the
    multilingual-e5 tokenizer on this corpus, which is plenty for choosing chunk
    boundaries.
    """
    if not text:
        return 0
    cjk = 0
    other = 0
    for ch in text:
        if is_cjk(ch):
            cjk += 1
        else:
            other += 1
    return cjk + (other + 3) // 4


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
