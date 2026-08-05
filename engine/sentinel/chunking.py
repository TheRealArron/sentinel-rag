"""Hierarchical (parent-document) chunking.

Search small, precise children; hand the model large, contextual parents. The
splitter is hand-written rather than LangChain's because chunk budgets and
sentence separators both have to be script-aware.

See docs/design/retrieval.md.
"""

from __future__ import annotations

import hashlib
import re

from .lang import detect_language, estimate_tokens
from .schemas import Chunk, Document

# Ordered coarse-to-fine. Each level is tried only when the level above leaves a
# piece over budget, so structure is preserved where it exists.
DEFAULT_SEPARATORS: tuple[str, ...] = (
    "\n## ",   # markdown section
    "\n### ",
    "\n\n",    # paragraph
    "\n",      # line (log records are line-oriented)
    "。",      # Japanese full stop
    "！",
    "？",
    ". ",      # English sentence
    "! ",
    "? ",
    "、",      # Japanese comma, last resort before words
    " ",
    "",        # hard character split
)


def _stable_id(*parts: str) -> str:
    """Content-addressed id, so re-indexing an unchanged document is a no-op.

    blake2b rather than sha1: this is a content address, not a security
    primitive, and blake2b is both faster and free of sha1's baggage.
    """
    h = hashlib.blake2b(digest_size=16)
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:24]


def _split_keep_separator(text: str, sep: str) -> list[str]:
    """Split on ``sep``, keeping it attached to the piece it terminates.

    Dropping the separator would turn "攻撃が検知されました。次に" into two pieces
    that no longer read as sentences, which hurts both the embedding and the text
    the analyst is shown.
    """
    if not sep:
        return [text]
    pieces = text.split(sep)
    out: list[str] = []
    for i, piece in enumerate(pieces):
        if i < len(pieces) - 1:
            out.append(piece + sep)
        elif piece:
            out.append(piece)
    return [p for p in out if p]


def _hard_split(text: str, max_tokens: int) -> list[str]:
    """Last-resort fixed-width split, sized from this text's token density."""
    est = estimate_tokens(text) or 1
    chars_per_token = max(1.0, len(text) / est)
    width = max(1, int(max_tokens * chars_per_token))
    return [text[i : i + width] for i in range(0, len(text), width)]


def _merge_adjacent(pieces: list[str], max_tokens: int) -> list[str]:
    """Greedily recombine small pieces so chunks approach, but never exceed, budget.

    Without this step a document of one-line records becomes one chunk per line:
    thousands of near-useless vectors instead of dozens of coherent ones.
    """
    merged: list[str] = []
    buf = ""
    for piece in pieces:
        candidate = buf + piece
        if buf and estimate_tokens(candidate) > max_tokens:
            merged.append(buf)
            buf = piece
        else:
            buf = candidate
    if buf:
        merged.append(buf)
    return merged


def split_text(text: str, max_tokens: int, separators: tuple[str, ...] = DEFAULT_SEPARATORS) -> list[str]:
    """Split ``text`` into pieces of at most ``max_tokens`` estimated tokens."""
    text = text.strip()
    if not text:
        return []
    if estimate_tokens(text) <= max_tokens:
        return [text]

    for i, sep in enumerate(separators):
        if sep == "":
            break
        if sep not in text:
            continue
        pieces = _split_keep_separator(text, sep)
        if len(pieces) < 2:
            continue
        expanded: list[str] = []
        for piece in pieces:
            if estimate_tokens(piece) > max_tokens:
                expanded.extend(split_text(piece, max_tokens, separators[i + 1 :]))
            else:
                expanded.append(piece)
        return [p for p in _merge_adjacent(expanded, max_tokens) if p.strip()]

    return [p for p in _hard_split(text, max_tokens) if p.strip()]


def _tail_tokens(text: str, tokens: int) -> str:
    """Return roughly the last ``tokens`` tokens of ``text``, on a word boundary."""
    if tokens <= 0 or not text:
        return ""
    est = estimate_tokens(text) or 1
    chars = max(1, int(tokens * max(1.0, len(text) / est)))
    tail = text[-chars:]
    # Snap forward to the next whitespace so we do not start mid-word. Japanese
    # has no spaces, so this is a no-op there, which is correct: any character
    # boundary is a valid boundary in Japanese.
    m = re.search(r"\s", tail)
    if m and m.start() < len(tail) // 3:
        tail = tail[m.start() + 1 :]
    return tail.strip()


def apply_overlap(pieces: list[str], overlap_tokens: int) -> list[str]:
    """Prefix each piece with the tail of its predecessor.

    Overlap exists so a detection sentence that straddles a chunk boundary is
    fully present in at least one chunk. Without it, "the attacker then escalated
    via" / "pkexec to root" become two chunks, neither of which retrieves for
    "privilege escalation via pkexec".
    """
    if overlap_tokens <= 0 or len(pieces) < 2:
        return pieces
    out = [pieces[0]]
    # Pairwise iteration: the operands are deliberately n and n-1 long, so
    # strict=False is the correct choice rather than an oversight.
    for prev, piece in zip(pieces, pieces[1:], strict=False):
        tail = _tail_tokens(prev, overlap_tokens)
        out.append(f"{tail}\n{piece}" if tail else piece)
    return out


def build_hierarchy(
    doc: Document,
    parent_tokens: int = 2000,
    child_tokens: int = 400,
    child_overlap: int = 60,
) -> tuple[list[Document], list[Chunk]]:
    """Split one source document into parents and their child chunks.

    Returns ``(parents, children)``. A document that already fits in
    ``parent_tokens`` yields exactly one parent, keeping ids stable for the common
    case of a short advisory.
    """
    if child_tokens >= parent_tokens:
        raise ValueError(f"child_tokens ({child_tokens}) must be smaller than parent_tokens ({parent_tokens})")

    parent_texts = split_text(doc.text, parent_tokens)
    if not parent_texts:
        return [], []

    parents: list[Document] = []
    children: list[Chunk] = []

    single = len(parent_texts) == 1
    for p_idx, p_text in enumerate(parent_texts):
        parent_id = doc.doc_id if single else f"{doc.doc_id}#p{p_idx}"
        title = doc.title if single else f"{doc.title} (part {p_idx + 1}/{len(parent_texts)})"
        parent = Document(
            doc_id=parent_id,
            title=title,
            text=p_text,
            source=doc.source,
            lang=doc.lang,
            doc_type=doc.doc_type,
            metadata={**doc.metadata, "parent_ordinal": p_idx, "root_doc_id": doc.doc_id},
        )
        parents.append(parent)

        child_texts = apply_overlap(split_text(p_text, child_tokens), child_overlap)
        for c_idx, c_text in enumerate(child_texts):
            # The title is prepended to every child. Retrieval quality on short
            # chunks depends heavily on this: a chunk reading only "Restart the
            # sshd service." is useless out of context, but "JPCERT: SSH brute
            # force advisory — Restart the sshd service." is retrievable.
            embed_text = f"{parent.title}\n{c_text}" if parent.title else c_text
            children.append(
                Chunk(
                    chunk_id=_stable_id(parent_id, str(c_idx), c_text),
                    parent_id=parent_id,
                    text=embed_text,
                    lang=detect_language(c_text) or parent.lang,
                    ordinal=c_idx,
                    metadata={
                        "root_doc_id": doc.doc_id,
                        "doc_type": doc.doc_type,
                        "source": doc.source,
                        "title": parent.title,
                        "parent_lang": parent.lang,
                        **{k: v for k, v in doc.metadata.items() if isinstance(v, (str, int, float, bool))},
                    },
                )
            )

    return parents, children
