#!/usr/bin/env python3
"""Regenerate the tokenizer agreement vectors.

`lang.estimate_tokens` has to approximate a SentencePiece tokenizer it is not
allowed to import: the chunker must work with no dependencies installed, and
chunk ids must not depend on whether `transformers` happens to be present. So
the estimate is a model of the real thing, and a model can drift from it
silently — which is exactly how nine child chunks came to be built past e5's
512-token input limit and truncated with no error.

The Go/Python Sigma and IOC bridges have the same shape of problem and solve it
the same way: run both implementations once, commit the answers, and let a
dependency-free test hold them together. These vectors are that, for the
tokenizer.

Selection is the chunks most at risk — the longest ones — because a breach of
the input limit can only come from the top of the distribution. Run:

    make tokenizer-check

after anything that changes chunking, the estimator, or the corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

from sentinel import corpus  # noqa: E402
from sentinel.chunking import build_hierarchy  # noqa: E402
from sentinel.config import Settings  # noqa: E402
from sentinel.lang import estimate_tokens  # noqa: E402

OUT = REPO / "engine" / "tests" / "testdata" / "tokenizer_vectors.json"

# How many of the longest chunks to pin, plus the longest Japanese ones so the
# other script is represented rather than crowded out by English CVE records.
TOP_N = 40
TOP_JA = 10


def main() -> int:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("sentence-transformers is required to regenerate these vectors", file=sys.stderr)
        return 2

    settings = Settings()
    model = SentenceTransformer(settings.embedding_model, device="cpu")
    tokenizer = model.tokenizer
    limit = int(model.max_seq_length)

    docs = corpus.load_advisories(settings.advisory_dir)
    rows = []
    for doc in docs:
        _, children = build_hierarchy(
            doc,
            parent_tokens=settings.parent_tokens,
            child_tokens=settings.child_tokens,
            child_overlap=settings.child_overlap,
        )
        for child in children:
            # The string that actually reaches the model: e5's mandatory passage
            # prefix, the prepended title, the overlap tail, and the body.
            text = f"passage: {child.text}"
            rows.append(
                {
                    "text": text,
                    "lang": child.lang,
                    "real_tokens": len(tokenizer(text)["input_ids"]),
                    "estimate": estimate_tokens(text),
                }
            )

    rows.sort(key=lambda r: -r["real_tokens"])
    picked = rows[:TOP_N]
    seen = {id(r) for r in picked}
    for row in rows:
        if len([r for r in picked if r["lang"] == "ja"]) >= TOP_JA:
            break
        if row["lang"] == "ja" and id(row) not in seen:
            picked.append(row)
            seen.add(id(row))

    picked.sort(key=lambda r: (-r["real_tokens"], r["text"]))
    worst = max(r["real_tokens"] / max(r["estimate"], 1) for r in picked)

    bundle = {
        "model": settings.embedding_model,
        "max_seq_length": limit,
        "chunk_settings": {
            "parent_tokens": settings.parent_tokens,
            "child_tokens": settings.child_tokens,
            "child_overlap": settings.child_overlap,
        },
        "corpus_chunks_total": len(rows),
        "corpus_max_real_tokens": rows[0]["real_tokens"] if rows else 0,
        "max_ratio_observed": round(worst, 4),
        "vectors": picked,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)}: {len(picked)} vectors from {len(rows)} chunks")
    print(f"  model={settings.embedding_model} limit={limit}")
    print(f"  longest chunk in corpus: {bundle['corpus_max_real_tokens']} tokens")
    print(f"  worst real/estimate ratio among pinned vectors: {worst:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
