"""Recall@k for the bilingual retriever.

Every retrieval claim in this project was, until now, an argument. The mechanisms
are real — asymmetric e5 prefixes, parent-document retrieval, script-aware
chunking, a per-language floor — and none of them had a number attached. At ten
documents there was nothing to measure; at 47 there is.

# How the query set was built, and where it is weak

`data/eval/retrieval.jsonl` holds 47 query → expected-document pairs. The
constraint that shaped it: **a query written by reading a document and inverting
its wording measures nothing.** It reproduces, one level up, exactly the
circularity that the bilingual `keywords` lists create — the answer is inside the
question.

So the 32 pairs marked `origin: "event"` were written from the *event* side
first: the 33 rule names, the correlated incidents, and the lines in
`data/samples/sample_syslog.log`. "Five failed passwords from one address inside
a minute, what do I do" is the question an analyst types after seeing
`correlated_brute_force`. Only afterwards was the corpus consulted to decide
which document answers it.

The 15 pairs marked `origin: "software"` are weaker and are labelled so. "Is our
OpenSSH vulnerable to unauthenticated RCE" is a real analyst question, but
choosing *OpenSSH* rather than some absent product means the corpus was consulted
first. They are reported separately so the difference is visible: if the
event-derived half scores materially worse, that gap is the honest number.

# What is measured

`hit@k` — the fraction of queries with at least one expected document in the top
k. With one to three relevant documents per query this is recall in the only
sense that matters operationally: did the analyst get an answer.

`MRR` — mean reciprocal rank of the first expected document, which distinguishes
"answered at rank 1" from "answered at rank 5".

`cross-lingual hit@k` — restricted to the 32 queries that have an expected
document in the *other* language, and counting only that document. This is the
number the bilingual claim actually rests on.

# The floor has to be switched off to measure anything

`per_language_floor` reserves slots for each language regardless of score. It is
a deliberate guarantee and it works. It also makes cross-lingual hit@k
meaningless when left on: a Japanese document is in the results because the floor
put it there, not because the embedder ranked it. So the report runs both ways
and prints both. Ranking quality is the floor-off column; the floor-on column
shows what the operator actually receives.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import repo_root

# Anchored to the repo root, like every data path in config.py. It used to be
# cwd-relative, so `make retrieval-report` — which runs from engine/ — looked
# for engine/data/eval/ and failed; CI passed an explicit --cases and never saw it.
DEFAULT_EVAL_PATH = repo_root() / "data" / "eval" / "retrieval.jsonl"
DEFAULT_KS = (1, 3, 5)


@dataclass
class EvalCase:
    id: str
    query: str
    lang: str
    origin: str
    expected: list[str]
    why: str = ""


@dataclass
class CaseResult:
    case: EvalCase
    ranked: list[str]          # root_doc_id per hit, best first
    ranked_langs: list[str]

    def first_hit_rank(self, only_lang: str = "") -> int:
        """1-based rank of the first expected document, or 0 for a miss.

        ``only_lang`` restricts to expected documents in that language, which is
        how the cross-lingual figure is computed.
        """
        # strict=True: the two lists are built in lockstep in run(), so a
        # length mismatch is a bug rather than something to truncate past.
        pairs = zip(self.ranked, self.ranked_langs, strict=True)
        for position, (doc_id, lang) in enumerate(pairs, start=1):
            if doc_id not in self.case.expected:
                continue
            if only_lang and lang != only_lang:
                continue
            return position
        return 0


@dataclass
class Metrics:
    label: str
    n: int = 0
    hits: dict[int, int] = field(default_factory=dict)
    reciprocal_ranks: list[float] = field(default_factory=list)

    def add(self, rank: int, ks: Sequence[int]) -> None:
        self.n += 1
        for k in ks:
            self.hits.setdefault(k, 0)
            if rank and rank <= k:
                self.hits[k] += 1
        self.reciprocal_ranks.append(1.0 / rank if rank else 0.0)

    def hit_at(self, k: int) -> float:
        return self.hits.get(k, 0) / self.n if self.n else 0.0

    def mrr(self) -> float:
        return sum(self.reciprocal_ranks) / len(self.reciprocal_ranks) if self.reciprocal_ranks else 0.0

    def to_dict(self, ks: Sequence[int]) -> dict[str, Any]:
        return {
            "label": self.label, "queries": self.n,
            **{f"hit@{k}": round(self.hit_at(k), 4) for k in ks},
            "mrr": round(self.mrr(), 4),
        }


def load_cases(path: Path = DEFAULT_EVAL_PATH) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            row = json.loads(raw)
            missing = {"id", "query", "lang", "origin", "expected"} - set(row)
            if missing:
                raise ValueError(f"{path}:{lineno}: missing {sorted(missing)}")
            cases.append(EvalCase(
                id=row["id"], query=row["query"], lang=row["lang"],
                origin=row["origin"], expected=list(row["expected"]),
                why=row.get("why", ""),
            ))
    return cases


def document_languages(engine) -> dict[str, str]:
    """root_doc_id -> language, read from the corpus rather than the index.

    Reading it from the corpus keeps the cross-lingual figure honest even if a
    document is missing from the index: an unindexed document counts as a miss
    rather than silently dropping out of the denominator.
    """
    from . import corpus

    langs: dict[str, str] = {}
    for document in corpus.load_advisories(engine.settings.advisory_dir):
        langs[document.doc_id] = document.lang
    return langs


def run(engine, cases: Sequence[EvalCase], k: int = 5, use_floor: bool = True) -> list[CaseResult]:
    """Retrieve for every case. ``use_floor=False`` disables the per-language floor."""
    retriever = engine.retriever
    original = retriever.settings
    if not use_floor:
        retriever.settings = dataclasses.replace(original, per_language_floor=0)
    try:
        langs = document_languages(engine)
        results: list[CaseResult] = []
        for case in cases:
            hits = retriever.retrieve(case.query, k=k, doc_types=["advisory"])
            ranked, ranked_langs = [], []
            for hit in hits:
                doc_id = hit.chunk.metadata.get("root_doc_id") or (
                    hit.parent.doc_id if hit.parent else ""
                )
                ranked.append(doc_id)
                ranked_langs.append(langs.get(doc_id, hit.chunk.lang))
            results.append(CaseResult(case=case, ranked=ranked, ranked_langs=ranked_langs))
        return results
    finally:
        retriever.settings = original


def summarise(results: Sequence[CaseResult], langs: dict[str, str],
              ks: Sequence[int] = DEFAULT_KS) -> dict[str, Any]:
    overall = Metrics("overall")
    by_query_lang: dict[str, Metrics] = {}
    by_origin: dict[str, Metrics] = {}
    cross = Metrics("cross-lingual")

    for result in results:
        case = result.case
        rank = result.first_hit_rank()
        overall.add(rank, ks)
        by_query_lang.setdefault(case.lang, Metrics(f"query lang = {case.lang}")).add(rank, ks)
        by_origin.setdefault(case.origin, Metrics(f"origin = {case.origin}")).add(rank, ks)

        # Cross-lingual: only queries that actually have an answer in the other
        # language, scored only on finding that answer.
        other = {lang for doc in case.expected if (lang := langs.get(doc)) and lang != case.lang}
        if other:
            best = 0
            for lang in other:
                rank_in_lang = result.first_hit_rank(only_lang=lang)
                if rank_in_lang and (best == 0 or rank_in_lang < best):
                    best = rank_in_lang
            cross.add(best, ks)

    return {
        "ks": list(ks),
        "overall": overall.to_dict(ks),
        "cross_lingual": cross.to_dict(ks),
        "by_query_lang": [m.to_dict(ks) for m in by_query_lang.values()],
        "by_origin": [m.to_dict(ks) for m in by_origin.values()],
    }


def evaluate(engine, cases: Sequence[EvalCase] | None = None, k: int = 5,
             ks: Sequence[int] = DEFAULT_KS) -> dict[str, Any]:
    """Full report: both floor settings, plus the backend that produced it."""
    cases = list(cases if cases is not None else load_cases())
    langs = document_languages(engine)
    report: dict[str, Any] = {
        "embedder": engine.embedder.name,
        "semantic": bool(getattr(engine.embedder, "semantic", False)),
        "vector_backend": engine.vectors.backend,
        "documents": len(langs),
        "queries": len(cases),
        "k": k,
    }
    for use_floor, key in ((False, "floor_off"), (True, "floor_on")):
        report[key] = summarise(run(engine, cases, k=k, use_floor=use_floor), langs, ks)
    report["misses"] = [
        {"id": r.case.id, "lang": r.case.lang, "query": r.case.query,
         "expected": r.case.expected, "got": r.ranked[:5]}
        for r in run(engine, cases, k=k, use_floor=False)
        if r.first_hit_rank() == 0
    ]
    return report


__all__ = ["EvalCase", "CaseResult", "Metrics", "evaluate", "load_cases", "run", "summarise"]
