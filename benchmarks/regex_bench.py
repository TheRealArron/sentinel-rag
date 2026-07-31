#!/usr/bin/env python3
"""Python half of the Go-vs-Python regex benchmark.

Runs the ingestor's real 33 detection patterns over the corpus the Go benchmark
generates, so the two numbers are directly comparable. See README.md in this
directory for results and interpretation.

    # generate the shared corpus with Go, then:
    python3 benchmarks/regex_bench.py --corpus /tmp/corpus.txt

Fairness notes, because a benchmark that flatters your own choice is worthless:

* Patterns are extracted from ingestor/internal/enrich/rules.go, not retyped, so
  the two languages cannot silently diverge.
* All patterns are precompiled before timing starts, exactly as Go does at
  package init.
* Timing excludes I/O and corpus generation on both sides.
* `re` is the standard library engine. Python can reach RE2 via the `google-re2`
  package; that is measured separately when available, because "Python is slow"
  and "Python's default engine is slow" are different claims.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RULES_GO = REPO / "ingestor" / "internal" / "enrich" / "rules.go"


def extract_patterns() -> list[tuple[str, str]]:
    """Pull the rule regexes straight out of the Go source."""
    src = RULES_GO.read_text(encoding="utf-8")
    pats = re.findall(r"Pattern:\s*regexp\.MustCompile\(`(.+?)`\)", src, re.DOTALL)
    names = re.findall(r'Name:\s*"([^"]+)"', src)
    if len(pats) != len(names):
        raise SystemExit(f"parse mismatch: {len(pats)} patterns vs {len(names)} names")
    return list(zip(names, pats))


def bench(compiled, corpus: list[str], repeats: int) -> tuple[float, int]:
    """Return (best ns/line, match count)."""
    timings = []
    matches = 0
    for _ in range(repeats):
        matches = 0
        start = time.perf_counter_ns()
        for line in corpus:
            for pattern in compiled:
                if pattern.search(line):
                    matches += 1
        timings.append((time.perf_counter_ns() - start) / len(corpus))
    return min(timings), matches


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True, help="shared corpus file produced by the Go benchmark")
    ap.add_argument("--repeats", type=int, default=5, help="timed runs; the best is reported")
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = ap.parse_args()

    rules = extract_patterns()
    corpus = [l for l in Path(args.corpus).read_text(encoding="utf-8").splitlines() if l]
    print(f"patterns: {len(rules)}   corpus: {len(corpus)} lines   repeats: {args.repeats}", file=sys.stderr)

    results: dict[str, object] = {"patterns": len(rules), "lines": len(corpus)}

    # --- stdlib re (backtracking) -----------------------------------------
    compiled = [re.compile(p) for _, p in rules]
    ns_per_line, matches = bench(compiled, corpus, args.repeats)
    results["re_ns_per_line"] = round(ns_per_line, 1)
    results["re_matches"] = matches
    print(f"re          : {ns_per_line:9.1f} ns/line   ({matches} matches)", file=sys.stderr)

    # --- google-re2 (same engine family as Go), if installed --------------
    try:
        import re2  # type: ignore

        compiled2 = [re2.compile(p) for _, p in rules]
        ns2, matches2 = bench(compiled2, corpus, args.repeats)
        results["re2_ns_per_line"] = round(ns2, 1)
        results["re2_matches"] = matches2
        print(f"google-re2  : {ns2:9.1f} ns/line   ({matches2} matches)", file=sys.stderr)
    except ImportError:
        results["re2_ns_per_line"] = None
        print("google-re2  :    (not installed — pip install google-re2)", file=sys.stderr)

    # --- per-pattern cost, to find the expensive rules --------------------
    per_pattern = []
    for (name, _), pattern in zip(rules, compiled):
        t = []
        for _ in range(3):
            start = time.perf_counter_ns()
            for line in corpus:
                pattern.search(line)
            t.append((time.perf_counter_ns() - start) / len(corpus))
        per_pattern.append((name, min(t)))
    per_pattern.sort(key=lambda kv: kv[1], reverse=True)
    results["slowest_patterns"] = [{"rule": n, "ns_per_line": round(v, 1)} for n, v in per_pattern[:5]]
    print("\nslowest patterns (Python re):", file=sys.stderr)
    for name, value in per_pattern[:5]:
        print(f"  {value:8.1f} ns/line  {name}", file=sys.stderr)
    print(f"  median across all rules: {statistics.median(v for _, v in per_pattern):.1f} ns/line", file=sys.stderr)

    # --- catastrophic backtracking ----------------------------------------
    # The finding that matters. Go's RE2 is linear on this input; Python's
    # backtracking engine is exponential. Kept small enough to terminate.
    evil = re.compile(r"^(a+)+$")
    redos = []
    for n in (18, 20, 22, 24, 26):
        text = "a" * n + "b"
        start = time.perf_counter_ns()
        evil.search(text)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        redos.append({"n": n, "ms": round(elapsed_ms, 3)})
        print(f"  ReDoS n={n:3d}: {elapsed_ms:10.3f} ms", file=sys.stderr)
        if elapsed_ms > 5000:
            break
    results["redos"] = redos

    if args.json:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
