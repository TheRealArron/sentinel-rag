"""Cross-implementation agreement between the transpiler and the Go ingestor.

The transpiler is only worth having if the consumer interprets its output the
way the transpiler intended. `sentinel sigma` reporting "3 compiled" while the
ingestor silently reads one of them differently is the worst failure mode
available here: it produces confident, wrong coverage.

So both implementations are pinned to one shared vector file,
``ingestor/internal/sigma/testdata/agreement.json``. This module checks the
Python reference evaluator against it; TestAgreesWithThePythonReferenceEvaluator
in ingestor/internal/sigma/sigma_test.go checks Go against the same file.
Neither side can drift without the other going red.

The vectors live in the Go testdata directory rather than somewhere neutral
because `go test` cannot read a file outside its module, while pytest can read
anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.sigma import compile_directory, evaluate

VECTORS = (Path(__file__).resolve().parents[2]
           / "ingestor" / "internal" / "sigma" / "testdata" / "agreement.json")


def _load_vectors() -> list[dict]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_vector_file_exists():
    assert VECTORS.exists(), f"missing {VECTORS} — regenerate with scripts/gen-sigma-vectors.py"


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_python_evaluator_matches_the_expected_verdict(vector):
    got = evaluate(vector["predicate"], vector["event"])
    assert got is vector["want"], (
        f"{vector['name']}: Python evaluator returned {got}, vectors say {vector['want']}"
    )


def test_vectors_cover_every_operator():
    """A vector suite that never exercises `not` would let the hardest case rot."""
    ops: set[str] = set()
    matches: set[str] = set()

    def walk(node: dict) -> None:
        ops.add(node["op"])
        if node["op"] == "match":
            matches.add(node["match"])
        for child in node.get("children", []):
            walk(child)

    for vector in _load_vectors():
        walk(vector["predicate"])

    assert {"and", "or", "not", "match"} <= ops, f"boolean coverage gap: {ops}"
    assert {"contains", "equals", "startswith", "endswith", "regex"} <= matches, (
        f"operator coverage gap: {matches}"
    )


def test_both_verdicts_are_represented():
    """All-True vectors would pass against an evaluator that always returns True."""
    wants = {v["want"] for v in _load_vectors()}
    assert wants == {True, False}, "vectors must contain both matches and non-matches"


def test_shipped_rules_are_covered_by_vectors():
    """Every rule the repo ships appears in the agreement suite.

    Otherwise a rule could use a construct the two implementations disagree
    about and no test would notice.
    """
    repo = Path(__file__).resolve().parents[2]
    report = compile_directory(repo / "rules" / "sigma")
    if not report.rules:
        pytest.skip("no sigma rules in the repo")

    covered = {v.get("rule") for v in _load_vectors()}
    for rule in report.rules:
        assert rule.name in covered, (
            f"{rule.name} ships but has no agreement vector — "
            f"regenerate with scripts/gen-sigma-vectors.py"
        )
