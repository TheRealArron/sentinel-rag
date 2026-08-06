"""Tests for the Sigma-to-Sentinel transpiler.

The through-line: a transpiler that quietly mistranslates is worse than one that
refuses. Most of these tests are about the refusals.
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from sentinel.sigma import (
    SigmaError,
    SigmaUnsupported,
    compile_directory,
    evaluate,
    load_yaml,
    transpile,
    write_bundle,
)

BASE = """
title: Test Rule
id: 11111111-2222-3333-4444-555555555555
status: stable
description: A rule for tests.
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|contains: 'Failed password'
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
"""


def compile_text(text: str):
    return transpile(load_yaml(text), source="test.yml")


# --------------------------------------------------------------------------- #
# the happy path
# --------------------------------------------------------------------------- #

def test_transpiles_a_minimal_rule():
    rule = compile_text(BASE)
    assert rule.title == "Test Rule"
    assert rule.sigma_id == "11111111-2222-3333-4444-555555555555"
    assert rule.level == "medium"
    assert rule.processes == ["sshd"]
    assert rule.predicate.op == "match"
    assert rule.predicate.field_name == "message"
    assert rule.predicate.values == ["Failed password"]


def test_level_maps_to_a_score():
    for level, expected in [("informational", 15), ("low", 35), ("medium", 55),
                            ("high", 72), ("critical", 88)]:
        rule = compile_text(BASE.replace("level: medium", f"level: {level}"))
        assert rule.score == expected, level


def test_attack_tags_become_bilingual_tags_and_mitre():
    rule = compile_text(BASE)
    assert rule.mitre == ["T1110.001"]
    # Both languages, because the whole product is bilingual: a Japanese-speaking
    # analyst filtering on 認証情報アクセス must find rules imported from an
    # English-language community ruleset.
    assert "credential-access" in rule.tags
    assert "認証情報アクセス" in rule.tags
    assert "password-guessing" in rule.tags
    assert "パスワード推測" in rule.tags
    assert "sigma" in rule.tags and "シグマ" in rule.tags


def test_tactic_sets_the_category():
    rule = compile_text(BASE)
    assert rule.category == "authentication"


def test_an_unknown_attack_technique_is_kept_in_mitre():
    """An unmapped technique still belongs in the ATT&CK list.

    Dropping it would lose the one piece of metadata an analyst can look up.
    """
    rule = compile_text(BASE.replace("attack.t1110.001", "attack.t9999.123"))
    assert rule.mitre == ["T9999.123"]


# --------------------------------------------------------------------------- #
# modifiers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("modifier,op", [
    ("contains", "contains"),
    ("startswith", "startswith"),
    ("endswith", "endswith"),
    ("re", "regex"),
])
def test_modifiers_map_to_match_operators(modifier, op):
    rule = compile_text(BASE.replace("message|contains:", f"message|{modifier}:"))
    assert rule.predicate.match_op == op


def test_all_modifier_becomes_a_conjunction():
    """`|contains|all` means every value must be present, not any.

    Getting this backwards would turn a precise rule into a noisy one, which is
    the kind of bug that is only visible in production at 3am.
    """
    rule = compile_text(BASE.replace(
        "    message|contains: 'Failed password'",
        "    message|contains|all:\n      - 'Failed'\n      - 'root'"))
    assert rule.predicate.op == "and"
    assert len(rule.predicate.children) == 2
    ev = {"message": "Failed password for root"}
    assert evaluate(rule.predicate.to_dict(), ev) is True
    assert evaluate(rule.predicate.to_dict(), {"message": "Failed password for arron"}) is False


def test_a_value_list_without_all_is_a_disjunction():
    rule = compile_text(BASE.replace(
        "    message|contains: 'Failed password'",
        "    message|contains:\n      - 'Failed'\n      - 'Invalid'"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Failed password"}) is True
    assert evaluate(d, {"message": "Invalid user"}) is True
    assert evaluate(d, {"message": "Accepted password"}) is False


def test_bare_equality_on_free_text_degrades_to_contains():
    """Sigma's bare `field: value` is equality.

    On a syslog message that is almost never what the author meant — the message
    has a timestamp and a PID around the interesting part — so it is widened to a
    substring match. Applying it literally would produce a rule that silently
    never fires.
    """
    rule = compile_text(BASE.replace("message|contains:", "message:"))
    assert rule.predicate.match_op == "contains"


def test_equality_on_a_structured_field_stays_exact():
    """`user: root` must not match `rooted` — that field is not free text."""
    rule = compile_text(BASE.replace("    message|contains: 'Failed password'",
                                     "    user: 'root'"))
    assert rule.predicate.match_op == "equals"
    d = rule.predicate.to_dict()
    assert evaluate(d, {"user": "root"}) is True
    assert evaluate(d, {"user": "rooted"}) is False


# --------------------------------------------------------------------------- #
# conditions
# --------------------------------------------------------------------------- #

def test_and_condition():
    rule = compile_text(BASE.replace(
        "  condition: selection",
        "  selection_user:\n    user: 'root'\n  condition: selection and selection_user"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Failed password", "user": "root"}) is True
    assert evaluate(d, {"message": "Failed password", "user": "arron"}) is False


def test_or_condition():
    rule = compile_text(BASE.replace(
        "  condition: selection",
        "  selection_alt:\n    message|contains: 'Invalid user'\n"
        "  condition: selection or selection_alt"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Invalid user oracle"}) is True
    assert evaluate(d, {"message": "Accepted password"}) is False


def test_not_filter_is_honoured():
    """`selection and not filter` is the most common Sigma shape.

    Ignoring the filter half would turn an exclusion into a false positive
    generator — exactly the mistake a flattened-regex transpiler makes.
    """
    rule = compile_text(BASE.replace(
        "  condition: selection",
        "  filter_internal:\n    source_ip|startswith: '10.'\n"
        "  condition: selection and not filter_internal"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Failed password", "source_ip": "203.0.113.9"}) is True
    assert evaluate(d, {"message": "Failed password", "source_ip": "10.0.0.5"}) is False


def test_one_of_wildcard():
    rule = compile_text(BASE.replace(
        "  condition: selection",
        "  selection_b:\n    message|contains: 'Invalid user'\n  condition: 1 of selection*"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Invalid user oracle"}) is True
    assert evaluate(d, {"message": "Failed password"}) is True
    assert evaluate(d, {"message": "Accepted password"}) is False


def test_all_of_them():
    rule = compile_text(BASE.replace(
        "  condition: selection",
        "  selection_b:\n    user: 'root'\n  condition: all of them"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "Failed password", "user": "root"}) is True
    assert evaluate(d, {"message": "Failed password", "user": "arron"}) is False


def test_bare_keyword_list_searches_the_message():
    rule = compile_text(BASE.replace(
        "  selection:\n    message|contains: 'Failed password'",
        "  keywords:\n    - 'POSSIBLE BREAK-IN ATTEMPT'\n    - 'authentication failure'"
    ).replace("  condition: selection", "  condition: keywords"))
    d = rule.predicate.to_dict()
    assert evaluate(d, {"message": "reverse mapping ... POSSIBLE BREAK-IN ATTEMPT!"}) is True
    assert evaluate(d, {"message": "session opened"}) is False


# --------------------------------------------------------------------------- #
# refusals — the important half
# --------------------------------------------------------------------------- #

def test_windows_logsource_is_refused():
    with pytest.raises(SigmaUnsupported) as exc:
        compile_text(BASE.replace("product: linux", "product: windows"))
    assert "windows" in str(exc.value).lower()


def test_aggregation_condition_is_refused():
    """`| count() > 5` is stateful, and this evaluator is stateless.

    Sentinel does have a correlator that could express it, but silently dropping
    the aggregation would turn "5 failures from one host" into "1 failure" — a
    rule that fires constantly. Refusing is the honest outcome.
    """
    with pytest.raises(SigmaUnsupported) as exc:
        compile_text(BASE.replace("  condition: selection",
                                  "  condition: selection | count(user) by source_ip > 5"))
    assert "aggregation" in str(exc.value).lower() or "count" in str(exc.value).lower()


@pytest.mark.parametrize("modifier", ["base64offset", "windash", "utf16"])
def test_encoding_modifiers_are_refused(modifier):
    with pytest.raises(SigmaUnsupported):
        compile_text(BASE.replace("message|contains:", f"message|{modifier}|contains:"))


def test_an_unmappable_field_is_refused():
    with pytest.raises(SigmaUnsupported):
        compile_text(BASE.replace("    message|contains: 'Failed password'",
                                  "    ParentProcessGuid: '{abc}'"))


def test_a_rule_without_a_detection_block_is_an_error():
    with pytest.raises(SigmaError):
        compile_text(BASE.replace("detection:", "not_detection:"))


def test_a_condition_naming_an_undefined_selection_is_an_error():
    with pytest.raises(SigmaError):
        compile_text(BASE.replace("  condition: selection", "  condition: nonexistent"))


# --------------------------------------------------------------------------- #
# directory compilation and the bundle
# --------------------------------------------------------------------------- #

def test_compile_directory_skips_rather_than_fails(tmp_path):
    """One unsupported rule must not cost you the other thirty-nine."""
    (tmp_path / "good.yml").write_text(BASE, encoding="utf-8")
    (tmp_path / "windows.yml").write_text(BASE.replace("product: linux", "product: windows"),
                                          encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: Broken\ndetection:\n  condition: nope\n",
                                         encoding="utf-8")

    report = compile_directory(tmp_path)
    assert len(report.rules) == 1
    assert len(report.skipped) == 1
    assert len(report.failed) == 1
    assert "windows" in report.skipped[0][1].lower()


def test_compile_directory_on_a_missing_path_is_empty(tmp_path):
    report = compile_directory(tmp_path / "nope")
    assert report.rules == [] and report.skipped == [] and report.failed == []


def test_bundle_is_versioned_and_serialisable(tmp_path):
    (tmp_path / "good.yml").write_text(BASE, encoding="utf-8")
    report = compile_directory(tmp_path)
    out = write_bundle(report, tmp_path / "out" / "sigma.json")

    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["version"] == 1
    assert len(bundle["rules"]) == 1
    rule = bundle["rules"][0]
    # The Go loader uses DisallowUnknownFields, so the key set is a contract.
    assert set(rule) == {"name", "title", "category", "score", "outcome", "mitre",
                         "tags", "processes", "source", "sigma_id", "level", "predicate"}


def test_rule_names_are_namespaced(tmp_path):
    """Imported rules are prefixed so they never collide with a built-in name."""
    (tmp_path / "good.yml").write_text(BASE, encoding="utf-8")
    report = compile_directory(tmp_path)
    assert report.rules[0].name.startswith("sigma_")


def test_the_shipped_rules_compile():
    repo = Path(__file__).resolve().parents[2]
    report = compile_directory(repo / "rules" / "sigma")
    assert report.failed == [], f"shipped rules failed to compile: {report.failed}"
    assert len(report.rules) >= 3
    # The deliberately-unsupported sample must still be skipped, so the refusal
    # path stays exercised by the repo's own content.
    assert len(report.skipped) >= 1


def test_scores_stay_in_range():
    repo = Path(__file__).resolve().parents[2]
    for rule in compile_directory(repo / "rules" / "sigma").rules:
        assert 0 <= rule.score <= 100


# --------------------------------------------------------------------------- #
# the no-PyYAML fallback parser
# --------------------------------------------------------------------------- #
#
# CI installs no runtime dependencies, so the Python job runs these tests with
# PyYAML absent — but a developer machine usually has it, which is exactly how
# the fallback parser shipped broken on all four sample rules while every local
# run was green. These tests force the fallback on regardless.

@contextmanager
def no_pyyaml():
    """Make `import yaml` fail, the way a dependency-free install behaves.

    Setting the entry to None is what actually blocks the import; an import-hook
    approach using find_module silently does nothing on Python 3.12, which is
    how the first version of this check passed while testing nothing.
    """
    saved = sys.modules.get("yaml", "absent")
    sys.modules["yaml"] = None
    try:
        yield
    finally:
        if saved == "absent":
            sys.modules.pop("yaml", None)
        else:
            sys.modules["yaml"] = saved


def test_the_fallback_parser_is_actually_engaged():
    """Guard the guard: if this passes trivially, every test below is vacuous."""
    with no_pyyaml(), pytest.raises(ImportError):
        import yaml  # noqa: F401


def test_shipped_rules_compile_without_pyyaml():
    repo = Path(__file__).resolve().parents[2]
    with no_pyyaml():
        report = compile_directory(repo / "rules" / "sigma")
    assert report.failed == [], f"fallback parser failed on: {report.failed}"
    assert len(report.rules) >= 3


def _pyyaml_available() -> bool:
    # Not pytest.importorskip: that skips only on ModuleNotFoundError, so a
    # PyYAML that is present but broken becomes an error rather than a skip.
    # Here either one means the same thing — there is nothing to compare against.
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _pyyaml_available(), reason="no PyYAML to compare against")
def test_both_parsers_produce_identical_rules():
    """The fallback is only safe if it means the same thing as PyYAML."""
    repo = Path(__file__).resolve().parents[2]

    with_yaml = compile_directory(repo / "rules" / "sigma")
    with no_pyyaml():
        without_yaml = compile_directory(repo / "rules" / "sigma")

    assert [r.to_dict() for r in with_yaml.rules] == [r.to_dict() for r in without_yaml.rules]
    assert [n for n, _ in with_yaml.skipped] == [n for n, _ in without_yaml.skipped]


def test_fallback_parses_a_block_sequence_under_a_key():
    """`tags:` followed by `- item` — the shape that broke every sample rule.

    A key's container type is unknown until its first child line arrives, and
    the original parser assumed a map.
    """
    with no_pyyaml():
        doc = load_yaml("tags:\n  - attack.persistence\n  - attack.t1098.004\n")
    assert doc == {"tags": ["attack.persistence", "attack.t1098.004"]}


def test_fallback_parses_a_folded_block_scalar():
    with no_pyyaml():
        doc = load_yaml("description: >\n  one line\n  and another\nlevel: high\n")
    assert doc == {"description": "one line and another", "level": "high"}


def test_fallback_parses_a_literal_block_scalar():
    with no_pyyaml():
        doc = load_yaml("description: |\n  line one\n  line two\nlevel: low\n")
    assert doc == {"description": "line one\nline two", "level": "low"}


def test_fallback_parses_nested_maps_and_inline_sequences():
    with no_pyyaml():
        doc = load_yaml(
            "detection:\n"
            "  selection:\n"
            "    message|contains:\n"
            "      - 'a'\n"
            "      - 'b'\n"
            "    user: root\n"
            "  condition: selection\n"
            "flow: [x, y]\n"
        )
    assert doc == {
        "detection": {
            "selection": {"message|contains": ["a", "b"], "user": "root"},
            "condition": "selection",
        },
        "flow": ["x", "y"],
    }


def test_fallback_refuses_what_it_cannot_parse():
    with no_pyyaml(), pytest.raises(SigmaError):
        load_yaml("detection:\n  - item\n    stray text without a colon\n")


def test_fallback_transpiles_an_end_to_end_rule():
    with no_pyyaml():
        rule = compile_text(BASE)
    assert rule.mitre == ["T1110.001"]
    assert rule.processes == ["sshd"]
    assert rule.score == 55
