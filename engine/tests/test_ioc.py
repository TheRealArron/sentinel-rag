"""Tests for the threat-feed compiler.

Two things are being protected here. The first is ordinary: feeds parse, refusals
are reported rather than swallowed, the store comes out sorted. The second is the
one that would hurt — the compiler writes a bundle that a Go binary reads, and if
the two disagree about a single hash bit the filter matches nothing while looking
completely healthy. The agreement tests at the bottom are the guard against that.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest

from sentinel.ioc import (
    BLOOM_HEADER_LEN,
    DEFAULT_FPR,
    DEFAULT_SALT1,
    DEFAULT_SALT2,
    STORE_HEADER_PREFIX,
    Bloom,
    Indicator,
    classify,
    compile_directory,
    fmix64,
    fnv1a,
    hashes,
    normalise_domain,
    normalise_hash,
    normalise_ip,
    probe,
    render_store,
    size_for,
    write_bundle,
)

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "ingestor" / "internal" / "ioc" / "testdata" / "agreement.json"


# ---------------------------------------------------------------- bloom


def test_bloom_has_no_false_negatives():
    """A filter may say "maybe" for a key it never saw. It must never say "no"
    for one it did — that is a detection silently lost."""
    keys = [f"198.51.100.{i % 256}/{i}" for i in range(5000)]
    bloom = Bloom(len(keys))
    for k in keys:
        bloom.add(k)
    for k in keys:
        assert bloom.may_contain(k), f"filter dropped {k!r}"


def test_observed_fpr_tracks_the_target():
    """The measurement that caught the original hashing being seventeen times
    worse than advertised. A degenerate probe sequence passes every other test
    here: it still has no false negatives and still serialises."""
    n, target, trials = 20_000, 1e-3, 100_000
    bloom = Bloom(n, target)
    for i in range(n):
        bloom.add(f"present-{i}.example.com")

    false_hits = sum(
        1 for i in range(trials) if bloom.may_contain(f"absent-{i}.example.org")
    )
    observed = false_hits / trials
    assert observed <= target * 4, (
        f"observed FPR {observed:.2e} exceeds 4x the {target:.0e} target"
    )
    assert abs(bloom.estimated_fpr() - observed) <= target * 4


def test_size_for_matches_the_formula():
    m, k = size_for(1_000_000, 1e-4)
    expected_m = math.ceil(-1e6 * math.log(1e-4) / (math.log(2) ** 2))
    assert m == expected_m
    assert k == 13
    # The documented figure: 1M indicators in roughly 2.3 MiB.
    assert 2 < m / 8 / 1024 / 1024 < 3


def test_size_for_rejects_impossible_rates():
    for p in (0, 1, -0.5, 2):
        with pytest.raises(ValueError):
            size_for(1000, p)


def test_bloom_header_layout():
    bloom = Bloom(100)
    bloom.add("192.0.2.1")
    blob = bloom.to_bytes()
    assert blob[:8] == b"SENTBLM1"
    # magic(8) + version(4) + k(4) + m(8) + n(8) + salt1(8) + salt2(8) + crc(4)
    assert BLOOM_HEADER_LEN == 52
    assert len(blob) == BLOOM_HEADER_LEN + (bloom.m + 7) // 8


def test_salt2_is_forced_odd():
    """An even stride shares a factor with an even m, so the probe sequence
    cycles early and the filter is quietly worse than its header claims. Go
    rejects a bundle whose salt2 is even, so the compiler must never write one."""
    bloom = Bloom(100, DEFAULT_FPR, DEFAULT_SALT1, 0xAAAA)
    assert bloom.salt2 % 2 == 1
    _, h2 = hashes("anything", bloom.salt1, bloom.salt2)
    assert h2 % 2 == 1


# ---------------------------------------------------------- normalisation


@pytest.mark.parametrize("raw,expected", [
    ("192.0.2.1", "192.0.2.1"),
    (" 192.0.2.1 ", "192.0.2.1"),
    ("::ffff:192.0.2.1", "192.0.2.1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:DB8::1", "2001:db8::1"),
    ("192.0.2.256", ""),
    ("192.0.2", ""),
    ("192.0.2.1/24", ""),
    ("", ""),
])
def test_normalise_ip(raw, expected):
    assert normalise_ip(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("evil.example.com", "evil.example.com"),
    ("EVIL.Example.COM", "evil.example.com"),
    ("evil.example.com.", "evil.example.com"),
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
    # Refused, deliberately: matching these needs IDNA, and two independently
    # half-correct IDNA implementations agreeing is not a basis for detection.
    ("пример.рф", ""),
    ("localhost", ""),
    ("1.2.3.4", ""),
    ("1.2.3", ""),
    ("-bad.example", ""),
    ("bad-.example", ""),
    ("a..b", ""),
])
def test_normalise_domain(raw, expected):
    assert normalise_domain(raw) == expected


def test_normalise_hash_accepts_only_real_digest_lengths():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert normalise_hash(md5.upper()) == md5
    assert normalise_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").startswith("da39")
    assert normalise_hash("abc") == ""
    assert normalise_hash("g" + md5[1:]) == ""
    assert normalise_hash(md5[:-1]) == ""


def test_classify_prefers_the_unambiguous_shapes():
    assert classify("192.0.2.1") == ("ip", "192.0.2.1")
    assert classify("D41D8CD98F00B204E9800998ECF8427E")[0] == "hash"
    assert classify("EVIL.example.com") == ("domain", "evil.example.com")
    assert classify("garbage here") == ("", "")


# -------------------------------------------------------------- compiling


@pytest.fixture()
def feed_dir(tmp_path: Path) -> Path:
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "c2.txt").write_text(
        "# a comment\n\n203.0.113.45\nc2.malware.example\n", encoding="utf-8"
    )
    (d / "malware.csv").write_text(
        "indicator,type,note\n"
        "d41d8cd98f00b204e9800998ecf8427e,hash,md5 of nothing\n"
        "dropper.example.net,domain,staging host\n",
        encoding="utf-8",
    )
    (d / "phish.json").write_text(
        json.dumps([
            {"indicator": "login.example.org", "type": "domain", "note": "harvesting"},
            "198.51.100.203",
        ]),
        encoding="utf-8",
    )
    return d


def test_compile_reads_all_three_formats(feed_dir: Path):
    report = compile_directory(feed_dir)
    values = [i.value for i in report.indicators]
    assert "203.0.113.45" in values
    assert "d41d8cd98f00b204e9800998ecf8427e" in values
    assert "login.example.org" in values
    assert "198.51.100.203" in values
    assert len(report.sources) == 3


def test_compile_sorts_by_byte_order(feed_dir: Path):
    """The Go store is binary-searched. An unsorted store does not fail loudly —
    it returns "not found" for indicators it holds."""
    report = compile_directory(feed_dir)
    values = [i.value for i in report.indicators]
    assert values == sorted(values)


def test_compile_attributes_each_indicator_to_its_feed(feed_dir: Path):
    report = compile_directory(feed_dir)
    by_value = {i.value: i for i in report.indicators}
    assert by_value["203.0.113.45"].feed == "c2"
    assert by_value["d41d8cd98f00b204e9800998ecf8427e"].feed == "malware"
    assert by_value["d41d8cd98f00b204e9800998ecf8427e"].note == "md5 of nothing"


def test_compile_collapses_duplicates_across_feeds(tmp_path: Path):
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "a.txt").write_text("203.0.113.45\n", encoding="utf-8")
    (d / "b.txt").write_text("203.0.113.45\n", encoding="utf-8")
    report = compile_directory(d)
    assert len(report.indicators) == 1
    assert report.duplicates == 1


def test_compile_reports_refusals_rather_than_dropping_them(tmp_path: Path):
    """Compiling a feed and silently discarding part of it is how you come to
    believe you have coverage you do not have."""
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "mixed.txt").write_text(
        "203.0.113.45\nпример.рф\nnot an indicator\nlocalhost\n", encoding="utf-8"
    )
    report = compile_directory(d)
    assert len(report.indicators) == 1
    refused = {v for v, _ in report.refused}
    assert refused == {"пример.рф", "not an indicator", "localhost"}
    assert "3 refused" in report.summary()


def test_declared_type_that_does_not_validate_is_refused_not_reguessed(tmp_path: Path):
    d = tmp_path / "feeds"
    d.mkdir()
    # A second, valid row keeps the compile from failing outright, so the test
    # observes the refusal rather than the empty-feed error.
    (d / "bad.csv").write_text(
        "indicator,type\n203.0.113.45,hash\n198.51.100.7,ip\n", encoding="utf-8"
    )
    report = compile_directory(d)
    assert [i.value for i in report.indicators] == ["198.51.100.7"]
    assert report.refused == [("203.0.113.45", "not a valid hash")]


def test_csv_without_an_indicator_column_is_an_error(tmp_path: Path):
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "bad.csv").write_text("address,note\n203.0.113.45,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="indicator"):
        compile_directory(d)


def test_metadata_cannot_break_the_record_framing(tmp_path: Path):
    """The store is tab-delimited and feed contents are external input, so a note
    containing a tab would shift every later column."""
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "f.json").write_text(
        json.dumps([{"indicator": "203.0.113.45", "note": "a\tb\nc"}]),
        encoding="utf-8",
    )
    report = compile_directory(d)
    assert "\t" not in report.indicators[0].note
    assert "\n" not in report.indicators[0].note
    store = render_store(report.indicators)
    assert len(store.strip().splitlines()) == 2  # header + one record


def test_empty_feed_directory_is_an_error(tmp_path: Path):
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "empty.txt").write_text("# nothing here\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no usable indicators"):
        compile_directory(d)


def test_store_header_records_the_count(feed_dir: Path):
    report = compile_directory(feed_dir)
    store = render_store(report.indicators)
    first = store.splitlines()[0]
    assert first.startswith(STORE_HEADER_PREFIX)
    assert f"count={len(report.indicators)}" in first
    assert store.endswith("\n"), "Go cannot reach the last record without it"


def test_write_bundle_is_atomic_and_leaves_no_temp_files(feed_dir: Path, tmp_path: Path):
    report = compile_directory(feed_dir)
    bloom_path = tmp_path / "out" / "ioc.bloom"
    store_path = tmp_path / "out" / "ioc.store"
    write_bundle(report, bloom_path, store_path)
    assert bloom_path.exists() and store_path.exists()
    assert not [p for p in (tmp_path / "out").iterdir() if p.name.startswith(".")]


def test_bundle_counts_match_so_go_will_load_the_pair(feed_dir: Path, tmp_path: Path):
    """Go refuses a filter and store built from different snapshots, because a
    stale filter would reject indicators the store has gained."""
    report = compile_directory(feed_dir)
    store = render_store(report.indicators)
    declared = int(store.splitlines()[0].split("count=")[1])
    assert declared == report.bloom.n


# -------------------------------------------------------------- agreement


def _vectors() -> dict:
    if not VECTORS.exists():
        pytest.skip(f"{VECTORS} missing — run scripts/gen-ioc-vectors.py")
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_vectors_describe_this_implementation():
    """The Python half of the cross-language agreement; the Go half is
    ingestor/internal/ioc/agreement_test.go. Both read the same file, so neither
    side can drift without a test going red.

    This half is not redundant with Go's. It checks the *generated* file still
    describes the compiler as it exists now — if someone edits ioc.py and forgets
    to regenerate, Go would keep agreeing with a stale file and only this fails.
    """
    v = _vectors()
    assert int(v["salt1"]) == DEFAULT_SALT1
    assert int(v["salt2"]) == DEFAULT_SALT2

    for case in v["hash_vectors"]:
        key = case["key"]
        assert fnv1a(key) == int(case["fnv1a"]), key
        assert fmix64(fnv1a(key)) == int(case["fmix64"]), key
        h1, h2 = hashes(key, DEFAULT_SALT1, DEFAULT_SALT2)
        assert h1 == int(case["h1"]), key
        assert h2 == int(case["h2"]), key

    for case in v["size_vectors"]:
        m, k = size_for(case["n"], case["p"])
        assert (m, k) == (int(case["m"]), case["k"]), case

    for case in v["probe_vectors"]:
        h1, h2 = hashes(case["key"], DEFAULT_SALT1, DEFAULT_SALT2)
        m = int(case["m"])
        got = [probe(h1, h2, i, m) for i in range(len(case["bits"]))]
        assert got == [int(b) for b in case["bits"]], case["key"]

    for case in v["normalise_vectors"]:
        kind, raw = case["type"], case["in"]
        if kind == "ip":
            got = normalise_ip(raw)
        elif kind == "domain":
            got = normalise_domain(raw)
        elif kind == "hash":
            got = normalise_hash(raw)
        else:
            classified, got = classify(raw)
            assert classified == case["classified"], raw
        assert got == case["out"], (kind, raw)


def test_bundle_vector_still_reproduces():
    v = _vectors()
    spec = v["bundle"]
    indicators = [
        Indicator(i["value"], i["type"], i["feed"], i["note"])
        for i in spec["indicators"]
    ]
    bloom = Bloom(len(indicators), spec["fpr"], DEFAULT_SALT1, DEFAULT_SALT2)
    for ind in indicators:
        bloom.add(ind.value)
    blob = bloom.to_bytes()

    assert blob.hex() == spec["bloom_hex"]
    assert hashlib.sha256(blob).hexdigest() == spec["bloom_sha256"]
    assert render_store(indicators) == spec["store"]
