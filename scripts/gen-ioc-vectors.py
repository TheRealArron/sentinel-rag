#!/usr/bin/env python3
"""Generate the Go/Python agreement vectors for the IOC bundle format.

    python3 scripts/gen-ioc-vectors.py

Writes ingestor/internal/ioc/testdata/agreement.json. Re-run it after touching
the hashing, the sizing formula, the normalisation rules or the file format, and
read the diff: a changed vector is a format change, and the diff is where you
notice it.

Why this file exists
--------------------

Python builds the bundle and Go reads it. If the two disagree about a single
hash bit, the failure is silent and total: the filter rejects every candidate,
so the ingestor starts cleanly, prints a healthy indicator count, and never
fires a single detection. Nothing in either codebase looks wrong, and no test on
either side alone would notice, because each is internally consistent.

The expected values come from the Python implementation rather than being hand
authored, so the file records what the compiler actually does. A hand-written
expectation could be wrong in both places at once.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))

from sentinel.ioc import (
    DEFAULT_SALT1,
    DEFAULT_SALT2,
    Bloom,
    Indicator,
    classify,
    fmix64,
    fnv1a,
    hashes,
    normalise_domain,
    normalise_hash,
    normalise_ip,
    probe,
    render_store,
    size_for,
)

OUT = REPO / "ingestor" / "internal" / "ioc" / "testdata" / "agreement.json"

# Keys chosen to cover the shapes the ingestor actually hashes, plus the
# boundaries: empty, single byte, and a full SHA-256 digest.
HASH_KEYS = [
    "",
    "a",
    "192.0.2.1",
    "203.0.113.45",
    "2001:db8::1",
    "evil.example.com",
    "xn--80ak6aa92e.com",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a" * 253,
]

# Sizing pairs spanning a tiny feed, the documented 1M-at-1e-4 figure, and the
# clamps at both ends.
SIZE_CASES = [
    (0, 1e-4), (1, 1e-4), (10, 1e-4), (1_000, 1e-3),
    (50_000, 1e-3), (1_000_000, 1e-4), (5_000_000, 1e-4),
    (1_000, 0.5), (1_000, 1e-12),
]

# Normalisation cases, including every documented refusal.
NORMALISE_CASES = [
    ("ip", "192.0.2.1"), ("ip", " 192.0.2.1 "), ("ip", "::ffff:192.0.2.1"),
    ("ip", "2001:0db8:0000:0000:0000:0000:0000:0001"), ("ip", "2001:DB8::1"),
    ("ip", "192.0.2.256"), ("ip", "192.0.2"), ("ip", "192.0.2.1/24"), ("ip", ""),
    ("domain", "evil.example.com"), ("domain", "EVIL.Example.COM"),
    ("domain", "evil.example.com."), ("domain", "xn--80ak6aa92e.com"),
    ("domain", "пример.рф"), ("domain", "localhost"), ("domain", "1.2.3.4"),
    ("domain", "1.2.3"), ("domain", "-bad.example"), ("domain", "bad-.example"),
    ("domain", "a..b"),
    ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "D41D8CD98F00B204E9800998ECF8427E"),
    ("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("hash", "abc"), ("hash", "g41d8cd98f00b204e9800998ecf8427e"),
    ("classify", "192.0.2.1"), ("classify", "EVIL.example.com"),
    ("classify", "D41D8CD98F00B204E9800998ECF8427E"), ("classify", "garbage here"),
]

# A complete bundle, hashed end to end. This is the vector that would catch a
# header-layout or byte-order mistake that the per-function vectors miss.
BUNDLE = [
    Indicator("192.0.2.1", "ip", "demo", "first"),
    Indicator("198.51.100.77", "ip", "demo", ""),
    Indicator("2001:db8::1", "ip", "demo", "v6"),
    Indicator("c2.malware.example", "domain", "demo", "c2"),
    Indicator("d41d8cd98f00b204e9800998ecf8427e", "hash", "demo", "md5"),
]


def _normalise(kind: str, value: str) -> dict:
    if kind == "ip":
        return {"type": kind, "in": value, "out": normalise_ip(value)}
    if kind == "domain":
        return {"type": kind, "in": value, "out": normalise_domain(value)}
    if kind == "hash":
        return {"type": kind, "in": value, "out": normalise_hash(value)}
    t, v = classify(value)
    return {"type": kind, "in": value, "out": v, "classified": t}


def main() -> int:
    # uint64 values are emitted as decimal *strings*. As JSON numbers they would
    # be correct in both languages but silently lossy in anything that routes
    # through a double, and these vectors exist precisely to catch silent loss.
    hash_vectors = []
    for key in HASH_KEYS:
        h1, h2 = hashes(key, DEFAULT_SALT1, DEFAULT_SALT2)
        base = fnv1a(key)
        hash_vectors.append({
            "key": key,
            "fnv1a": str(base),
            "fmix64": str(fmix64(base)),
            "h1": str(h1),
            "h2": str(h2),
        })

    size_vectors = []
    for n, p in SIZE_CASES:
        m, k = size_for(n, p)
        size_vectors.append({"n": n, "p": p, "m": str(m), "k": k})

    # Probe positions for a fixed geometry, so a modulo or wrap-around
    # discrepancy is visible as a bit index rather than only as a changed filter.
    probe_m, probe_k = size_for(1000, 1e-3)
    probe_vectors = []
    for key in HASH_KEYS[:6]:
        h1, h2 = hashes(key, DEFAULT_SALT1, DEFAULT_SALT2)
        probe_vectors.append({
            "key": key,
            "m": str(probe_m),
            "bits": [str(probe(h1, h2, i, probe_m)) for i in range(probe_k)],
        })

    bloom = Bloom(len(BUNDLE), 1e-4, DEFAULT_SALT1, DEFAULT_SALT2)
    for ind in BUNDLE:
        bloom.add(ind.value)
    blob = bloom.to_bytes()
    store = render_store(BUNDLE)

    payload = {
        "_comment": "Generated by scripts/gen-ioc-vectors.py — do not hand-edit.",
        "salt1": str(DEFAULT_SALT1),
        "salt2": str(DEFAULT_SALT2),
        "hash_vectors": hash_vectors,
        "size_vectors": size_vectors,
        "probe_vectors": probe_vectors,
        "normalise_vectors": [_normalise(k, v) for k, v in NORMALISE_CASES],
        "bundle": {
            "indicators": [
                {"value": i.value, "type": i.type, "feed": i.feed, "note": i.note}
                for i in BUNDLE
            ],
            "fpr": 1e-4,
            "bloom_hex": blob.hex(),
            "bloom_sha256": hashlib.sha256(blob).hexdigest(),
            "store": store,
        },
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)}: "
          f"{len(hash_vectors)} hash, {len(size_vectors)} size, "
          f"{len(probe_vectors)} probe, {len(payload['normalise_vectors'])} normalise vectors, "
          f"1 full bundle ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
