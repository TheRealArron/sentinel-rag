"""Threat-feed compiler: raw indicator feeds → the bundle the Go ingestor loads.

This is the Phase 10 counterpart to the Sigma transpiler, and it follows the same
division of labour: Python does the parsing, normalising and compiling, Go does
the matching at ingest speed. Refreshing a feed is a file drop and a restart, not
a rebuild.

The output is two files:

*   ``ioc.bloom`` — a Bloom filter, RAM-resident in the ingestor, that rejects
    almost every candidate without touching the disk.
*   ``ioc.store`` — every indicator, sorted, binary-searched on demand to confirm
    the filter's maybes exactly.

See ``docs/design/ioc.md`` for why it is split that way, and
``ingestor/internal/ioc`` for the reading half.

Bit-for-bit agreement with Go is a hard requirement, not an aspiration. A builder
and a reader that disagree on one hash bit produce a filter that matches nothing
and reports no error — the ingestor would start cleanly, print a healthy-looking
indicator count, and never fire. Everything in the hashing section below is a
literal transcription of ``ingestor/internal/ioc/bloom.go``, and
``scripts/gen-ioc-vectors.py`` pins the two together.

Standard library only. The engine's test suite runs without ``requirements.txt``
installed, and a threat-feed compiler that needs a scientific Python stack to
turn a text file into a bit array would be its own kind of joke.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import math
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# format constants — must match ingestor/internal/ioc
# --------------------------------------------------------------------------

BLOOM_MAGIC = b"SENTBLM1"
BLOOM_VERSION = 1
BLOOM_HEADER_LEN = 8 + 4 + 4 + 8 + 8 + 8 + 8 + 4

STORE_HEADER_PREFIX = "#sentinel-ioc-store"
STORE_VERSION = 1

DEFAULT_FPR = 1e-4
DEFAULT_SALT1 = 0x9E3779B97F4A7C15
DEFAULT_SALT2 = 0xBF58476D1CE4E5B9

MAX_BLOOM_BITS = 1 << 31
MASK64 = 0xFFFFFFFFFFFFFFFF

TYPE_IP = "ip"
TYPE_DOMAIN = "domain"
TYPE_HASH = "hash"

# --------------------------------------------------------------------------
# hashing — a literal transcription of bloom.go, pinned by the vector suite
# --------------------------------------------------------------------------

_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3


def fnv1a(key: str) -> int:
    """FNV-1a 64 over the UTF-8 bytes of ``key``."""
    h = _FNV_OFFSET
    for b in key.encode("utf-8"):
        h = ((h ^ b) * _FNV_PRIME) & MASK64
    return h


def fmix64(h: int) -> int:
    """The murmur3 64-bit finaliser.

    Not decoration. Salting FNV directly and skipping this step measured a
    false-positive rate seventeen times worse than the target, because FNV's low
    bits barely avalanche and the probe index is taken modulo an even number —
    so the k probes collapse toward each other. The Go side documents the whole
    diagnosis in ``hashes``.
    """
    h &= MASK64
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & MASK64
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & MASK64
    h ^= h >> 33
    return h


def hashes(key: str, salt1: int, salt2: int) -> tuple[int, int]:
    """The two base hashes for a key. ``h2`` is forced odd, as in Go."""
    h = fnv1a(key)
    return fmix64(h ^ salt1), fmix64(h ^ salt2) | 1


def probe(h1: int, h2: int, i: int, m: int) -> int:
    """Bit index of the i-th probe.

    Go computes this in ``uint64`` and lets the addition wrap; Python integers do
    not wrap, so the mask is what keeps the two implementations identical.
    """
    return ((h1 + i * h2) & MASK64) % m


def size_for(n: int, p: float) -> tuple[int, int]:
    """Bit count and probe count for ``n`` keys at target rate ``p``.

    Mirrors ``SizeFor``. ``math.floor(x + 0.5)`` rather than ``round`` is
    deliberate: Go's ``math.Round`` rounds halves away from zero while Python's
    ``round`` rounds halves to even, so on an exact .5 the two would choose
    different k and produce incompatible filters.
    """
    if not (0 < p < 1):
        raise ValueError(f"target false-positive rate must be in (0,1), got {p}")
    if n == 0:
        n = 1
    ln2 = math.log(2)
    mf = -n * math.log(p) / (ln2 * ln2)
    if mf > MAX_BLOOM_BITS:
        raise ValueError(
            f"filter for {n} indicators at p={p} needs {mf:.0f} bits, "
            f"over the {MAX_BLOOM_BITS}-bit cap"
        )
    m = math.ceil(mf)
    if m < 8:
        m = 8
    kf = math.floor(m / n * ln2 + 0.5)
    kf = max(1, min(30, kf))
    return m, int(kf)


class Bloom:
    """A Bloom filter that serialises to the format the Go ingestor reads."""

    def __init__(self, n: int, p: float = DEFAULT_FPR,
                 salt1: int = DEFAULT_SALT1, salt2: int = DEFAULT_SALT2) -> None:
        self.m, self.k = size_for(n, p)
        self.salt1 = salt1 & MASK64
        self.salt2 = (salt2 & MASK64) | 1
        self.n = 0
        self.bits = bytearray((self.m + 7) // 8)

    def add(self, key: str) -> None:
        h1, h2 = hashes(key, self.salt1, self.salt2)
        for i in range(self.k):
            pos = probe(h1, h2, i, self.m)
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.n += 1

    def may_contain(self, key: str) -> bool:
        h1, h2 = hashes(key, self.salt1, self.salt2)
        for i in range(self.k):
            pos = probe(h1, h2, i, self.m)
            if not self.bits[pos >> 3] & (1 << (pos & 7)):
                return False
        return True

    def estimated_fpr(self) -> float:
        if not self.m or not self.n:
            return 0.0
        return (1 - math.exp(-self.k * self.n / self.m)) ** self.k

    def to_bytes(self) -> bytes:
        body = bytes(self.bits)
        header = (
            BLOOM_MAGIC
            + struct.pack("<II", BLOOM_VERSION, self.k)
            + struct.pack("<QQQQ", self.m, self.n, self.salt1, self.salt2)
            + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
        )
        assert len(header) == BLOOM_HEADER_LEN, "bloom header length drifted from Go"
        return header + body


# --------------------------------------------------------------------------
# normalisation — must agree with ingestor/internal/ioc/indicator.go
# --------------------------------------------------------------------------

_LABEL_OK = re.compile(r"^[a-z0-9-]+$")


def normalise_ip(value: str) -> str:
    """Canonical text form of an IP, or "" if it is not one.

    Mirrors ``NormaliseIP``, including folding IPv4-mapped IPv6 to its IPv4 form.
    A feed and a log line that spell the same address differently must produce
    the same key, or the indicator never fires.
    """
    value = value.strip()
    if not value:
        return ""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def normalise_domain(value: str) -> str:
    """Lowercased, validated domain, or "" if it cannot be used.

    Non-ASCII domains are refused rather than guessed at: matching them needs
    IDNA, the Go side deliberately carries no such dependency, and two
    independently half-correct IDNA implementations agreeing is not something to
    build a detection on. The compiler counts what it refused instead of passing
    it through — see ``Report.refused``.
    """
    value = value.strip().rstrip(".")
    if not value or len(value) > 253:
        return ""
    lower = value.lower()
    labels = lower.split(".")
    if len(labels) < 2:
        return ""
    for label in labels:
        if not label or len(label) > 63:
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""
        if not _LABEL_OK.match(label):
            return ""
    # An all-digit final label means a dotted number — an IP or a version string.
    if labels[-1].isdigit():
        return ""
    return lower


def normalise_hash(value: str) -> str:
    """Lowercased hex digest of a recognised length (MD5, SHA-1, SHA-256)."""
    value = value.strip()
    if len(value) not in (32, 40, 64):
        return ""
    lower = value.lower()
    if any(c not in "0123456789abcdef" for c in lower):
        return ""
    return lower


def normalise(kind: str, value: str) -> str:
    if kind == TYPE_IP:
        return normalise_ip(value)
    if kind == TYPE_DOMAIN:
        return normalise_domain(value)
    if kind == TYPE_HASH:
        return normalise_hash(value)
    return ""


def classify(value: str) -> tuple[str, str]:
    """Guess an untyped indicator's type and return its canonical form."""
    v = normalise_ip(value)
    if v:
        return TYPE_IP, v
    v = normalise_hash(value)
    if v:
        return TYPE_HASH, v
    v = normalise_domain(value)
    if v:
        return TYPE_DOMAIN, v
    return "", ""


# --------------------------------------------------------------------------
# feed parsing
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Indicator:
    value: str
    type: str
    feed: str
    note: str = ""


@dataclass
class Report:
    """What a compile run produced, and what it threw away."""

    indicators: list[Indicator] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    #: value -> why, for entries that could not be normalised
    refused: list[tuple[str, str]] = field(default_factory=list)
    duplicates: int = 0
    bloom: Bloom | None = None

    def summary(self) -> str:
        parts = [f"{len(self.indicators)} indicators from {len(self.sources)} feed(s)"]
        by_type: dict[str, int] = {}
        for ind in self.indicators:
            by_type[ind.type] = by_type.get(ind.type, 0) + 1
        if by_type:
            parts.append(", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))
        if self.duplicates:
            parts.append(f"{self.duplicates} duplicate(s) collapsed")
        if self.refused:
            parts.append(f"{len(self.refused)} refused")
        return "; ".join(parts)


def _clean_field(s: str) -> str:
    """Strip the framing characters out of feed-supplied metadata.

    Feed contents are external input and the store is tab-delimited, so a note
    containing a tab would shift every later column and corrupt the record.
    """
    return " ".join(s.replace("\t", " ").replace("\n", " ").replace("\r", " ").split())[:200]


# Every parser yields the same 4-tuple: (value, declared type, feed, note).
# Declared type may be "", meaning "let classify() work it out".
Row = tuple[str, str, str, str]


def _parse_txt(path: Path, feed: str) -> list[Row]:
    """One indicator per line; ``#`` comments and blanks ignored."""
    out: list[Row] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append((line, "", feed, ""))
    return out


def _parse_csv(path: Path, feed: str) -> list[Row]:
    """CSV with an ``indicator`` column, plus optional ``type`` and ``note``.

    Column names are matched case-insensitively; a file without an ``indicator``
    column is an error rather than an empty result, because a feed that compiles
    to nothing looks exactly like a feed with nothing in it.
    """
    out: list[Row] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError(f"{path}: empty CSV")
        cols = {(name or "").strip().lower(): name for name in reader.fieldnames}
        key = cols.get("indicator") or cols.get("ioc") or cols.get("value")
        if key is None:
            raise ValueError(f"{path}: no 'indicator' column (found {sorted(cols)})")
        tcol = cols.get("type")
        ncol = cols.get("note") or cols.get("description")
        for row in reader:
            value = (row.get(key) or "").strip()
            if not value or value.startswith("#"):
                continue
            kind = (row.get(tcol) or "").strip().lower() if tcol else ""
            note = (row.get(ncol) or "").strip() if ncol else ""
            out.append((value, kind, feed, note))
    return out


def _parse_json(path: Path, feed: str) -> list[Row]:
    """A list of strings, or of ``{"indicator", "type", "note"}`` objects."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("indicators", data.get("data", []))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list of indicators")
    out: list[Row] = []
    for item in data:
        if isinstance(item, str):
            out.append((item.strip(), "", feed, ""))
        elif isinstance(item, dict):
            value = str(item.get("indicator") or item.get("value") or "").strip()
            if not value:
                continue
            out.append((
                value,
                str(item.get("type") or "").strip().lower(),
                feed,
                str(item.get("note") or item.get("description") or "").strip(),
            ))
    return out


def compile_directory(root: Path, *, fpr: float = DEFAULT_FPR,
                      salt1: int = DEFAULT_SALT1,
                      salt2: int = DEFAULT_SALT2) -> Report:
    """Parse, normalise, deduplicate and sort every feed under ``root``.

    Sorting happens here because the Go store is binary-searched: an unsorted
    store does not fail, it returns "not found" for indicators it holds. Byte
    order, matching Go's string comparison — not locale-aware or case-insensitive
    ordering, which would disagree on exactly the records where it matters.
    """
    report = Report()
    if not root.exists():
        raise FileNotFoundError(f"no such feed directory: {root}")

    raw: list[Row] = []
    for path in sorted(root.iterdir()):
        if path.is_dir() or path.name.startswith("."):
            continue
        feed = path.stem
        suffix = path.suffix.lower()
        if suffix in (".txt", ".list", ""):
            rows = _parse_txt(path, feed)
        elif suffix == ".csv":
            rows = _parse_csv(path, feed)
        elif suffix == ".json":
            rows = _parse_json(path, feed)
        else:
            continue
        report.sources.append(str(path))
        raw.extend(rows)

    seen: dict[str, Indicator] = {}
    for value, kind, feed, note in raw:
        if kind:
            norm = normalise(kind, value)
            if not norm:
                # A declared type that does not validate is a feed bug worth
                # reporting, not something to silently re-guess.
                report.refused.append((value, f"not a valid {kind}"))
                continue
        else:
            kind, norm = classify(value)
            if not norm:
                report.refused.append((value, "unrecognised indicator format"))
                continue
        if norm in seen:
            report.duplicates += 1
            continue
        seen[norm] = Indicator(norm, kind, _clean_field(feed), _clean_field(note))

    report.indicators = sorted(seen.values(), key=lambda i: i.value)
    if not report.indicators:
        raise ValueError(f"{root}: no usable indicators after normalisation")

    bloom = Bloom(len(report.indicators), fpr, salt1, salt2)
    for ind in report.indicators:
        bloom.add(ind.value)
    report.bloom = bloom
    return report


def render_store(indicators: list[Indicator]) -> str:
    """The sorted store, as text."""
    lines = [f"{STORE_HEADER_PREFIX} v{STORE_VERSION} count={len(indicators)}"]
    lines.extend(f"{i.value}\t{i.type}\t{i.feed}\t{i.note}" for i in indicators)
    return "\n".join(lines) + "\n"


def write_bundle(report: Report, bloom_path: Path, store_path: Path) -> None:
    """Write both halves of the bundle atomically.

    The ingestor may be running and a restart may land mid-write. A partially
    written store is not a parse error — it is a *shorter* sorted file, which
    loads cleanly and silently lacks whatever had not been flushed yet. Renaming
    into place means a reader sees either the old bundle or the new one.
    """
    if report.bloom is None:
        raise ValueError("report has no compiled filter")
    bloom_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(store_path, render_store(report.indicators).encode("utf-8"))
    _write_atomic(bloom_path, report.bloom.to_bytes())


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
