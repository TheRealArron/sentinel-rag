"""Loading the bilingual threat-intelligence corpus and the log stream.

Advisories are markdown files with a small front-matter block. The front-matter
parser is hand-written rather than PyYAML-based for the same reason the rest of
the engine avoids hard dependencies, and because the schema here is a dozen flat
keys — a full YAML parser would be more attack surface (and more install weight)
than the job needs.

Log events are grouped into **windows** before indexing rather than indexed one
line at a time. A single syslog line makes a terrible parent document: it has no
context, so an LLM handed one line has nothing to reason from. Grouping by
(source address, time bucket) reconstructs the session — the scan, the failures,
the success, the sudo — which is the unit an analyst actually triages.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .lang import detect_language
from .schemas import Document, LogEvent, iter_jsonl

FRONT_MATTER_RE = re.compile(r"\A---\s*\n(?P<meta>.*?)\n---\s*\n?(?P<body>.*)\Z", re.DOTALL)
_LIST_INLINE_RE = re.compile(r"\A\[(?P<items>.*)\]\Z", re.DOTALL)


def parse_front_matter(text: str) -> tuple[dict[str, Any], str]:
    """Split a markdown file into (metadata, body).

    Understands ``key: value``, inline lists ``key: [a, b]``, and block lists:

        keywords:
          - brute force
          - ブルートフォース

    A file with no front matter is returned as ``({}, text)`` rather than an
    error, so dropping a plain markdown note into the advisory directory still
    works.
    """
    match = FRONT_MATTER_RE.match(text)
    if not match:
        return {}, text

    meta: dict[str, Any] = {}
    pending_key: str | None = None
    for raw_line in match.group("meta").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        stripped = raw_line.strip()

        if stripped.startswith("- "):
            if pending_key is None:
                continue
            meta.setdefault(pending_key, [])
            if isinstance(meta[pending_key], list):
                meta[pending_key].append(_coerce(stripped[2:].strip()))
            continue

        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if not value:
            # A bare "key:" opens a block list.
            pending_key = key
            meta[key] = []
            continue
        pending_key = None
        inline = _LIST_INLINE_RE.match(value)
        if inline:
            items = [_coerce(p.strip()) for p in inline.group("items").split(",") if p.strip()]
            meta[key] = items
        else:
            meta[key] = _coerce(value)
    return meta, match.group("body")


def _coerce(value: str) -> Any:
    """Strip quotes and convert obvious scalars, leaving everything else a string."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    low = value.lower()
    if low in {"true", "yes"}:
        return True
    if low in {"false", "no"}:
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


def load_advisory(path: Path) -> Document:
    """Load one advisory markdown file into a Document."""
    text = path.read_text(encoding="utf-8")
    meta, body = parse_front_matter(text)

    title = str(meta.get("title") or _first_heading(body) or path.stem)
    doc_id = str(meta.get("id") or f"advisory:{path.stem}")
    lang = str(meta.get("lang") or detect_language(f"{title}\n{body}"))

    keywords = meta.get("keywords") or []
    if isinstance(keywords, str):
        keywords = [k.strip() for k in keywords.split(",") if k.strip()]
    mitre = meta.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [m.strip() for m in mitre.split(",") if m.strip()]

    # Keywords are folded into the indexed text, not just kept as metadata. They
    # are the EN/JA lexical bridge: an advisory written in Japanese that lists
    # "brute force" among its keywords can be retrieved by an English query even
    # when the embedder is the non-semantic fallback.
    header_lines = [f"# {title}"]
    if keywords:
        header_lines.append("keywords: " + ", ".join(str(k) for k in keywords))
    if mitre:
        header_lines.append("MITRE ATT&CK: " + ", ".join(str(m) for m in mitre))
    if meta.get("cve"):
        header_lines.append(f"CVE: {meta['cve']}")

    return Document(
        doc_id=doc_id,
        title=title,
        text="\n".join(header_lines) + "\n\n" + body.strip(),
        source=str(meta.get("source") or path.name),
        lang=lang,
        doc_type="advisory",
        metadata={
            "publisher": str(meta.get("publisher") or ""),
            "published": str(meta.get("published") or ""),
            "severity": str(meta.get("severity") or ""),
            "cve": str(meta.get("cve") or ""),
            "keywords": ", ".join(str(k) for k in keywords),
            "mitre": ", ".join(str(m) for m in mitre),
            "path": str(path),
        },
    )


def _first_heading(body: str) -> str | None:
    for line in body.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return None


def load_advisories(advisory_dir: Path) -> list[Document]:
    """Load every ``*.md`` under ``advisory_dir``, sorted for deterministic ids."""
    advisory_dir = Path(advisory_dir)
    if not advisory_dir.exists():
        return []
    docs: list[Document] = []
    for path in sorted(advisory_dir.rglob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        try:
            docs.append(load_advisory(path))
        except (OSError, UnicodeDecodeError):
            continue
    return docs


# --------------------------------------------------------------------------- #
# log events
# --------------------------------------------------------------------------- #

def load_events(events_path: Path, limit: int | None = None) -> list[LogEvent]:
    """Read enriched events emitted by the Go ingestor."""
    return [LogEvent.from_dict(obj) for obj in iter_jsonl(events_path, limit=limit)]


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def group_events(events: Sequence[LogEvent], window_minutes: int = 10) -> list[list[LogEvent]]:
    """Group events into (source address, time bucket) windows.

    Events with no source address are grouped by host instead, so kernel and
    systemd messages still form coherent windows rather than one parent each.
    Ordering inside a window follows the ingestor's sequence number, which is log
    order — the narrative only reads correctly in that order.
    """
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")
    buckets: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    span = timedelta(minutes=window_minutes)
    for ev in events:
        ts = _parse_ts(ev.timestamp) or _parse_ts(ev.ingested_at)
        if ts is None:
            bucket = "unknown-time"
        else:
            epoch_minutes = int(ts.timestamp() // 60)
            bucket_start = epoch_minutes - (epoch_minutes % int(span.total_seconds() // 60))
            bucket = datetime.fromtimestamp(bucket_start * 60, tz=timezone.utc).isoformat()
        key = (ev.source_ip or f"host:{ev.host or 'unknown'}", bucket)
        buckets[key].append(ev)

    ordered = sorted(buckets.items(), key=lambda kv: (kv[0][1], kv[0][0]))
    return [sorted(group, key=lambda e: e.seq) for _key, group in ordered]


def events_to_document(group: Sequence[LogEvent]) -> Document:
    """Render one window of events as a parent document.

    The rendered document leads with a summary line because that is what the
    child chunks inherit as their title, and a child whose title already says
    "17 events, peak severity critical, source 203.0.113.45" retrieves far better
    than one titled with a bare timestamp.
    """
    if not group:
        raise ValueError("cannot build a document from an empty event group")

    first, last = group[0], group[-1]
    actor = first.source_ip or f"host:{first.host or 'unknown'}"
    peak = max(group, key=lambda e: e.score)
    categories = sorted({e.category for e in group if e.category})
    rules = sorted({e.rule for e in group if e.rule})
    mitre = sorted({m for e in group for m in e.mitre})
    users = sorted({e.user for e in group if e.user})
    tags = sorted({t for e in group for t in e.tags})
    incidents = [e for e in group if e.is_incident]

    title = (
        f"Log window {first.timestamp[:19]} .. {last.timestamp[:19]} — {actor} — "
        f"{len(group)} events, peak {peak.severity} ({peak.score})"
    )

    header = [
        f"# {title}",
        f"source: {actor}",
        f"hosts: {', '.join(sorted({e.host for e in group if e.host})) or 'unknown'}",
        f"categories: {', '.join(categories) or 'none'}",
        f"detections: {', '.join(rules) or 'none'}",
        f"MITRE ATT&CK: {', '.join(mitre) or 'none'}",
        f"users referenced: {', '.join(users) or 'none'}",
        f"tags: {', '.join(tags) or 'none'}",
        f"correlated incidents: {len(incidents)}",
        "",
        "## Events",
    ]
    body = "\n\n".join(ev.as_text() for ev in group)

    doc_id = f"events:{actor}:{first.timestamp[:16]}:{first.raw_sha256[:12]}"
    return Document(
        doc_id=doc_id,
        title=title,
        text="\n".join(header) + "\n" + body,
        source="sentinel-ingestor",
        # Log text is overwhelmingly English regardless of the operator's
        # language, and the Japanese tags in it are keywords rather than prose, so
        # pinning the language avoids mislabelling a window as Japanese just
        # because the bilingual tags tipped the ratio.
        lang="en",
        doc_type="log_window",
        metadata={
            "actor": actor,
            "event_count": len(group),
            "peak_score": peak.score,
            "peak_severity": peak.severity,
            "incident_count": len(incidents),
            "categories": ", ".join(categories),
            "rules": ", ".join(rules),
            "mitre": ", ".join(mitre),
            "first_seen": first.timestamp,
            "last_seen": last.timestamp,
            "hosts": ", ".join(sorted({e.host for e in group if e.host})),
        },
    )


def events_to_documents(events: Sequence[LogEvent], window_minutes: int = 10) -> list[Document]:
    return [events_to_document(g) for g in group_events(events, window_minutes) if g]


def iter_new_events(events_path: Path, seen: set[str]) -> Iterator[LogEvent]:
    """Yield events whose fingerprint has not been seen yet.

    Used by the incremental indexer and by the API's live refresh. Deduplicating
    on the Go side's SHA-256 of the raw line means re-reading a rotated file, or
    re-running the ingestor over the same input, cannot duplicate vectors.
    """
    for obj in iter_jsonl(events_path):
        fingerprint = obj.get("raw_sha256") or ""
        if fingerprint and fingerprint in seen:
            continue
        if fingerprint:
            seen.add(fingerprint)
        yield LogEvent.from_dict(obj)


def corpus_stats(advisory_dir: Path) -> dict[str, Any]:
    docs = load_advisories(advisory_dir)
    by_lang: dict[str, int] = {}
    for doc in docs:
        by_lang[doc.lang] = by_lang.get(doc.lang, 0) + 1
    return {"advisories": len(docs), "by_language": by_lang}


def unique(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
