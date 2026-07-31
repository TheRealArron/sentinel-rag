"""Data contracts shared across the engine.

Plain dataclasses rather than pydantic models: the engine has to run with zero
third-party packages installed (see config.py), and these types are internal, so
the validation pydantic buys us is not worth making it a hard dependency. The
FastAPI layer serialises these with ``to_dict``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .lang import detect_language

# Severity ordering mirrors the Go ingestor's event.SeverityFor.
SEVERITY_ORDER = ["info", "notice", "warning", "high", "critical"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LogEvent:
    """One enriched event produced by the Go ingestor."""

    seq: int = 0
    raw_sha256: str = ""
    timestamp: str = ""
    ingested_at: str = ""
    host: str = ""
    facility: str = ""
    process: str = ""
    pid: int = 0
    message: str = ""
    category: str = "uncategorised"
    severity: str = "info"
    score: int = 0
    rule: str = ""
    outcome: str = ""
    mitre: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source_ip: str = ""
    source_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    user: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    sanitized: bool = False
    parse_ok: bool = False
    raw: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEvent:
        """Build from the ingestor's JSON, ignoring unknown keys.

        Tolerating unknown keys matters: the Go side can add a field and roll out
        before the Python side is redeployed without breaking ingestion.
        """
        known = set(cls.__dataclass_fields__)
        kwargs = {k: v for k, v in data.items() if k in known}
        # Defend against a hand-edited or truncated JSONL line producing a
        # wrong-typed field that would explode much later, in the dashboard.
        for key in ("seq", "pid", "score", "source_port", "dest_port"):
            if key in kwargs and not isinstance(kwargs[key], int):
                try:
                    kwargs[key] = int(kwargs[key])
                except (TypeError, ValueError):
                    kwargs[key] = 0
        for key in ("mitre", "tags"):
            if key in kwargs and not isinstance(kwargs[key], list):
                kwargs[key] = []
        if "fields" in kwargs and not isinstance(kwargs["fields"], dict):
            kwargs["fields"] = {}
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "raw_sha256": self.raw_sha256,
            "timestamp": self.timestamp,
            "ingested_at": self.ingested_at,
            "host": self.host,
            "facility": self.facility,
            "process": self.process,
            "pid": self.pid,
            "message": self.message,
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "rule": self.rule,
            "outcome": self.outcome,
            "mitre": list(self.mitre),
            "tags": list(self.tags),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "user": self.user,
            "fields": dict(self.fields),
            "sanitized": self.sanitized,
            "parse_ok": self.parse_ok,
        }

    @property
    def is_incident(self) -> bool:
        return self.process == "sentinel-correlator" or self.rule.startswith("correlated_")

    def as_text(self) -> str:
        """Render the event as the text that gets embedded.

        The rendering is not the raw log line. Bilingual tags, the MITRE ids, and
        the rule name are folded in so the vector carries the cross-lingual
        vocabulary that lets an English log line match a Japanese advisory.
        """
        parts = [f"[{self.severity.upper()} {self.score}] {self.timestamp} {self.host} {self.process}: {self.message}"]
        if self.rule:
            parts.append(f"detection: {self.rule} ({self.category})")
        if self.mitre:
            parts.append("MITRE ATT&CK: " + ", ".join(self.mitre))
        entity_bits = []
        if self.source_ip:
            entity_bits.append(f"source={self.source_ip}:{self.source_port or '-'}")
        if self.dest_ip:
            entity_bits.append(f"destination={self.dest_ip}:{self.dest_port or '-'}")
        if self.user:
            entity_bits.append(f"user={self.user}")
        if self.outcome:
            entity_bits.append(f"outcome={self.outcome}")
        if entity_bits:
            parts.append(" ".join(entity_bits))
        if self.tags:
            parts.append("tags: " + ", ".join(self.tags))
        return "\n".join(parts)


@dataclass
class Document:
    """A parent document: an advisory, or a window of correlated log events."""

    doc_id: str
    title: str
    text: str
    source: str = ""
    lang: str = ""
    doc_type: str = "advisory"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.lang:
            self.lang = detect_language(f"{self.title}\n{self.text}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "text": self.text,
            "source": self.source,
            "lang": self.lang,
            "doc_type": self.doc_type,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Document:
        return cls(
            doc_id=data["doc_id"],
            title=data.get("title", ""),
            text=data.get("text", ""),
            source=data.get("source", ""),
            lang=data.get("lang", ""),
            doc_type=data.get("doc_type", "advisory"),
            metadata=data.get("metadata", {}) or {},
        )


@dataclass
class Chunk:
    """A child chunk: small and precise, embedded and searched."""

    chunk_id: str
    parent_id: str
    text: str
    lang: str
    ordinal: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "parent_id": self.parent_id,
            "text": self.text,
            "lang": self.lang,
            "ordinal": self.ordinal,
            "metadata": dict(self.metadata),
        }


@dataclass
class Retrieved:
    """A child hit plus the parent context that will be handed to the LLM."""

    chunk: Chunk
    score: float
    parent: Document | None = None

    def to_dict(self) -> dict[str, Any]:
        # `lang` is the *parent's* language, because that is the document the
        # caller is being handed and the value the aggregate language_mix counts.
        # A child's detected language can legitimately differ — a log-window
        # chunk dense with Japanese bridge tags classifies as `ja` while its
        # parent is pinned `en` — so it is reported separately rather than
        # silently standing in for the document's language.
        return {
            "chunk_id": self.chunk.chunk_id,
            "parent_id": self.chunk.parent_id,
            "lang": self.parent.lang if self.parent else self.chunk.lang,
            "chunk_lang": self.chunk.lang,
            "similarity": round(self.score, 4),
            "matched_text": self.chunk.text,
            "parent_title": self.parent.title if self.parent else "",
            "parent_source": self.parent.source if self.parent else "",
            "doc_type": self.parent.doc_type if self.parent else "",
        }


@dataclass
class Citation:
    """A source the analyst actually used, for the alert footer."""

    doc_id: str
    title: str
    source: str
    lang: str
    similarity: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "source": self.source,
            "lang": self.lang,
            "similarity": round(self.similarity, 4),
        }


@dataclass
class Alert:
    """The engine's output: a bilingual, cited, actionable security alert."""

    alert_id: str
    created_at: str = field(default_factory=utcnow_iso)
    severity: str = "info"
    confidence: float = 0.0
    title_en: str = ""
    title_ja: str = ""
    summary_en: str = ""
    summary_ja: str = ""
    attack_narrative: str = ""
    mitre: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    indicators: dict[str, Any] = field(default_factory=dict)
    citations: list[Citation] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    anonymized: bool = False
    degraded: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "title": {"en": self.title_en, "ja": self.title_ja},
            "summary": {"en": self.summary_en, "ja": self.summary_ja},
            "attack_narrative": self.attack_narrative,
            "mitre": list(self.mitre),
            "recommended_actions": list(self.recommended_actions),
            "indicators": dict(self.indicators),
            "citations": [c.to_dict() for c in self.citations],
            "event_ids": list(self.event_ids),
            "model": self.model,
            "provider": self.provider,
            "anonymized": self.anonymized,
            "degraded": self.degraded,
            "notes": list(self.notes),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def iter_jsonl(path: Any, limit: int | None = None) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL file, skipping malformed lines.

    A partially written final line is normal when the Go ingestor is running with
    ``-follow``: it flushes on a timer, so a reader can catch it mid-line. That is
    a reason to skip the line, not to crash the API.
    """
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        return
    count = 0
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            yield obj
            count += 1
            if limit is not None and count >= limit:
                return
