"""Shared fixtures.

Every fixture points the engine at a tmp_path and forces the dependency-free
backends. That is deliberate: the test suite must pass on a machine with nothing
pip-installed and no API keys, so CI tests the code rather than the network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ENGINE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = ENGINE_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from sentinel.config import Settings  # noqa: E402
from sentinel.engine import SentinelEngine  # noqa: E402
from sentinel.schemas import LogEvent  # noqa: E402

SAMPLE_EVENTS = REPO_ROOT / "data" / "samples" / "events.sample.jsonl"
SAMPLE_SYSLOG = REPO_ROOT / "data" / "samples" / "sample_syslog.log"
ADVISORY_DIR = REPO_ROOT / "data" / "advisories"


@pytest.fixture
def sample_event_dicts() -> list[dict]:
    assert SAMPLE_EVENTS.exists(), f"missing fixture {SAMPLE_EVENTS}"
    rows = []
    with SAMPLE_EVENTS.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


@pytest.fixture
def sample_events(sample_event_dicts) -> list[LogEvent]:
    return [LogEvent.from_dict(row) for row in sample_event_dicts]


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    """Isolated Settings with the zero-dependency backends pinned."""
    for name in (
        "SENTINEL_LLM_PROVIDER", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY",
        "SENTINEL_API_TOKEN", "SENTINEL_RESPONSE_MODE", "SENTINEL_ANONYMIZE",
    ):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINEL_EVENTS_PATH", str(tmp_path / "data" / "events.jsonl"))
    monkeypatch.setenv("SENTINEL_ADVISORY_DIR", str(ADVISORY_DIR))
    monkeypatch.setenv("SENTINEL_INDEX_DIR", str(tmp_path / "index"))
    monkeypatch.setenv("SENTINEL_CHROMA_DIR", str(tmp_path / "chroma"))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SENTINEL_EMBEDDING_BACKEND", "hashing")
    monkeypatch.setenv("SENTINEL_VECTOR_BACKEND", "local")
    monkeypatch.setenv("SENTINEL_LLM_PROVIDER", "heuristic")
    monkeypatch.setenv("SENTINEL_HASHING_DIM", "256")

    built = Settings()
    built.validate()
    return built


@pytest.fixture
def engine(settings) -> SentinelEngine:
    settings.events_path.parent.mkdir(parents=True, exist_ok=True)
    settings.events_path.write_bytes(SAMPLE_EVENTS.read_bytes())
    built = SentinelEngine(settings)
    built.events.refresh()
    return built


@pytest.fixture
def indexed_engine(engine) -> SentinelEngine:
    engine.index_all()
    return engine
