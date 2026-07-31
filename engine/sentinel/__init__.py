"""Sentinel RAG — bilingual AI-powered SecOps engine.

The Python half of the system: it indexes the Go ingestor's structured events
alongside Japanese (JPCERT/CC) and English (CVE) threat advisories, retrieves
across both languages, and produces cited bilingual security alerts.

Public surface:

    from sentinel import SentinelEngine, get_settings

    engine = SentinelEngine()
    engine.index_all()
    alert = engine.triage_top()
    print(alert.to_json())

Submodules are import-light on purpose — nothing here pulls in torch, chromadb, or
an HTTP framework at import time, so ``import sentinel`` stays fast and works on a
machine with no third-party packages installed.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "SentinelEngine",
    "Settings",
    "get_settings",
    "Alert",
    "LogEvent",
    "Document",
]


def __getattr__(name: str):
    """Lazily resolve the public names.

    Keeping these out of module scope means ``python -c 'import sentinel'`` does
    not construct settings or touch the filesystem, which matters because config
    validation raises on a bad environment and an import should not.
    """
    if name == "SentinelEngine":
        from .engine import SentinelEngine

        return SentinelEngine
    if name in {"Settings", "get_settings"}:
        from . import config

        return getattr(config, name)
    if name in {"Alert", "LogEvent", "Document"}:
        from . import schemas

        return getattr(schemas, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
