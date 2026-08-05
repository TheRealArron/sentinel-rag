"""Sentinel RAG — bilingual AI-powered SecOps engine.

    from sentinel import SentinelEngine

    engine = SentinelEngine()
    engine.index_all()
    print(engine.triage_top().to_json())

Submodules are import-light: ``import sentinel`` touches no filesystem and pulls
in no heavy dependency.
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
