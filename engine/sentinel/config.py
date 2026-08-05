"""Configuration for the Sentinel RAG engine.

Every knob is an environment variable so the same image runs unchanged on a
laptop, in docker-compose, and under systemd. Defaults are chosen so that
``python -m sentinel demo`` works on a clean checkout with no API keys and no
pip installs: the engine degrades to local embeddings, a local vector index, and
a deterministic heuristic analyst rather than failing.

Backend selection is three-valued (``auto`` / explicit / explicit) on purpose.
``auto`` picks the best backend that is actually importable, which is what you
want in development; naming a backend explicitly makes the process fail loudly
if that backend is missing, which is what you want in production. Silently
running a demo-grade embedder against real logs is the failure mode worth
engineering against.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

# Repository root, derived from this file's location: engine/sentinel/config.py
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name, str(default))
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, "1" if default else "0").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean, got {raw!r}")


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return default if not raw else Path(raw).expanduser()


def _env_list(name: str, default: str) -> list[str]:
    return [p.strip() for p in _env(name, default).split(",") if p.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable runtime configuration."""

    # --- paths -------------------------------------------------------------
    data_dir: Path = field(default_factory=lambda: _env_path("SENTINEL_DATA_DIR", _REPO_ROOT / "data"))
    events_path: Path = field(default_factory=lambda: _env_path("SENTINEL_EVENTS_PATH", _REPO_ROOT / "data" / "events.jsonl"))
    advisory_dir: Path = field(default_factory=lambda: _env_path("SENTINEL_ADVISORY_DIR", _REPO_ROOT / "data" / "advisories"))
    chroma_dir: Path = field(default_factory=lambda: _env_path("SENTINEL_CHROMA_DIR", _REPO_ROOT / "data" / "chroma"))
    index_dir: Path = field(default_factory=lambda: _env_path("SENTINEL_INDEX_DIR", _REPO_ROOT / "data" / "index"))
    audit_log: Path = field(default_factory=lambda: _env_path("SENTINEL_AUDIT_LOG", _REPO_ROOT / "data" / "audit.log"))

    # --- embeddings --------------------------------------------------------
    # multilingual-e5-large is the model the cross-lingual claim rests on: it is
    # trained so that a query and a passage in different languages land near each
    # other. e5 requires the "query: " / "passage: " prefixes, which
    # embeddings.py applies; dropping them measurably degrades retrieval.
    embedding_backend: str = field(default_factory=lambda: _env("SENTINEL_EMBEDDING_BACKEND", "auto"))
    embedding_model: str = field(default_factory=lambda: _env("SENTINEL_EMBEDDING_MODEL", "intfloat/multilingual-e5-large"))
    embedding_device: str = field(default_factory=lambda: _env("SENTINEL_EMBEDDING_DEVICE", "cpu"))
    embedding_batch_size: int = field(default_factory=lambda: _env_int("SENTINEL_EMBEDDING_BATCH", 16))
    hashing_dim: int = field(default_factory=lambda: _env_int("SENTINEL_HASHING_DIM", 512))

    # --- vector store ------------------------------------------------------
    vector_backend: str = field(default_factory=lambda: _env("SENTINEL_VECTOR_BACKEND", "auto"))
    collection_name: str = field(default_factory=lambda: _env("SENTINEL_COLLECTION", "sentinel_children"))

    # --- hierarchical chunking --------------------------------------------
    child_tokens: int = field(default_factory=lambda: _env_int("SENTINEL_CHILD_TOKENS", 400))
    child_overlap: int = field(default_factory=lambda: _env_int("SENTINEL_CHILD_OVERLAP", 60))
    parent_tokens: int = field(default_factory=lambda: _env_int("SENTINEL_PARENT_TOKENS", 2000))

    # --- retrieval ---------------------------------------------------------
    top_k: int = field(default_factory=lambda: _env_int("SENTINEL_TOP_K", 8))
    candidate_k: int = field(default_factory=lambda: _env_int("SENTINEL_CANDIDATE_K", 32))
    max_parents: int = field(default_factory=lambda: _env_int("SENTINEL_MAX_PARENTS", 5))
    min_similarity: float = field(default_factory=lambda: _env_float("SENTINEL_MIN_SIMILARITY", 0.0))
    # Guarantee at least this many hits per language when both are available, so
    # an English query cannot silently return an English-only context.
    per_language_floor: int = field(default_factory=lambda: _env_int("SENTINEL_PER_LANGUAGE_FLOOR", 2))

    # --- LLM ---------------------------------------------------------------
    llm_provider: str = field(default_factory=lambda: _env("SENTINEL_LLM_PROVIDER", "auto"))
    llm_model: str = field(default_factory=lambda: _env("SENTINEL_LLM_MODEL", "gemini-2.0-flash"))
    openai_model: str = field(default_factory=lambda: _env("SENTINEL_OPENAI_MODEL", "gpt-4o-mini"))
    llm_temperature: float = field(default_factory=lambda: _env_float("SENTINEL_LLM_TEMPERATURE", 0.1))
    llm_max_tokens: int = field(default_factory=lambda: _env_int("SENTINEL_LLM_MAX_TOKENS", 1600))
    # Bounds the prompt as well as the completion. Output caps stop a runaway
    # answer; this stops a long-form injection padded with attacker-chosen log
    # text from costing money per request and crowding the real evidence out of
    # the context window.
    llm_max_prompt_chars: int = field(default_factory=lambda: _env_int("SENTINEL_LLM_MAX_PROMPT_CHARS", 48000))
    llm_timeout: float = field(default_factory=lambda: _env_float("SENTINEL_LLM_TIMEOUT", 60.0))
    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY", _env("GOOGLE_API_KEY", "")))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY", ""))

    # --- local inference / air-gap (Phase 7) ------------------------------
    # none | ollama | openai-compatible. The second covers vLLM, llama.cpp's
    # llama-server, and LM Studio, so the runtime is a URL rather than a code
    # change. Both talk over urllib, so local inference needs no pip install —
    # which matters because the host this is for may have no way to do one.
    local_backend: str = field(default_factory=lambda: _env("SENTINEL_LOCAL_BACKEND", "none"))
    local_base_url: str = field(default_factory=lambda: _env("SENTINEL_LOCAL_BASE_URL", "http://127.0.0.1:11434"))
    local_model: str = field(default_factory=lambda: _env("SENTINEL_LOCAL_MODEL", "qwen2.5:7b"))
    # Generous by default: a 7B model on a laptop CPU is tens of seconds, and a
    # timeout that fires routinely turns into an escalation that routinely leaks.
    local_timeout: float = field(default_factory=lambda: _env_float("SENTINEL_LOCAL_TIMEOUT", 180.0))
    local_api_key: str = field(default_factory=lambda: _env("SENTINEL_LOCAL_API_KEY", ""))
    local_json_mode: bool = field(default_factory=lambda: _env_bool("SENTINEL_LOCAL_JSON_MODE", False))

    # Cloud escalation is opt-in and NAMED, never inferred. Someone who chose
    # local inference chose that their logs stay on the machine; a fallback that
    # fires silently on the first slow response inverts that guarantee at exactly
    # the moment nobody is watching.
    llm_fallback: str = field(default_factory=lambda: _env("SENTINEL_LLM_FALLBACK", "none"))

    # A control, not a preference: under air-gap no cloud client is constructed
    # at all, and naming one is a configuration error.
    air_gap: bool = field(default_factory=lambda: _env_bool("SENTINEL_AIR_GAP", False))

    # --- privacy -----------------------------------------------------------
    # Pseudonymise host-identifying data before it leaves the machine. This is
    # the technical control behind the project's privacy claim, so it defaults on.
    anonymize: bool = field(default_factory=lambda: _env_bool("SENTINEL_ANONYMIZE", True))
    anonymize_public_ips: bool = field(default_factory=lambda: _env_bool("SENTINEL_ANONYMIZE_PUBLIC_IPS", False))

    # --- Shadow Search (Phase 6) ------------------------------------------
    # Proactive correlation runs unattended, so its thresholds decide what a
    # sleeping operator is woken for. shadow_min_baseline is the important one:
    # below it the engine reports findings as unranked observations rather than
    # anomalies, because on a short history everything looks novel.
    shadow_window_hours: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_WINDOW_HOURS", 24))
    shadow_top_n: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_TOP_N", 5))
    shadow_min_baseline: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_MIN_BASELINE", 200))
    shadow_min_surprise: float = field(default_factory=lambda: _env_float("SENTINEL_SHADOW_MIN_SURPRISE", 4.0))
    shadow_min_count: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_MIN_COUNT", 1))
    shadow_min_similarity: float = field(default_factory=lambda: _env_float("SENTINEL_SHADOW_MIN_SIMILARITY", 0.05))
    shadow_k: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_K", 4))
    shadow_cooldown_hours: int = field(default_factory=lambda: _env_int("SENTINEL_SHADOW_COOLDOWN_HOURS", 24))

    # --- active response (Phase 4) ----------------------------------------
    response_mode: str = field(default_factory=lambda: _env("SENTINEL_RESPONSE_MODE", "dry-run"))
    response_min_score: int = field(default_factory=lambda: _env_int("SENTINEL_RESPONSE_MIN_SCORE", 90))
    # Addresses that must never be blocked, whatever the model says. Loopback and
    # RFC1918 are here because a false positive that firewalls the operator out
    # of their own server is worse than the attack it was defending against.
    response_allowlist: list[str] = field(
        default_factory=lambda: _env_list(
            "SENTINEL_RESPONSE_ALLOWLIST",
            "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fe80::/10",
        )
    )
    ufw_binary: str = field(default_factory=lambda: _env("SENTINEL_UFW_BINARY", "ufw"))

    # --- fleet hub (Phase 9) ----------------------------------------------
    # mTLS ingest from remote Go probes. Certificates come from scripts/sentinel-ca.sh.
    # Binds all interfaces by design: a hub that only listens on loopback cannot
    # receive from the fleet. Unlike the dashboard, this port is safe to expose —
    # it refuses every connection that does not present a CA-signed client
    # certificate, before any application data is read.
    hub_host: str = field(default_factory=lambda: _env("SENTINEL_HUB_HOST", "0.0.0.0"))  # noqa: S104
    hub_port: int = field(default_factory=lambda: _env_int("SENTINEL_HUB_PORT", 8443))
    hub_cert: str = field(default_factory=lambda: _env("SENTINEL_HUB_CERT", ""))
    hub_key: str = field(default_factory=lambda: _env("SENTINEL_HUB_KEY", ""))
    hub_ca: str = field(default_factory=lambda: _env("SENTINEL_HUB_CA", ""))
    # Hot-reloaded deny list of certificate fingerprints. Revoking one probe must
    # not require reissuing the fleet.
    hub_revocation_list: str = field(default_factory=lambda: _env("SENTINEL_HUB_REVOCATION_LIST", ""))
    # Optional second gate: even a CA-signed certificate must be named here.
    hub_allowed_probes: list[str] = field(default_factory=lambda: _env_list("SENTINEL_HUB_ALLOWED_PROBES", ""))
    # Off by default, and it should stay off. Enabling it lets a probe declare
    # which host its events describe, so any valid certificate becomes a licence
    # to file logs about any machine in the fleet.
    hub_trust_claimed_host: bool = field(default_factory=lambda: _env_bool("SENTINEL_HUB_TRUST_CLAIMED_HOST", False))
    # Fail closed on a host/certificate disagreement instead of rewriting. Off by
    # default: rejecting drops 100% of a probe's telemetry over a hostname
    # change, which hands an attacker a way to silence a probe. Rewriting
    # neutralises the claim without losing the event.
    hub_reject_host_mismatch: bool = field(default_factory=lambda: _env_bool("SENTINEL_HUB_REJECT_HOST_MISMATCH", False))

    # --- API ---------------------------------------------------------------
    api_host: str = field(default_factory=lambda: _env("SENTINEL_API_HOST", "127.0.0.1"))
    api_port: int = field(default_factory=lambda: _env_int("SENTINEL_API_PORT", 8000))
    api_token: str = field(default_factory=lambda: _env("SENTINEL_API_TOKEN", ""))
    # Rate limiting. LLM endpoints cost real money and real CPU, and an unmetered
    # /api/analyze is both a wallet drain and a way to keep the engine too busy to
    # notice events. Enforced in the shared router so BOTH the FastAPI app and the
    # stdlib server are covered — a control present in only one supported
    # deployment path is not a control.
    api_rate_limit_enabled: bool = field(default_factory=lambda: _env_bool("SENTINEL_API_RATE_LIMIT", True))
    api_rate_capacity: int = field(default_factory=lambda: _env_int("SENTINEL_API_RATE_CAPACITY", 240))
    api_rate_refill: float = field(default_factory=lambda: _env_float("SENTINEL_API_RATE_REFILL", 4.0))

    # CSRF. The dashboard is unauthenticated by default, so a page the operator
    # visits could otherwise issue a simple cross-origin POST to
    # /api/response/block. Requiring application/json forces a preflight that this
    # server (which sends no CORS headers at all) will never satisfy.
    api_require_json_content_type: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_API_REQUIRE_JSON", True))
    # Extra origins permitted to make mutating requests, beyond the dashboard's
    # own. Only needed behind a reverse proxy.
    api_allowed_origins: list[str] = field(
        default_factory=lambda: _env_list("SENTINEL_API_ALLOWED_ORIGINS", ""))

    max_events_in_memory: int = field(default_factory=lambda: _env_int("SENTINEL_MAX_EVENTS", 20000))

    def validate(self) -> None:
        """Fail fast on impossible combinations rather than at query time."""
        if self.embedding_backend not in {"auto", "e5", "hashing"}:
            raise ValueError(f"SENTINEL_EMBEDDING_BACKEND must be auto|e5|hashing, got {self.embedding_backend!r}")
        if self.vector_backend not in {"auto", "chroma", "local"}:
            raise ValueError(f"SENTINEL_VECTOR_BACKEND must be auto|chroma|local, got {self.vector_backend!r}")
        if self.llm_provider not in {"auto", "gemini", "openai", "ollama", "local", "heuristic"}:
            raise ValueError(
                f"SENTINEL_LLM_PROVIDER must be auto|gemini|openai|ollama|local|heuristic, "
                f"got {self.llm_provider!r}"
            )
        if self.local_backend not in {"none", "ollama", "openai-compatible"}:
            raise ValueError(
                f"SENTINEL_LOCAL_BACKEND must be none|ollama|openai-compatible, got {self.local_backend!r}"
            )
        if self.llm_fallback not in {"none", "gemini", "openai"}:
            raise ValueError(
                f"SENTINEL_LLM_FALLBACK must be none|gemini|openai, got {self.llm_fallback!r}"
            )
        if self.local_timeout <= 0:
            raise ValueError("SENTINEL_LOCAL_TIMEOUT must be positive")
        if not self.local_base_url.startswith(("http://", "https://")):
            raise ValueError(
                f"SENTINEL_LOCAL_BASE_URL must be an http(s) URL, got {self.local_base_url!r}"
            )

        # Air-gap is enforced here as configuration, and again in get_llm as a
        # control. Both, because a mode whose only enforcement is validation is a
        # mode that stops being enforced the moment validation is skipped.
        if self.air_gap:
            if self.llm_provider in {"gemini", "openai"}:
                raise ValueError(
                    f"SENTINEL_AIR_GAP=1 conflicts with SENTINEL_LLM_PROVIDER={self.llm_provider!r}. "
                    f"Air-gap means no egress; use ollama or local."
                )
            if self.llm_fallback != "none":
                raise ValueError(
                    f"SENTINEL_AIR_GAP=1 conflicts with SENTINEL_LLM_FALLBACK={self.llm_fallback!r}. "
                    f"Air-gap means no egress, including on failure."
                )
        if self.llm_fallback != "none" and self.local_backend == "none":
            raise ValueError(
                f"SENTINEL_LLM_FALLBACK={self.llm_fallback!r} needs a local primary to fall back "
                f"*from*; set SENTINEL_LOCAL_BACKEND, or set the provider directly."
            )
        if self.response_mode not in {"dry-run", "enforce", "disabled"}:
            raise ValueError(f"SENTINEL_RESPONSE_MODE must be dry-run|enforce|disabled, got {self.response_mode!r}")
        if self.child_tokens >= self.parent_tokens:
            raise ValueError(
                f"child_tokens ({self.child_tokens}) must be smaller than parent_tokens "
                f"({self.parent_tokens}): the point of hierarchical retrieval is a precise "
                f"child pointing at a broader parent"
            )
        if self.child_overlap >= self.child_tokens:
            raise ValueError(f"child_overlap ({self.child_overlap}) must be smaller than child_tokens ({self.child_tokens})")
        if self.shadow_window_hours <= 0:
            raise ValueError("SENTINEL_SHADOW_WINDOW_HOURS must be positive")
        if self.shadow_top_n <= 0:
            raise ValueError("SENTINEL_SHADOW_TOP_N must be positive")
        if self.shadow_min_surprise < 0:
            raise ValueError("SENTINEL_SHADOW_MIN_SURPRISE must not be negative")
        if self.llm_max_tokens <= 0 or self.llm_max_prompt_chars <= 0:
            raise ValueError("SENTINEL_LLM_MAX_TOKENS and _MAX_PROMPT_CHARS must be positive")
        if self.api_rate_capacity <= 0 or self.api_rate_refill <= 0:
            raise ValueError("SENTINEL_API_RATE_CAPACITY and _REFILL must be positive")
        if not 1 <= self.hub_port <= 65535:
            raise ValueError(f"SENTINEL_HUB_PORT must be 1-65535, got {self.hub_port}")
        if self.top_k <= 0 or self.candidate_k <= 0:
            raise ValueError("top_k and candidate_k must be positive")
        if self.candidate_k < self.top_k:
            raise ValueError(f"candidate_k ({self.candidate_k}) must be >= top_k ({self.top_k})")
        if self.llm_fallback == "gemini" and not self.gemini_api_key:
            raise ValueError("SENTINEL_LLM_FALLBACK=gemini but GEMINI_API_KEY is not set")
        if self.llm_fallback == "openai" and not self.openai_api_key:
            raise ValueError("SENTINEL_LLM_FALLBACK=openai but OPENAI_API_KEY is not set")
        if self.llm_provider == "gemini" and not self.gemini_api_key:
            raise ValueError("SENTINEL_LLM_PROVIDER=gemini but GEMINI_API_KEY is not set")
        if self.llm_provider == "openai" and not self.openai_api_key:
            raise ValueError("SENTINEL_LLM_PROVIDER=openai but OPENAI_API_KEY is not set")

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.chroma_dir, self.index_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)

    def redacted(self) -> dict[str, Any]:
        """Config as a dict with secrets masked, for /api/config and logs."""
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name.endswith(("_api_key", "_token")):
                value = f"set ({len(value)} chars)" if value else "unset"
            elif isinstance(value, Path):
                value = str(value)
            out[f.name] = value
        return out


_cached: Settings | None = None


def get_settings(refresh: bool = False) -> Settings:
    """Return the process-wide Settings, building it on first use.

    Cached because reading and validating the environment on every request is
    pure overhead; ``refresh=True`` exists for tests that monkeypatch os.environ.
    """
    global _cached
    if _cached is None or refresh:
        settings = Settings()
        settings.validate()
        _cached = settings
    return _cached


def repo_root() -> Path:
    return _REPO_ROOT
