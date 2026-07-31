"""LLM backends for the reasoning step.

One narrow interface (``complete(system, user) -> str``) with three
implementations: Gemini, OpenAI, and ``NoLLM``. Keeping the interface this small
is what makes the analyst testable — the tests drive a stub through the same
seam, so no test needs a network or an API key.

``NoLLM`` is not a fake model. It reports ``available = False``, and the analyst
branches to a deterministic rule-based alert builder instead of asking it
anything. A fake that emitted plausible prose without a model behind it would be
the worst possible failure mode in a security tool: an alert that reads like
analysis but contains none.

Both providers are asked for JSON explicitly (``response_mime_type`` on Gemini,
``response_format`` on OpenAI) because parsing prose for structure is a
reliability tax paid on every request.
"""

from __future__ import annotations

import json
import random
import time
from typing import Protocol, runtime_checkable

from .config import Settings

# Transient failures worth retrying: rate limits, overload, gateway errors.
_RETRYABLE_MARKERS = (
    "429", "500", "502", "503", "504",
    "rate limit", "ratelimit", "overloaded", "unavailable",
    "deadline", "timeout", "temporarily",
)


class LLMError(RuntimeError):
    """Raised when a provider fails in a way the caller should surface."""


@runtime_checkable
class LLM(Protocol):
    provider: str
    model: str
    available: bool

    def complete(self, system: str, user: str) -> str: ...


def _is_retryable(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(marker in text for marker in _RETRYABLE_MARKERS)


def _with_retries(fn, attempts: int = 3, base_delay: float = 0.75):
    """Retry with exponential backoff and jitter.

    Jitter matters even for a single-user home server: without it, a retry storm
    after a rate limit re-arrives in lockstep and gets rate-limited again.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - provider SDKs raise broadly
            last = exc
            if attempt == attempts - 1 or not _is_retryable(exc):
                break
            # Retry jitter, not a secret: `random` is the right tool here.
            time.sleep(base_delay * (2**attempt) + random.uniform(0, 0.25))  # noqa: S311
    raise LLMError(f"LLM request failed after {attempts} attempt(s): {last}") from last


class NoLLM:
    """Placeholder used when no API key or SDK is present."""

    provider = "none"
    available = False

    def __init__(self, reason: str = "no LLM provider configured") -> None:
        self.model = "heuristic"
        self.reason = reason

    def complete(self, system: str, user: str) -> str:
        raise LLMError(
            f"No LLM is configured ({self.reason}). The analyst falls back to "
            f"rule-based alert generation; set GEMINI_API_KEY for model reasoning."
        )


class GeminiLLM:
    """Google Gemini via the google-generativeai SDK."""

    provider = "gemini"
    available = True

    def __init__(self, settings: Settings) -> None:
        try:
            import google.generativeai as genai
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError(
                "google-generativeai is not installed. Install engine/requirements.txt "
                "or set SENTINEL_LLM_PROVIDER=heuristic."
            ) from exc
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY (or GOOGLE_API_KEY) is not set")
        genai.configure(api_key=settings.gemini_api_key)
        self._genai = genai
        self.model = settings.llm_model
        self._settings = settings

    def complete(self, system: str, user: str) -> str:
        def call() -> str:
            model = self._genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system,
                generation_config={
                    "temperature": self._settings.llm_temperature,
                    "max_output_tokens": self._settings.llm_max_tokens,
                    "response_mime_type": "application/json",
                },
            )
            response = model.generate_content(
                user,
                request_options={"timeout": self._settings.llm_timeout},
            )
            text = getattr(response, "text", "") or ""
            if not text.strip():
                # A blocked or empty candidate is a real outcome worth reporting
                # rather than silently returning "{}" and producing an empty alert.
                feedback = getattr(response, "prompt_feedback", None)
                raise LLMError(f"Gemini returned no text (prompt_feedback={feedback})")
            return text

        return _with_retries(call)


class OpenAILLM:
    """OpenAI chat completions, kept as a second option for portability."""

    provider = "openai"
    available = True

    def __init__(self, settings: Settings) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError(
                "openai is not installed. Install engine/requirements.txt or set "
                "SENTINEL_LLM_PROVIDER=heuristic."
            ) from exc
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._client = OpenAI(api_key=settings.openai_api_key, timeout=settings.llm_timeout)
        self.model = settings.openai_model
        self._settings = settings

    def complete(self, system: str, user: str) -> str:
        def call() -> str:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                response_format={"type": "json_object"},
            )
            text = response.choices[0].message.content or ""
            if not text.strip():
                raise LLMError("OpenAI returned an empty completion")
            return text

        return _with_retries(call)


def get_llm(settings: Settings) -> LLM:
    """Build the configured LLM.

    ``auto`` prefers Gemini, then OpenAI, then degrades to ``NoLLM``. An explicit
    provider raises instead of degrading, so production cannot silently fall back
    to rule-based alerts.
    """
    provider = settings.llm_provider
    if provider == "heuristic":
        return NoLLM("SENTINEL_LLM_PROVIDER=heuristic")
    if provider == "gemini":
        return GeminiLLM(settings)
    if provider == "openai":
        return OpenAILLM(settings)

    last = ""
    if settings.gemini_api_key:
        try:
            return GeminiLLM(settings)
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
    else:
        last = "GEMINI_API_KEY unset"
    if settings.openai_api_key:
        try:
            return OpenAILLM(settings)
        except Exception as exc:  # noqa: BLE001
            last = f"{last}; {exc}" if last else str(exc)
    return NoLLM(last or "no API key found in the environment")


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response.

    Even with JSON mode requested, responses arrive wrapped in ```json fences or
    with a leading sentence often enough that parsing has to tolerate it. The
    brace-matching scan handles nesting and braces inside strings, which a regex
    for ``\\{.*\\}`` does not.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("empty model response")

    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2:
            body = lines[1:]
            if body and body[-1].strip().startswith("```"):
                body = body[:-1]
            text = "\n".join(body).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = text.find("{", start + 1)

    raise ValueError(f"no JSON object found in model response: {text[:200]!r}")
