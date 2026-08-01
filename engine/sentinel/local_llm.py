"""Phase 7 — local inference, so nothing has to leave the host at all.

Two backends, both spoken over the standard library's HTTP client:

*   **Ollama** (``/api/chat``) — the easiest way to run Llama, Qwen, Gemma or
    Mistral on a home server. One binary, one ``ollama pull``.
*   **OpenAI-compatible** (``/v1/chat/completions``) — which is not one server but
    a family. **vLLM**, **llama.cpp's** ``llama-server``, **LM Studio**, **text-
    generation-webui** and Ollama's own compatibility endpoint all speak it. One
    client covers all of them, so "which local runtime" becomes a URL rather than
    a code change.

# Why urllib and not the openai package

Both backends here talk to ``localhost``. Pulling in an HTTP client library to
POST one JSON document to a socket on the same machine would make the *air-gap*
feature — the one whose entire point is self-sufficiency — depend on PyPI being
reachable to install it. ``urllib.request`` is in the standard library, so local
inference works on a machine that has never had network access.

The consequence is that this module is the only LLM backend that needs **no
third-party package at all**. On an air-gapped host, `pip install` may not be an
option, and that is exactly the host this is for.

# The timeout is the interesting parameter

A 7B model on a laptop CPU answers in 10-60 seconds. The same model on a busy
host, or a 70B model on the same hardware, may take ten minutes. The engine
therefore treats "too slow" as a distinct outcome from "failed", because they
have different correct responses: a failure means try something else, whereas
slowness on a local model usually means the hardware is simply not up to the
model, and the right answer is a smaller model rather than a different provider.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .llm import LLMError

# Ollama's default listen address.
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
# vLLM / llama-server / LM Studio conventions differ on port but not on path.
DEFAULT_OPENAI_COMPATIBLE_URL = "http://127.0.0.1:8000"


class LocalTimeout(LLMError):
    """The local model did not answer inside the budget.

    Distinct from a generic failure on purpose: a caller may reasonably treat a
    slow local model differently from a broken one.
    """


def _post_json(url: str, payload: dict[str, Any], timeout: float,
               headers: dict[str, str] | None = None) -> dict[str, Any]:
    """POST JSON, read JSON back. Raises LLMError or LocalTimeout."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed http(s) scheme, checked below
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    if request.type not in {"http", "https"}:
        raise LLMError(f"refusing non-HTTP local inference URL: {url!r}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read().decode("utf-8", errors="replace")
    except TimeoutError as exc:
        raise LocalTimeout(f"local inference exceeded {timeout:.0f}s at {url}") from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300] if exc.fp else ""
        raise LLMError(f"local inference HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        # socket.timeout arrives wrapped in URLError on some Python builds.
        if isinstance(exc.reason, TimeoutError) or "timed out" in str(exc.reason).lower():
            raise LocalTimeout(f"local inference exceeded {timeout:.0f}s at {url}") from exc
        raise LLMError(
            f"cannot reach local inference at {url}: {exc.reason}. "
            f"Is the server running? (ollama serve / vllm serve)"
        ) from exc
    except OSError as exc:
        raise LLMError(f"local inference transport error at {url}: {exc}") from exc

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"local inference returned non-JSON from {url}: {raw[:200]!r}") from exc
    if not isinstance(parsed, dict):
        raise LLMError(f"local inference returned {type(parsed).__name__}, expected an object")
    return parsed


def _get_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")  # noqa: S310
    if request.type not in {"http", "https"}:
        raise LLMError(f"refusing non-HTTP local inference URL: {url!r}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as exc:
        raise LLMError(f"cannot query {url}: {exc}") from exc


class OllamaLLM:
    """Local inference through Ollama's native chat API."""

    provider = "ollama"
    available = True

    def __init__(self, settings) -> None:
        self.base_url = settings.local_base_url.rstrip("/") or DEFAULT_OLLAMA_URL
        self.model = settings.local_model
        self.timeout = settings.local_timeout
        self._settings = settings

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Single-shot: the analyst wants one document, not a token stream.
            "stream": False,
            # Ollama's structured-output switch. Same reasoning as the cloud
            # providers: parsing prose for structure is a tax paid every request.
            "format": "json",
            "options": {
                "temperature": self._settings.llm_temperature,
                "num_predict": self._settings.llm_max_tokens,
            },
        }
        data = _post_json(f"{self.base_url}/api/chat", payload, self.timeout)
        content = (data.get("message") or {}).get("content", "")
        if not str(content).strip():
            raise LLMError(f"Ollama returned an empty message (model={self.model!r})")
        return str(content)

    def models(self) -> list[str]:
        """Installed models, for preflight. Empty on any error — this is
        diagnostics, and a failing probe must not take the engine down."""
        try:
            data = _get_json(f"{self.base_url}/api/tags", min(self.timeout, 10.0))
        except LLMError:
            return []
        return [str(m.get("name", "")) for m in data.get("models", []) if m.get("name")]

    def health(self) -> dict[str, Any]:
        models = self.models()
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "reachable": bool(models),
            "model": self.model,
            "model_installed": any(
                m == self.model or m.split(":")[0] == self.model.split(":")[0] for m in models
            ),
            "installed_models": models[:20],
        }


class OpenAICompatibleLLM:
    """Local inference through an OpenAI-compatible ``/v1/chat/completions``.

    Covers vLLM, llama.cpp's llama-server, LM Studio, and anything else that
    implements the same shape — the runtime becomes a URL rather than a code
    change.
    """

    provider = "local-openai"
    available = True

    def __init__(self, settings) -> None:
        self.base_url = (settings.local_base_url.rstrip("/") or DEFAULT_OPENAI_COMPATIBLE_URL)
        self.model = settings.local_model
        self.timeout = settings.local_timeout
        self._settings = settings

    def complete(self, system: str, user: str) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self._settings.llm_temperature,
            "max_tokens": self._settings.llm_max_tokens,
            "stream": False,
        }
        if self._settings.local_json_mode:
            # Not universal across local servers: vLLM supports it with a guided
            # decoding backend, llama-server's support depends on build. Off by
            # default, because a 400 here would fail every request, and
            # extract_json already tolerates fenced or prose-wrapped output.
            payload["response_format"] = {"type": "json_object"}

        headers = {}
        if self._settings.local_api_key:
            headers["Authorization"] = f"Bearer {self._settings.local_api_key}"

        data = _post_json(f"{self.base_url}/v1/chat/completions", payload, self.timeout, headers)
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"local server returned no choices (model={self.model!r})")
        content = (choices[0].get("message") or {}).get("content", "")
        if not str(content).strip():
            raise LLMError(f"local server returned an empty completion (model={self.model!r})")
        return str(content)

    def models(self) -> list[str]:
        try:
            data = _get_json(f"{self.base_url}/v1/models", min(self.timeout, 10.0))
        except LLMError:
            return []
        return [str(m.get("id", "")) for m in data.get("data", []) if m.get("id")]

    def health(self) -> dict[str, Any]:
        models = self.models()
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "reachable": bool(models),
            "model": self.model,
            "model_installed": self.model in models if models else False,
            "installed_models": models[:20],
        }


def build_local_llm(settings):
    """Construct the configured local backend, or None when disabled."""
    backend = settings.local_backend
    if backend in {"", "none"}:
        return None
    if backend == "ollama":
        return OllamaLLM(settings)
    if backend == "openai-compatible":
        return OpenAICompatibleLLM(settings)
    raise ValueError(
        f"SENTINEL_LOCAL_BACKEND must be none|ollama|openai-compatible, got {backend!r}"
    )
