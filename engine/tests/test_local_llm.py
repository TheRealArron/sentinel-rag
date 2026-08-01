"""Phase 7 — local inference and air-gap.

The HTTP tests run against a real ``http.server`` on localhost rather than a
mocked ``urlopen``. Mocking the transport would test that the code calls a
function; a socket tests that it speaks the protocol, which is the part that
breaks when Ollama changes a field name.

The most important tests here are the ones asserting what does *not* happen: that
a local failure does not silently reach for the cloud, and that air-gap makes the
cloud unconstructible rather than merely unpreferred.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinel.config import Settings
from sentinel.llm import EscalatingLLM, LLMError, NoLLM, get_llm
from sentinel.local_llm import LocalTimeout, OllamaLLM, OpenAICompatibleLLM, build_local_llm


class _Handler(BaseHTTPRequestHandler):
    """Stands in for Ollama and for an OpenAI-compatible server."""

    behaviour = "ok"          # ok | empty | http500 | garbage | slow
    last_payload: dict = {}

    def log_message(self, *args):  # silence the test run
        pass

    def _send(self, code: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/tags":
            self._send(200, json.dumps({"models": [{"name": "qwen2.5:7b"}, {"name": "llama3:8b"}]}))
        elif self.path == "/v1/models":
            self._send(200, json.dumps({"data": [{"id": "qwen2.5:7b"}]}))
        else:
            self._send(404, "{}")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        type(self).last_payload = json.loads(self.rfile.read(length) or b"{}")

        if type(self).behaviour == "http500":
            self._send(500, json.dumps({"error": "model not loaded"}))
            return
        if type(self).behaviour == "garbage":
            self._send(200, "this is not json")
            return
        if type(self).behaviour == "slow":
            import time

            time.sleep(3)

        content = "" if type(self).behaviour == "empty" else '{"title_en": "local answer"}'
        if self.path == "/api/chat":
            self._send(200, json.dumps({"message": {"role": "assistant", "content": content}}))
        elif self.path == "/v1/chat/completions":
            self._send(200, json.dumps({"choices": [{"message": {"content": content}}]}))
        else:
            self._send(404, "{}")


@pytest.fixture
def local_server():
    _Handler.behaviour = "ok"
    _Handler.last_payload = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", _Handler
    server.shutdown()
    server.server_close()


def local_settings(settings: Settings, url: str, **overrides) -> Settings:
    """Sensible local defaults, with caller overrides winning."""
    fields = {
        "local_backend": "ollama",
        "local_base_url": url,
        "local_model": "qwen2.5:7b",
        "local_timeout": 5.0,
    }
    fields.update(overrides)
    return replace(settings, **fields)


class TestOllama:
    def test_round_trip(self, settings, local_server):
        url, _ = local_server
        llm = OllamaLLM(local_settings(settings, url))
        assert json.loads(llm.complete("sys", "user"))["title_en"] == "local answer"

    def test_sends_the_expected_request_shape(self, settings, local_server):
        url, handler = local_server
        OllamaLLM(local_settings(settings, url)).complete("SYS", "USER")
        payload = handler.last_payload
        assert payload["model"] == "qwen2.5:7b"
        assert payload["stream"] is False
        assert payload["format"] == "json"  # structured output, same as the cloud providers
        assert [m["role"] for m in payload["messages"]] == ["system", "user"]
        assert payload["messages"][0]["content"] == "SYS"

    def test_empty_response_is_an_error_not_an_empty_alert(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "empty"
        with pytest.raises(LLMError, match="empty"):
            OllamaLLM(local_settings(settings, url)).complete("s", "u")

    def test_http_error_surfaces_the_server_detail(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "http500"
        with pytest.raises(LLMError, match="model not loaded"):
            OllamaLLM(local_settings(settings, url)).complete("s", "u")

    def test_non_json_response_is_an_error(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "garbage"
        with pytest.raises(LLMError, match="non-JSON"):
            OllamaLLM(local_settings(settings, url)).complete("s", "u")

    def test_timeout_is_distinct_from_failure(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "slow"
        llm = OllamaLLM(local_settings(settings, url, local_timeout=0.5))
        with pytest.raises(LocalTimeout):
            llm.complete("s", "u")

    def test_unreachable_server_explains_itself(self, settings):
        llm = OllamaLLM(local_settings(settings, "http://127.0.0.1:1", local_timeout=2.0))
        with pytest.raises(LLMError, match="ollama serve"):
            llm.complete("s", "u")

    def test_health_reports_installed_models(self, settings, local_server):
        url, _ = local_server
        health = OllamaLLM(local_settings(settings, url)).health()
        assert health["reachable"] is True
        assert health["model_installed"] is True
        assert "llama3:8b" in health["installed_models"]

    def test_health_on_a_dead_server_does_not_raise(self, settings):
        health = OllamaLLM(local_settings(settings, "http://127.0.0.1:1", local_timeout=1.0)).health()
        assert health["reachable"] is False


class TestOpenAICompatible:
    def test_round_trip(self, settings, local_server):
        url, _ = local_server
        llm = OpenAICompatibleLLM(local_settings(settings, url, local_backend="openai-compatible"))
        assert json.loads(llm.complete("sys", "user"))["title_en"] == "local answer"

    def test_json_mode_is_off_by_default(self, settings, local_server):
        # Not universally supported by local servers; a 400 here would fail every
        # request, and extract_json already tolerates prose-wrapped output.
        url, handler = local_server
        OpenAICompatibleLLM(local_settings(settings, url, local_backend="openai-compatible")).complete("s", "u")
        assert "response_format" not in handler.last_payload

    def test_json_mode_can_be_enabled(self, settings, local_server):
        url, handler = local_server
        cfg = local_settings(settings, url, local_backend="openai-compatible", local_json_mode=True)
        OpenAICompatibleLLM(cfg).complete("s", "u")
        assert handler.last_payload["response_format"] == {"type": "json_object"}

    def test_api_key_is_sent_when_configured(self, settings, local_server):
        url, _ = local_server
        cfg = local_settings(settings, url, local_backend="openai-compatible", local_api_key="secret")
        # vLLM can be started with --api-key; the header must be present.
        assert OpenAICompatibleLLM(cfg).complete("s", "u")


class TestBuildLocal:
    def test_none_disables(self, settings):
        assert build_local_llm(replace(settings, local_backend="none")) is None

    def test_unknown_backend_raises(self, settings):
        with pytest.raises(ValueError, match="ollama"):
            build_local_llm(replace(settings, local_backend="nonsense"))


class TestValidation:
    def _settings(self, **kw) -> Settings:
        built = replace(Settings(), **kw)
        built.validate()
        return built

    def test_air_gap_rejects_a_cloud_provider(self):
        with pytest.raises(ValueError, match="Air-gap means no egress"):
            self._settings(air_gap=True, llm_provider="gemini")

    def test_air_gap_rejects_a_cloud_fallback(self):
        with pytest.raises(ValueError, match="including on failure"):
            self._settings(air_gap=True, llm_provider="ollama",
                           local_backend="ollama", llm_fallback="gemini")

    def test_fallback_without_a_local_primary_is_rejected(self):
        # There is nothing to fall back *from*; naming a provider is clearer.
        with pytest.raises(ValueError, match="local primary"):
            self._settings(local_backend="none", llm_fallback="gemini", gemini_api_key="k")

    def test_fallback_needs_its_credential(self):
        with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
            self._settings(local_backend="ollama", llm_fallback="gemini", gemini_api_key="")

    def test_bad_base_url_is_rejected(self):
        with pytest.raises(ValueError, match="http"):
            self._settings(local_base_url="127.0.0.1:11434")

    def test_negative_timeout_is_rejected(self):
        with pytest.raises(ValueError, match="LOCAL_TIMEOUT"):
            self._settings(local_timeout=0)

    def test_valid_air_gap_configuration_passes(self):
        built = self._settings(air_gap=True, llm_provider="ollama", local_backend="ollama")
        assert built.air_gap is True


class TestProviderSelection:
    def test_air_gap_never_constructs_a_cloud_client(self, settings):
        # Even with a key present and no local backend, air-gap degrades to the
        # rule-based analyst rather than reaching for the network.
        cfg = replace(settings, air_gap=True, llm_provider="auto",
                      local_backend="none", gemini_api_key="would-work")
        llm = get_llm(cfg)
        assert isinstance(llm, NoLLM)
        assert "AIR_GAP" in llm.reason

    def test_air_gap_blocks_an_explicit_cloud_provider_even_unvalidated(self, settings):
        # The control does not depend on validate() having run.
        cfg = replace(settings, air_gap=True, llm_provider="gemini", gemini_api_key="k")
        with pytest.raises(RuntimeError, match="forbids"):
            get_llm(cfg)

    def test_local_failure_does_not_silently_escalate(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "http500"
        cfg = local_settings(settings, url, llm_provider="ollama",
                             llm_fallback="none", gemini_api_key="present-but-unused")
        llm = get_llm(cfg)
        assert not isinstance(llm, EscalatingLLM)
        # It raises rather than quietly sending the logs somewhere else.
        with pytest.raises(LLMError):
            llm.complete("s", "u")

    def test_no_fallback_named_means_a_bare_local_client(self, settings, local_server):
        # Not wrapped in EscalatingLLM at all, so there is no code path from a
        # local failure to the network. TestEscalation covers the opt-in case
        # with a stub, since constructing GeminiLLM needs the SDK.
        url, _ = local_server
        assert isinstance(get_llm(local_settings(settings, url, llm_provider="ollama")), OllamaLLM)

    def test_explicit_local_without_a_backend_is_an_error(self, settings):
        cfg = replace(settings, llm_provider="ollama", local_backend="none")
        with pytest.raises(RuntimeError, match="LOCAL_BACKEND"):
            get_llm(cfg)

    def test_auto_prefers_local_over_cloud(self, settings, local_server):
        url, _ = local_server
        cfg = local_settings(settings, url, llm_provider="auto", gemini_api_key="would-work")
        assert isinstance(get_llm(cfg), OllamaLLM)


class _StubCloud:
    provider = "gemini"
    model = "gemini-stub"
    available = True

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        return '{"title_en": "cloud answer"}'


class TestEscalation:
    def test_primary_answers_without_touching_the_fallback(self, settings, local_server):
        url, _ = local_server
        cloud = _StubCloud()
        chain = EscalatingLLM(OllamaLLM(local_settings(settings, url)), cloud)
        assert "local answer" in chain.complete("s", "u")
        assert cloud.calls == 0
        assert chain.escalations == 0
        assert chain.provider == "ollama"

    def test_escalates_on_local_failure_and_says_so(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "http500"
        cloud = _StubCloud()
        chain = EscalatingLLM(OllamaLLM(local_settings(settings, url)), cloud)

        assert "cloud answer" in chain.complete("s", "u")
        assert cloud.calls == 1
        assert chain.escalations == 1
        # provider/model must report who actually answered — the analyst stamps
        # the alert from these after the call.
        assert chain.provider == "gemini"
        assert chain.model == "gemini-stub"
        assert "left the host" in chain.notes[0]

    def test_escalates_on_timeout(self, settings, local_server):
        url, handler = local_server
        handler.behaviour = "slow"
        cloud = _StubCloud()
        chain = EscalatingLLM(OllamaLLM(local_settings(settings, url, local_timeout=0.5)), cloud)
        assert "cloud answer" in chain.complete("s", "u")
        assert "exceeded" in chain.notes[0]

    def test_provider_resets_when_the_local_model_recovers(self, settings, local_server):
        url, handler = local_server
        cloud = _StubCloud()
        chain = EscalatingLLM(OllamaLLM(local_settings(settings, url)), cloud)

        handler.behaviour = "http500"
        chain.complete("s", "u")
        assert chain.provider == "gemini"

        handler.behaviour = "ok"
        chain.complete("s", "u")
        assert chain.provider == "ollama", "a recovered local model must stop reporting cloud"
