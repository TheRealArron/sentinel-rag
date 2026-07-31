"""FastAPI adapter.

Paths are declared explicitly rather than behind one catch-all so ``/docs`` is a
real, browsable API reference. Each handler does nothing but translate the
framework's request into ``routes.Request`` and hand it to the shared router, so
there is no logic here to drift from the stdlib server.
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest
    from fastapi.responses import HTMLResponse, JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    FASTAPI_AVAILABLE = False

from .engine import SentinelEngine
from .routes import Request, Response, Router

DESCRIPTION = """\
Sentinel RAG — bilingual (EN/JA) AI-powered SecOps engine.

A Go ingestor parses and scores raw Linux logs; this service embeds them alongside
Japanese (JPCERT/CC) and English (CVE) threat advisories, retrieves across both
languages with a hierarchical parent-document retriever, and produces cited,
bilingual security alerts.
"""


def _to_request(fastapi_request: FastAPIRequest, body: dict[str, Any] | None = None) -> Request:
    return Request(
        method=fastapi_request.method,
        path=fastapi_request.url.path,
        query=dict(fastapi_request.query_params.items()),
        body=body or {},
        headers={k.lower(): v for k, v in fastapi_request.headers.items()},
    )


def _to_fastapi_response(response: Response):
    if response.body_text is not None:
        return HTMLResponse(content=response.body_text, status_code=response.status)
    return JSONResponse(content=response.payload, status_code=response.status)


async def _json_body(fastapi_request: FastAPIRequest) -> dict[str, Any]:
    """Parse a JSON body, tolerating an empty one.

    An empty POST body is legitimate here: ``POST /api/analyze`` with no body means
    "triage whatever is most severe right now", which is the common case from the
    dashboard's one-click button.
    """
    raw = await fastapi_request.body()
    if not raw:
        return {}
    import json

    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"__invalid_json__": True}
    return parsed if isinstance(parsed, dict) else {}


def create_app(engine: SentinelEngine | None = None) -> FastAPI:
    if not FASTAPI_AVAILABLE:  # pragma: no cover
        raise RuntimeError(
            "fastapi is not installed. Install engine/requirements.txt, or run the "
            "dependency-free server with: python -m sentinel serve --stdlib"
        )

    engine = engine or SentinelEngine()
    router = Router(engine)
    app = FastAPI(title="Sentinel RAG", description=DESCRIPTION, version="1.0.0")

    async def handle(fastapi_request: FastAPIRequest, with_body: bool = False):
        body = await _json_body(fastapi_request) if with_body else {}
        if body.get("__invalid_json__"):
            return JSONResponse({"error": "request body is not valid JSON"}, status_code=400)
        return _to_fastapi_response(router.dispatch(_to_request(fastapi_request, body)))

    # --- reads -------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse, summary="Real-time threat dashboard")
    async def dashboard(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/health", summary="Liveness probe (no model load)")
    async def health(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/stats", summary="Event, index, corpus and response statistics")
    async def stats(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/config", summary="Effective configuration with secrets masked")
    async def config(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/events", summary="Filtered event feed, newest first")
    async def events(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/events/summary", summary="Aggregated event counts")
    async def events_summary(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/search", summary="Bilingual retrieval over the corpus")
    async def search_get(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/response/status", summary="Active-response mode and guard rails")
    async def response_status(request: FastAPIRequest):
        return await handle(request)

    @app.get("/api/response/history", summary="Audit trail of response decisions")
    async def response_history(request: FastAPIRequest):
        return await handle(request)

    # --- writes ------------------------------------------------------------
    @app.post("/api/search", summary="Bilingual retrieval (JSON body)")
    async def search_post(request: FastAPIRequest):
        return await handle(request, with_body=True)

    @app.post("/api/analyze", summary="Generate a bilingual, cited alert")
    async def analyze(request: FastAPIRequest):
        return await handle(request, with_body=True)

    @app.post("/api/index", summary="Index advisories and events")
    async def index(request: FastAPIRequest):
        return await handle(request, with_body=True)

    @app.post("/api/response/block", summary="Block a source address via UFW")
    async def response_block(request: FastAPIRequest):
        return await handle(request, with_body=True)

    @app.post("/api/response/unblock", summary="Remove a UFW deny rule")
    async def response_unblock(request: FastAPIRequest):
        return await handle(request, with_body=True)

    app.state.engine = engine
    app.state.router = router
    return app


# Module-level app for `uvicorn sentinel.api:app`. Guarded so that importing this
# module for create_app() on a machine without FastAPI does not explode.
if FASTAPI_AVAILABLE:  # pragma: no cover
    try:
        app = create_app()
    except Exception:  # noqa: BLE001 - a bad config should not break imports
        app = None
