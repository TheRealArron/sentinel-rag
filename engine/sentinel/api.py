"""FastAPI adapter.

Each path is registered individually rather than behind one catch-all so ``/docs``
is a real, browsable API reference, and every handler does nothing but translate
the framework's request into ``routes.Request`` and hand it to the shared router.

# Why the path list is generated from ROUTES

The *handlers* could not drift from the stdlib server, because both servers call
the same router. The *path list* could, and did: ``/api/shadow``,
``/api/shadow/run``, ``/api/graph``, ``/api/graph.dot`` and ``/index.html`` were
registered in routes.py, served correctly by the stdlib fallback, and returned 404
under uvicorn — which is what ``serve`` picks whenever FastAPI is installed, and
therefore what the Docker image and every documented production run actually use.
The dashboard polls two of them, so the Shadow Search and attack-graph panels were
dead in exactly the configuration meant for real use. Nothing caught it: adding an
endpoint was one edit there and one edit here, and no test installs FastAPI.

So the table is now the single source of truth. Registration walks ``ROUTES``,
which means a new endpoint is the ``@route`` decorator and nothing else, and a
path that exists in one server necessarily exists in the other. SUMMARIES only
adds prose for ``/docs``; a route missing from it still gets registered, and
tests/test_api.py asserts none is missing.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
    from fastapi.responses import Response as FastAPIResponse

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    FASTAPI_AVAILABLE = False

from .engine import SentinelEngine
from .routes import ROUTES, Request, Response, Route, Router

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
        client=fastapi_request.client.host if fastapi_request.client else "",
    )


def _to_fastapi_response(response: Response):
    if response.body_text is not None:
        # media_type from the router, not HTMLResponse's text/html: /api/graph.dot
        # answers with text/vnd.graphviz, and a browser told that DOT is HTML will
        # try to render it.
        return FastAPIResponse(
            content=response.body_text,
            status_code=response.status,
            media_type=response.content_type,
        )
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


# Prose for the generated OpenAPI page. Keyed by the same (method, path) tuples the
# router uses, so an endpoint renamed in routes.py loses its summary loudly (the
# parity test names it) rather than silently describing the wrong thing.
SUMMARIES: dict[tuple[str, str], str] = {
    ("GET", "/"): "Real-time threat dashboard",
    ("GET", "/index.html"): "Real-time threat dashboard (alias)",
    ("GET", "/api/health"): "Liveness probe (no model load)",
    ("GET", "/api/stats"): "Event, index, corpus and response statistics",
    ("GET", "/api/config"): "Effective configuration with secrets masked",
    ("GET", "/api/events"): "Filtered event feed, newest first",
    ("GET", "/api/events/summary"): "Aggregated event counts",
    ("GET", "/api/search"): "Bilingual retrieval over the corpus",
    ("POST", "/api/search"): "Bilingual retrieval (JSON body)",
    ("POST", "/api/analyze"): "Generate a bilingual, cited alert",
    ("POST", "/api/index"): "Index advisories and events",
    ("GET", "/api/graph"): "Attack-path graph, with an optional blast radius from a seed",
    ("GET", "/api/graph.dot"): "The same graph as Graphviz DOT",
    ("GET", "/api/shadow"): "Most recent Shadow Search report, read from disk",
    ("POST", "/api/shadow/run"): "Run a Shadow Search pass now",
    ("GET", "/api/response/status"): "Active-response mode and guard rails",
    ("GET", "/api/response/history"): "Audit trail of response decisions",
    ("POST", "/api/response/block"): "Block a source address via UFW",
    ("POST", "/api/response/unblock"): "Remove a UFW deny rule",
}

# Routes whose body is text rather than JSON. The response itself already carries
# the router's media type; this only teaches the schema generator about it, so
# /docs does not claim the dashboard is JSON.
#
# Paths, not response classes: this module has to import on a machine with no
# FastAPI — missing_summaries() below is asserted in exactly that environment —
# and a mapping to HTMLResponse would be evaluated at import time.
_HTML_ROUTES = frozenset({"/", "/index.html"})
_PLAIN_TEXT_ROUTES = frozenset({"/api/graph.dot"})


def _response_class(path: str) -> type:
    if path in _HTML_ROUTES:
        return HTMLResponse
    if path in _PLAIN_TEXT_ROUTES:
        return PlainTextResponse
    return JSONResponse


def missing_summaries() -> list[tuple[str, str]]:
    """Router routes with no /docs prose. Asserted empty by the test suite.

    Exposed as a function rather than checked at import so it can be asserted
    without FastAPI installed — which is the situation in CI, and the reason the
    drift this module used to have went unnoticed for so long.
    """
    return sorted(key for key in ROUTES if key not in SUMMARIES)


def _register(app: FastAPI, router: Router, spec: Route) -> None:
    """Attach one router route to the FastAPI app."""

    async def handler(request: FastAPIRequest):
        body: dict[str, Any] = {}
        if spec.method == "POST":
            body = await _json_body(request)
            if body.get("__invalid_json__"):
                return JSONResponse({"error": "request body is not valid JSON"}, status_code=400)
        return _to_fastapi_response(router.dispatch(_to_request(request, body)))

    # A distinct, readable name per route. FastAPI would otherwise derive the
    # OpenAPI operation id from the closure's name, which is the same for every
    # route here — so they are named explicitly, and a generated client gets
    # `get_api_shadow` rather than a numbered collision.
    path_name = "dashboard" if spec.path == "/" else spec.path
    name = re.sub(r"[^a-z0-9]+", "_", f"{spec.method} {path_name}".lower()).strip("_")
    handler.__name__ = name

    app.add_api_route(
        spec.path,
        handler,
        methods=[spec.method],
        summary=SUMMARIES.get((spec.method, spec.path), f"{spec.method} {spec.path}"),
        response_class=_response_class(spec.path),
        operation_id=name,
    )


def create_app(engine: SentinelEngine | None = None) -> FastAPI:
    if not FASTAPI_AVAILABLE:  # pragma: no cover
        raise RuntimeError(
            "fastapi is not installed. Install engine/requirements.txt, or run the "
            "dependency-free server with: python -m sentinel serve --stdlib"
        )

    engine = engine or SentinelEngine()
    router = Router(engine)
    app = FastAPI(title="Sentinel RAG", description=DESCRIPTION, version="1.0.0")

    # Deliberately NO CORSMiddleware. Installing one with an allowlist would
    # *loosen* the current policy, not tighten it: with no middleware FastAPI
    # sends no Access-Control-Allow-Origin at all, so no cross-origin page can
    # read any response. CSRF — which CORS does not address, because it governs
    # reading rather than sending — is handled in guard.py, in the shared router,
    # so the stdlib server is covered by the same rules.
    #
    # Rate limiting is there too, rather than SlowAPI, for the same reason: a
    # FastAPI-only limiter would leave `python -m sentinel serve --stdlib`
    # completely unmetered.

    # Sorted so /docs lists endpoints in a stable order across restarts.
    for key in sorted(ROUTES):
        _register(app, router, ROUTES[key])

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
