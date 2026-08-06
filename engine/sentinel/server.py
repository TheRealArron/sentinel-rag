"""Dependency-free HTTP server.

This exists so ``python -m sentinel serve`` works on a bare Ubuntu box with no
pip install at all — the demo path in the README depends on it. It serves exactly
the same routes as the FastAPI app because both delegate to ``routes.Router``.

It is a real server, not a toy: threaded, with a request body size cap, a
bind-address default of localhost, and no directory traversal surface (the only
file it ever serves is the packaged dashboard). What it lacks versus uvicorn is
HTTP/1.1 keep-alive tuning, async I/O, and OpenAPI docs — which is why
``requirements.txt`` installs uvicorn and the README recommends it for anything
beyond a demo.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .engine import SentinelEngine
from .routes import Request, Router

# 1 MiB is far more than any endpoint needs; the cap stops a request body from
# being an easy way to exhaust memory.
MAX_BODY_BYTES = 1 << 20


class _Handler(BaseHTTPRequestHandler):
    server_version = "SentinelRAG/1.0"
    protocol_version = "HTTP/1.1"
    router: Router  # injected by make_server

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        # One tidy line per request on stderr instead of BaseHTTPRequestHandler's
        # default format, which interleaves badly with application logging.
        sys.stderr.write(f"[sentinel] {self.address_string()} {fmt % args}\n")

    def _read_body(self) -> tuple[dict[str, Any], str | None]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}, "invalid Content-Length header"
        if length <= 0:
            return {}, None
        if length > MAX_BODY_BYTES:
            return {}, f"request body exceeds {MAX_BODY_BYTES} bytes"
        raw = self.rfile.read(length)
        if not raw:
            return {}, None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}, "request body is not valid JSON"
        return (parsed if isinstance(parsed, dict) else {}), None

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        body: dict[str, Any] = {}
        if method == "POST":
            body, error = self._read_body()
            if error:
                self._send(400, json.dumps({"error": error}).encode("utf-8"))
                return

        request = Request(
            method=method,
            path=parsed.path,
            query=dict(parse_qsl(parsed.query, keep_blank_values=True)),
            body=body,
            headers={k.lower(): v for k, v in self.headers.items()},
            client=self.client_address[0] if self.client_address else "",
        )
        response = self.router.dispatch(request)
        self._send(response.status, response.rendered(), response.content_type)

    def _send(self, status: int, payload: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # No Access-Control-Allow-Origin, ever. Sending none is the strictest
        # possible CORS policy: a cross-origin page cannot read any response.
        # Combined with the application/json requirement on mutating routes, a
        # cross-origin request cannot be made to take effect either.
        # The dashboard inlines all of its CSS and JS, so a strict CSP costs
        # nothing here and removes the injected-script risk from rendering
        # attacker-controlled log text.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    # -- verbs -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - required name
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        request = Request(method="GET", path=parsed.path, headers={})
        response = self.router.dispatch(request)
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.rendered())))
        self.end_headers()


def make_server(engine: SentinelEngine | None = None, host: str = "", port: int = 0) -> ThreadingHTTPServer:
    engine = engine or SentinelEngine()
    host = host or engine.settings.api_host
    port = port or engine.settings.api_port

    router = Router(engine)
    handler = type("SentinelHandler", (_Handler,), {"router": router})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True

    # Trust the address we actually bound, not the one in settings.
    #
    # The CSRF allowlist is built from settings.api_port, but `serve --port N`
    # and `port=0` both bind somewhere else — so on any non-default port the
    # dashboard's own POSTs arrived with an Origin that was not on the list and
    # were refused. The block button 403'd against a control meant to stop
    # *other* sites, not this one. Binding is the only moment the real origin is
    # known, so the allowlist is completed here.
    bound_host, bound_port = server.server_address[:2]
    router.csrf.allowed_origins |= router.csrf.default_origins(str(bound_host), int(bound_port))
    return server


def serve(engine: SentinelEngine | None = None, host: str = "", port: int = 0) -> None:
    server = make_server(engine, host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"Sentinel RAG dashboard: http://{bound_host}:{bound_port}/", file=sys.stderr)
    print("(stdlib server — install engine/requirements.txt and use uvicorn for production)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()
