"""Framework-agnostic HTTP handlers.

The routing table and every handler live here as plain functions over plain
dicts. FastAPI (``api.py``) and the stdlib ``http.server`` fallback
(``server.py``) are both thin adapters over this module.

That split is not architecture for its own sake — it buys three things:

*   The dashboard works on a clean checkout with nothing pip-installed, because
    the stdlib adapter needs no FastAPI.
*   Every endpoint is unit-testable without a client, a server, or a socket.
*   Request handling has one implementation, so the two servers cannot drift.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import SentinelEngine, event_from_fingerprints
from .lang import LANG_EN, LANG_JA

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Endpoints that change state or spend money. When SENTINEL_API_TOKEN is set,
# these require it; reads stay open so the dashboard works without a token.
PROTECTED: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/index"),
        ("POST", "/api/shadow/run"),
        ("POST", "/api/response/block"),
        ("POST", "/api/response/unblock"),
        ("POST", "/api/analyze"),
    }
)

_IP_RE = re.compile(r"\A[0-9a-fA-F.:]{2,45}\Z")


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def q(self, key: str, default: str = "") -> str:
        return self.query.get(key, default)

    def q_int(self, key: str, default: int) -> int:
        raw = self.query.get(key)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            raise BadRequest(f"query parameter {key!r} must be an integer, got {raw!r}") from None

    def q_bool(self, key: str, default: bool = False) -> bool:
        raw = self.query.get(key)
        if raw is None or raw == "":
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def bearer(self) -> str:
        value = self.headers.get("authorization") or self.headers.get("Authorization") or ""
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return ""


@dataclass
class Response:
    status: int = 200
    payload: Any = None
    content_type: str = "application/json; charset=utf-8"
    body_text: str | None = None

    def rendered(self) -> bytes:
        if self.body_text is not None:
            return self.body_text.encode("utf-8")
        return json.dumps(self.payload, ensure_ascii=False).encode("utf-8")


class BadRequest(Exception):
    """400: the caller sent something invalid."""


class Unauthorized(Exception):
    """401: a protected endpoint was called without the API token."""


class NotFound(Exception):
    """404."""


Handler = Callable[["Router", Request], Response]


class Router:
    def __init__(self, engine: SentinelEngine) -> None:
        self.engine = engine
        self.routes: dict[tuple[str, str], Handler] = {
            ("GET", "/"): Router.dashboard,
            ("GET", "/index.html"): Router.dashboard,
            ("GET", "/api/health"): Router.health,
            ("GET", "/api/stats"): Router.stats,
            ("GET", "/api/config"): Router.config,
            ("GET", "/api/events"): Router.events,
            ("GET", "/api/events/summary"): Router.events_summary,
            ("GET", "/api/search"): Router.search,
            ("POST", "/api/search"): Router.search,
            ("POST", "/api/analyze"): Router.analyze,
            ("POST", "/api/index"): Router.index,
            ("GET", "/api/graph"): Router.graph,
            ("GET", "/api/graph.dot"): Router.graph_dot,
            ("GET", "/api/shadow"): Router.shadow_latest,
            ("POST", "/api/shadow/run"): Router.shadow_run,
            ("GET", "/api/response/status"): Router.response_status,
            ("GET", "/api/response/history"): Router.response_history,
            ("POST", "/api/response/block"): Router.response_block,
            ("POST", "/api/response/unblock"): Router.response_unblock,
        }

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, request: Request) -> Response:
        """Route a request, converting handler exceptions into HTTP responses."""
        key = (request.method.upper(), _normalise(request.path))
        handler = self.routes.get(key)
        if handler is None:
            # Distinguish "wrong method" from "no such path": a 405 tells the
            # caller their URL was right, which saves real debugging time.
            if any(p == key[1] for _m, p in self.routes):
                return Response(405, {"error": "method not allowed", "path": key[1]})
            return Response(404, {"error": "not found", "path": key[1]})

        try:
            self._authorise(key, request)
            return handler(self, request)
        except Unauthorized as exc:
            return Response(401, {"error": str(exc)})
        except BadRequest as exc:
            return Response(400, {"error": str(exc)})
        except NotFound as exc:
            return Response(404, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            # Return the exception type and message but never a traceback: stack
            # frames leak filesystem layout and package versions to a caller.
            return Response(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _authorise(self, key: tuple[str, str], request: Request) -> None:
        token = self.engine.settings.api_token
        if not token or key not in PROTECTED:
            return
        provided = request.bearer()
        # Constant-time comparison: a plain != on a secret is a timing oracle.
        import hmac

        if not provided or not hmac.compare_digest(provided, token):
            raise Unauthorized(
                "this endpoint requires the SENTINEL_API_TOKEN bearer token"
            )

    # -- handlers ----------------------------------------------------------

    def dashboard(self, request: Request) -> Response:
        path = STATIC_DIR / "dashboard.html"
        if not path.exists():
            raise NotFound("dashboard.html is missing from the package")
        return Response(
            200,
            content_type="text/html; charset=utf-8",
            body_text=path.read_text(encoding="utf-8"),
        )

    def health(self, request: Request) -> Response:
        return Response(200, self.engine.health())

    def stats(self, request: Request) -> Response:
        return Response(200, self.engine.stats())

    def config(self, request: Request) -> Response:
        return Response(200, self.engine.settings.redacted())

    def events(self, request: Request) -> Response:
        self.engine.events.refresh()
        limit = max(1, min(request.q_int("limit", 100), 2000))
        events = self.engine.events.query(
            limit=limit,
            min_score=request.q_int("min_score", 0),
            severity=request.q("severity"),
            category=request.q("category"),
            source_ip=request.q("source_ip"),
            rule=request.q("rule"),
            incidents_only=request.q_bool("incidents_only"),
            search=request.q("q"),
        )
        return Response(200, {"count": len(events), "events": [e.to_dict() for e in events]})

    def events_summary(self, request: Request) -> Response:
        self.engine.events.refresh()
        return Response(200, self.engine.events.summary())

    def search(self, request: Request) -> Response:
        query = (request.body.get("query") or request.q("q") or "").strip()
        if not query:
            raise BadRequest("a non-empty 'query' (POST body) or 'q' (query string) is required")
        k = _as_int(request.body.get("k"), request.q_int("k", self.engine.settings.top_k))
        languages = _as_str_list(request.body.get("languages")) or _split(request.q("languages"))
        doc_types = _as_str_list(request.body.get("doc_types")) or _split(request.q("doc_types"))

        for lang in languages:
            if lang not in {LANG_EN, LANG_JA}:
                raise BadRequest(f"unsupported language {lang!r}; expected 'en' or 'ja'")

        results = self.engine.search(
            query,
            k=k,
            languages=languages or None,
            doc_types=doc_types or None,
        )
        return Response(
            200,
            {
                "query": query,
                "count": len(results),
                "language_mix": self.engine.retriever.language_mix(results),
                "embedder": self.engine.embedder.name,
                "embedder_semantic": self.engine.embedder.semantic,
                "vector_backend": self.engine.vectors.backend,
                "results": [r.to_dict() for r in results],
            },
        )

    def analyze(self, request: Request) -> Response:
        """Analyse specific events, a question, or the top recent events."""
        body = request.body
        question = str(body.get("question") or "").strip()
        event_ids = _as_str_list(body.get("event_ids"))

        if event_ids:
            events = event_from_fingerprints(self.engine, event_ids)
            if not events:
                raise BadRequest(
                    "none of the supplied event_ids are in the event buffer; "
                    "they may have aged out or the fingerprints may be wrong"
                )
            alert = self.engine.analyze_events(events, question=question)
        elif question and not body.get("triage"):
            alert = self.engine.analyze_question(question)
        else:
            limit = _as_int(body.get("limit"), 25)
            min_score = _as_int(body.get("min_score"), 60)
            alert = self.engine.triage_top(limit=limit, min_score=min_score, question=question)
        return Response(200, alert.to_dict())

    def index(self, request: Request) -> Response:
        rebuild = bool(request.body.get("rebuild")) or request.q_bool("rebuild")
        stats = self.engine.index_all(rebuild=rebuild)
        return Response(200, {"rebuild": rebuild, **stats.to_dict(), "index": self.engine.indexer.stats()})

    def graph(self, request: Request) -> Response:
        """Entity graph, shapes, and optionally a blast radius from a seed."""
        graph = self.engine.attack_graph(
            limit=max(1, min(request.q_int("limit", 2000), 20000)),
            min_score=request.q_int("min_score", 0),
        )
        seed = request.q("seed")
        if seed and seed not in graph.nodes:
            raise BadRequest(
                f"unknown seed {seed!r}; expected an id like 'source_ip:203.0.113.45' "
                f"(see the 'nodes' array)"
            )
        return Response(200, graph.to_dict(seed=seed, max_hops=max(1, min(request.q_int("hops", 3), 8))))

    def graph_dot(self, request: Request) -> Response:
        """Graphviz DOT, for `curl … | dot -Tsvg > attack.svg`."""
        graph = self.engine.attack_graph(min_score=request.q_int("min_score", 0))
        return Response(200, content_type="text/vnd.graphviz; charset=utf-8",
                        body_text=graph.to_dot())

    def shadow_latest(self, request: Request) -> Response:
        """The most recent report, read from disk. Cheap: never runs a search.

        The dashboard polls this every few seconds; running a full baseline build
        on each poll would make the panel the most expensive thing in the system.
        """
        return Response(200, self.engine.shadow_latest())

    def shadow_run(self, request: Request) -> Response:
        """Execute a Shadow Search pass now. Protected: it costs retrieval and,
        with a provider configured, LLM calls."""
        as_of = None
        if request.body.get("as_of"):
            from datetime import datetime, timezone

            try:
                as_of = datetime.fromisoformat(str(request.body["as_of"]).replace("Z", "+00:00"))
            except ValueError:
                raise BadRequest("'as_of' must be an ISO timestamp") from None
            if as_of.tzinfo is None:
                as_of = as_of.replace(tzinfo=timezone.utc)

        report = self.engine.shadow_search(
            window_hours=_as_int(request.body.get("window_hours"), 0) or None,
            limit=_as_int(request.body.get("limit"), 0) or None,
            ignore_cooldown=bool(request.body.get("ignore_cooldown")),
            now=as_of,
        )
        return Response(200, report.to_dict())

    def response_status(self, request: Request) -> Response:
        return Response(200, self.engine.responder.status())

    def response_history(self, request: Request) -> Response:
        limit = max(1, min(request.q_int("limit", 100), 1000))
        return Response(200, {"actions": self.engine.responder.history(limit)})

    def response_block(self, request: Request) -> Response:
        ip = str(request.body.get("ip") or "").strip()
        if not ip or not _IP_RE.match(ip):
            raise BadRequest("'ip' must be a valid IPv4 or IPv6 address")
        score = _as_int(request.body.get("score"), -1)
        if score < 0:
            # The score must come from the ingestor's deterministic rules, so the
            # caller has to state it; defaulting it would let a block through with
            # no evidence behind it.
            raise BadRequest("'score' is required: pass the deterministic ingestor score for the triggering event")
        reason = str(request.body.get("reason") or "").strip() or "operator request via API"
        dry_run = request.body.get("dry_run")
        action = self.engine.responder.block(
            ip, score=score, reason=reason,
            dry_run=None if dry_run is None else bool(dry_run),
        )
        return Response(200 if action.allowed else 403, action.to_dict())

    def response_unblock(self, request: Request) -> Response:
        ip = str(request.body.get("ip") or "").strip()
        if not ip or not _IP_RE.match(ip):
            raise BadRequest("'ip' must be a valid IPv4 or IPv6 address")
        action = self.engine.responder.unblock(ip)
        return Response(200 if action.allowed else 400, action.to_dict())


def _normalise(path: str) -> str:
    path = path.split("?", 1)[0]
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def _as_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise BadRequest(f"expected an integer, got {value!r}") from None


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return _split(value)
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    raise BadRequest(f"expected a list of strings, got {type(value).__name__}")
