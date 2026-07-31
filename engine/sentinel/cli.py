"""Command-line interface.

    python -m sentinel demo               end-to-end walkthrough, no setup needed
    python -m sentinel index --rebuild    (re)build the hierarchical index
    python -m sentinel search "SSH総当たり攻撃"
    python -m sentinel analyze --min-score 60
    python -m sentinel serve              dashboard + JSON API
    python -m sentinel stats
    python -m sentinel block 203.0.113.45 --score 92

Output is deliberately readable on a terminal rather than JSON-by-default: this is
the interface an operator uses while ssh'd into the home server. ``--json`` is
there for scripting.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from .config import Settings, get_settings
from .engine import SentinelEngine
from .schemas import Alert

DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEVERITY_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[0;31m",
    "warning": "\033[0;33m",
    "notice": "\033[0;32m",
    "info": "\033[0;36m",
}


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


class Printer:
    """Terminal output that degrades to plain text when piped."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.colour = _use_colour(self.stream)

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.colour else text

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def header(self, text: str) -> None:
        self.line()
        self.line(self._c(BOLD, text))
        self.line(self._c(DIM, "─" * min(len(text), 78)))

    def kv(self, key: str, value: object) -> None:
        self.line(f"  {self._c(DIM, key + ':'):<34} {value}")

    def severity(self, severity: str) -> str:
        return self._c(SEVERITY_COLOR.get(severity, ""), severity.upper())

    def dim(self, text: str) -> str:
        return self._c(DIM, text)

    def bold(self, text: str) -> str:
        return self._c(BOLD, text)


def print_alert(alert: Alert, printer: Printer, lang: str = "both") -> None:
    printer.header(f"[{printer.severity(alert.severity)}] {alert.title_en or alert.title_ja}")
    if lang in {"both", "ja"} and alert.title_ja:
        printer.line(f"  {printer.dim('JA')} {alert.title_ja}")
    printer.line()
    printer.kv("alert id", alert.alert_id)
    printer.kv("confidence", f"{alert.confidence:.0%}")
    printer.kv("provider / model", f"{alert.provider} / {alert.model}")
    printer.kv("pseudonymised", "yes" if alert.anonymized else "no")
    if alert.degraded:
        printer.kv("mode", "rule-based (no LLM configured)")

    if lang in {"both", "en"} and alert.summary_en:
        printer.header("Summary (EN)")
        printer.line(_wrap(alert.summary_en))
    if lang in {"both", "ja"} and alert.summary_ja:
        printer.header("概要 (JA)")
        printer.line(_wrap(alert.summary_ja))

    if alert.attack_narrative:
        printer.header("Attack narrative")
        printer.line(_wrap(alert.attack_narrative))

    if alert.recommended_actions:
        printer.header("Recommended actions")
        for i, action in enumerate(alert.recommended_actions, 1):
            printer.line(f"  {i:>2}. {action}")

    if alert.mitre:
        printer.header("MITRE ATT&CK")
        printer.line("  " + ", ".join(alert.mitre))

    if alert.citations:
        printer.header("Cited sources")
        for i, citation in enumerate(alert.citations, 1):
            printer.line(f"  [S{i}] ({citation.lang}) {citation.title}")
            printer.line(f"       {printer.dim(citation.source)}  similarity={citation.similarity:.3f}")

    if alert.indicators:
        printer.header("Indicators")
        for key, value in alert.indicators.items():
            if value not in ([], "", 0, None):
                printer.kv(key, value if not isinstance(value, list) else ", ".join(map(str, value)))

    if alert.notes:
        printer.header("Analyst notes")
        for note in alert.notes:
            wrapped = _wrap(note, indent="    ").lstrip()
            printer.line(f"  · {wrapped}")
    printer.line()


def _wrap(text: str, width: int = 92, indent: str = "  ") -> str:
    import textwrap

    paragraphs = text.split("\n")
    out = []
    for para in paragraphs:
        if not para.strip():
            out.append("")
            continue
        out.extend(textwrap.wrap(para, width=width, initial_indent=indent, subsequent_indent=indent) or [indent])
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_index(args, engine: SentinelEngine, printer: Printer) -> int:
    if args.advisories_only:
        stats = engine.indexer.index_advisories()
    else:
        stats = engine.index_all(rebuild=args.rebuild)
    if args.json:
        print(json.dumps({**stats.to_dict(), "index": engine.indexer.stats()}, ensure_ascii=False, indent=2))
        return 0
    printer.header("Index build")
    for key, value in stats.to_dict().items():
        printer.kv(key, value)
    printer.header("Index state")
    for key, value in engine.indexer.stats().items():
        printer.kv(key, value)
    return 0


def cmd_search(args, engine: SentinelEngine, printer: Printer) -> int:
    results = engine.search(
        args.query,
        k=args.k,
        languages=args.lang.split(",") if args.lang else None,
        doc_types=args.types.split(",") if args.types else None,
    )
    if args.json:
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
        return 0

    printer.header(f"{len(results)} result(s) for: {args.query}")
    printer.kv("embedder", f"{engine.embedder.name} (semantic={engine.embedder.semantic})")
    printer.kv("vector backend", engine.vectors.backend)
    printer.kv("language mix", engine.retriever.language_mix(results))
    if not results:
        printer.line()
        printer.line("  No hits. Has the index been built? Try: python -m sentinel index")
        return 0
    for i, item in enumerate(results, 1):
        parent = item.parent
        title = parent.title if parent else item.chunk.parent_id
        doc_type = parent.doc_type if parent else "unknown"
        meta = f"lang={item.chunk.lang} similarity={item.score:.3f} type={doc_type}"
        excerpt = item.chunk.text.strip().replace("\n", " ")
        printer.line()
        printer.line(f"  [S{i}] {printer.bold(title)}")
        printer.line(f"       {printer.dim(meta)}")
        printer.line(f"       {excerpt[:220]}{'…' if len(excerpt) > 220 else ''}")
    printer.line()
    return 0


def cmd_analyze(args, engine: SentinelEngine, printer: Printer) -> int:
    if args.question and not args.triage:
        alert = engine.analyze_question(args.question)
    else:
        alert = engine.triage_top(limit=args.limit, min_score=args.min_score, question=args.question or "")
    if args.json:
        print(alert.to_json())
        return 0
    print_alert(alert, printer, lang=args.lang)
    return 0


def cmd_serve(args, engine: SentinelEngine, printer: Printer) -> int:
    host = args.host or engine.settings.api_host
    port = args.port or engine.settings.api_port

    if not args.stdlib:
        try:
            import uvicorn

            from .api import create_app

            app = create_app(engine)
            printer.line(f"Sentinel RAG (uvicorn) on http://{host}:{port}/  — docs at /docs")
            uvicorn.run(app, host=host, port=port, log_level="info")
            return 0
        except (ImportError, RuntimeError) as exc:
            printer.line(f"{printer.dim('uvicorn/fastapi unavailable')} ({exc}); falling back to the stdlib server")

    from .server import serve

    serve(engine, host=host, port=port)
    return 0


def cmd_stats(args, engine: SentinelEngine, printer: Printer) -> int:
    stats = engine.stats()
    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2, default=str))
        return 0
    for section, values in stats.items():
        printer.header(section)
        if isinstance(values, dict):
            for key, value in values.items():
                printer.kv(key, value)
        else:
            printer.line(f"  {values}")
    return 0


def cmd_warm(args, engine: SentinelEngine, printer: Printer) -> int:
    info = engine.warm()
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0
    printer.header("Loaded components")
    for key, value in info.items():
        printer.kv(key, value)
    return 0


def cmd_block(args, engine: SentinelEngine, printer: Printer) -> int:
    action = engine.responder.block(args.ip, score=args.score, reason=args.reason, dry_run=args.dry_run or None)
    if args.json:
        print(json.dumps(action.to_dict(), ensure_ascii=False, indent=2))
        return 0 if action.allowed else 1
    printer.header(f"Response: block {args.ip}")
    for key, value in action.to_dict().items():
        printer.kv(key, value if not isinstance(value, list) else " ".join(value))
    return 0 if action.allowed else 1


def cmd_unblock(args, engine: SentinelEngine, printer: Printer) -> int:
    action = engine.responder.unblock(args.ip)
    if args.json:
        print(json.dumps(action.to_dict(), ensure_ascii=False, indent=2))
        return 0 if action.allowed else 1
    printer.header(f"Response: unblock {args.ip}")
    for key, value in action.to_dict().items():
        printer.kv(key, value if not isinstance(value, list) else " ".join(value))
    return 0 if action.allowed else 1


def cmd_demo(args, engine: SentinelEngine, printer: Printer) -> int:
    """End-to-end walkthrough that works on a clean checkout.

    If no ingestor output exists yet, the captured sample is copied in, so the
    demo does not require a Go toolchain to show the full pipeline.
    """
    settings = engine.settings
    sample = settings.data_dir / "samples" / "events.sample.jsonl"

    printer.header("1/4 — event source")
    if not settings.events_path.exists() or settings.events_path.stat().st_size == 0:
        if not sample.exists():
            printer.line(f"  No events at {settings.events_path} and no sample at {sample}.")
            printer.line("  Build the ingestor and run: make ingest")
            return 1
        settings.events_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sample, settings.events_path)
        printer.kv("copied sample", f"{sample} -> {settings.events_path}")
    engine.events.refresh()
    summary = engine.events.summary()
    printer.kv("events", summary["events"])
    printer.kv("correlated incidents", summary["incidents"])
    printer.kv("by severity", summary["by_severity"])

    printer.header("2/4 — backends")
    for key, value in engine.warm().items():
        printer.kv(key, value)

    printer.header("3/4 — hierarchical index")
    stats = engine.index_all(rebuild=args.rebuild)
    for key, value in stats.to_dict().items():
        printer.kv(key, value)

    printer.header("4/4 — bilingual retrieval check")
    for probe in ("SSH brute force from the internet", "SSH ブルートフォース 攻撃 対策"):
        results = engine.search(probe, k=4)
        printer.kv(f"query: {probe}", f"{len(results)} hits, languages={engine.retriever.language_mix(results)}")

    alert = engine.triage_top(limit=args.limit, min_score=args.min_score)
    print_alert(alert, printer, lang=args.lang)

    printer.line(printer.dim("  Next: python -m sentinel serve   (dashboard on http://127.0.0.1:8000/)"))
    printer.line()
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel",
        description="Sentinel RAG — bilingual AI-powered SecOps engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--lang", default="both", choices=["both", "en", "ja"], help="alert output language")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("index", help="build or refresh the hierarchical index")
    p.add_argument("--rebuild", action="store_true", help="drop the index first")
    p.add_argument("--advisories-only", action="store_true", help="skip log events")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("search", help="bilingual retrieval over the corpus")
    p.add_argument("query")
    p.add_argument("-k", type=int, default=None, help="number of parents to return")
    p.add_argument("--lang", dest="lang", default="", help="comma-separated: en,ja")
    p.add_argument("--types", default="", help="comma-separated: advisory,log_window")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("analyze", help="generate a bilingual alert")
    p.add_argument("--question", default="", help="natural-language question (EN or JA)")
    p.add_argument("--triage", action="store_true", help="analyse recent events even with a question")
    p.add_argument("--limit", type=int, default=25, help="max events to analyse")
    p.add_argument("--min-score", type=int, default=60, help="ignore events below this score")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("serve", help="run the dashboard and JSON API")
    p.add_argument("--host", default="")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--stdlib", action="store_true", help="force the dependency-free server")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("stats", help="show event, index and response statistics")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("warm", help="load the embedder, index and LLM, then report")
    p.set_defaults(func=cmd_warm)

    p = sub.add_parser("block", help="block a source address via UFW")
    p.add_argument("ip")
    p.add_argument("--score", type=int, required=True, help="deterministic ingestor score for the trigger")
    p.add_argument("--reason", default="operator request via CLI")
    p.add_argument("--dry-run", action="store_true", help="rehearse even in enforce mode")
    p.set_defaults(func=cmd_block)

    p = sub.add_parser("unblock", help="remove a UFW deny rule")
    p.add_argument("ip")
    p.set_defaults(func=cmd_unblock)

    p = sub.add_parser("demo", help="end-to-end walkthrough (no setup required)")
    p.add_argument("--rebuild", action="store_true", help="rebuild the index from scratch")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--min-score", type=int, default=40)
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    printer = Printer()

    # The subcommand's own --lang (search has none, analyze does) must not be
    # shadowed by the global one; argparse resolves this by declaration order, so
    # normalise here rather than relying on it.
    if not hasattr(args, "lang") or args.lang is None:
        args.lang = "both"

    try:
        engine = SentinelEngine(settings or get_settings())
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        return int(args.func(args, engine, printer) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
