"""Phase 9 fleet hub: mTLS ingest from remote Go probes.

Probes ship NDJSON over mutually authenticated TLS. The hub verifies who is
talking, decides whether it still trusts them, and appends to the event log.

Two things worth knowing before reading: the hub pins each event's ``host`` to the
client certificate's Common Name (mTLS proves who connected, not what the logs
describe), and revocation is a hot-reloaded fingerprint deny list.

See docs/design/transport.md.
"""

from __future__ import annotations

import json
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import Settings
from .schemas import utcnow_iso

# A single POST may stream indefinitely (that is the point), but one *line* is
# bounded by the same reasoning as the ingestor's own cap: a 500 MB line is a
# cheap denial of service against any line-oriented reader.
MAX_LINE_BYTES = 1 << 20
# Total bytes accepted in one request before the hub insists on a reconnect.
# Bounds the damage a single misbehaving probe can do in one connection.
MAX_REQUEST_BYTES = 256 << 20


class RevocationList:
    """Hot-reloaded deny list of certificate fingerprints.

    Revoking one probe is a single file write: no restart, no CA key, and no
    other certificate affected. See docs/design/transport.md for why not OCSP or
    a signed CRL.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = Path(path) if path else None
        self._fingerprints: set[str] = set()
        self._names: set[str] = set()
        self._mtime: float = -1.0
        self._lock = threading.Lock()

    @staticmethod
    def _normalise(value: str) -> str:
        return value.replace(":", "").replace(" ", "").lower()

    def reload_if_changed(self) -> None:
        if self.path is None:
            return
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            with self._lock:
                self._fingerprints.clear()
                self._names.clear()
                self._mtime = -1.0
            return
        if mtime == self._mtime:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            entries = data.get("revoked", []) if isinstance(data, dict) else []
        except (OSError, json.JSONDecodeError):
            # A malformed revocation file must NOT fail open. Keeping the previous
            # in-memory list means a corrupted write cannot silently re-admit a
            # revoked probe.
            return
        with self._lock:
            self._fingerprints = {
                self._normalise(str(e.get("fingerprint", ""))) for e in entries if e.get("fingerprint")
            }
            self._names = {str(e.get("name", "")) for e in entries if e.get("name")}
            self._mtime = mtime

    def is_revoked(self, fingerprint: str = "", name: str = "") -> bool:
        self.reload_if_changed()
        with self._lock:
            if fingerprint and self._normalise(fingerprint) in self._fingerprints:
                return True
            return bool(name and name in self._names)

    def summary(self) -> dict[str, Any]:
        self.reload_if_changed()
        with self._lock:
            return {
                "path": str(self.path) if self.path else None,
                "revoked": sorted(self._names),
                "count": len(self._fingerprints),
            }


@dataclass
class ProbeStats:
    """Per-probe accounting, so the fleet's health is observable."""

    name: str
    events: int = 0
    rejected: int = 0
    bytes_received: int = 0
    connections: int = 0
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "events": self.events,
            "rejected": self.rejected,
            "bytes_received": self.bytes_received,
            "connections": self.connections,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class FleetHub:
    """Accepts events from authenticated probes and appends them to the log."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.revocations = RevocationList(settings.hub_revocation_list)
        self.probes: dict[str, ProbeStats] = {}
        # Probes whose log host field disagrees with their certificate. Not fatal,
        # but worth an operator's attention: it is either a misconfiguration or
        # someone trying to file logs under another machine's name.
        self._mismatches: dict[str, int] = {}
        self._lock = threading.Lock()
        self._sink = Path(settings.events_path)
        self._sink.parent.mkdir(parents=True, exist_ok=True)

    # -- authorisation -----------------------------------------------------

    def authorise(self, common_name: str, fingerprint: str) -> tuple[bool, str]:
        """Decide whether this probe may submit. Returns (allowed, reason)."""
        if not common_name:
            return False, "client certificate has no Common Name"
        if self.revocations.is_revoked(fingerprint=fingerprint, name=common_name):
            return False, f"certificate for {common_name!r} is revoked"
        allow = self.settings.hub_allowed_probes
        if allow and common_name not in allow:
            return False, f"{common_name!r} is not in SENTINEL_HUB_ALLOWED_PROBES"
        return True, ""

    def accept_line(self, probe: str, line: str) -> tuple[bool, str]:
        """Validate and persist one NDJSON event from ``probe``.

        The host claim is neutralised rather than obeyed: ``host`` becomes the
        authenticated CN and the original is kept as ``_claimed_host``. Rejecting
        instead would let a hostname change silence a probe entirely.
        See docs/design/transport.md.
        """
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False, "not valid JSON"
        if not isinstance(event, dict):
            return False, "event is not an object"

        claimed = str(event.get("host", "") or "")
        mismatch = bool(claimed) and claimed != probe

        if mismatch and not self.settings.hub_trust_claimed_host:
            if self.settings.hub_reject_host_mismatch:
                return False, f"event claims host {claimed!r} but the certificate says {probe!r}"
            event["_claimed_host"] = claimed
            with self._lock:
                self._mismatches[probe] = self._mismatches.get(probe, 0) + 1

        # Stamped, not trusted-from-input: a probe cannot forge its own identity
        # into the record, and downstream consumers get an authenticated field.
        if not self.settings.hub_trust_claimed_host:
            event["host"] = probe
        event["_probe"] = probe
        event["_received_at"] = utcnow_iso()

        with self._lock, self._sink.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        return True, ""

    # -- accounting --------------------------------------------------------

    def note_connection(self, probe: str) -> ProbeStats:
        with self._lock:
            stats = self.probes.get(probe)
            if stats is None:
                stats = ProbeStats(name=probe)
                self.probes[probe] = stats
            stats.connections += 1
            stats.last_seen = utcnow_iso()
            return stats

    def note_batch(self, probe: str, accepted: int, rejected: int, size: int) -> None:
        with self._lock:
            stats = self.probes.setdefault(probe, ProbeStats(name=probe))
            stats.events += accepted
            stats.rejected += rejected
            stats.bytes_received += size
            stats.last_seen = utcnow_iso()

    def status(self) -> dict[str, Any]:
        with self._lock:
            probes = [p.to_dict() for p in self.probes.values()]
        with self._lock:
            mismatches = dict(self._mismatches)
        return {
            "probes": sorted(probes, key=lambda p: p["name"]),
            "host_mismatches": mismatches,
            "revocations": self.revocations.summary(),
            "sink": str(self._sink),
            "host_pinning": not self.settings.hub_trust_claimed_host,
            "allowed_probes": sorted(self.settings.hub_allowed_probes) or "any signed by the CA",
        }


def build_ssl_context(settings: Settings) -> ssl.SSLContext:
    """A TLS context that *requires* a client certificate signed by our CA."""
    for label, path in (("cert", settings.hub_cert), ("key", settings.hub_key), ("CA", settings.hub_ca)):
        if not path:
            raise ValueError(f"the hub needs a {label}: set SENTINEL_HUB_{label.upper()}")
        if not Path(path).exists():
            raise FileNotFoundError(f"hub {label} not found: {path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 is still widely deployed but 1.3 removes whole classes of
    # negotiation bug, and both ends here are ours, so there is no legacy peer to
    # accommodate.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # CERT_REQUIRED plus a CA file is the whole of "mutual": without it this is
    # ordinary one-way TLS and anyone may connect.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(settings.hub_ca))
    context.load_cert_chain(certfile=str(settings.hub_cert), keyfile=str(settings.hub_key))
    return context


def peer_identity(cert: dict[str, Any] | None) -> str:
    """Common Name from a peer certificate dict, or ''."""
    if not cert:
        return ""
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return ""


class _HubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SentinelHub/1.0"
    hub: FleetHub  # injected

    def log_message(self, fmt: str, *args: Any) -> None:
        import sys

        sys.stderr.write(f"[hub] {self.address_string()} {fmt % args}\n")

    # -- identity ----------------------------------------------------------

    def _identify(self) -> tuple[str, str]:
        """(common_name, sha256_fingerprint) of the authenticated peer."""
        sock = self.connection
        cert = sock.getpeercert() if hasattr(sock, "getpeercert") else None
        name = peer_identity(cert)
        fingerprint = ""
        try:
            der = sock.getpeercert(binary_form=True)
            if der:
                import hashlib

                fingerprint = hashlib.sha256(der).hexdigest()
        except (AttributeError, ValueError):
            pass
        return name, fingerprint

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if status >= 400:
            # An error is answered BEFORE the request body has been read, so the
            # unread bytes are still in the socket. On a keep-alive connection the
            # next request would then be parsed starting from the middle of the
            # previous body — which manifests as a stream of nonsense 400s and
            # took a live run to notice.
            #
            # The alternative, draining the body first, is worse here: it invites
            # a peer we have just refused to make us read an unbounded amount of
            # data. Refusing and hanging up is the correct shape.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    # -- verbs -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        name, fingerprint = self._identify()
        allowed, reason = self.hub.authorise(name, fingerprint)
        if not allowed:
            self._json(403, {"error": reason})
            return
        if self.path.rstrip("/") in {"", "/health"}:
            self._json(200, {"status": "ok", "probe": name})
        elif self.path.rstrip("/") == "/status":
            self._json(200, self.hub.status())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        name, fingerprint = self._identify()
        allowed, reason = self.hub.authorise(name, fingerprint)
        if not allowed:
            # Logged at the hub, because a revoked probe still trying to ship is
            # itself a finding worth seeing.
            self.log_message("REJECTED %s: %s", name or "<anonymous>", reason)
            self._json(403, {"error": reason})
            return

        if self.path.rstrip("/") != "/ingest":
            self._json(404, {"error": "not found"})
            return

        self.hub.note_connection(name)
        accepted = rejected = total = 0
        errors: list[str] = []

        for raw in self._iter_lines():
            total += len(raw)
            line = raw.strip()
            if not line:
                continue
            ok, why = self.hub.accept_line(name, line)
            if ok:
                accepted += 1
            else:
                rejected += 1
                if len(errors) < 5:
                    errors.append(why)

        self.hub.note_batch(name, accepted, rejected, total)
        if rejected:
            self.log_message("probe %s: %d accepted, %d rejected (%s)",
                             name, accepted, rejected, "; ".join(errors))
        self._json(200, {"accepted": accepted, "rejected": rejected, "errors": errors})

    def _iter_lines(self):
        """Yield decoded lines from a chunked or length-delimited body."""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            yield from self._iter_chunked()
            return
        try:
            remaining = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        remaining = min(remaining, MAX_REQUEST_BYTES)
        while remaining > 0:
            line = self.rfile.readline(min(MAX_LINE_BYTES, remaining) + 1)
            if not line:
                return
            remaining -= len(line)
            yield line.decode("utf-8", errors="replace")

    def _iter_chunked(self):
        """Streaming ingest: the probe holds the connection open and appends.

        This is what makes shipping *live* rather than batched — a probe with
        `-follow` writes each line as it happens and the hub sees it immediately,
        without either side buffering a file.
        """
        received = 0
        while True:
            size_line = self.rfile.readline(64)
            if not size_line:
                return
            try:
                size = int(size_line.split(b";")[0].strip(), 16)
            except ValueError:
                return
            if size == 0:
                self.rfile.readline()  # trailing CRLF
                return
            received += size
            if received > MAX_REQUEST_BYTES:
                return
            chunk = self.rfile.read(size)
            self.rfile.readline()  # CRLF after the chunk
            yield from chunk.decode("utf-8", errors="replace").splitlines()


def make_hub_server(settings: Settings, hub: FleetHub | None = None) -> ThreadingHTTPServer:
    hub = hub or FleetHub(settings)
    handler = type("SentinelHubHandler", (_HubHandler,), {"hub": hub})
    server = ThreadingHTTPServer((settings.hub_host, settings.hub_port), handler)
    server.daemon_threads = True
    context = build_ssl_context(settings)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.sentinel_hub = hub  # type: ignore[attr-defined]
    return server


def serve_hub(settings: Settings) -> None:
    import sys

    server = make_hub_server(settings)
    host, port = server.server_address[:2]
    print(f"Sentinel hub listening on https://{host}:{port}/ (mTLS required)", file=sys.stderr)
    print(f"  CA: {settings.hub_ca}", file=sys.stderr)
    print(f"  revocations: {server.sentinel_hub.revocations.summary()}", file=sys.stderr)  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()


__all__ = [
    "MAX_LINE_BYTES",
    "FleetHub",
    "RevocationList",
    "build_ssl_context",
    "make_hub_server",
    "peer_identity",
    "serve_hub",
]
