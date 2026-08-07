"""Rate limiting and CSRF for the shared router.

Both adapters (FastAPI and the stdlib server) dispatch through ``routes.Router``,
so putting these here covers both — a FastAPI middleware would guard only one.

See docs/design/api-hardening.md for why not SlowAPI, and why a CORS allowlist
would have loosened rather than tightened this.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Hard cap on tracked clients. One bucket plus its key costs a few hundred bytes,
# so this bounds the limiter at low single-digit megabytes no matter how many
# addresses it is shown. See RateLimiter._evict for why a cap is needed rather
# than an idle sweep alone.
MAX_TRACKED_CLIENTS = 4096


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket, per client, with per-endpoint cost.

    A bucket, not a fixed window: bursts are normal (dashboard load), sustained
    load is not.
    """

    def __init__(self, capacity: int = 240, refill_per_second: float = 4.0) -> None:
        self.capacity = float(max(1, capacity))
        self.refill = max(0.01, refill_per_second)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def check(self, key: str, cost: int) -> tuple[bool, float]:
        """Spend ``cost`` tokens for ``key``. Returns (allowed, retry_after)."""
        now = self._now()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
                self._evict(now)
            bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.refill)
            bucket.updated = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            deficit = cost - bucket.tokens
            return False, deficit / self.refill

    def _evict(self, now: float) -> None:
        """Keep the client table under a hard cap.

        The key is a source address, so the number of entries is chosen by
        whoever is sending requests. An earlier version dropped only buckets that
        had been idle longer than ``capacity / refill`` — 60 seconds at the
        defaults — and described that as bounding growth. It does not. A caller
        rotating source addresses *faster* than the idle threshold leaves every
        bucket looking fresh, so nothing is ever evicted and the table grows for
        as long as the addresses keep changing.

        That is not a theoretical rotation budget. A single host with a routed
        IPv6 /64 can source from 2^64 distinct addresses, all of which reach this
        server and each of which mints a bucket. The control meant to protect the
        API became a way to exhaust its memory.

        So: sweep the genuinely idle first, and if that is not enough, evict by
        least-recently-used until the table is back under the cap.

        Evicting LRU rather than refusing new clients is deliberate, and it is
        the safe direction here. An attacker mid-flood is by definition
        *recently* used, so they are the last to be evicted and stay throttled;
        what gets dropped is idle clients, who were not being throttled anyway.
        Refusing to track new clients instead would let an attacker who filled
        the table lock every subsequent visitor out of rate limiting entirely.
        """
        if len(self._buckets) < MAX_TRACKED_CLIENTS:
            return

        idle_for_full = self.capacity / self.refill
        for key in [k for k, b in self._buckets.items() if now - b.updated > idle_for_full]:
            del self._buckets[key]
        if len(self._buckets) < MAX_TRACKED_CLIENTS:
            return

        # Everything is active. Drop the oldest tenth, so the O(n log n) sort is
        # amortised over the next n/10 insertions rather than run per request.
        ordered = sorted(self._buckets.items(), key=lambda kv: kv[1].updated)
        for key, _bucket in ordered[: max(1, len(ordered) // 10)]:
            del self._buckets[key]

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"tracked_clients": len(self._buckets),
                    "capacity": self.capacity, "refill_per_second": self.refill}


@dataclass
class CSRFPolicy:
    """Origin and content-type checks for state-changing requests."""

    allowed_origins: set[str] = field(default_factory=set)
    require_json: bool = True

    @staticmethod
    def _normalise(origin: str) -> str:
        parsed = urlparse(origin)
        if not parsed.scheme or not parsed.hostname:
            return ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme}://{parsed.hostname}:{port}"

    def default_origins(self, host: str, port: int) -> set[str]:
        """Origins the dashboard is legitimately served from."""
        names = {host, "localhost", "127.0.0.1", "[::1]"}
        if host in {"0.0.0.0", "::"}:  # noqa: S104 - comparison, not a bind
            names |= {"localhost", "127.0.0.1"}
        return {f"http://{n}:{port}" for n in names if n} | {f"https://{n}:{port}" for n in names if n}

    def check(self, method: str, content_type: str, origin: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        if method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            return True, ""

        # No Origin means the caller is not a browser page, so not a CSRF vector.
        if origin and self._normalise(origin) not in self.allowed_origins:
            return False, (
                f"cross-origin request from {origin!r} refused. The dashboard API is "
                f"same-origin only; use the API token from a non-browser client."
            )

        if self.require_json:
            base = (content_type or "").split(";")[0].strip().lower()
            if base != "application/json":
                # Forces a cross-origin preflight, which is never satisfied.
                return False, (
                    "mutating requests must send Content-Type: application/json "
                    "(this is what forces a cross-origin preflight, which is refused)"
                )
        return True, ""

