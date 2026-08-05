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
        """Drop long-idle buckets. Unbounded growth is attacker-controlled, since
        the key is a source address."""
        if len(self._buckets) < 4096:
            return
        idle_for_full = self.capacity / self.refill
        stale = [k for k, b in self._buckets.items() if now - b.updated > idle_for_full]
        for key in stale:
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

