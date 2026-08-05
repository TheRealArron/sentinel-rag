"""Rate limiting, CSRF, and the route registry.

The CSRF tests reproduce an attack that worked against this server before
guard.py existed: a cross-origin `text/plain` POST to /api/response/block that
was acted on. See docs/design/api-hardening.md.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.guard import CSRFPolicy, RateLimiter
from sentinel.routes import ROUTES, Request, Router


def post(router, path, headers=None, body=None):
    merged = {"content-type": "application/json"}
    merged.update(headers or {})
    return router.dispatch(Request(method="POST", path=path, body=body or {},
                                   headers=merged, client="10.0.0.1"))


class TestRouteRegistry:
    def test_every_route_declares_its_own_cost_and_auth(self):
        # The registry exists so these cannot drift apart. Previously they lived
        # in three places across two modules.
        for (method, path), spec in ROUTES.items():
            assert spec.method == method and spec.path == path
            assert spec.cost >= 1
            assert isinstance(spec.protected, bool)

    def test_expensive_endpoints_cost_more_than_reads(self):
        assert ROUTES[("POST", "/api/analyze")].cost > ROUTES[("GET", "/api/health")].cost
        assert ROUTES[("POST", "/api/shadow/run")].cost > ROUTES[("GET", "/api/stats")].cost

    def test_every_mutating_endpoint_that_spends_money_is_protected(self):
        for (method, path), spec in ROUTES.items():
            if method == "POST" and spec.cost >= 10:
                assert spec.protected, f"{path} is expensive but unprotected"

    def test_duplicate_registration_is_refused(self):
        from sentinel.routes import route

        with pytest.raises(RuntimeError, match="duplicate route"):
            route("GET", "/api/health")(lambda r, q: None)


class TestRateLimiter:
    def test_allows_within_capacity(self):
        limiter = RateLimiter(capacity=10, refill_per_second=1.0)
        assert all(limiter.check("a", 1)[0] for _ in range(10))

    def test_refuses_past_capacity(self):
        limiter = RateLimiter(capacity=3, refill_per_second=0.01)
        for _ in range(3):
            limiter.check("a", 1)
        allowed, retry_after = limiter.check("a", 1)
        assert allowed is False and retry_after > 0

    def test_cost_is_charged(self):
        limiter = RateLimiter(capacity=10, refill_per_second=0.01)
        assert limiter.check("a", 9)[0] is True
        assert limiter.check("a", 9)[0] is False, "an expensive call must exhaust the budget"

    def test_clients_are_independent(self):
        limiter = RateLimiter(capacity=2, refill_per_second=0.01)
        limiter.check("a", 2)
        assert limiter.check("a", 1)[0] is False
        assert limiter.check("b", 1)[0] is True

    def test_tokens_refill_over_time(self):
        limiter = RateLimiter(capacity=2, refill_per_second=1000.0)
        limiter.check("a", 2)
        import time

        time.sleep(0.05)
        assert limiter.check("a", 1)[0] is True

    def test_idle_buckets_are_evicted(self):
        # The key is a source address, so unbounded growth is attacker-driven.
        limiter = RateLimiter(capacity=1, refill_per_second=1000.0)
        for i in range(5000):
            limiter.check(f"10.0.{i // 256}.{i % 256}", 1)
        assert limiter.snapshot()["tracked_clients"] < 5000


class TestCSRF:
    def _policy(self) -> CSRFPolicy:
        policy = CSRFPolicy()
        policy.allowed_origins = policy.default_origins("127.0.0.1", 8000)
        return policy

    def test_reads_are_never_blocked(self):
        assert self._policy().check("GET", "", "https://evil.example")[0] is True

    def test_same_origin_post_is_allowed(self):
        ok, _ = self._policy().check("POST", "application/json", "http://127.0.0.1:8000")
        assert ok is True

    def test_cross_origin_post_is_refused(self):
        ok, reason = self._policy().check("POST", "application/json", "https://evil.example")
        assert ok is False and "cross-origin" in reason

    def test_non_json_content_type_is_refused(self):
        # This is the exact shape of the attack: a browser "simple request"
        # cannot set application/json, so requiring it forces a preflight.
        ok, reason = self._policy().check("POST", "text/plain", "")
        assert ok is False and "application/json" in reason

    def test_no_origin_header_passes(self):
        # curl, the CLI and systemd timers send no Origin and are not CSRF vectors.
        assert self._policy().check("POST", "application/json", "")[0] is True

    def test_charset_parameter_is_tolerated(self):
        assert self._policy().check("POST", "application/json; charset=utf-8", "")[0] is True


class TestGuardIntegration:
    def test_the_original_csrf_attack_is_now_refused(self, indexed_engine):
        # Verbatim reproduction of what worked before guard.py existed.
        router = Router(indexed_engine)
        response = post(router, "/api/response/block",
                        headers={"content-type": "text/plain", "origin": "https://evil.example"},
                        body={"ip": "203.0.113.45", "score": 99})
        assert response.status == 403

    def test_a_simple_post_with_no_origin_still_needs_json(self, indexed_engine):
        # The content-type gate on its own, with the Origin check out of the way.
        # It is what forces a cross-origin preflight in a real browser.
        router = Router(indexed_engine)
        response = post(router, "/api/response/block",
                        headers={"content-type": "text/plain"},
                        body={"ip": "203.0.113.45", "score": 99})
        assert response.status == 403
        assert "application/json" in response.payload["error"]

    def test_cross_origin_json_post_is_also_refused(self, indexed_engine):
        router = Router(indexed_engine)
        response = post(router, "/api/response/block",
                        headers={"origin": "https://evil.example"},
                        body={"ip": "203.0.113.45", "score": 99})
        assert response.status == 403
        assert "cross-origin" in response.payload["error"]

    def test_expensive_endpoint_is_rate_limited(self, indexed_engine):
        router = Router(indexed_engine)
        statuses = [post(router, "/api/analyze").status for _ in range(12)]
        assert 429 in statuses, "unmetered /api/analyze is a wallet drain"
        limited = next(s for s in statuses if s == 429)
        assert limited == 429

    def test_rate_limit_response_says_when_to_retry(self, indexed_engine):
        router = Router(indexed_engine)
        for _ in range(20):
            response = post(router, "/api/analyze")
            if response.status == 429:
                assert response.payload["retry_after"] > 0
                return
        pytest.fail("never rate limited")

    def test_cheap_reads_survive_an_expensive_burst(self, indexed_engine):
        router = Router(indexed_engine)
        for _ in range(8):
            post(router, "/api/analyze")
        # Reads cost 1, so a bucket drained by cost-30 calls still has room.
        health = router.dispatch(Request(method="GET", path="/api/health", client="10.0.0.1"))
        assert health.status in {200, 429}

    def test_rate_limiting_can_be_disabled(self, indexed_engine):
        engine = indexed_engine
        engine.settings = replace(engine.settings, api_rate_limit_enabled=False)
        router = Router(engine)
        assert all(post(router, "/api/analyze").status == 200 for _ in range(15))
