# API hardening

## Rate limiting lives in the shared router, not in middleware

The engine serves the same routes from two adapters: FastAPI in production and a
stdlib `http.server` on a bare checkout. A limiter installed as FastAPI
middleware — SlowAPI, say — guards exactly one of them and leaves
`python -m sentinel serve --stdlib` completely unmetered.

A control absent from a supported deployment path is not a control. So the
limiter is a token bucket in `guard.py`, called from `routes.Router.dispatch`,
which both adapters go through.

A bucket rather than a fixed window: bursts are normal (the dashboard polls
several endpoints on load) while sustained load is not. A fixed window either
rejects the legitimate burst or permits a sustained flood across the boundary.

Cost is per endpoint. An LLM analysis is worth ~30 cheap reads, because unmetered
`/api/analyze` is both a wallet drain and a way to keep the engine too busy to
notice events.

Idle buckets are evicted. Without it, one request per source address is a slow
memory leak — and the address is attacker-chosen.

## The CSRF hole, and why CORS was never the fix

The dashboard is unauthenticated by default (it binds to localhost). Before
`guard.py`, any page the operator visited could issue a *simple* cross-origin
POST — no preflight — and have it acted on. Confirmed against a running server:

```
curl -X POST http://127.0.0.1:8000/api/response/block \
     -H 'Content-Type: text/plain' -H 'Origin: https://evil.example' \
     -d '{"ip":"203.0.113.45","score":99}'
-> {"allowed": true, ...}
```

**A CORS allowlist would not have fixed this.** CORS governs whether a page may
*read* a response. It does not stop the request being sent, and it does not stop
the server acting on it.

The project already had the strictest possible CORS policy — no
`Access-Control-Allow-Origin` header at all, because no CORS middleware is
installed. Adding one with an allowlist would have *loosened* it.

The two fixes that do work:

1. **Require `Content-Type: application/json` on mutating requests.** That header
   is not on the browser's simple-request list, so a cross-origin `fetch` must
   preflight — and the preflight fails, because no CORS headers are sent.
2. **Reject a mismatched `Origin`.** A request with no `Origin` is not from a
   browser page (curl, the CLI, a systemd timer) and is not a CSRF vector, so it
   passes.

## Token comparison

`SENTINEL_API_TOKEN` is compared with `hmac.compare_digest`. A plain `!=` on a
secret leaks its length and prefix through timing.
