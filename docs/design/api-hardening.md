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


## The score behind a block is looked up, not asserted

The pre-flight pass above found the CSRF hole. It did not find this one, which
sat one layer further in and is the same shape: a safety property enforced by
what the caller *says* rather than by what the system can *check*.

`POST /api/response/block` required a `score` field and acted on it:

```python
score = _as_int(request.body.get("score"), -1)   # from the request body
```

Every layer downstream then re-checked that number against the threshold and
agreed with itself. The host-side responder — the component whose entire purpose
is to be correct even if the engine is compromised — read `.score` out of the
engine's own audit log, so its "independent" re-check was a second reading of the
caller's number.

The README claimed the threshold was *"checked against the deterministic ingestor
score, never the model's opinion"*. That was true of the intent and false of the
mechanism. Nothing verified the score came from the ingestor at all.

**Now:** the endpoint takes an address and, optionally, an `event_id`. The engine
resolves the highest-scoring event the ingestor recorded for that address and
uses *its* score. `score` in the request body is a 400, not a silently ignored
field — a caller that thinks it is supplying evidence should be told it is not.

Three properties follow, each with a test:

- An address the ingestor has never seen cannot be blocked, at any score.
- An `event_id` must belong to the address being blocked, so the score-100
  honeytoken event for one host cannot be borrowed to block another.
- The audit trail records `evidence_id`, so every block has a provenance link
  back to the log line that justified it.

**The host-side responder re-derives the score from `events.jsonl`**, not from
the engine's audit entry. That file is written by the Go ingestor, which has no
network listener and no LLM client; the audit log is written by the component
under review. Re-reading a number the engine wrote and calling it independent
verification was the flaw in the original design, and it is the reason the script
now reads the ingestor's output directly.

The engine's recorded score and the re-derived one can legitimately differ — the
engine's buffer is capped and its view can lag the file — so a mismatch is logged
rather than treated as an attack, and the number the script acts on is always the
one it derived itself.
