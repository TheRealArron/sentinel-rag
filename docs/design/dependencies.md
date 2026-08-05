# The optional-dependency design

Every third-party package is optional. With none installed the engine runs on a
lexical hashing embedder, a pure-Python exact vector index, the stdlib HTTP
server, and rule-based alerts. `python -m sentinel stats` reports which backends
are live, so a degraded deployment is visible rather than silent.

CI runs the whole Python suite **without** installing `requirements.txt`. If a
test starts needing torch, the fallback path has quietly rotted.

## Backend selection is three-valued

`auto` picks the best importable backend — right for development. Naming a backend
explicitly makes a missing one a startup error — right for production. Silently
running a demo-grade embedder against real logs is the failure worth engineering
against.

## Where this is a real constraint, not a preference

* **The Go ingestor imports nothing outside the standard library.** It parses
  attacker-controlled input and ships `FROM scratch` with no shell or libc. This
  is why `grpc-go` was rejected for the fleet transport (see transport.md) and why
  the honeytoken config is JSON rather than YAML.
* **Local inference talks HTTP through `urllib`.** Pulling in an HTTP client to
  POST one JSON document to a socket on the same machine would make the air-gap
  feature — whose whole point is self-sufficiency — depend on PyPI being reachable
  to install it.

## What it costs

The fallback embedder has **no cross-lingual ability at all**; in that mode the
EN/JA bridge is carried by the bilingual tag pairs the ingestor attaches and the
`keywords` front-matter on advisories — shared literal tokens, not shared
semantics. `Embedder.semantic` reports which regime you are in and the API
surfaces it, so nobody mistakes a demo for a deployment.
