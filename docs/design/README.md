# Design notes

Why the code is the way it is. Source files carry short comments for local
"why"; the long-form reasoning lives here so the code stays readable.

| Note | Covers |
|---|---|
| [transport.md](transport.md) | HTTPS vs gRPC, mTLS, certificate revocation |
| [api-hardening.md](api-hardening.md) | Rate limiting, CSRF, why not CORS or SlowAPI |
| [retrieval.md](retrieval.md) | Bilingual floor, script-aware chunking, e5 prefixes |
| [grounding.md](grounding.md) | Citation validation, severity clamping, prompt budget |
| [privacy.md](privacy.md) | What is pseudonymised, and what deliberately is not |
| [dependencies.md](dependencies.md) | Why the optional-dependency design, and its limits |
| [sigma.md](sigma.md) | The Sigma subset, what it refuses, and how the two matchers stay in sync |
| [ioc.md](ioc.md) | Bloom prefilter over an on-disk exact store, the FPR defect a measurement caught, and why a feed cannot arm the firewall |

These notes explain individual decisions. For the narrative version —
the five hardest defects and how each was caught — see
[`site/index.html`](../../site/index.html).
