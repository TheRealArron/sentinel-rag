# Design notes

Why the code is the way it is. Source files carry short comments for local
"why"; the long-form reasoning lives here so the code stays readable.

| Note | Covers |
|---|---|
| [corpus.md](corpus.md) | Real advisory feeds, the JVN licensing line, and what the bilingual numbers actually show |
| [detection.md](detection.md) | Rule precedence, the surface split, and the username that could choose the verdict |
| [transport.md](transport.md) | HTTPS vs gRPC, mTLS, certificate revocation |
| [api-hardening.md](api-hardening.md) | Rate limiting, CSRF, why not CORS or SlowAPI |
| [retrieval.md](retrieval.md) | Bilingual floor, script-aware chunking, e5 prefixes |
| [grounding.md](grounding.md) | Citation validation, severity clamping, prompt budget |
| [privacy.md](privacy.md) | What is pseudonymised, and what deliberately is not |
| [dependencies.md](dependencies.md) | Why the optional-dependency design, and its limits |
| [sigma.md](sigma.md) | The Sigma subset, what it refuses, and how the two matchers stay in sync |
| [ioc.md](ioc.md) | Bloom prefilter over an on-disk exact store, the FPR defect a measurement caught, and why a feed cannot arm the firewall |
| [scaling.md](scaling.md) | Where the system actually breaks: four defects where attacker-chosen input drove unbounded work or memory, measured before and after |
| [spool.md](spool.md) | Delivery when the hub is gone: duplicate sends, torn batches, a loss counter mixing units, and a cap in bytes guarding work per file |

These notes explain individual decisions. For the narrative version —
the five hardest defects and how each was caught — see
[`site/index.html`](../../site/index.html).
