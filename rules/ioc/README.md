# Threat feeds

Indicator feeds compiled into the bundle the Go ingestor matches against.

```bash
make ioc          # compile this directory into rules/external/ioc.{bloom,store}
make ioc-check    # compile without writing, and refresh the agreement vectors
```

The ingestor loads the bundle at startup, so refreshing a feed is a recompile and
a restart — never a Go rebuild. Design reasoning:
[`docs/design/ioc.md`](../../docs/design/ioc.md).

## The demo feeds are fabricated on purpose

Every address shipped here comes from a range reserved for documentation —
`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` (RFC 5737), `2001:db8::/32`
(RFC 3849) — and every hostname is under `.example`. None of them can ever
resolve to real infrastructure.

That is not tidiness. This feed is wired to a detector that raises an event's
score, and a shipped indicator that named a live address would eventually flag
somebody's DNS resolver or CDN edge on a machine where nobody chose to trust this
feed. A demo dataset should not be able to do that.

Replace them with real feeds before this means anything operationally.

## Formats

The file's stem becomes the feed name recorded on every indicator it contributes,
so an analyst can see which source made the claim. Three formats are accepted:

**`.txt` / `.list`** — one indicator per line, `#` comments and blanks ignored,
type inferred from shape:

```
203.0.113.45
c2.malware.example
d41d8cd98f00b204e9800998ecf8427e
```

**`.csv`** — needs an `indicator` column (or `ioc`, or `value`); `type` and
`note` are optional. Column names are matched case-insensitively:

```csv
indicator,type,note
e3b0c44298fc...,hash,dropper seen 2026-07
dropper.example.net,domain,staging host
```

**`.json`** — a list of strings, of objects, or a mix:

```json
[
  {"indicator": "login.example.org", "type": "domain", "note": "harvesting"},
  "198.51.100.203"
]
```

Anything else in this directory is ignored.

## Indicator types

`ip`, `domain` and `hash` (MD5, SHA-1, SHA-256). Leaving `type` off is fine —
the compiler classifies by shape. Declaring a type that does not validate is
reported as a refusal rather than silently re-guessed, because a feed asserting
`203.0.113.45` is a hash is a bug in the feed and worth seeing.

They are **not** weighted equally when scoring. A hash identifies an immutable
artefact; an IP is shared by NAT, CDNs and hosting providers and is reassigned
constantly. See [`docs/design/ioc.md`](../../docs/design/ioc.md#scoring-and-the-one-thing-a-feed-is-not-allowed-to-do).

## What gets refused

Refusals are printed by `make ioc`, never swallowed — compiling a feed and
silently discarding part of it is how you come to believe you have coverage you
do not have.

- **Internationalised domains.** Matching `пример.рф` needs IDNA, and the
  ingestor deliberately carries no dependencies. A half-correct ASCII fold would
  be worse than refusing, because the Go reader would have to reproduce it
  exactly. Punycode (`xn--…`) is already ASCII and is accepted.
- **Single-label names** (`localhost`) and **dotted numbers** (`1.2.3`), which
  are version strings rather than hostnames.
- **CIDR ranges.** Indicators are single values; `203.0.113.0/24` is a policy,
  not an indicator.
- Malformed addresses, bad label syntax, and hex strings that are not a real
  digest length.

## What a feed cannot do

A confirmed indicator can raise an event to high or even critical severity, but
it is capped one point below the score that triggers an automated firewall block.
Feed contents are external, mutable data, and a mistaken entry for a public
resolver is a normal occurrence in threat intelligence — so blocking still
requires a honeytoken or a correlated incident, both derived from this host's own
observations. See [`config/README.md`](../../config/README.md) for the other half
of that argument.
