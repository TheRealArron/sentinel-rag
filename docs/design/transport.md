# Fleet transport and trust

## HTTPS, not gRPC

The mTLS work — the load-bearing part — is identical under both, because mTLS is
a TLS-layer property and gRPC's mutual auth *is* TLS mutual auth.

What differs is cost. `grpc-go` pulls ~40 transitive modules into the ingestor,
whose dependency-freedom is a stated security property: it parses
attacker-controlled input, ships `FROM scratch` with no shell or libc, and CI
enforces the empty `go.mod`. That buys protobuf typing and HTTP/2 multiplexing,
neither of which one append-only line stream per probe uses.

`crypto/tls` and `ssl` keep both halves standard library. NDJSON over chunked
HTTP/1.1 is what Vector, Fluent Bit and the Elastic Beats already do. gRPC earns
its keep when schemas evolve across team boundaries — real, but not this.

## What mTLS proves, and the gap it leaves

It proves *a* probe holding a CA-signed key is connected. It does **not** prove
which host the logs describe. Without binding the two, a compromised probe-04 can
file clean logs as probe-07 and hide inside the fleet.

So the hub overwrites each event's `host` with the certificate's Common Name.

The first version of that enforcement *rejected* mismatches, and running it showed
why that is wrong: a probe whose syslog hostname differs from its certificate then
loses 100% of its telemetry, which hands an attacker a way to **silence** a probe
by changing a hostname. Worse than the impersonation it prevented.

The claim is now neutralised rather than obeyed: `host` becomes the authenticated
CN, the original is kept as `_claimed_host`, and the mismatch is counted and
surfaced. You cannot be lied to, and you cannot be made to go blind.
`SENTINEL_HUB_REJECT_HOST_MISMATCH=1` restores hard rejection.

## Revocation

**Not OCSP.** A per-connection network call makes the responder a hard dependency
of the fleet. When it is down you choose between failing open — accepting revoked
probes exactly when something is wrong — and failing closed, a total telemetry
blackout. Disproportionate for a handful of machines.

**Not a signed CRL.** A CRL is signed so it can cross an untrusted channel. This
list lives on the machine that enforces it: an attacker who can edit it already
owns the hub, so the signature guards nothing, while still requiring the CA key
online to add one line.

**Instead:** a JSON deny list keyed on certificate fingerprint, re-read when its
mtime changes. `sentinel-ca.sh revoke probe-04` is one file write — immediate, no
restart, no CA key, and no other certificate touched. Paired with 90-day client
certificates so the list only covers the theft-to-expiry window. A malformed list
keeps its previous entries rather than failing open.

## Rejection must close the connection

Answering 403 before reading the request body leaves unread bytes in the socket;
on a keep-alive connection the next request is then parsed from the middle of the
previous body. Draining first would be worse — it invites a peer you just refused
to make you read unbounded data. So errors send `Connection: close`.
