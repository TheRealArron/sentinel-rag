# Pseudonymisation

Raw logs stay on the host. What reaches a hosted model is pseudonymised first.

**Masked:** internal hostnames, local usernames, private and link-local IPs, MAC
addresses, email addresses. Each becomes a stable placeholder (`HOST_1`,
`USER_2`); the mapping is in memory only, never written or transmitted, and
`restore()` reverses it locally so the operator reads a normal alert.

**Deliberately not masked: the attacker's public IP.** It is not the operator's
personal data, it is the most actionable field in the alert, and masking it breaks
both the remediation advice and the firewall response.
`SENTINEL_ANONYMIZE_PUBLIC_IPS=1` for anyone whose threat model differs.

**Detection uses a learned vocabulary** — the exact host and user strings the
ingestor already extracted — not a regex guessing at what looks like a username.
Guessing produces both misses and absurd false positives ("Failed" as a username).

## A bug worth recording

Python's `ipaddress.is_private` includes the RFC 5737 documentation ranges
(`203.0.113.0/24`), while Go's `net.IP.IsPrivate` does not. The two halves of the
system disagreed about whether the same address was internal, and the Python side
would have masked exactly the addresses used to represent attackers.
`privacy.py` now defines the private ranges explicitly, matching the Go semantics.
