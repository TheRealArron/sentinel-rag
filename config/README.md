# Configuration

## `honeytokens.json` — Phase 5, deceptive defence

Canary usernames, file paths, hostnames, and process names that exist **nowhere**
on your system. Any log line referencing one is attacker activity by
construction, which is why it is the only detector in Sentinel that scores 100 on
a single event and the only one that clears the firewall-response threshold
(`SENTINEL_RESPONSE_MIN_SCORE`, default 90) without correlation.

### Arming them

Loaded automatically from `config/honeytokens.json` if present. It is optional —
a clone with the file deleted simply runs without deception detection:

```bash
./ingestor/bin/sentinel-ingestor -in /var/log/auth.log -out data/events.jsonl -stats
# sentinel-ingestor: 9 honeytoken(s) armed from config/honeytokens.json: user=4 [...]
```

Naming it explicitly makes a missing file an **error** rather than a silent
no-op, which is what you want in production — an operator who asked for canaries
must not be left believing they are armed when they are not:

```bash
./ingestor/bin/sentinel-ingestor -honeytokens /etc/sentinel/honeytokens.json ...
```

### Verify before you trust them — run this on the host

```bash
./ingestor/bin/sentinel-ingestor -honeytokens-verify /etc/passwd
# ok: none of the 9 honeytoken(s) exist in /etc/passwd
```

A canary that collides with a real account is worse than no canary: it fires on
every legitimate login, trains you to ignore the highest-severity alert in the
system, and — because this detector is wired to active response — can get a real
user's address firewalled. The check exits non-zero on a collision so it can gate
a deploy.

**Run it on the host, not inside the container.** A container has its own
`/etc/passwd`, so the check would pass vacuously there and prove nothing.

### Making them convincing

A canary only works if an attacker plausibly tries it. The defaults are shaped
like entries in real credential-stuffing wordlists.

- **Do** pick names that fit your environment's conventions. If your real
  accounts are `svc-web-01`, then `svc-db-07` is a good canary and
  `hunter2_decoy` is not.
- **Do** create the canary *files* as empty, root-owned, mode-0600 files. A path
  that does not exist produces "No such file or directory" in the log — still a
  detection, but a file that exists and is read produces a cleaner audit trail
  and keeps the attacker engaged fractionally longer.
- **Don't** reference them from any script, cron job, or dashboard. The moment
  something legitimate touches one, its false-positive rate stops being zero and
  the score of 100 stops being justified.
- **Don't** put a real secret in a canary file. It is bait, not a vault.

### Schema

Each list takes bare strings or `{"value", "note"}` objects, so simple lists stay
simple:

```json
{
  "users":     ["admin_backup", {"value": "svc_deploy", "note": "why this one"}],
  "paths":     ["/etc/.backup_credentials"],
  "hosts":     ["vault-internal.lan"],
  "processes": ["sentinel-decoy-agent"]
}
```

Unknown top-level keys are rejected. A typo like `"user"` for `"users"` would
otherwise parse cleanly into a set with nothing in it, and a honeypot that is
silently unarmed is the worst possible outcome.

Non-username tokens must be at least 4 characters. A 2-character "path" would
match constantly and turn the highest-severity detector into noise.

### Why JSON and not YAML

The ingestor imports nothing outside the Go standard library — a security
property on the component that parses attacker-controlled input, not a stylistic
preference. YAML would mean a third-party parser, or a half-correct hand-rolled
subset, which is worse. `encoding/json` is in the standard library and the schema
here is a list of strings.

### Why a hash set and not a Bloom filter

A Bloom filter buys memory at the cost of false positives, and wins when the set
is large enough that storing it hurts. This set is 5–50 entries — a few hundred
bytes. A Go map is one hash and a pointer chase with **zero** false positives.

False positives are precisely what cannot be tolerated at this position: the
event scores 100 and is the only thing permitted to trigger an automated firewall
block. "Probably a honeytoken" is not a basis for cutting off a network. The
Bloom filter belongs in Phase 10's IOC matching, where the set is millions of
indicators, memory is the binding constraint, and a positive can afford a
confirmation lookup.
