# Sample data

## `sample_syslog.log`

23 lines of synthetic RFC 3164 syslog telling one complete intrusion story, in
order:

| Lines | What happens |
|---|---|
| 1–3 | Background noise: a cron job, a pre-auth disconnect, a firewall-blocked telnet probe |
| 4 | **A second scanner tries the canary username `admin_backup`** — score 100, the only single event that clears the firewall threshold |
| 5–9 | Five SSH password failures from `203.0.113.45` inside 8 seconds, across five usernames |
| 10–11 | **A successful login for `arron` from the same address** — the guessing stopped because it worked |
| 12–13 | `sudo` to root, then a `curl … \| bash` dropper |
| 14–17 | Persistence: a new `svc-backup` account, added to `sudo`, key-based re-entry, a backdoor key written to `/root/.ssh/authorized_keys` |
| 18 | **Credential hunting trips the canary *file* `/etc/.backup_credentials`** — score 100 again, this time a path token |
| 19–20 | Anti-forensics (`journalctl --vacuum-time=1s`) and a cryptominer service |
| 21 | A `sudo` command containing **U+202E** (Trojan Source) so the displayed path differs from the executed one |
| 22 | The same `Failed password for root` rule from an *internal* address — scores lower, on purpose |
| 23 | A line no rule matches — kept at `info` rather than dropped |

The two canary lines (4 and 18) are placed deliberately. Line 4 uses a **different
source address** from the brute-force campaign, and line 18 carries **no address
at all**, so neither perturbs the five-failure correlation window that the rest of
the fixture and its tests depend on. A test asserts that window is still
`failure_count=5` with the same five usernames.

Line 21 is the interesting one for testing the sanitiser: run
`grep -aP '[\x{202a}-\x{202e}]' sample_syslog.log` to confirm the bidi override
is really in the file. The ingestor strips it, scores the *attempt* at +25, and
reclassifies the event as `defense-evasion`.

Line 22 exists to demonstrate that the same detection rule produces different
severities depending on source scope: a public source adds +8, a private one
subtracts 4.

## `events.sample.jsonl`

The ingestor's output for the log above: 23 parsed events plus **2 synthetic
correlated incidents** (`correlated_brute_force` at the fifth failure,
`correlated_successful_login_after_bruteforce` on the success). It is used three
ways — as the `python -m sentinel demo` data source when no ingestor output
exists, as the Python test-suite fixture, and as executable documentation of the
Go → Python schema.

**Provenance:** captured output of `sentinel-ingestor` run over
`sample_syslog.log`. Regenerate with:

```bash
make sample     # TZ=UTC ./ingestor/bin/sentinel-ingestor -in sample_syslog.log
git diff --stat data/samples/events.sample.jsonl
```

`TZ=UTC` is required, not cosmetic. RFC 3164 timestamps carry no timezone, so
the ingestor reads them in the host's local zone and normalises to UTC — without
pinning TZ this file would differ between a developer in Asia/Tokyo and a CI
runner in UTC, and the drift check would fail on every machine but one.

CI regenerates the file and diffs it (ignoring `ingested_at`, which is
wall-clock); a mismatch fails the build. If the Go rules change, trust the
ingestor and commit the regenerated file.

## Regenerating from your own logs

```bash
# one-shot over a real log
./ingestor/bin/sentinel-ingestor -in /var/log/auth.log -out data/events.jsonl -stats

# live tail, medium severity and above
./ingestor/bin/sentinel-ingestor -in /var/log/syslog -follow -min-score 40 -out data/events.jsonl
```
