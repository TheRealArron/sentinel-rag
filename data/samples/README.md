# Sample data

## `sample_syslog.log`

21 lines of synthetic RFC 3164 syslog telling one complete intrusion story, in
order:

| Lines | What happens |
|---|---|
| 1–3 | Background noise: a cron job, a pre-auth disconnect, a firewall-blocked telnet probe |
| 4–8 | Five SSH password failures from `203.0.113.45` inside 8 seconds, across five usernames |
| 9–10 | **A successful login for `arron` from the same address** — the guessing stopped because it worked |
| 11–12 | `sudo` to root, then a `curl … \| bash` dropper |
| 13–16 | Persistence: a new `svc-backup` account, added to `sudo`, key-based re-entry, a backdoor key written to `/root/.ssh/authorized_keys` |
| 17–18 | Anti-forensics (`journalctl --vacuum-time=1s`) and a cryptominer service |
| 19 | A `sudo` command containing **U+202E** (Trojan Source) so the displayed path differs from the executed one |
| 20 | The same `Failed password for root` rule from an *internal* address — scores lower, on purpose |
| 21 | A line no rule matches — kept at `info` rather than dropped |

Line 19 is the interesting one for testing the sanitiser: run
`grep -aP '[\x{202a}-\x{202e}]' sample_syslog.log` to confirm the bidi override
is really in the file. The ingestor strips it, scores the *attempt* at +25, and
reclassifies the event as `defense-evasion`.

Line 20 exists to demonstrate that the same detection rule produces different
severities depending on source scope: a public source adds +8, a private one
subtracts 4.

## `events.sample.jsonl`

The ingestor's output for the log above: 21 parsed events plus **2 synthetic
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
