# Session log

One entry per autonomous iteration. Appended, never rewritten. Numbers here were
printed by the command shown next to them in the same session; anything carried
over from an earlier document is marked as recorded rather than measured.

---

## Iteration 1 — a second correlation key, for distributed spraying

**Date:** 2026-09-18

### Environment, before anything else

The working directory this session was started in
(`/media/arrowbro135/Data/Documents/Career/Bilingual AI-Powered SecOps Engine`)
contained **no files** — three empty, root-owned directories on the root
filesystem, which `df` shows at 98% (2.3 GB free). A `touch` there returns
`Permission denied`.

`/media/arrowbro135/Data` is not a mount point. The real 371 GB ext4 partition
is mounted at `/media/arrowbro135/Data**1**` — udisks2 chose the `Data1` name
because a stale root-owned skeleton was occupying `Data`. It is an auto-mount;
`/etc/fstab` has no entry for it. The repo is intact on the Data1 path, clean, 0
ahead / 0 behind `origin/main` at `4e5e119`.

Side effects confirmed by running things, not by inspection:

| | |
|---|---|
| `.venv/bin/pytest` and every other console script | **broken** — shebangs point at the old `Data` path |
| `.venv/bin/python -m pytest` | works (pytest 9.1.1) |
| `.venv/ci/bin/python -m ruff` | works (ruff 0.16.7) |
| `.venv/go/bin/go` | works (go1.22.12) |
| `Makefile` | path-agnostic (`PYTHON ?= python3`, `GO ?= go`) |
| `~/Documents` symlink | points at the empty skeleton, currently broken |

The user chose to work in place on the Data1 path with no system changes, so
every command below overrides `PYTHON`/`GO` via `PATH` rather than absolute
paths — the Makefile's `$(PYTHON)` is unquoted and a path with spaces breaks it.
That is an artefact of the override, not a repo defect: the defaults are bare
names.

`docs/design/session-log.md`, which the loop is supposed to append to, **did not
exist**. This file is new.

### What I audited, and what I found

`ingestor/internal/correlate/correlate.go` (466 lines), `pipeline.go`,
`enrich/rules.go`, `enrich.go`, `event.go`.

- **Confirmed:** correlation is keyed only on source IP. `Observe` returns `nil`
  when `ev.SourceIP == ""` and every piece of state hangs off
  `c.state[ev.SourceIP]`. N sources × 1 attempt against one account leaves N
  states holding one failure each, so `FailureThreshold` is never approached and
  distributed spraying is invisible at any volume. This is structural, not a
  tuning miss.
- **Confirmed:** `pam_authentication_failure` never captures `rhost`. A probe
  over the literal pattern returned `ip=""` on all four PAM lines tested,
  including ones carrying a valid `rhost=203.0.113.45`. The first lazy `.*?`
  never has to expand, because the optional `rhost` group can match empty and the
  rest of the pattern still succeeds.
- **The backlog is wrong about the second half of that item.** It records that
  "every PAM failure gets +10 `root_involved` from `user=root` regardless of
  target account". It does not. The same probe shows `user` captures correctly:
  `user="admin"` for the admin line, `user="root"` only where the line actually
  says so. The `user` group is anchored at `$`, so it resolves; only `ip` is
  broken. Corrected here rather than carried forward.
- `ev.SourceIP` on PAM events is populated by the `firstIP(redacted)` fallback at
  `enrich.go:108`, so a detector that counts distinct sources does see them.

### What I chose, and why

**The account-keyed correlator.** It is the user's top-ranked backlog item, the
gap is structural rather than a threshold that needs nudging, it is contained in
one package, and the per-rule FP corpus already exists to measure it against.

Over the alternatives: the 512-token truncation fix shifts every retrieval number
and wants a clean 30-minute e5-large run, which suits an iteration that is not
also introducing a detection; the PAM `rhost` fix is real but masked by `firstIP`
and changes no verdict today; `recommended_actions` provenance needs a product
decision about what operators see.

### What I changed

`ingestor/internal/correlate/correlate.go`:

- `Config` gains `SprayThreshold` (5) and `MaxTrackedAccounts` (4096).
- `clock` — the `windowAt`/`skewed` pair extracted into a struct embedded in both
  state types. Not an abstraction for its own sake: `windowClock`'s rules (do not
  trust the future, never run backwards) are subtle enough that a hand-copied
  second version would drift.
- `accountState` + `accounts` map, LRU-evicted by `evictOldestAccounts`.
- `observeAccount`, `pruneSources`, `offAccountCooldown`, `sourceList`,
  `sourceCount`, `publicSources`, `distributedSprayIncident`.
- Two new rules: `correlated_distributed_spray` (84, any public source) and
  `correlated_distributed_auth_failure` (70, all sources internal).

`correlate_test.go`: 11 new tests. `docs/design/detection.md` and `README.md`
updated with the measured numbers only.

Eviction is written out a second time rather than made generic — the ingestor has
no type parameters anywhere, and sharing fifteen lines would cost an interface or
a callback.

### Mutation table

Every leg removed, package tests re-run, leg restored. Two entries are the
*corrected* runs: the first pass produced a false clean bill on M2 and an invalid
mutation on M8, described below.

| Leg removed | Test that failed |
|---|---|
| M1 wiring: never call the account pass | `TestDistributedSprayAcrossSources`, `TestAccountStateIsBounded`, `TestSprayHasItsOwnCooldown` |
| M2′ the `ev.User != ""` guard | `TestFailuresWithoutAnAccountAreNotTracked` |
| M3 `MaxTrackedAccounts` eviction | `TestAccountStateIsBounded` |
| M4 the per-account source cap | `TestAccountStateIsBounded` |
| M5 window pruning of sources | `TestSpraySourcesOutsideWindowDoNotAccumulate`, `TestAccountStateIsBounded` |
| M6 the spray cooldown | `TestSprayHasItsOwnCooldown` |
| M7 the public/internal score split | `TestInternalSprayIsReportedBelowTheActingScore` |
| M8′ refresh of an already-known source | `TestAKnownSourceIsRefreshedOnceTheSetIsFull` |
| M9 the overflow reset on drain | `TestAccountStateIsBounded` |

Mutation testing caught two defects in my own verification, which is the point of
doing it:

- **M2 first reported "tests still pass".** The string `if ev.User != "" {` is not
  unique in the file — the script mutated the *pre-existing* per-source username
  guard instead of the new one. Re-run against a unique match, it fails the test
  written for it.
- **M8 did not compile.** Removing `known ||` leaves `known` unused. Rewritten as
  `(known && false) ||`, it compiled and **passed** — the refresh leg had no test
  at all. `TestAKnownSourceIsRefreshedOnceTheSetIsFull` was written in response:
  without the refresh, the one source that never stops attacking ages out of its
  own campaign while 63 newer peers hold the set at its cap.

### Measurements

Commands run from the repo root with `PATH="$R/.venv/go/bin:$PATH"` or
`PATH="$R/.venv/ci/bin:$PATH"`.

`make test-go GO=go` — all 9 packages with tests pass under `-race`.
`make test-py PYTHON=python` in `.venv/ci` (**no requirements.txt installed**) —
590 passed, 1 skipped. `make lint PYTHON=python` — ruff: all checks passed.
`make vet GO=go` — clean, gofmt clean.

Detection, via the built binary (`TZ=UTC ./ingestor/bin/sentinel-ingestor -in F
-out -`), counting events whose `process` is `sentinel-correlator`:

| Corpus | Lines | Incidents before | Incidents after |
|---|---:|---:|---:|
| `data/baseline.log` | 604 | 0 | 0 |
| benign corpus `testdata/detection/benign.log` | 108 | 0 | 0 |
| `data/samples/sample_syslog.log` | 25 | 2 | 2 (same two rules) |
| six-line distributed spray (crafted) | 6 | **0** | **1** |

"Before" is the same binary rebuilt with `git stash push -- ingestor/internal/correlate/`,
so it is a real measurement of the previous code, not an assumption.

The true positive, in full:

```
score= 84 critical correlated_distributed_spray
INCIDENT distributed password spray: 5 distinct sources failed against
"svc-deploy" within 1m0s (sources: 198.51.100.23, 198.51.100.90,
203.0.113.11, 203.0.113.150, 203.0.113.77)
  distinct_sources=5  public_sources=5  total_failures_seen=5
```

Five of six sources named; the sixth attempt is inside the cooldown.

`make detection-report GO=go` — `TestBenignCorpusStaysQuiet`: 108 lines, **1
scored ≥40**, matching the committed `benignBudget` of 1. Unchanged.

`make sample GO=go` — the fixture does **not** regenerate byte-identically, and
this is not drift. The only field that differs is `ingested_at`, which is
wall-clock; comparing both versions with that key removed gives an exact match
(checked field-by-field over all 25 events, `fields that differ: ['ingested_at']`).
CI normalises the same way, `jq -Sc 'del(.ingested_at)'` at `ci.yml:156`. The
regenerated file was reverted rather than committed.

`make sigma-check` / `make ioc-check` — Go↔Python agreement vectors regenerate
unchanged (40 sigma vectors, 10/9/6/30 ioc vectors; `git status` clean afterwards).
`go.mod` untouched and still dependency-free.

### What I did NOT verify

- **Docker.** `docker compose up` was not attempted. Beyond the DNS timeout the
  user reports, this session cannot reach the daemon at all — `docker ps` returns
  `permission denied` on `/var/run/docker.sock`, and there is no passwordless
  sudo. Container behaviour is unverified, not merely skipped.
- **The Python engine's view of the new rules.** Nothing on the Python side was
  changed, and the two new rule names appear in no Python fixture, dashboard
  grouping, or response playbook that I checked — I did not grep for how an
  unknown `rule` value is rendered. The events carry `category: authentication`
  and standard tags, so I *expect* they flow through as any other incident, but I
  did not run the dashboard or `make analyze` against them.
- **Scale.** No benchmark was run on the second key. It adds one map lookup and a
  bounded prune per auth failure on the single-goroutine collector path; I did not
  measure the cost, and `make bench` was not run.
- **Real-world false positives.** 0 incidents on 712 lines of two synthetic/
  hand-authored corpora is not a false-positive rate on real traffic. Neither
  corpus contains a fleet of internal hosts retrying a rotated credential, which
  is the exact scenario the 70-score branch exists for — that branch has unit
  tests and no corpus evidence.
- The e5/retrieval side was untouched and not re-run this iteration.

### Found and not fixed

- **`pam_authentication_failure` still never captures `rhost`** (verified above).
  The fix is to move the lazy `.*?` *inside* each optional group —
  `(?:.*?\brhost=(?P<ip>[0-9a-fA-F.:]*))?(?:.*?\buser=(?P<user>\S+))?\s*$` — so
  the group either matches with its run-up or not at all. I probed the defect but
  have **not** tested that replacement; it is a hypothesis, not a verified fix.
  Changing it will start populating `ip` on PAM lines where `firstIP` currently
  supplies the address, so the before/after event stream needs comparing.
- **The backlog's `root_involved` claim is false** — corrected above. Whoever
  resumes should not go looking for that bug.
- **Case-sensitivity of the account key** and **sprays slower than the window**
  are both documented in `detection.md` under "What this does not fix" rather
  than fixed.
- `data/events.jsonl` still has no rotation, index, or retention; Shadow Search
  still recomputes its baseline over full history. Untouched.
