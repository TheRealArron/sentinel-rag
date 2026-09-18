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

---

## Iteration 2 — the 512-token truncation, and a variant that was measured and rejected

**Date:** 2026-09-18 / 19

### What I audited, and what I found

`engine/sentinel/chunking.py`, `lang.py`, `embeddings.py`, `indexer.py`,
`retrieval_eval.py`, `cli.py`, and `docs/design/retrieval.md`.

The recorded defect reproduces exactly. Running e5-large's own tokenizer over the
child chunks the current code produces: **9 of 93 chunks over the 512-token
limit, longest 824, 1397 tokens discarded**. That matches what `retrieval.md`
records, so the recorded figure was sound.

The cause is not the one I would have guessed from the backlog entry, and the
decomposition matters:

* The estimator is the whole story. The worst chunk estimated 433 tokens and held
  788 — a ratio of **1.82**. The prepended title contributes 36.
* **8 of the 9 were already over the limit before the title was added.**
* `estimate_tokens` counted everything non-CJK at four characters per token.
  SentencePiece merges letters into word pieces but emits digits and punctuation
  singly, so `CVE-2026-46279` and `mm/alloc_tag:` cost far more than their length
  suggests. Japanese was already safe (it over-estimates, median ratio 0.79).
* Separately, `max est_body = 461` against a 400 budget, because `apply_overlap`
  adds its tail *after* `split_text` has enforced the budget. A 15% contributor
  next to the estimator's 80%.

### What I chose, and why

Four candidate estimators, each re-chunking the whole corpus and measured with
the real tokenizer:

| estimator | chunks | over 512 | max tokens | real/est max |
|---|---:|---:|---:|---:|
| current (non-CJK at 4 chars/token) | 93 | 9 | 824 | 1.80 |
| digits+punctuation at 1 token each | 126 | **0** | 497 | 1.06 |
| non-CJK at 3 chars/token | 107 | 7 | 626 | 1.31 |
| digits+punctuation at 2 chars/token | 102 | 6 | 603 | 1.38 |

Only the third character class closes it, which is why the fix is that and not a
uniform tightening.

I also built the obvious companion change — reserving the title and overlap
inside `child_tokens`, so the budget bounds the *embedded* string structurally
rather than empirically — and then **measured it and threw it away**. It works on
its own terms (174 chunks, longest 380) and it costs retrieval on every metric:

| e5-large | pre-fix | estimator + reservation | estimator only |
|---|---:|---:|---:|
| overall hit@5 | 0.915 | 0.894 | **0.936** |
| overall MRR | 0.858 | 0.852 | **0.871** |
| cross-lingual hit@5 | 0.562 | 0.531 | **0.594** |
| misses at k=5 | 4 | 5 | **3** |

Smaller chunks retrieve worse. Shipping the reservation would have fixed the
defect and made the product worse, and nothing short of running the evaluation
would have shown that — the unit tests were green for both.

### What I changed

`engine/sentinel/lang.py` — `estimate_tokens` counts three classes instead of
two. That is the entire production change; `chunking.py` is untouched.

New: `scripts/gen-tokenizer-vectors.py`, `engine/tests/testdata/tokenizer_vectors.json`
(49 longest chunks with real token counts), `engine/tests/test_tokenizer_vectors.py`,
and a `make tokenizer-check` target. Docs: `retrieval.md` and `README.md`.

**Why the vectors exist.** The suite passed before and after the defect existed,
because every test that measured a chunk against its budget measured it with the
same estimator that was wrong — they agreed with each other and with nothing
real. The Go/Python Sigma and IOC bridges already solve this shape of problem by
committing one side's answers; these do the same for the tokenizer, and the test
that reads them needs no dependencies.

### Mutation table

| Leg removed | Test that failed |
|---|---|
| estimator reverted to the two-class model | `test_identifier_dense_text_costs_more_than_prose_of_the_same_length`, `test_the_estimator_still_produces_the_committed_estimates` |
| a 600-token chunk planted in the vectors | `test_no_chunk_reaches_the_model_input_limit`, `test_the_estimator_does_not_underestimate_beyond_its_headroom`, `test_the_headroom_under_the_limit_is_recorded_and_still_positive` |

Stronger than a mutation: with `lang.py` and `chunking.py` reverted to HEAD and
the vectors regenerated from that code, the new gate fails with *"9 chunk(s) at
or past the 512-token limit, longest 824"* and *"27 vector(s) underestimate by
more than 1.10x, worst ratio 1.787"*. The gate detects the real defect on the
real corpus, not a synthetic stand-in.

### Measurements

Retrieval, `make retrieval-report`, 47 queries, floor off, each run in a **fresh
index directory** (chunk ids are content-addressed, so a reused store keeps the
old chunks alongside the new — see below):

| | hashing before | hashing after | small before | small after | large before | large after |
|---|---:|---:|---:|---:|---:|---:|
| overall hit@1 | 0.660 | 0.638 | 0.787 | 0.830 | 0.830 | 0.830 |
| overall hit@3 | 0.787 | 0.766 | 0.894 | 0.915 | 0.872 | 0.894 |
| overall hit@5 | 0.830 | **0.851** | 0.936 | 0.936 | 0.915 | **0.936** |
| overall MRR | 0.720 | 0.713 | 0.839 | **0.870** | 0.858 | **0.871** |
| cross-lingual hit@5 | 0.188 | **0.312** | 0.438 | 0.438 | 0.562 | **0.594** |
| cross-lingual MRR | 0.112 | **0.183** | 0.212 | 0.213 | 0.249 | **0.258** |
| misses at k=5 | 8 | 7 | 3 | 3 | 4 | **3** |

The pre-fix e5-large run reproduced the committed table **exactly** — all six
slices, both floor settings, and the same four misses — which is what gives me
confidence the environment and the recorded numbers are both sound.

Chunking: 93 → 126 chunks, 9 → **0** over the limit, longest 824 → **497**, 1397
→ **0** tokens discarded, worst real/estimate 1.80 → 1.05.

`make test-py` in `.venv/ci` with **no requirements.txt installed**: 596 passed,
1 skipped. `make lint`: ruff clean. `make vet`, `make test-go`: unchanged, all 9
packages pass under `-race`. `go.mod` untouched and still dependency-free.

### What I did NOT verify

- **Whether any of the retrieval movement is real.** The biggest change to a
  headline figure is one query out of 32. Nothing is tested for significance and
  a 47-query set judged by one person cannot support much. I would not defend
  "the fix improved retrieval" — I would defend "the fix stopped discarding 1397
  tokens and did not make retrieval worse".
- **The per-direction asymmetry and the same-language-preference analysis** in
  `retrieval.md` were not re-run on the new boundaries. Both are now explicitly
  marked as describing the pre-fix configuration. The first needs the `--json`
  report rather than the printed table.
- **The headroom is empirical, not structural, and it is 15 tokens.** The
  embedded estimate reaches 502 against a 400 budget; at the worst observed ratio
  that permits ~529 real tokens, which would not fit. It does not happen only
  because the longest chunks are ones the estimator overestimates. A larger
  corpus can consume that margin and only `make tokenizer-check` would notice.
- **Docker** — still unreachable here: `docker ps` gives `permission denied` on
  the socket and there is no passwordless sudo, on top of the user's DNS timeout.
- The chars-per-token calibration table was recomputed with my own grouping (3
  hand-written summaries, 39 NVD records); the earlier table grouped five
  summaries. Both columns shift slightly with the grouping and I did not
  reconstruct the original method.

### Found and not fixed — a defect in the default path

`make retrieval-report` on a machine with an existing index **reports wrong
numbers, silently**, and this is the same shape as the `--cases` bug already
recorded in this repo: the command a user actually types is not the one that was
exercised.

`cmd_eval_retrieval` calls `engine.index_all()`, which adds incrementally and
never removes. Chunk ids are content-addressed, so changing chunking produces
*new* ids and leaves every old chunk in the store. Measured, on this machine,
immediately after the change:

```
default index after `make retrieval-report`:  1203 vectors
a clean build of the same corpus:              908 vectors
overall hit@5, stale index:  0.702
overall hit@5, clean index:  0.851
```

295 stale chunks, and a headline figure wrong by 0.149 — in the pessimistic
direction here, but nothing makes that the general case. Every number in this
iteration was measured in a fresh index directory for exactly this reason; the
numbers in `retrieval.md` are reproducible from a clean index and not otherwise.

I rebuilt the user's `data/index` with `make reindex` afterwards, since my own
run had mixed old and new chunks into it. `data/index/` is gitignored, so a fresh
clone is unaffected — this bites anyone who has run the tool before.

The fix is not obvious enough to bolt on here. `index_all(rebuild=True)` in the
eval path is correct but forces a 25-minute re-embed of the whole corpus on every
e5-large run. Detecting that the store holds chunk ids outside the current chunk
set, and refusing to report rather than reporting quietly, is cheaper and more in
keeping with the rest of this codebase. That is the next iteration.

Also still open from iteration 1: `pam_authentication_failure` never captures
`rhost`; the candidate pattern is written down there and remains untested.

---

## Iteration 3 — the evaluation was measuring a stale index

**Date:** 2026-09-19

### What I audited, and what I found

`engine/sentinel/indexer.py`, `store.py`, `engine.py`, `cli.py`,
`retrieval_eval.py`, and the fixtures in `engine/tests/conftest.py`.

This defect was found by iteration 2's own verification, not by looking for it.
Running the *undecorated* `make retrieval-report` — the command the README
documents, with no flags — reported overall hit@5 **0.702** where every
fresh-directory run in that iteration had measured **0.851**.

The cause is two deliberate properties meeting:

* `index_documents` skips ids already in the store (`existing_ids`) and never
  removes one. That is correct for the write path: re-indexing an unchanged
  corpus must embed nothing, since embedding dominates the cost.
* Child ids are content-addressed over parent id, ordinal and text.

Together, changing the chunker or the estimator produces entirely new ids and
leaves every superseded vector in place. Only `index --rebuild` calls `reset()`.
Nothing on the read path checked, so the superseded chunks stayed retrievable and
competed for the top k. Measured on this machine:

```
store after `make retrieval-report`:  1203 vectors
a clean build of the same corpus:      908 vectors
overall hit@5, stale index:  0.702
overall hit@5, clean index:  0.851
```

**This is the third instance of the same pattern in this repo**, and the reason
it keeps surviving is structural: CI starts from an empty index directory, and
every fixture in `conftest.py` points at `tmp_path`. Neither can reach a state
that only exists on a machine that has run the tool before. The `--cases` bug had
exactly this shape.

### What I chose, and why

**Detect and refuse, rather than prune.** `eval-retrieval` now compares
`vectors.count()` against `IndexStats.children_total` — the number of chunks the
current corpus and chunking actually produce, which the indexer already computes
— and returns non-zero with the gap named and `make reindex` suggested.

Over the alternatives: `index_all(rebuild=True)` in the eval path is correct but
forces a 25-minute re-embed on every e5-large run, and would have made iteration
2 considerably more expensive for no measurement benefit. Pruning the store to
the current id set is the real fix, but it changes the write path for every
caller including the dashboard, and `index_all` is not the only thing that writes
vectors — deleting "anything not in this set" risks removing chunks added by
another path. A guard that converts a silent wrong number into a loud actionable
one is strictly better than today and does not risk data.

No new store surface was needed: `count()` and `children_total` both already
existed.

### What I changed

- `retrieval_eval.stale_chunk_count(store_count, corpus_chunk_count)` — the
  detector, with the measurement above in its docstring.
- `cmd_eval_retrieval` — refuses before evaluating, printing the two counts and
  `make reindex`. No override flag; the remedy is one command.
- `engine/tests/test_retrieval_eval.py` — four tests in
  `TestStaleIndexIsRefusedRatherThanMeasured`.
- `docs/design/retrieval.md` — a new "The index the numbers are measured against"
  section, and the tables now say why each run used a fresh directory.

### Mutation table

| Leg removed | Test that failed |
|---|---|
| the guard in `cmd_eval_retrieval` (report anyway) | `test_the_command_refuses_instead_of_printing_wrong_numbers` |
| `stale_chunk_count` always returns 0 | `test_chunks_the_corpus_no_longer_produces_are_detected`, `test_the_command_refuses_instead_of_printing_wrong_numbers` |

The refusal test asserts `"hit@5" not in out`, so a mutation that prints the
report *and* the warning still fails — the point is that no numbers escape.

### Measurements

End to end, through `make`, not through the test suite:

| Scenario | Result |
|---|---|
| clean index, `make retrieval-report PYTHON=python3` | reports normally — 0.638 / 0.766 / **0.851** / 0.713 |
| index built at `child_tokens=400`, re-run at `SENTINEL_CHILD_TOKENS=200` | **refuses**: "index is stale: 2742 vectors in the store, but the current corpus and chunking produce 1869", `make` exits 1 |
| index built on 400 events, re-run against the full event log | reports normally — later events form new windows rather than rewriting existing ones |

`make test-py` in `.venv/ci` with **no requirements.txt installed**: 600 passed,
1 skipped. `make lint`: ruff clean. `make vet` clean, all 9 Go packages pass under
`-race`, `go.mod` untouched.

I also rebuilt the user's `data/index` with `make reindex` at the end of
iteration 2, because my own undecorated run had mixed old and new chunks into it.
It now holds 908 vectors, matching a clean build. `data/index/` is gitignored.

### What I did NOT verify

- **Whether the guard is too strict in real use.** It compares counts, not id
  sets, so anything that adds vectors outside `index_all` reads as staleness. I
  tested the ordinary-ingestion case and it does not trip; I did **not** test a
  truncation landing mid-window, which would rewrite that window's document and
  should trip it. Someone actively ingesting who hits this gets told to re-embed
  their whole corpus, which on e5-large is 25 minutes.
- **The dashboard and `sentinel analyze` still read a stale index silently.**
  Only the evaluation path refuses. The content there is older cuts of the same
  documents rather than wrong documents, so I judged it less severe, but it is
  unfixed and unmeasured.
- **ChromaVectorStore.** Everything here ran on `LocalVectorStore`, which is what
  the eval and the tests use. `count()` exists on both, so the check should
  behave the same, but I did not run it against Chroma.
- Docker remains unreachable in this session (`permission denied` on the socket,
  no passwordless sudo), independently of the user's DNS timeout.

### Found and not fixed

- **Pruning is still the real fix.** A store that cannot be brought into line
  with its corpus except by re-embedding everything is a design gap, not just a
  reporting one. It needs `VectorStore.prune(keep_ids)` on both backends and a
  decision about which callers are allowed to prune.
- `pam_authentication_failure` still never captures `rhost` (iteration 1 has the
  verified defect and an untested candidate pattern).
- The per-direction and same-language-preference analyses in `retrieval.md` are
  still marked as pre-fix and un-rerun.
