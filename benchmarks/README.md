# Benchmarks — Go vs Python for log-pattern matching

The ingestor is written in Go. This directory exists to check whether that was
the right call, using the project's **actual 33 detection patterns** against an
identical corpus, rather than repeating the folklore that "Go is fast and Python
is slow."

**The headline result contradicts the folklore.** Python's `re` is roughly **two
times faster** than Go's `regexp` on this workload. The case for Go survives, but
it is a different case than the one usually made, and it is stronger for being
accurate.

## Reproducing

```bash
# generate the shared corpus from the Go side, so both languages see identical input
cd ingestor
SENTINEL_BENCH_CORPUS_OUT=/tmp/corpus.txt go test ./internal/enrich/ -run TestDumpBenchCorpus -v

# Go
go test ./internal/enrich/ -run '^$' -bench BenchmarkRuleSetSingleThread -benchtime=3s

# Python
pip install google-re2        # optional, for the third column
python3 benchmarks/regex_bench.py --corpus /tmp/corpus.txt --repeats 8
```

Fairness controls, because a benchmark that flatters your own choice is worthless:

* Patterns are **extracted from `ingestor/internal/enrich/rules.go`**, not
  retyped, so the two harnesses cannot silently diverge. All 33 compile unchanged
  under both engines.
* The corpus is generated once by Go and written to disk; Python reads that exact
  file.
* Both sides precompile every pattern before timing starts.
* Timing excludes I/O and corpus generation.
* Each language is run alternately, three rounds, minimum reported.

## Results

10,000 generated `sshd`/`sudo`/`kernel` lines × 33 patterns, single-threaded.
Ryzen laptop, Go 1.26.5, CPython 3.12. Five alternating rounds per engine.

| Engine | Algorithm | min ns/line | median | max | Relative (min) |
|---|---|---:|---:|---:|---:|
| Python `re` | backtracking | **22,234** | 32,326 | 35,488 | **1.00× (fastest)** |
| Python `google-re2` | RE2 (NFA/DFA) | 40,132 | 58,236 | 62,814 | 1.80× slower |
| Go `regexp` | RE2 (NFA/DFA) | 40,296 | 58,722 | 72,836 | 1.81× slower |

**Minimum is the reported statistic, not the mean.** This is a thermally
throttled laptop, not a quiet benchmark rig; run-to-run noise only ever *adds*
time, so the minimum is the best available estimate of true cost. Medians and
maxima are shown so the spread is visible rather than hidden.

The single most informative number in the table is the last comparison:

```
Go regexp / google-re2  =  1.00×
```

The two RE2 implementations — one compiled Go, one a C++ library behind a CPython
binding — cost **the same to within measurement error**, while the backtracking
engine is 1.8× faster than both. That is the whole story in one line: **the gap
is the regex algorithm, not the language.** RE2 gives up average-case speed to
buy a worst-case guarantee, and it costs the same wherever you run it.

Any explanation that reaches for "compiled versus interpreted" has to account for
Go and CPython landing on the identical number here.

### The worst case it buys

`^(a+)+$` against `"a"*n + "b"` — nested quantifiers over an overlapping class,
the textbook ReDoS trigger. It never matches, which forces a backtracking engine
to explore every path.

| n | Python `re` | Go `regexp` |
|---:|---:|---:|
| 18 | 22 ms | — |
| 20 | 102 ms | 1.0 µs |
| 22 | 404 ms | — |
| 24 | 1,453 ms | — |
| 26 | 5,161 ms | — |
| 2,000 | *(would not terminate)* | 94 µs |

Python grows ~3.6× per two additional characters. Go grows **91× for a 100×
larger input** — linear, asserted by `TestReDoSIsLinearInGo`, not just measured.

Extrapolating Python's curve to n=40, the input the Go benchmark uses:
**~10 hours, versus 2 microseconds.** (Extrapolated, not measured — waiting for it
was not a good use of an afternoon.)

## What this actually justifies

Reordered by what the evidence supports:

1. **Guaranteed linear-time matching on hostile input.** This is a log parser.
   The input is chosen by a remote attacker — they pick the SSH username. If one
   rule in the set is backtracking-vulnerable, a single crafted username is a
   denial of service against the entire security monitoring pipeline, and the
   monitoring goes down exactly when it is needed. RE2 makes that class of bug
   *unrepresentable* rather than something to audit for on every new rule. On a
   security tool this is a correctness property, not a performance one, and it is
   the strongest reason in the list.

2. **Real parallelism.** Measured end-to-end on the actual binary over a 500k-line
   file: 10,268 → 52,986 lines/s from 1 to 16 workers, a **5.2× speedup**. Python
   would need multiprocessing to approach this, which means serialising log lines
   across process boundaries — and the per-line work here is small enough that the
   IPC would eat much of the gain. This is where the GIL argument is legitimate,
   and it is about parallelism, not about `re` being slow.

3. **A static, dependency-free binary.** The ingestor imports nothing outside the
   standard library, so the container is `FROM scratch` with no shell, no libc,
   and no package manager. On the component that reads attacker-controlled input,
   the absence of a supply chain is worth more than a constant factor.

4. **Bounded memory by construction.** 27 MB peak on a 47 MB input; 5.9 MB peak
   when fed a single 4 MiB line.

Net: Go is ~2× slower per match and ~5.2× faster in aggregate, so the throughput
win is real but modest — roughly 2.6×. **Go was chosen for the guarantees, and
parallelism happens to more than cover the per-match deficit.** If the ReDoS
argument did not exist, this would be a much closer call, and an honest reading is
that a Python ingestor using `google-re2` and multiprocessing would be a
defensible alternative.

## Where the time goes

Slowest patterns under Python `re` (ns/line, whole 10k corpus):

| ns/line | Rule |
|---:|---|
| 6,412 | `segfault` |
| 6,681 | `sudo_not_in_sudoers` |
| 5,470 | `reverse_shell_bash_devtcp` |
| 5,205 | `disk_error` |
| 4,477 | `sudo_incorrect_password` |

Median across all 33 rules: **896 ns/line**. The distribution is heavily skewed —
the five slowest cost as much as the other twenty-eight combined. They share a
shape: leading alternations with no literal anchor, so the engine cannot reject
the line cheaply.

That points directly at the optimisation named in the main README: a
required-literal prefilter (`strings.Contains` before the regex) would let most
rules reject most lines without entering the engine at all. It is not implemented
— 53k lines/s already exceeds what a home server generates by four orders of
magnitude, and unmeasured optimisation is how simple code stops being simple.
This table is what would justify implementing it, if the workload ever changed.

## Threats to validity

* One machine, one corpus shape. A corpus of longer lines, or one where more
  rules match, would shift the numbers.
* The corpus is synthetic. It is modelled on the real sample log, but real
  `/var/log/auth.log` has a different rule-hit distribution.
* CPython 3.12 only. PyPy would likely change the Python column substantially.
* `re` numbers are single-threaded by construction; the comparison deliberately
  isolates per-match cost from the parallelism question rather than conflating
  the two.

---

## The cost of the detection-surface split

`docs/design/detection.md` describes a fix that stops an attacker-chosen SSH
username from selecting which rule fires. It added work to the hot path: rules
are evaluated in two passes, the attacker-chosen spans of a line are blanked
between them, and raw-surface matches are re-confirmed against the blanked text.

That was shipped flagged as *expected to be small, but not measured*. Here is the
measurement.

### What the split costs, isolated

`BenchmarkSurfaceSplit` compares the same matching work with and without the
redaction machinery around it. Paired baselines, because the two corpora are
different lines and comparing across them would measure the line rather than the
change. Go 1.22.12, 13th Gen Intel Core i7-13620H, `-benchtime=2s -count=5`,
minimum of five reported.

| Line | Baseline | With the split | Delta | Allocs |
|---|---:|---:|---:|---:|
| carries a `user` capture | 102.2 µs | 111.7 µs | **+9.2%** | 2 → 6 |
| carries no untrusted span | 119.2 µs | 119.3 µs | **+0.0%** | 4 → 4 |

The second row is the design working as intended: with nothing attacker-chosen to
blank, `redactUntrusted` returns its input unchanged and `confirmAgainstRedacted`
returns immediately, so the whole mechanism costs one string comparison. The 21 ns
difference is noise.

An earlier version of this benchmark compared `ApplyWith` against a bare two-pass
match and reported a much larger delta as "the cost of redaction". That was wrong
— the bare match also skipped captures, modifiers, tag merging and scoring, so it
was measuring most of enrichment. The numbers above replaced it.

### End to end

500,000 synthetic `sshd` lines (49 MB) from the same generator as `benchCorpus`,
written to `/dev/null` so the numbers measure the parse path rather than the
disk. Same machine, same binary flags, one run each.

| Workers | Before | After | Throughput | Peak RSS |
|---:|---:|---:|---:|---:|
| 1 | 54.04 s | 64.30 s | 9,252 → 7,776 lines/s | 20.1 → 21.1 MB |
| 16 | 5.95 s | 7.03 s | 84,034 → 71,124 lines/s | 27.4 → 30.8 MB |

**+18% wall time at 16 workers, and this is the worst case.** Every line in this
corpus is an sshd authentication line carrying a username, so every line pays the
full redaction cost. Real syslog is a mix — kernel, systemd, cron, dbus — and
those lines take the 0.0% path. The 9.2% figure above is the per-line cost when
you pay it; the 18% here is what happens when you pay it on every line, plus the
widened `.+` username captures, which ask the regex engine to do more work than
`[^\s]+` did.

Memory is unchanged in character: still flat, still bounded by buffers rather
than input, 30.8 MB peak on a 49 MB file.

### Threats to validity

- **Different hardware from the headline table in the main README.** That one was
  taken on a Ryzen laptop with Go 1.26.5 and reports 52,986 lines/s at 16
  workers; this is an i7-13620H with Go 1.22.12. The two are **not** comparable,
  and the numbers here should be read only against each other.
- **One run per cell**, not a distribution. The 18% gap is far outside run-to-run
  variance on this machine, but the individual figures are not precise.
- **The corpus is adversarially uniform.** It was chosen to make the cost
  visible, not to represent a real log stream.
- **Not measured:** whether the split changes throughput on a realistic mixed
  corpus, and whether the extra allocations matter under sustained load. Both are
  answerable; neither was answered here.

Is 71,000 lines/s still enough? A home server generates on the order of tens of
lines per second. The margin is four orders of magnitude either way, so the fix
is bought with headroom that was never going to be used — which is the right
trade for closing a remotely reachable defect, and would be the wrong one if the
margin were thin.
