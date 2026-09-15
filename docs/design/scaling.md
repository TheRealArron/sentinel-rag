# Scaling: where this system actually breaks

An audit of the load-bearing paths, the four defects it found, and the numbers
before and after. Everything here was measured on this machine (13th Gen Core
i7-13620H, Linux) with the scripts described under each heading. Nothing is
extrapolated except where it says so.

The four are grouped by what they have in common, because it turned out to be one
mistake wearing four hats: **a quantity chosen by an attacker was allowed to drive
work or memory that nothing bounded.** Log volume is not the input that breaks a
SecOps tool. Distinct source addresses are, and an attacker picks those.

| Defect | Symptom | Before | After |
|---|---|---|---|
| Cubic shape detection | Dashboard hangs during a scan | 330 s @ 1600 events | 0.11 s |
| Quadratic index writes | Indexing never finishes | 50.9 s / 1.66 GB @ 4000 vectors | 0.70 s / 13.2 MB |
| Unbounded correlator state | Heap growth from usernames | unbounded | 64 users / 128 stamps per source |
| Unbounded rate-limiter table | Heap growth from source IPs | 12,288 buckets and climbing | 4,096 hard cap |

---

## 1. The attack graph DoS'd itself during an attack

`AttackGraph.shapes()` runs synchronously on every `/api/graph` request, over a
buffer of up to 20,000 events. Three of its four detectors scanned every edge in
the graph once per node, and `_chains` asked for a fresh breadth-first search
once per **(source, target) pair**.

Reproduce with a synthetic graph where each event contributes a distinct source
address and a distinct file:

```
events   nodes   edges   shapes_s
   100     320     300      0.056
   200     620     600      0.400
   400    1220    1200      4.493
   800    2420    2400     40.119
  1600    4820    4800    330.399
```

Every doubling multiplied the time by seven to nine — cubic. The input driving it
is the number of distinct source addresses, which is exactly what explodes during
a distributed scan or a botnet credential attempt. **A dashboard poll during the
incident the graph exists to display would have hung the server for hours.** The
tool's failure mode was triggered by the attack it was watching.

Three changes:

* Endpoint indexes (`_edges_from`, `_edges_to`) built as edges are added, so the
  scan-per-node detectors became scan-once.
* `_chains` runs **one** traversal per source instead of one per pair. A single
  BFS already yields the distance to every reachable node, so the deepest target
  in that one traversal is the same answer the pair loop computed.
* A source that never obtained access has no outgoing access edge and cannot
  begin a chain, so it is rejected by a dict lookup. This is the common case
  during brute force — thousands of addresses that only ever failed — and the old
  code still paid a function call per pair to reach the same conclusion. That
  call overhead alone was most of the 330 seconds.

Pruning fixes the realistic explosion but not credential stuffing that *works*,
where many sources genuinely authenticate. So the work is also capped:
`MAX_CHAIN_SOURCES` traversals, ranked by peak score, and `MAX_SHAPES` findings
returned. The output was always going to be a ranked top-N — nobody triages the
251st kill chain — so computing more than that bought nothing.

After, at the API's own 20,000-event ceiling:

```
                     build_s   shapes_s
all sources succeed    0.574      0.551      (worst case)
all sources fail       1.261      0.066      (a real scan)
```

Regression tests are in `tests/test_graph.py::TestShapeDetectionScales`. They
assert the **work bound**, not the wall clock: a timing assertion tight enough to
catch a regression is also tight enough to flake on a loaded CI runner.

One note on how the test was written, because the first version was worthless.
It imported `MAX_CHAIN_SOURCES` and asserted the traversal count against it —
circular, since raising the constant raises the bound with it. Confirmed still
passing with the cap set to 100,000. It now asserts the count is *sub-linear in
the attacker-supplied source count*, and fails at 2000/2000 when the cap is
removed.

## 2. Indexing was quadratic, so the documented limit was unreachable

`LocalVectorStore.add` rewrote the entire JSONL file, and the indexer calls it
once per embedding batch of 16. A run of *n* vectors therefore performed *n/16*
full rewrites of a file growing towards *n*.

```
vectors  wall time  bytes written  final file  amplification
    500      0.9 s        27.8 MB      1.6 MB          16.9x
   1000      2.3 s       106.3 MB      3.3 MB          32.2x
   2000     10.6 s       415.3 MB      6.6 MB          63.0x
   4000     50.9 s      1655.1 MB     13.2 MB         125.5x
```

Extrapolated to `LOCAL_BACKEND_SOFT_LIMIT`, a 50,000-vector index would have
taken about **2.2 hours** and written about **258 GB** to produce a 165 MB file.
So the documented soft limit could never be reached, and — worse — the constant's
comment justified it by *query* cost while the real ceiling was in the writer. It
described the wrong bottleneck.

JSONL is an append-friendly format; the code simply was not using it that way.
`add` now appends only new rows, duplicate ids resolve last-wins at load, and the
file is compacted when superseded rows outnumber live ones — which bounds it at
roughly twice its minimum size and keeps writes amortised O(1).

```
vectors  wall time  full rewrites
    500      0.10 s             0
   1000      0.20 s             0
   2000      0.42 s             0
   4000      0.70 s             0
```

And the soft limit is now a real number rather than a hypothetical:

```
vectors  index    file     reload   query
 10000    2.16 s   33.0MB   1.18 s   380 ms
 25000    6.57 s   82.5MB   2.51 s  1062 ms
 50000   13.81 s  165.0MB   6.22 s  1743 ms
```

At 50,000 the *query* is what hurts, at 1.74 s — which is what the constant
always claimed, and is now true.

### Durability

Compaction still goes through temp-file-and-rename, so it is atomic. A plain
append is not: a crash mid-write can leave a partial final line. That is strictly
safer than what it replaced, because existing rows are never rewritten and only
the newest append is ever at risk.

Tolerating the torn line at read time is not sufficient, though, and this is the
subtle part. The bytes stay on disk, so the *next* append lands directly after
them and welds two half-records into one corrupt line — losing a vector that had
been written successfully. `_load` therefore truncates back to the last complete
record. `test_torn_final_line_is_repaired_not_just_skipped` fails without it.

## 3. Bounding the outer map is not bounding memory

`correlate.Correlator` documents its memory story carefully: `MaxTrackedIPs`
caps tracked sources at 8192 with LRU eviction, "because an attacker choosing a
fresh source address per packet must not be able to grow our heap without limit."

The reasoning is right and the bound was only half applied. Each `sourceState`
held an unbounded `users` set and an unbounded `failures` slice, and **both are
grown by attacker-controlled input** — the SSH username is chosen by whoever is
connecting, and the sanitiser permits 256 bytes of it. 8192 sources times an
unbounded set per source is not a bound.

Both are now capped (`maxUsersPerSource = 64`, `maxFailuresPerSource = 128`),
which is far above anything the detection logic reads: spraying is declared at 3
distinct users, the alert lists 10, and the brute-force threshold defaults to 5.
Saturating either changes no verdict. It only makes the reported *detail*
approximate, and the true volume is preserved in `total_failures_seen`, which is
a counter rather than a collection and stays exact.

Two details worth recording:

* A saturated count is reported as `>=128`, not `128`. Rendering a capped figure
  as though it were exact would understate a flood by an arbitrary amount.
* Expiry runs **before** recording, not after. The first version pruned
  afterwards, which let a buffer still full of stale timestamps reject the new
  one — so a source that saturated once could never register another failure even
  after its window drained completely, and would sit at a count of zero while
  being actively attacked. `test_a_saturated_source_recovers_once_its_window_drains`
  caught it.

## 4. The rate limiter's own bound did not bind

`RateLimiter` keys buckets on the source address and swept entries idle longer
than `capacity / refill` — 60 seconds at the defaults — with a comment noting
that growth is attacker-controlled.

The sweep does not bound anything. A caller rotating source addresses *faster*
than the idle threshold leaves every bucket looking fresh, so nothing is ever
evicted and the table grows for as long as the addresses keep changing. This is
not a theoretical rotation budget: a single host with a routed IPv6 /64 can
source from 2^64 distinct addresses, all of which reach the server and each of
which mints a bucket. The control protecting the API had become a way to exhaust
its memory. Measured: 12,288 buckets retained where the intended ceiling was
4,096, still climbing linearly with the number of addresses used.

Now the idle sweep runs first, and if the table is still at the cap, eviction
continues by least-recently-used until it is under.

LRU is the right direction here, and it is worth being explicit about why, since
evicting a bucket resets that client's allowance. An attacker mid-flood is by
definition *recently* used, so they are the last evicted and stay throttled; what
gets dropped is idle clients, who were not being throttled anyway. Refusing to
track new clients instead would let an attacker who filled the table lock every
subsequent visitor out of rate limiting entirely.

---

## What was checked and found sound

Recording this because "audited" should mean something, and because the parts
that held up are the reason the four above were findable at all.

* **`EventBuffer`** — bounded deque, byte-offset incremental reads, inode and
  truncation detection for logrotate, and a `_seen` set that is explicitly
  cleared rather than allowed to grow. This is the pattern the other three
  defects should have followed.
* **The ingest pipeline** — bounded line reads that discard past a cap rather
  than accumulate, a reorder buffer that restores log order before stateful
  correlation, and backpressure through bounded channels.
* **`ParentDocumentRetriever`** — every loop bounded by `candidate_k` or the
  language count; the per-language floor costs one extra query per language.
* **`ShadowSearch`** — linear in the event buffer, which is itself capped.
* **The two HTTP adapters** — FastAPI and the stdlib server genuinely share one
  `routes.Router`, so the security controls cannot diverge between them. Body
  size cap, strict CSP, no CORS headers at all.
* **Chroma** — the production vector backend was never affected by defect 2; its
  `upsert` is incremental. The quadratic write path only ever hit the
  dependency-free fallback, which is the default on a clean checkout and
  therefore the path most people would meet first.

## Method

```bash
# graph scaling
python3 scratch/measure_graph.py          # linear-ish workload
python3 scratch/measure_graph2.py         # source x target product
python3 scratch/measure_graph3.py         # worst case at the 20k API cap

# index write amplification
python3 scratch/measure_index.py          # instruments _flush, counts bytes
python3 scratch/measure_index_big.py      # index / reload / query at the soft limit
```

The measurement scripts are not committed — they are throwaway harnesses, and the
properties they demonstrated are now pinned by tests that run in CI:

* `tests/test_graph.py::TestShapeDetectionScales`
* `tests/test_retrieval.py::TestLocalVectorStore` (append-log behaviour)
* `tests/test_guard.py::TestRateLimiterMemoryIsBounded`
* `internal/correlate/correlate_test.go::TestPerSourceStateIsBounded`

Each was confirmed to fail against the defect it describes before being kept.

---

## Since

`internal/ship` was not covered by this audit and was examined separately; see
[spool.md](spool.md). It found the same mistake a fifth time — the spool cap is
expressed in bytes while every operation on it cost one pass over its *files*,
and outage duration, which an attacker chooses, sets the file count. It also
found the torn-write defect from §2 repeated in another package, which is the
better argument for writing these notes down.
