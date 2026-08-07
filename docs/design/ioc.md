# Threat-feed matching at feed scale

Phase 5 chose a plain hash set for honeytokens and explicitly deferred the Bloom
filter to "IOC matching, where the candidate set is millions of indicators,
memory is the binding constraint, and a positive can afford a confirmation lookup
before it means anything." This note is that phase, and it is mostly about the
second half of that sentence — the confirmation lookup is what makes the rest of
it work.

## The structure

```
candidate ──▶ Bloom filter (RAM, 2.3 MiB/M) ──▶ miss: proven absent, stop
                     │
                   hit (real or false)
                     ▼
              sorted store (disk) ──▶ binary search ──▶ exact verdict
```

A Bloom filter has no false negatives, so a miss is a *proof* of absence and
costs one cache-resident probe. That is the overwhelming majority of candidates
and it never touches the disk. A hit is only a maybe, and is resolved against the
sorted store before it is allowed to mean anything.

The output of the package therefore has **zero false positives** — the same
correctness property honeytokens have, and the property Phase 5 said a
probabilistic structure could not offer — while resident memory is proportional
to bits-per-key rather than bytes-per-key.

## Why the exact tier is on disk

This is the part that is easy to get wrong, and getting it wrong makes the whole
design pointless.

A Bloom filter in front of an **in-memory** exact set saves nothing. If the set
is resident anyway, the filter is a pure addition: extra memory, an extra hash,
and no benefit except a slightly faster negative path. The memory saving only
exists because the exact data is *not* resident.

So the store is a sorted file, binary-searched on demand. The Bloom filter
answers almost every candidate without a lookup, and the top few levels of the
search stay in page cache because every search visits them.

Keeping it a **text** file rather than an indexed binary blob is deliberate: an
operator can `grep` a store to answer "is this address in my feeds" with no
Sentinel tooling at all, and a feed refresh produces a readable diff. The sort
order *is* the index, so no side table is needed.

## Measured

All figures from this repository, reproducible as noted. Nothing here is
estimated.

### Memory

```
go test ./internal/ioc/ -run TestMemoryFootprintAtFeedScale -v
```

| 1,000,000 indicators | Resident | Per indicator |
|---|---|---|
| Indicator text alone | 33.5 MiB | 35 bytes |
| Go `map[string]struct{}` | **73.9 MiB** | 77 bytes |
| Bloom filter (13 probes, FPR 1e-4) | **2.3 MiB** | 19.2 bits |

**32x**, scaling linearly — the aggregated feed sets this is aimed at run to
several million indicators, where the map side passes a third of a gigabyte.

The map figure includes the indicator text, not just bucket overhead. The first
version of that measurement did not, and reported 38 MiB: it built the map from
an already-allocated `[]string`, and a map keyed on strings does not copy them,
so the number omitted the 33 MiB a real loader would allocate reading the feed
off disk. It understated the map by roughly half, in the direction that flattered
this package. `strings.Clone` inside the measured region is the fix.

### Speed

```
go test ./internal/ioc/ -bench . -benchmem -run '^$'
```

| Operation | Cost |
|---|---|
| Bloom probe, miss | 114 ns |
| Bloom probe, hit | 169 ns |
| Store lookup (confirmation seek) | 30 µs |
| Candidate extraction, before gating | 30.6 µs |
| Candidate extraction, after gating | 23.1 µs |
| `Feed.Match`, clean line, end to end | 7.7 µs |

**The Bloom filter is not what makes this fast.** A probe is 114 nanoseconds;
extraction is two orders of magnitude more. It is worth stating plainly, because
"we put a Bloom filter in front of it" invites the opposite assumption. What the
filter actually buys is the 32x memory saving and the avoidance of a ~30 µs store
lookup per candidate. Both real; neither is what a reader would guess.

The dominant cost is pulling candidates out of a log line. Measured individually
on a UFW line: IPv4 5.2 µs, IPv6 5.5 µs, hash 8.1 µs, hostname 9.7 µs — about
28 µs of regex, against roughly 65 µs for the entire 33-rule detection sweep.
Adding that unconditionally would have made feed matching nearly half the cost of
enrichment, for a stage that answers "no" almost every time.

So the regexes are gated behind one linear byte scan that records whether the
message contains `.`, contains `:`, and its longest run of hex digits. Each gate
is a **necessary condition** of its pattern, not a heuristic — an IPv4 or
hostname needs a dot, an IPv6 needs a colon, a digest needs 32+ consecutive hex
characters — so a gate can never skip a regex that would have matched.
`TestGatesNeverSkipARealMatch` checks that against the ungated path directly,
because an unsound gate would drop indicators silently.

## The hashing defect that only a measurement would have caught

The filter originally salted FNV-1a directly: `fnv1a(salt1||key)` and
`fnv1a(salt2||key)`, on the reasoning that Bloom filters need uniformity rather
than cryptographic strength. That reasoning is correct and the implementation was
still wrong. `TestObservedFPRMatchesTarget` measured **1.7e-2 against a 1e-3
target** — seventeen times worse than the header advertised.

FNV-1a's round is `h = (h XOR b) * prime`, and multiplication never propagates
information downward: bit 0 of a product depends only on bit 0 of its operands.
So the low bits of an FNV hash are close to a plain XOR of the input's low bits,
and two FNV hashes over the same key with different prefixes stay strongly
correlated there. The probe index is `(h1 + i·h2) mod m` with `m` even, so the
modulo reads exactly those correlated low bits and the *k* probes collapse toward
each other. A nominally 10-probe filter was setting far fewer than 10 distinct
bits per key.

Nothing about that is visible from the structure. The filter still had no false
negatives, still round-tripped, still reported a healthy `EstimatedFPR` from its
header arithmetic. It was simply worse than it claimed, and only a measurement
notices — which is the argument in [`benchmarks/`](../../benchmarks/) applied to
a data structure instead of a language.

The fix is the murmur3 64-bit finaliser on each hash: a bijection built from
shift-XOR and multiply specifically to avalanche high bits into low ones.
Measured after: **1.04e-3 against the 1e-3 target**. Salting then happens by XOR
before the finaliser rather than by prefixing bytes, which also hashes the key
once instead of twice.

## Scoring, and the one thing a feed is not allowed to do

Indicator types are not weighted equally, because their evidential value is not
equal:

| Type | Weight | Why |
|---|---|---|
| Hash | +45 | Identifies the artefact itself. Immutable. |
| Domain | +35 | Chosen by its operator, so it carries intent — but domains get parked, sinkholed and resold. |
| IP | +25 | The weakest indicator in common use, and routinely treated as the strongest. Shared by NAT, CDNs and hosting providers; reassigned constantly. |

Multiple hits take the **maximum** weight, not the sum. One connection log can
legitimately mention a source IP, a destination IP and a hostname, so additive
weights would let an ordinary verbose line climb on nothing but repetition. The
extra hits are still recorded as context; they just do not compound.

A feed hit never overwrites a built-in rule's verdict. "Failed SSH password from
a known C2" is a better alert than either half alone, so the rule keeps the
verdict and the indicator rides along as context. An event that matched no rule
at all becomes `ioc_match`, which is most of the value of importing a feed.

No ATT&CK technique is attached. A feed hit says an indicator was *seen*, not
what was done with it — the same address can appear in reconnaissance, C2 or
exfiltration — and inventing a technique would put an unearned attribution into
the attack graph and the analyst's prompt.

### The cap

The package has no false positives in the sense that matters to it: every filter
hit is confirmed exactly, so a reported indicator really is in the feed. That is
narrower than it sounds. It says the *lookup* was right, not that the *feed* was
— and feed contents are external, mutable, and outside this system's control. A
mistaken or poisoned entry for a public resolver or a CDN address is a normal
occurrence in threat intelligence, not an exotic attack.

Phase 5 established that a honeytoken is the only signal permitted to reach the
score that triggers an automated firewall block, because it is the only one with
no benign explanation and no external dependency. Letting a feed hit stack on top
of a rule match and cross that line would have quietly revoked that property: the
auto-blocker would begin acting on third-party data, and the first symptom would
be a blocked upstream resolver.

So a feed-influenced event is capped at **89**, one below the default
`SENTINEL_RESPONSE_MIN_SCORE`. `TestIOCCannotReachTheResponseThreshold` pins the
relationship, so changing either number fails loudly rather than silently arming
the firewall from a feed.

Critical *severity* is deliberately still reachable. Severity is a label for a
human and starts at 80; the responder threshold is 90 and is the number that
actuates. Capping the label instead would under-report a confirmed malware hash
to an analyst in order to protect against a machine — the wrong trade in both
directions.

## Why Python compiles and Go reads

The same split as [Sigma](sigma.md), for the same reason: the ingestor has an
empty `go.mod`, and feed formats are CSV, JSON and vendor-specific text. Parsing
those belongs on the side that already has the tooling.

```
rules/ioc/*.{txt,csv,json}  ──[ sentinel ioc ]──▶  rules/external/ioc.{bloom,store}  ──▶  ingestor
```

This creates the phase's sharpest failure mode. If the compiler and the reader
disagree about a **single hash bit**, the filter rejects every candidate: the
ingestor starts cleanly, prints a healthy indicator count, and never fires. Each
codebase stays internally consistent, so no test on either side alone would
notice.

`scripts/gen-ioc-vectors.py` therefore generates
`ingestor/internal/ioc/testdata/agreement.json` from the Python implementation,
and both sides assert against it: `ingestor/internal/ioc/agreement_test.go` and
`engine/tests/test_ioc.py`. The vectors cover the raw FNV output, the finaliser,
both salted hashes, the probe positions, the sizing formula, every normalisation
rule including the refusals, and a complete bundle compared byte for byte.
Changing one shift constant from 33 to 32 was confirmed to fail it.

Two subtleties the vectors exist to pin:

* **Rounding.** Go's `math.Round` rounds halves away from zero; Python's `round`
  rounds them to even. On an exact `.5` the two would choose different *k* and
  produce incompatible filters, so the Python side uses `floor(x + 0.5)`.
* **Wrapping.** Go computes `h1 + i·h2` in `uint64` and lets it wrap. Python
  integers do not wrap, so the compiler masks to 64 bits.

## Normalisation, and the refusal

A feed and a log line that spell the same address differently must produce the
same key, or the indicator never fires — and the symptom is indistinguishable
from a clean network. So IPs are canonicalised through `net.ParseIP` (with
IPv4-mapped IPv6 folded to its IPv4 form), domains are lowercased and
root-dot-stripped, digests are lowercased and length-checked.

**Internationalised domains are refused**, on both sides, consistently. Matching
`пример.рф` requires IDNA, which is a Unicode table problem rather than a string
transformation; the standard library has no implementation, and the ingestor
parses attacker-controlled input, so `golang.org/x/net` is not a trade worth
making here. A half-correct ASCII fold would be worse than refusing: it would
produce a normalised form the compiler would have to reproduce *exactly*, and two
independently half-correct IDNA implementations agreeing is not something to
build a detection on. The compiler reports how many entries it refused rather
than passing them through silently.

## Operating it

```bash
make ioc          # compile rules/ioc/ into rules/external/ioc.{bloom,store}
make ioc-check    # compile without writing, and refresh the agreement vectors
```

The ingestor loads the bundle at startup, so a feed refresh is a recompile and a
restart — never a rebuild. `-ioc-bloom=""` disables matching, which is what
`make sample` uses so the committed fixture describes a default install.

A missing default bundle is silent, because most installs have no feeds
compiled. A missing **explicit** `-ioc-bloom` is an error: an operator who
pointed the ingestor at a feed and saw it start cleanly will assume indicators
are being checked, and starting anyway with matching off is the failure that gets
noticed after an incident rather than during one.

`-stats` reports `bloom_hits`, `confirmed` and `bloom_false_positives`. That last
ratio is the filter's *observed* false-positive rate on real traffic, which is
the only number that says whether the sizing is still right — a filter built for
a feed that has since doubled degrades quietly, and this is where it shows.
