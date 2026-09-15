# The spool: delivering telemetry when the hub is gone

An audit of `internal/ship`, the five defects it found, and the numbers before
and after. Measured on this machine (13th Gen Core i7-13620H, Linux). Nothing is
extrapolated except where it says so.

`transport.md` covers how the probe proves who it is. This note covers what
happens after that: getting the events there, and what the shipper owes an
operator when it cannot.

The package doc already states the standard — *"silent truncation of security
telemetry is its own incident"*. Four of the five defects are that standard not
being met by the code underneath it, and the fifth is the previous audit's
finding wearing a new hat.

| Defect | Symptom | Before | After |
|---|---|---|---|
| Unserialised flush | Duplicate events at the hub | every event delivered 4x | exactly once |
| Non-atomic spool write | Torn batch posted to the hub | `{"seq":3,"raw_sha` | truncated and counted |
| `Dropped` mixes units | Loss under-reported | 3 reported for 300 lost | 300 |
| Spool rescanned per flush | Quadratic work during an outage | 32,004,000 entries @ 8k files | 0 |
| No durability barrier | Spooled batch lost to a power cut | page cache | fsync + rename + dir sync |

---

## 1. Three callers, one spool, no lock

`Flush` is reachable from three places at once: the pipeline's collector
goroutine when a batch fills, the shipper's own ticker every `FlushEvery`, and
`Close`. `main.go` adds a fourth, calling `Flush` on the `-stats` path while the
deferred `Close` is still pending. Each one calls `replaySpool`, which lists the
spool directory, posts every file, then deletes it.

Nothing serialised that. Two concurrent flushes both enumerated the same files
and both sent them, and the delete raced behind. Under a four-goroutine flush
against six spooled files, **every one of the 60 events arrived four times**:

```
60 event(s) delivered more than once by concurrent flushes:
  4x {"seq":26,"raw_sha256":"0000000000000000000000000000000
  4x {"seq":2,"raw_sha256":"00000000000000000000000000000000
```

Duplicate delivery is not a cosmetic fault here. The hub's job is to reconstruct
what happened on a host, and this is the one component whose entire purpose is an
accurate record. Four copies of a failed login is a brute-force pattern that did
not occur.

A `send` mutex now serialises everything that talks to the hub or mutates the
spool. It is held across the network call deliberately, so a slow hub applies
backpressure to the pipeline instead of letting work pile up in memory. Lock
order is always `send` then `mu`, and nothing takes them the other way.

Serialising also restores the ordering the package claims. Replay is documented
as oldest-first precisely so a reconstructed timeline is truthful, and concurrent
senders interleave batches no matter how carefully the listing is sorted.

## 2. The spool wrote torn batches, and replayed them

`spool()` used `os.WriteFile`, which neither fsyncs nor renames. Both matter, and
they fail differently.

Without the fsync the batch sits in the page cache, so a power cut loses events
that the shipper has already reported as safely spooled — for a buffer whose
entire reason to exist is the window when the network is down, and which the
package doc introduces with *"the moment the network breaks is exactly the moment
worth recording"*.

Without the rename, a crash mid-write leaves a **partial file under its final
name**. It is listed like any other batch and posted verbatim, so the hub is
handed a body whose last line is half a record:

```
hub was handed an unparseable fragment: "{\"seq\":3,\"raw_sha"
```

This is the previous audit's finding in a different package. `LocalVectorStore`
had the same shape, and the note there applies unchanged: tolerating a torn
record at read time is not enough, because the bytes stay on disk.

`ioc.writeFileAtomic` already argues the whole case — *"the rename is atomic with
respect to other processes, but not with respect to a power cut"* — and every
durable write in the engine follows it. The spool was the one that did neither.
It now writes to a temporary file, fsyncs, renames, and then syncs the directory.

The directory sync goes one step beyond `writeFileAtomic`, and the asymmetry is
deliberate: the IOC bundle is derived from an upstream feed, so a lost rename
means rebuilding it. A spooled batch is derived from nothing. It *is* the
delivery queue, and nothing the shipper can reach can regenerate it.

Atomic writes stop new torn batches appearing but do not clean up a spool that
survived the upgrade, so `replaySpool` also drops an incomplete trailing line
rather than posting it. The fragment is one event at most — it was the last line
— and it is counted, not swallowed.

## 3. One number reporting two units

`Stats.Dropped` is a single figure surfaced through `-stats`, and it is the only
signal an operator gets that telemetry was lost. It was being incremented in two
different units. `spool()` added the *event* count when there was no spool
directory; `trimSpool()` added **1 per evicted file**, and a file holds up to
`BatchSize` events.

Evicting three 100-event files reported `3`:

```
Dropped = 3, which is not a whole number of 100-event batches
```

That is 100x under-reporting in the test's shape and up to 500x at the default
`BatchSize`. The count is already on disk — `spool()` writes
`<unixnano>-<count>.ndjson` — and simply was not being read. A file whose name
does not parse falls back to 1 rather than 0, because under-reporting is the
thing being fixed.

Eviction is now counted whether or not the unlink succeeds. A file the shipper
has stopped tracking will never be replayed, so it is lost to the hub either way,
and the accounting has to say so.

## 4. The cap was in bytes; the work was per file

This is the previous audit's thesis again: **a quantity chosen by an attacker
drove work that nothing bounded.**

Every operation on the spool cost one pass over its files. `trimSpool`
enumerated the directory and stat'd every entry on each `spool()`, `replaySpool`
enumerated it on each `Flush`, and `Stats` enumerated it per call. The cap is
expressed in bytes — `SpoolMaxMB`, default 256 — but nothing bounds the *file
count*, and the file count is what the work scales with.

One file is written per flush, so outage duration picks it. The package doc
observes that an attacker who can reach the host can arrange for the network to
break; the same attacker therefore chooses how long the outage lasts.

Spooling N one-event batches, then one replay attempt and one stats read:

```
   files   entries_read   seconds        entries_read   seconds
                  (before)                       (after)
     500         125,250     1.748                   0     1.422
    1000         500,500     3.451                   0     2.830
    2000       2,001,000     9.345                   0     5.917
    4000       8,002,000    29.905                   0    11.222
    8000      32,004,000    95.036                   0    23.103
```

Clean n²/2. Sixteen times the files cost 256 times the directory work.

The extrapolation matters more than the measurement. A one-event batch encodes to
219 bytes, so at the default 256 MiB cap the spool holds **1,225,732 files**, and
reaching that cap costs about 7.5x10¹¹ directory entries examined. Long before
that the probe is spending every flush stat'ing a million files it already knows
about.

The listing is now built once, in `scanSpool`, and maintained incrementally.
Trimming costs what it evicts rather than what it retains, which is the point:
eviction is rare, and the retained set is the quantity an attacker sizes.

The new code is also faster in wall clock — 23.1 s against 95.0 s at 8,000 files
— despite adding two syncs per spooled batch that the old path did not perform.

One behaviour changed with it: the directory is scanned once, at construction, so
a file dropped into the spool by hand while the shipper is running is no longer
picked up. That was never a supported way to feed it — two writers sharing one
spool directory would already have double-sent every batch in it.

---

## What was checked and found sound

* **mTLS setup** — a bad certificate is a startup error, not a per-request one,
  and the reasoning is right: a shipper that starts and then silently fails to
  authenticate is indistinguishable from a quiet network. TLS 1.3 floor, hub
  pinned to its own CA, `InsecureSkipVerify` reachable only by explicit opt-in.
* **403 handling** — a revoked probe is surfaced distinctly from a network fault,
  because retrying cannot help and spooling forever would hide it.
* **Replay ordering** — stopping at the first failure, rather than skipping past
  it, is correct on both counts it claims: ordering holds, and a hub that is
  still down is not handed the whole backlog.
* **Response reading** — capped with `io.LimitReader`, so a hostile or broken hub
  cannot make the probe read an unbounded body.
* **Composition with the local sink** — shipping tees rather than replaces, so a
  hub outage plus a spool overflow is not silent total loss.

## Method

The measurement harness is not committed; it is a throwaway that instruments the
`readDir` seam and prints the table above. The seam itself is committed, because
the work bound is the property worth pinning and a wall-clock assertion tight
enough to catch defect 4 would flake on a loaded runner.

The properties are pinned by tests in `internal/ship/ship_test.go`:

* `TestConcurrentFlushDoesNotDuplicateSpooledEvents`
* `TestTornWriteIsNeverReplayed`
* `TestTornBatchFromAnOlderBuildIsTruncatedNotPosted`
* `TestDroppedCountsEventsNotFiles`
* `TestSpoolWorkDoesNotScaleWithSpoolSize`

Each was confirmed to fail against the defect it describes before being kept, by
reintroducing that defect alone into a scratch copy of the package. `TestSpoolWork…`
asserts sub-linearity in the retained spool rather than comparing against the
constant that sets the bound — the trap recorded in `scaling.md`, where a bound
test that imports its own limit keeps passing as the limit is loosened.

Defect 2's fsync has no regression test and cannot have one: no unit test
observes whether a write reached the platter without cutting power. The atomicity
it pairs with *is* observable, and is tested. The fsync rests on the argument
above and on consistency with every other durable write in the project.
