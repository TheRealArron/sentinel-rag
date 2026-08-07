package ioc

import (
	"fmt"
	"os"
	"sort"
	"sync/atomic"
)

// Hit is a confirmed indicator match.
type Hit struct {
	Record    Record
	Candidate Candidate
}

// Stats records what the two tiers actually did. Exported so the ingestor can
// print it with -stats.
//
// Confirmed and FalsePositives are the pair worth watching. Their ratio is the
// filter's *observed* false-positive rate on real traffic, which is the only
// number that says whether the sizing was right — a filter that was built for a
// feed twice its eventual size, or reused after the feed grew, degrades quietly
// and this is where it shows up.
type Stats struct {
	Candidates     int64 `json:"candidates"`
	BloomHits      int64 `json:"bloom_hits"`
	Confirmed      int64 `json:"confirmed"`
	FalsePositives int64 `json:"bloom_false_positives"`
	LookupErrors   int64 `json:"lookup_errors"`
}

// Feed is the two-tier matcher: a RAM-resident Bloom prefilter in front of an
// on-disk exact store. See the package comment for why it is shaped this way.
//
// Safe for concurrent use by every pipeline worker: the filter is immutable
// after load, the store reads via ReadAt, and the counters are atomic.
type Feed struct {
	bloom *Bloom
	store *Store

	candidates atomic.Int64
	bloomHits  atomic.Int64
	confirmed  atomic.Int64
	falsePos   atomic.Int64
	lookupErrs atomic.Int64
}

// Load reads a compiled feed bundle: the Bloom filter and the sorted store that
// the Python feed compiler emits together.
//
// The two files are a matched pair. A filter built from one snapshot and a store
// from another is the subtle failure this guards against — the filter would
// admit indicators the store no longer has (harmless, just wasted seeks) but
// also *miss* indicators the store gained, which is a silent detection gap. The
// compiler writes the store's declared count into the filter's key count, and
// Load refuses the pair if they disagree.
func Load(bloomPath, storePath string) (*Feed, error) {
	data, err := os.ReadFile(bloomPath)
	if err != nil {
		return nil, fmt.Errorf("read ioc bloom %s: %w", bloomPath, err)
	}
	b, err := UnmarshalBloom(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", bloomPath, err)
	}
	s, err := OpenStore(storePath)
	if err != nil {
		return nil, err
	}
	if s.Count() != int64(b.Len()) {
		s.Close()
		return nil, fmt.Errorf(
			"ioc bundle mismatch: %s holds %d indicators, %s was built for %d -- "+
				"rebuild both with `make ioc`",
			storePath, s.Count(), bloomPath, b.Len())
	}
	return &Feed{bloom: b, store: s}, nil
}

// NewFeed assembles a feed from an already-built filter and store. Used by tests
// and by tooling that builds both in memory.
func NewFeed(b *Bloom, s *Store) *Feed { return &Feed{bloom: b, store: s} }

// Close releases the store's file handle.
func (f *Feed) Close() error {
	if f == nil {
		return nil
	}
	return f.store.Close()
}

// Len reports how many indicators the feed covers.
func (f *Feed) Len() int64 {
	if f == nil || f.bloom == nil {
		return 0
	}
	return int64(f.bloom.Len())
}

// Match returns every confirmed indicator referenced by an event.
//
// The order of operations is the whole design: extract candidates, reject almost
// all of them against the in-memory filter, and only then pay for an exact
// lookup. A candidate that the filter rejects has been *proven* absent — Bloom
// filters have no false negatives — so the early return is not an approximation.
//
// A lookup error (a truncated or unlinked store mid-run) is counted and the
// candidate is skipped rather than aborting ingestion. Losing enrichment on some
// events is bad; dropping the events entirely because a side index broke is
// worse, and the error surfaces in Stats and on the event itself.
func (f *Feed) Match(entities map[string]string, message string) ([]Hit, error) {
	if f == nil || f.bloom == nil || f.store == nil {
		return nil, nil
	}
	candidates := ExtractCandidates(entities, message)
	if len(candidates) == 0 {
		return nil, nil
	}
	f.candidates.Add(int64(len(candidates)))

	var hits []Hit
	var firstErr error
	for _, c := range candidates {
		if !f.bloom.MayContain(c.Value) {
			continue // proven absent, no disk touched
		}
		f.bloomHits.Add(1)

		rec, ok, err := f.store.Lookup(c.Value)
		if err != nil {
			f.lookupErrs.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !ok {
			// The filter said maybe and the store said no. This is the designed
			// cost of the prefilter, not an anomaly, so it is counted rather than
			// logged.
			f.falsePos.Add(1)
			continue
		}
		f.confirmed.Add(1)
		hits = append(hits, Hit{Record: rec, Candidate: c})
	}

	// Deterministic order: an event matching two indicators must produce the same
	// event JSON on every run, or the committed sample fixture drifts.
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Record.Type != hits[j].Record.Type {
			return hits[i].Record.Type < hits[j].Record.Type
		}
		return hits[i].Record.Indicator < hits[j].Record.Indicator
	})
	return hits, firstErr
}

// Stats snapshots the counters.
func (f *Feed) Stats() Stats {
	if f == nil {
		return Stats{}
	}
	return Stats{
		Candidates:     f.candidates.Load(),
		BloomHits:      f.bloomHits.Load(),
		Confirmed:      f.confirmed.Load(),
		FalsePositives: f.falsePos.Load(),
		LookupErrors:   f.lookupErrs.Load(),
	}
}

// Summary renders the loaded feed for startup logging, including the filter's
// memory footprint and its estimated false-positive rate at the fill it actually
// has. Both are printed because they are the two numbers that justify the
// design, and an operator should be able to check them rather than trust them.
func (f *Feed) Summary() string {
	if f == nil || f.bloom == nil {
		return "no ioc feed loaded"
	}
	return fmt.Sprintf("%d indicators, bloom %s (%d probes, est. FPR %.2e), store %s",
		f.bloom.Len(), humanBytes((f.bloom.Bits()+7)/8),
		f.bloom.Probes(), f.bloom.EstimatedFPR(), f.store.Path())
}

// humanBytes renders a byte count at a sensible scale. A demo-sized feed shows
// bytes rather than "0.0 KiB", which reads as a bug.
func humanBytes(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/1024/1024)
	}
}
