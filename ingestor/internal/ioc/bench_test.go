package ioc

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// benchScale is the feed size the design is argued at: a few million indicators
// is what an aggregated commercial or community feed set actually looks like.
const benchScale = 1_000_000

// benchIndicators generates a deterministic feed of mixed indicator types.
func benchIndicators(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			out[i] = fmt.Sprintf("%d.%d.%d.%d", 100+(i/16777216)%56, (i/65536)%256, (i/256)%256, i%256)
		case 1:
			out[i] = fmt.Sprintf("host%07d.malware%d.example", i, i%97)
		default:
			out[i] = fmt.Sprintf("%064x", i)
		}
	}
	return out
}

// TestMemoryFootprintAtFeedScale measures the claim this package is built on,
// rather than asserting it.
//
// The claim: at feed scale, holding every indicator in a Go map costs tens to
// hundreds of megabytes resident, while the Bloom filter that fronts them costs
// single-digit megabytes — and that difference is what justifies accepting a
// probabilistic structure and a confirmation step at all.
//
// Run it directly to see the numbers:
//
//	go test ./internal/ioc/ -run TestMemoryFootprintAtFeedScale -v
//
// The map figure has to include the indicator *text*, not only the map's
// buckets. The first version of this measured the heap delta around building a
// map from an already-allocated []string, and reported 38 MiB — but a map keyed
// on those strings does not copy them, so that number was the bucket overhead
// alone and silently omitted the 33 MiB of text a real loader would have
// allocated reading the feed off disk. It understated the map by roughly half,
// in the direction that flatters this package.
//
// strings.Clone is what fixes it: each key is freshly allocated inside the
// measured region, so the delta is what a from-disk load actually retains. The
// Bloom filter needs no such accounting because it retains nothing — that is the
// whole point, and it is only a fair comparison if the other side is charged for
// what it keeps.
func TestMemoryFootprintAtFeedScale(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a few hundred megabytes; skipped under -short")
	}
	keys := benchIndicators(benchScale)

	var rawBytes int
	for _, k := range keys {
		rawBytes += len(k)
	}

	// Measure the heap delta with the map alive, forcing a GC on both sides so
	// the difference is retained memory rather than uncollected garbage.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[strings.Clone(k)] = struct{}{}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	mapBytes := after.HeapAlloc - before.HeapAlloc
	runtime.KeepAlive(set)

	b, err := New(uint64(len(keys)), DefaultFPR, DefaultSalt1, DefaultSalt2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, k := range keys {
		b.Add(k)
	}
	bloomBytes := (b.Bits() + 7) / 8

	mib := func(v uint64) float64 { return float64(v) / 1024 / 1024 }
	t.Logf("indicators:      %d", len(keys))
	t.Logf("  indicator text %.1f MiB (the bytes themselves)", mib(uint64(rawBytes)))
	t.Logf("  go map         %.1f MiB resident (text + string headers + buckets)", mib(mapBytes))
	t.Logf("  bloom filter   %.1f MiB resident (%d probes, est. FPR %.2e)",
		mib(bloomBytes), b.Probes(), b.EstimatedFPR())
	t.Logf("  ratio          %.0fx smaller than the map", float64(mapBytes)/float64(bloomBytes))
	t.Logf("  per indicator  %.1f bytes as a map, %.1f bits as a filter",
		float64(mapBytes)/float64(len(keys)),
		float64(b.Bits())/float64(len(keys)))

	// A guard, not the point of the test: if this ever stops being a large win,
	// the design's justification has gone with it.
	if bloomBytes*10 > mapBytes {
		t.Errorf("bloom is %.1f MiB against a %.1f MiB map — less than a 10x saving, "+
			"which no longer justifies the confirmation step",
			mib(bloomBytes), mib(mapBytes))
	}
}

// The common case: a candidate that is not in the feed. This is what runs on
// essentially every log line, and it must not touch the disk.
func BenchmarkBloomMiss(b *testing.B) {
	keys := benchIndicators(benchScale)
	f, err := New(uint64(len(keys)), DefaultFPR, DefaultSalt1, DefaultSalt2)
	if err != nil {
		b.Fatal(err)
	}
	for _, k := range keys {
		f.Add(k)
	}
	absent := benchIndicators(1000)
	for i := range absent {
		absent[i] = "absent-" + absent[i]
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.MayContain(absent[i%len(absent)])
	}
}

func BenchmarkBloomHit(b *testing.B) {
	keys := benchIndicators(benchScale)
	f, err := New(uint64(len(keys)), DefaultFPR, DefaultSalt1, DefaultSalt2)
	if err != nil {
		b.Fatal(err)
	}
	for _, k := range keys {
		f.Add(k)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.MayContain(keys[i%len(keys)])
	}
}

// The confirmation seek, so the cost of a filter hit is a measured number rather
// than an assumption. Run against a store large enough that the binary search is
// doing real work.
func BenchmarkStoreLookup(b *testing.B) {
	const n = 200_000
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{
			Indicator: fmt.Sprintf("host%07d.malware.example", i),
			Type:      TypeDomain,
			Feed:      "bench",
		}
	}
	prepared, err := prepare(recs)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "store")
	if err := writeStore(path, prepared); err != nil {
		b.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("host%07d.malware.example", i%n)
		if _, ok, err := s.Lookup(key); err != nil || !ok {
			b.Fatalf("Lookup(%q) ok=%v err=%v", key, ok, err)
		}
	}
}

// The honest comparison. The Bloom filter's job is to keep candidates off the
// disk, but if pulling candidates out of a log line costs more than looking them
// up, then the filter is saving memory rather than time — and the package
// comment should say so. This measures the extraction half on its own.
func BenchmarkExtractCandidates(b *testing.B) {
	entities := map[string]string{"source_ip": "203.0.113.45", "dest_ip": "192.168.1.42"}
	msg := "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.45 " +
		"DST=192.168.1.42 LEN=60 PROTO=TCP SPT=51000 DPT=23 host=c2.malware.example"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractCandidates(entities, msg)
	}
}

// End to end on a clean line: extraction plus the filter rejections, which is
// what the ingestor pays on the overwhelming majority of events.
func BenchmarkFeedMatchClean(b *testing.B) {
	feed := benchFeed(b)
	entities := map[string]string{"source_ip": "10.1.2.3"}
	msg := "Accepted publickey for alice from 10.1.2.3 port 51234 ssh2"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := feed.Match(entities, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func benchFeed(b *testing.B) *Feed {
	b.Helper()
	const n = 100_000
	keys := benchIndicators(n)
	recs := make([]Record, 0, n)
	for _, k := range keys {
		recs = append(recs, Record{Indicator: k, Feed: "bench"})
	}
	dir := b.TempDir()
	bloomPath := filepath.Join(dir, "ioc.bloom")
	storePath := filepath.Join(dir, "ioc.store")
	if err := Build(bloomPath, storePath, recs, DefaultFPR, DefaultSalt1, DefaultSalt2); err != nil {
		b.Fatal(err)
	}
	feed, err := Load(bloomPath, storePath)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { feed.Close() })
	return feed
}
