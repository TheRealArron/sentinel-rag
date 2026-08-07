package ioc

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

const (
	testSalt1 = uint64(0x5345_4e54_494e_454c) // "SENTINEL"
	testSalt2 = uint64(0x494f_4300_0000_0001) // "IOC\0...1"
)

// A Bloom filter is allowed to say "maybe" for a key it never saw. It is never
// allowed to say "no" for a key it did — that would be a silent detection gap,
// and no amount of confirmation downstream can recover from it.
func TestBloomHasNoFalseNegatives(t *testing.T) {
	keys := make([]string, 20000)
	for i := range keys {
		keys[i] = fmt.Sprintf("198.51.100.%d/%d", i%256, i)
	}
	b, err := New(uint64(len(keys)), DefaultFPR, testSalt1, testSalt2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, k := range keys {
		b.Add(k)
	}
	for _, k := range keys {
		if !b.MayContain(k) {
			t.Fatalf("false negative for %q — the filter dropped a key it was given", k)
		}
	}
}

// The observed false-positive rate has to track the target. This is the test
// that would catch a degenerate probe sequence (see normaliseSalt2): such a
// filter passes every other test here, because it still has no false negatives
// and still round-trips — it is only *worse than it claims*, and only this
// measurement notices.
func TestObservedFPRMatchesTarget(t *testing.T) {
	const (
		n      = 50000
		target = 1e-3
		trials = 400000
	)
	b, err := New(n, target, testSalt1, testSalt2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < n; i++ {
		b.Add(fmt.Sprintf("present-%d.example.com", i))
	}

	false_ := 0
	for i := 0; i < trials; i++ {
		if b.MayContain(fmt.Sprintf("absent-%d.example.org", i)) {
			false_++
		}
	}
	observed := float64(false_) / float64(trials)

	// A generous bound: this is a probabilistic property and the test must not
	// flake, but 4x the target is far tighter than the order-of-magnitude gap a
	// broken probe sequence produces.
	if observed > target*4 {
		t.Errorf("observed FPR %.2e exceeds 4x the %.0e target (%d/%d) — probe sequence is degenerate",
			observed, target, false_, trials)
	}
	// Also check the header's own estimate is honest about the filter it
	// describes, since that number is what the ingestor prints at startup.
	if est := b.EstimatedFPR(); math.Abs(est-observed) > target*4 {
		t.Errorf("EstimatedFPR %.2e disagrees with observed %.2e", est, observed)
	}
	t.Logf("n=%d target=%.0e observed=%.2e estimated=%.2e bits=%d k=%d",
		n, target, observed, b.EstimatedFPR(), b.Bits(), b.Probes())
}

func TestSizeForRejectsImpossibleRates(t *testing.T) {
	for _, p := range []float64{0, 1, -0.5, 2} {
		if _, _, err := SizeFor(1000, p); err == nil {
			t.Errorf("SizeFor accepted an out-of-range rate %g", p)
		}
	}
}

func TestSizeForTracksTheFormula(t *testing.T) {
	// 1M keys at 1e-4 is the sizing the docs quote, so it is pinned here: if the
	// formula drifts, the documented memory figure becomes a lie.
	m, k, err := SizeFor(1_000_000, 1e-4)
	if err != nil {
		t.Fatalf("SizeFor: %v", err)
	}
	wantM := uint64(math.Ceil(-1e6 * math.Log(1e-4) / (math.Ln2 * math.Ln2)))
	if m != wantM {
		t.Errorf("m = %d, want %d", m, wantM)
	}
	if k != 13 {
		t.Errorf("k = %d, want 13", k)
	}
	if mib := float64(m) / 8 / 1024 / 1024; mib < 2 || mib > 3 {
		t.Errorf("1M indicators sized to %.2f MiB, expected ~2.3 MiB", mib)
	}
}

func TestBloomRoundTrips(t *testing.T) {
	b, err := New(1000, DefaultFPR, testSalt1, testSalt2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 1000; i++ {
		b.Add(fmt.Sprintf("key-%d", i))
	}
	blob, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	got, err := UnmarshalBloom(blob)
	if err != nil {
		t.Fatalf("UnmarshalBloom: %v", err)
	}
	if got.Bits() != b.Bits() || got.Probes() != b.Probes() || got.Len() != b.Len() {
		t.Fatalf("header drift: got m=%d k=%d n=%d, want m=%d k=%d n=%d",
			got.Bits(), got.Probes(), got.Len(), b.Bits(), b.Probes(), b.Len())
	}
	for i := 0; i < 1000; i++ {
		if !got.MayContain(fmt.Sprintf("key-%d", i)) {
			t.Fatalf("key-%d lost across serialisation", i)
		}
	}
}

// Corruption has to be rejected rather than tolerated. A filter with a zeroed or
// truncated tail still answers every query — it just answers some of them wrong,
// in the false-negative direction, which is the one direction that loses
// detections.
func TestUnmarshalRejectsCorruption(t *testing.T) {
	b, _ := New(500, DefaultFPR, testSalt1, testSalt2)
	for i := 0; i < 500; i++ {
		b.Add(fmt.Sprintf("k%d", i))
	}
	good, _ := b.MarshalBinary()

	cases := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{"bad magic", func(d []byte) []byte { d[0] = 'X'; return d }, "bad magic"},
		{"wrong version", func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[8:12], 99)
			return d
		}, "version"},
		{"truncated header", func(d []byte) []byte { return d[:10] }, "truncated"},
		{"truncated body", func(d []byte) []byte { return d[:len(d)-32] }, "body"},
		{"flipped bit", func(d []byte) []byte { d[len(d)-1] ^= 0x01; return d }, "checksum"},
		{"zero bits", func(d []byte) []byte {
			binary.LittleEndian.PutUint64(d[16:24], 0)
			return d
		}, "zero bits"},
		{"zero probes", func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[12:16], 0)
			return d
		}, "zero probes"},
		{"even salt2", func(d []byte) []byte {
			binary.LittleEndian.PutUint64(d[40:48], 0xAAAA)
			return d
		}, "even"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := make([]byte, len(good))
			copy(cp, good)
			_, err := UnmarshalBloom(tc.mutate(cp))
			if err == nil {
				t.Fatalf("accepted a %s filter", tc.name)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The odd-salt rule is a property of construction, not just of validation: New
// must fix an even salt rather than build a filter Unmarshal would later reject.
func TestNewForcesOddSalt(t *testing.T) {
	b, err := New(100, DefaultFPR, testSalt1, 0xAAAA)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	blob, _ := b.MarshalBinary()
	if _, err := UnmarshalBloom(blob); err != nil {
		t.Fatalf("New produced a filter its own reader rejects: %v", err)
	}
}

func TestNilBloomIsSafe(t *testing.T) {
	var b *Bloom
	if b.MayContain("anything") {
		t.Error("nil filter claimed a match")
	}
	if b.Len() != 0 || b.Bits() != 0 || b.Probes() != 0 || b.EstimatedFPR() != 0 {
		t.Error("nil filter reported non-zero geometry")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
