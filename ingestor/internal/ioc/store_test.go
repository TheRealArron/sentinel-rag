package ioc

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// buildTestBundle writes a bloom/store pair into a temp dir and returns a loaded
// feed plus the store path.
func buildTestBundle(t *testing.T, recs []Record) (*Feed, string) {
	t.Helper()
	dir := t.TempDir()
	bloomPath := filepath.Join(dir, "ioc.bloom")
	storePath := filepath.Join(dir, "ioc.store")
	if err := Build(bloomPath, storePath, recs, DefaultFPR, testSalt1, testSalt2); err != nil {
		t.Fatalf("Build: %v", err)
	}
	feed, err := Load(bloomPath, storePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { feed.Close() })
	return feed, storePath
}

// The property that matters: every record written must be findable. Binary
// search over variable-length lines has off-by-one failure modes that only show
// up at particular sizes and boundaries, and they fail by returning "not found"
// — indistinguishable from a clean feed with no threats in it.
func TestStoreFindsEveryRecord(t *testing.T) {
	// Sizes chosen around block-boundary arithmetic: a single record, sizes that
	// straddle readChunk, and one comfortably past it.
	for _, n := range []int{1, 2, 3, 7, 8, 9, 63, 64, 65, 511, 512, 513, 5000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			recs := make([]Record, n)
			for i := range recs {
				recs[i] = Record{
					Indicator: fmt.Sprintf("host%06d.example.com", i),
					Type:      TypeDomain,
					Feed:      "test",
					Note:      "synthetic",
				}
			}
			dir := t.TempDir()
			storePath := filepath.Join(dir, "s")
			if err := writeStore(storePath, mustPrepare(t, recs)); err != nil {
				t.Fatalf("writeStore: %v", err)
			}
			s, err := OpenStore(storePath)
			if err != nil {
				t.Fatalf("OpenStore: %v", err)
			}
			defer s.Close()

			for i := 0; i < n; i++ {
				key := fmt.Sprintf("host%06d.example.com", i)
				rec, ok, err := s.Lookup(key)
				if err != nil {
					t.Fatalf("Lookup(%q): %v", key, err)
				}
				if !ok {
					t.Fatalf("Lookup(%q) missed a record the store contains", key)
				}
				if rec.Indicator != key || rec.Type != TypeDomain || rec.Feed != "test" {
					t.Fatalf("Lookup(%q) returned %+v", key, rec)
				}
			}
		})
	}
}

// Absent keys must miss — including keys that sort before the first record,
// after the last, and between two adjacent ones. Sorting before everything is
// the interesting case: it lands on the header line.
func TestStoreMissesAbsentKeys(t *testing.T) {
	recs := []Record{
		{Indicator: "10.0.0.5", Type: TypeIP, Feed: "f"},
		{Indicator: "evil.example.com", Type: TypeDomain, Feed: "f"},
		{Indicator: "malware.example.net", Type: TypeDomain, Feed: "f"},
	}
	feed, storePath := buildTestBundle(t, recs)
	_ = feed
	s, err := OpenStore(storePath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	absent := []string{
		"0.0.0.0",             // sorts below every record
		"1.1.1.1",             // below the first
		"10.0.0.4",            // just below a record
		"10.0.0.6",            // just above a record
		"good.example.com",    // between two records
		"zzz.example.org",     // above every record
		"evil.example.co",     // prefix of a record
		"evil.example.commmm", // record is a prefix of it
	}
	for _, key := range absent {
		if _, ok, err := s.Lookup(key); err != nil {
			t.Fatalf("Lookup(%q): %v", key, err)
		} else if ok {
			t.Errorf("Lookup(%q) claimed a match the store does not contain", key)
		}
	}
}

// The header is skipped by ordering rather than by a special case, which is only
// safe if '#' really does sort below every byte a normalised indicator can start
// with. Pin it, because it is an invisible coupling between the writer and the
// search.
func TestHeaderSortsBeforeEveryIndicator(t *testing.T) {
	// Every first byte a normalised indicator can have: digits (IPv4, and hashes
	// starting with a digit), ':' (IPv6 like ::1), and lowercase letters.
	var firsts []byte
	for c := byte('0'); c <= '9'; c++ {
		firsts = append(firsts, c)
	}
	for c := byte('a'); c <= 'z'; c++ {
		firsts = append(firsts, c)
	}
	firsts = append(firsts, ':')
	for _, c := range firsts {
		if '#' >= c {
			t.Errorf("'#' (0x%02x) does not sort below indicator byte %q (0x%02x); "+
				"the store header would no longer be skipped by ordering", '#', c, c)
		}
	}
}

func TestOpenStoreRejectsMalformedFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"empty", "", "empty"},
		{"no header", "10.0.0.1\tip\tf\t\n", "header"},
		{"no trailing newline", "#sentinel-ioc-store v1 count=1\n10.0.0.1\tip\tf\t", "newline"},
		{"wrong version", "#sentinel-ioc-store v99 count=0\n", "version"},
		{"no version", "#sentinel-ioc-store count=0\n", "no version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "s")
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := OpenStore(p)
			if err == nil {
				t.Fatalf("accepted a %s store", tc.name)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Every pipeline worker confirms against the same store concurrently. This is
// the test that fails if a Seek-then-Read implementation ever creeps back in:
// under -race the shared offset shows up as interleaved reads returning another
// goroutine's record.
func TestConcurrentLookupsAreIsolated(t *testing.T) {
	const n = 2000
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Indicator: fmt.Sprintf("h%05d.example.com", i), Type: TypeDomain, Feed: "f"}
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "s")
	if err := writeStore(storePath, mustPrepare(t, recs)); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += 8 {
				key := fmt.Sprintf("h%05d.example.com", i)
				rec, ok, err := s.Lookup(key)
				if err != nil {
					t.Errorf("Lookup(%q): %v", key, err)
					return
				}
				if !ok || rec.Indicator != key {
					t.Errorf("Lookup(%q) returned %+v ok=%v — another goroutine's record?",
						key, rec, ok)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// A store built from one feed snapshot and a filter from another is a silent
// detection gap: the filter would reject indicators the store has gained.
func TestLoadRejectsMismatchedBundle(t *testing.T) {
	dir := t.TempDir()
	bloomPath := filepath.Join(dir, "a.bloom")
	storeA := filepath.Join(dir, "a.store")
	storeB := filepath.Join(dir, "b.store")

	small := []Record{{Indicator: "10.0.0.1", Type: TypeIP, Feed: "f"}}
	big := []Record{
		{Indicator: "10.0.0.1", Type: TypeIP, Feed: "f"},
		{Indicator: "10.0.0.2", Type: TypeIP, Feed: "f"},
	}
	if err := Build(bloomPath, storeA, small, DefaultFPR, testSalt1, testSalt2); err != nil {
		t.Fatal(err)
	}
	if err := writeStore(storeB, mustPrepare(t, big)); err != nil {
		t.Fatal(err)
	}
	_, err := Load(bloomPath, storeB)
	if err == nil {
		t.Fatal("Load accepted a filter and store built from different snapshots")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not name the mismatch", err)
	}
}

// The writer must sort, deduplicate and normalise regardless of input order,
// because the search's correctness depends on the ordering and callers feed it
// whatever a threat feed happened to contain.
func TestBuildNormalisesAndSorts(t *testing.T) {
	recs := []Record{
		{Indicator: "EVIL.Example.COM.", Type: TypeDomain, Feed: "f"},
		{Indicator: "10.0.0.1", Type: TypeIP, Feed: "f"},
		{Indicator: "evil.example.com", Type: TypeDomain, Feed: "dup"},
		{Indicator: "::ffff:192.0.2.9", Type: TypeIP, Feed: "f"},
		{Indicator: "DEADBEEFDEADBEEFDEADBEEFDEADBEEF", Type: TypeHash, Feed: "f"},
		{Indicator: "not a real indicator", Feed: "f"},
	}
	feed, storePath := buildTestBundle(t, recs)

	// The duplicate collapsed and the junk was dropped: 4 records, not 6.
	if got := feed.Len(); got != 4 {
		t.Errorf("feed holds %d indicators, want 4", got)
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	want := "#sentinel-ioc-store v1 count=4\n" +
		"10.0.0.1\tip\tf\t\n" +
		"192.0.2.9\tip\tf\t\n" + // IPv4-mapped IPv6 folded to its IPv4 form
		"deadbeefdeadbeefdeadbeefdeadbeef\thash\tf\t\n" +
		"evil.example.com\tdomain\tf\t\n" // uppercase and trailing dot normalised
	if string(data) != want {
		t.Errorf("store contents:\n%q\nwant:\n%q", data, want)
	}
}

func mustPrepare(t *testing.T, recs []Record) []Record {
	t.Helper()
	out, err := prepare(recs)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return out
}
