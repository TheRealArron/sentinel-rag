package ship

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
)

// hub is a stand-in for the Sentinel hub: it records every NDJSON line it is
// given so a test can assert on what was actually delivered rather than on what
// the shipper believes it delivered.
type hub struct {
	server *httptest.Server

	mu       sync.Mutex
	lines    []string
	requests int

	status int           // response code to return; 0 means 200
	delay  time.Duration // held open, to widen the window for concurrent senders
}

func newHub(t *testing.T) *hub {
	t.Helper()
	h := &hub{}
	h.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if h.delay > 0 {
			time.Sleep(h.delay)
		}
		h.mu.Lock()
		h.requests++
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if line != "" {
				h.lines = append(h.lines, line)
			}
		}
		status := h.status
		h.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *hub) delivered() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

func (h *hub) counts() (lines, requests int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.lines), h.requests
}

// newShipper wires a Shipper to the test hub. Insecure skips the mTLS material,
// which is exercised separately — these tests are about delivery semantics.
func newShipper(t *testing.T, h *hub, cfg Config) *Shipper {
	t.Helper()
	cfg.URL = h.server.URL
	cfg.Insecure = true
	if cfg.SpoolDir == "" {
		cfg.SpoolDir = t.TempDir()
	}
	if cfg.FlushEvery <= 0 {
		// Long enough that the background ticker does not fire on its own during
		// a test that drives Flush explicitly.
		cfg.FlushEvery = time.Hour
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testEvent(seq int64) *event.Event {
	return &event.Event{
		Seq:       seq,
		RawSHA256: fmt.Sprintf("%064x", seq),
		Message:   fmt.Sprintf("event %d", seq),
		Category:  "authentication",
		Severity:  "high",
		Score:     70,
	}
}

// writeSpoolFile drops a pre-made spool batch on disk, as a failed send would.
func spoolBatch(t *testing.T, dir string, nanos int64, events []*event.Event) {
	t.Helper()
	body, err := encode(events)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	name := filepath.Join(dir, fmt.Sprintf("%d-%09d.ndjson", nanos, len(events)))
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("write spool: %v", err)
	}
}

// Flush is reachable from three places at once — the pipeline's collector
// goroutine when a batch fills, the background ticker every FlushEvery, and
// Close. Each one calls replaySpool, which lists the spool directory, posts every
// file, and deletes it. Nothing serialises that, so two concurrent flushes both
// read the same files and both send them.
//
// The consequence is duplicate security telemetry at the hub: the same events
// arrive twice, from a component whose whole purpose is an accurate record.
func TestConcurrentFlushDoesNotDuplicateSpooledEvents(t *testing.T) {
	h := newHub(t)
	h.delay = 20 * time.Millisecond // widen the race window

	dir := t.TempDir()
	const files, perFile = 6, 10
	for i := 0; i < files; i++ {
		batch := make([]*event.Event, perFile)
		for j := range batch {
			batch[j] = testEvent(int64(i*perFile + j))
		}
		spoolBatch(t, dir, time.Now().UnixNano()+int64(i), batch)
	}

	s := newShipper(t, h, Config{SpoolDir: dir})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Flush()
		}()
	}
	wg.Wait()

	seen := map[string]int{}
	for _, line := range h.delivered() {
		seen[line]++
	}
	var dupes []string
	for line, n := range seen {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%dx %.60s", n, line))
		}
	}
	if len(dupes) > 0 {
		t.Errorf("%d event(s) delivered more than once by concurrent flushes:\n  %s",
			len(dupes), strings.Join(dupes[:min(3, len(dupes))], "\n  "))
	}
	if got := len(seen); got != files*perFile {
		t.Errorf("hub received %d distinct events, want %d", got, files*perFile)
	}
	if remaining, _ := os.ReadDir(dir); len(remaining) != 0 {
		t.Errorf("%d spool file(s) left behind after a successful replay", len(remaining))
	}
}

// Dropped is reported as a single number through -stats and is the operator's
// only signal that telemetry was lost. It has to count one thing.
//
// spool() adds the *event* count when there is no spool directory; trimSpool()
// adds 1 per *file* evicted, and a file holds up to BatchSize events. Mixing the
// two makes the figure meaningless and under-reports loss by up to 500x, in a
// package whose own comment calls silent truncation of security telemetry "its
// own incident".
func TestDroppedCountsEventsNotFiles(t *testing.T) {
	h := newHub(t)
	dir := t.TempDir()

	// A cap small enough that spooling a second batch evicts the first.
	s := newShipper(t, h, Config{SpoolDir: dir, SpoolMaxMB: 1})

	const perFile = 100
	batch := make([]*event.Event, perFile)
	for j := range batch {
		batch[j] = testEvent(int64(j))
	}
	body, err := encode(batch)
	if err != nil {
		t.Fatal(err)
	}

	// Enough batches to exceed 1 MiB and force eviction. spool() and trimSpool()
	// are only ever reached with send held, so hold it here too.
	perBatch := int64(len(body))
	needed := int((1<<20)/perBatch) + 3
	s.send.Lock()
	for i := 0; i < needed; i++ {
		s.spool(body, perFile)
	}
	s.send.Unlock()

	st := s.Stats()
	if st.Dropped == 0 {
		t.Fatalf("nothing was reported dropped after spooling %d batches past a 1 MiB cap "+
			"(%d bytes each)", needed, perBatch)
	}
	// Every eviction discards a whole file of perFile events, so the reported
	// figure must be a multiple of perFile — never a count of files.
	if st.Dropped%perFile != 0 {
		t.Errorf("Dropped = %d, which is not a whole number of %d-event batches: "+
			"the counter is mixing files and events", st.Dropped, perFile)
	}
}

// A write that dies between CreateTemp and Rename must leave nothing replayable.
//
// This is the half of durability a unit test can actually observe. No test can
// prove the fsync reached the platter without cutting power — that call rests on
// the argument in its own comment — but the atomicity it pairs with is checkable:
// a torn write must not be visible under a ".ndjson" name, because replaySpool
// would post it as a truncated batch with a torn last line.
func TestTornWriteIsNeverReplayed(t *testing.T) {
	h := newHub(t)
	dir := t.TempDir()

	// A batch half-written when the power went out, as CreateTemp would have left
	// it, plus one legitimately spooled batch behind it.
	if err := os.WriteFile(filepath.Join(dir, ".spool-torn.tmp"),
		[]byte(`{"seq":99,"message":"half a rec`), 0o600); err != nil {
		t.Fatal(err)
	}
	spoolBatch(t, dir, time.Now().UnixNano(), []*event.Event{testEvent(1)})

	s := newShipper(t, h, Config{SpoolDir: dir})
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	for _, line := range h.delivered() {
		if strings.Contains(line, "half a rec") {
			t.Errorf("a torn write was delivered to the hub: %q", line)
		}
	}
	if lines, _ := h.counts(); lines != 1 {
		t.Errorf("hub received %d lines, want just the one intact batch", lines)
	}
	// The debris must also be swept, or a crash loop fills a disk with files the
	// size cap never accounts for.
	left, _ := os.ReadDir(dir)
	if len(left) != 0 {
		t.Errorf("%d file(s) left in the spool, want none: %v", len(left), left)
	}
}

// Atomic writes stop new torn batches appearing, but they do not clean up a
// spool that survived the upgrade. A probe that crashed mid-write on the old
// build still has a half-written .ndjson on disk, and replaying it hands the hub
// a body whose last line is a fragment.
func TestTornBatchFromAnOlderBuildIsTruncatedNotPosted(t *testing.T) {
	h := newHub(t)
	dir := t.TempDir()

	// Two whole records followed by the fragment a crash left behind. The name
	// claims three events, which is what the old writer would have recorded.
	whole, err := encode([]*event.Event{testEvent(1), testEvent(2)})
	if err != nil {
		t.Fatal(err)
	}
	torn := append(append([]byte(nil), whole...), []byte(`{"seq":3,"raw_sha`)...)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d-%09d.ndjson", time.Now().UnixNano(), 3)),
		torn, 0o600); err != nil {
		t.Fatal(err)
	}

	s := newShipper(t, h, Config{SpoolDir: dir})
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	for _, line := range h.delivered() {
		if !strings.HasSuffix(line, "}") {
			t.Errorf("hub was handed an unparseable fragment: %q", line)
		}
	}
	if lines, _ := h.counts(); lines != 2 {
		t.Errorf("hub received %d lines, want the 2 complete records", lines)
	}
	// The fragment was a real event and it is gone; that has to show up in the
	// number an operator reads, not be silently swallowed.
	if st := s.Stats(); st.Replayed != 2 || st.Dropped != 1 {
		t.Errorf("Replayed=%d Dropped=%d, want 2 and 1", st.Replayed, st.Dropped)
	}
}

// A spooled batch is the copy of record while the hub is unreachable, so what
// lands on disk must be exactly what was handed over — no truncation, no partial
// write.
func TestSpooledContentIsWrittenIntact(t *testing.T) {
	h := newHub(t)
	dir := t.TempDir()
	s := newShipper(t, h, Config{SpoolDir: dir})

	body, err := encode([]*event.Event{testEvent(1)})
	if err != nil {
		t.Fatal(err)
	}
	s.send.Lock()
	s.spool(body, 1)
	s.send.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one spool file, got %d (err %v)", len(entries), err)
	}
	// Content must be complete and parseable, not a partial write.
	got, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("spooled content differs from what was handed to spool()")
	}
}

// The spool cap is expressed in bytes, but every operation on the spool cost one
// pass over its files: trimSpool enumerated the directory and stat'd every entry
// on each spool(), replaySpool enumerated it on each Flush, and Stats enumerated
// it per call. Nothing bounds the file count — one file is written per flush, so
// outage duration picks it, and this package's own doc note observes that an
// attacker who can reach the host can arrange for the network to break.
//
// The bound asserted here is directory entries examined after construction, not
// wall-clock time: a timing assertion tight enough to catch this would flake on a
// loaded runner. Work must not scale with the retained spool, so it is measured
// at two sizes and the larger must not cost meaningfully more.
func TestSpoolWorkDoesNotScaleWithSpoolSize(t *testing.T) {
	var entriesRead int64

	orig := readDir
	readDir = func(name string) ([]os.DirEntry, error) {
		ents, err := orig(name)
		atomic.AddInt64(&entriesRead, int64(len(ents)))
		return ents, err
	}
	t.Cleanup(func() { readDir = orig })

	// Entries examined while spooling n batches, replaying against a down hub,
	// and reporting stats — everything the steady state does during an outage.
	measure := func(n int) int64 {
		h := newHub(t)
		h.status = http.StatusInternalServerError // never drains, so the spool grows
		// A cap far above what this writes, so nothing is evicted and n files are
		// genuinely retained.
		s := newShipper(t, h, Config{SpoolDir: t.TempDir(), SpoolMaxMB: 64})

		body, err := encode([]*event.Event{testEvent(1)})
		if err != nil {
			t.Fatal(err)
		}

		atomic.StoreInt64(&entriesRead, 0) // construction may scan once; measure after
		s.send.Lock()
		for i := 0; i < n; i++ {
			s.spool(body, 1)
		}
		s.send.Unlock()
		_ = s.Flush()
		_ = s.Stats()

		if got := s.Stats().SpoolFile; got != n {
			t.Fatalf("spool holds %d files, want %d — the measurement is not exercising what it claims", got, n)
		}
		return atomic.LoadInt64(&entriesRead)
	}

	const small, large = 50, 400
	smallWork := measure(small)
	largeWork := measure(large)

	// 8x the files must not mean materially more work. Against the rescanning
	// version this is quadratic — roughly n^2/2 entries from trimSpool alone,
	// so ~1,250 against ~80,000.
	if largeWork > 2*smallWork+int64(large) {
		t.Errorf("examined %d directory entries at %d spool files vs %d at %d: "+
			"per-flush work scales with the retained spool, which an attacker sizes "+
			"by keeping the hub unreachable", largeWork, large, smallWork, small)
	}
}

// Replay must stop at the first failure so ordering is preserved and a hub that
// is still down is not hammered with the whole backlog.
func TestReplayStopsAtTheFirstFailure(t *testing.T) {
	h := newHub(t)
	h.status = http.StatusInternalServerError
	dir := t.TempDir()

	for i := 0; i < 5; i++ {
		spoolBatch(t, dir, time.Now().UnixNano()+int64(i), []*event.Event{testEvent(int64(i))})
	}
	s := newShipper(t, h, Config{SpoolDir: dir})
	_ = s.Flush()

	_, requests := h.counts()
	if requests != 1 {
		t.Errorf("%d requests against a failing hub; replay should stop after the first", requests)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 5 {
		t.Errorf("%d spool files remain, want all 5 retained after a failed replay", len(entries))
	}
}

// A probe the hub has revoked gets 403. Retrying cannot help, and the operator
// has to be able to tell that apart from a flaky network.
func TestRevokedProbeSurfacesADistinctError(t *testing.T) {
	h := newHub(t)
	h.status = http.StatusForbidden
	s := newShipper(t, h, Config{})

	if err := s.Write(testEvent(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = s.Flush()

	last := s.LastError()
	if !strings.Contains(last, "403") || !strings.Contains(strings.ToLower(last), "reject") {
		t.Errorf("LastError = %q; a revoked probe must be distinguishable from a network fault", last)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
