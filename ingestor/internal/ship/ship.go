// Package ship streams enriched events to a remote Sentinel hub over mutually
// authenticated TLS.
//
// # Why crypto/tls and net/http rather than gRPC
//
// The mutual-TLS work is identical either way — mTLS is a property of the TLS
// layer, and gRPC's mutual auth *is* TLS mutual auth. What differs is that
// grpc-go would bring roughly forty transitive modules into this binary, whose
// freedom from dependencies is a stated security property: it parses
// attacker-controlled input and ships as a FROM-scratch container with no shell
// and no libc. That cost buys protobuf typing and HTTP/2 multiplexing, neither
// of which a single append-only line stream per probe needs.
//
// NDJSON over chunked HTTP/1.1 is also what Vector, Fluent Bit and the Elastic
// Beats do. It is the ordinary choice for log shipping, not a lesser one.
//
// # Why there is a spool
//
// A log shipper that drops events when the hub is unreachable is worse than
// useless: the moment the network breaks is exactly the moment worth recording,
// and an attacker who can reach the host can arrange for the network to break.
// So an unreachable hub means events go to a bounded on-disk spool and are
// replayed on reconnect, oldest first.
//
// The spool is capped. An unbounded one converts a hub outage into a full disk,
// which takes down the machine it was meant to protect; when the cap is hit the
// oldest spool file is dropped and the loss is counted and reported, because
// silent truncation of security telemetry is its own incident.
package ship

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
)

// Config describes the remote endpoint and its credentials.
type Config struct {
	URL        string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	SpoolDir   string
	SpoolMaxMB int
	BatchSize  int
	FlushEvery time.Duration
	Timeout    time.Duration
	Insecure   bool
}

// Stats is the shipper's own accounting, surfaced through -stats.
type Stats struct {
	Sent      int64 `json:"shipped"`
	Spooled   int64 `json:"spooled"`
	Replayed  int64 `json:"replayed"`
	Dropped   int64 `json:"dropped"`
	Failures  int64 `json:"send_failures"`
	SpoolFile int   `json:"spool_files"`
}

// Shipper batches events and delivers them to the hub.
type Shipper struct {
	cfg    Config
	client *http.Client

	// send serialises everything that talks to the hub or mutates the spool
	// directory. Flush is reachable from three places at once — the pipeline's
	// collector goroutine when a batch fills, the background ticker, and Close —
	// and replaySpool lists the spool, posts each file, then deletes it. With
	// nothing serialising that, two concurrent flushes both enumerated the same
	// files and both sent them: the hub received the same events several times
	// over, from the one component whose purpose is an accurate record. Measured
	// at four-way duplication under a four-goroutine flush.
	//
	// Serialising also restores the ordering the package claims. Replay is
	// documented as oldest-first precisely so a reconstructed timeline is
	// truthful, and concurrent senders interleave batches regardless of the sort.
	//
	// Held across the network call, so a slow hub applies backpressure to the
	// pipeline rather than letting work pile up in memory. Lock order is always
	// send then mu; nothing acquires them the other way.
	send sync.Mutex

	mu      sync.Mutex
	pending []*event.Event
	stats   Stats
	lastErr error
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup

	// spoolIdx is the spool directory held in memory, oldest first, with
	// spoolBytes its running total.
	//
	// The cap is expressed in bytes but every operation on the spool cost one
	// pass over its *files*: trimSpool enumerated the directory and stat'd every
	// entry on each spool(), replaySpool enumerated it on each Flush, and Stats
	// enumerated it per call. Nothing bounds the file count. One file is written
	// per flush, so it is outage duration that picks it — and this package's own
	// doc note observes that an attacker who can reach the host can arrange for
	// the network to break. At the default 2s ticker and a low event rate the
	// files are a few hundred bytes, so the 256 MB cap is reached at roughly
	// 850,000 of them, at which point each 2s flush stat'd all 850,000.
	//
	// The listing is therefore built once, in scanSpool, and maintained
	// incrementally. Every mutation happens under the send mutex, so the order
	// is stable while replaySpool walks it.
	spoolIdx   []spoolEntry
	spoolBytes int64
}

// spoolEntry is one file in the spool as tracked in memory. Base names sort
// chronologically, so the slice order is the replay order.
type spoolEntry struct {
	name   string
	size   int64
	events int64
}

// readDir is indirected so a test can count how often the spool directory is
// enumerated. That count is the work bound this design exists to hold — one
// enumeration at startup, none per flush — and it is the thing worth asserting,
// since a wall-clock assertion tight enough to catch the regression would flake.
var readDir = os.ReadDir

// New builds a Shipper, loading the client certificate and the CA that the hub
// must present. A misconfigured certificate is a startup error rather than a
// per-request one: a shipper that starts and then silently fails to authenticate
// looks exactly like a quiet network.
func New(cfg Config) (*Shipper, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("remote URL is required")
	}
	if !strings.HasPrefix(cfg.URL, "https://") {
		return nil, fmt.Errorf("remote URL must be https, got %q — plaintext log shipping is not supported", cfg.URL)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.SpoolMaxMB <= 0 {
		cfg.SpoolMaxMB = 256
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
	}

	// The client certificate is this probe's identity. Without it the hub closes
	// the connection during the handshake — which is the point of mutual TLS:
	// rejection happens before any application data is exchanged.
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else if !cfg.Insecure {
		return nil, fmt.Errorf("-remote-cert and -remote-key are required (the hub demands mutual TLS)")
	}

	// Pinning the hub to our own CA is the other half. Trusting the system root
	// store would let any publicly-trusted certificate impersonate the hub, and
	// logs are a map of the infrastructure and its weaknesses.
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	} else if !cfg.Insecure {
		return nil, fmt.Errorf("-remote-ca is required so the probe can verify the hub")
	}

	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- opt-in, for local testing only
	}

	s := &Shipper{
		cfg:  cfg,
		done: make(chan struct{}),
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: false},
		},
	}
	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
			return nil, fmt.Errorf("create spool %s: %w", cfg.SpoolDir, err)
		}
		s.scanSpool()
	}

	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// Write implements sink.Sink, so the pipeline ships without knowing it is doing
// anything unusual.
func (s *Shipper) Write(ev *event.Event) error {
	s.mu.Lock()
	s.pending = append(s.pending, ev)
	full := len(s.pending) >= s.cfg.BatchSize
	s.mu.Unlock()
	if full {
		return s.Flush()
	}
	return nil
}

// Flush sends everything buffered, spooling it if the hub cannot be reached.
func (s *Shipper) Flush() error {
	s.send.Lock()
	defer s.send.Unlock()

	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()
	if len(batch) == 0 {
		s.replaySpool()
		return nil
	}

	body, err := encode(batch)
	if err != nil {
		return err
	}
	if err := s.post(body); err != nil {
		s.mu.Lock()
		s.stats.Failures++
		s.lastErr = err
		s.mu.Unlock()
		s.spool(body, len(batch))
		return nil // spooled, not lost — the caller should not treat this as fatal
	}
	s.mu.Lock()
	s.stats.Sent += int64(len(batch))
	s.lastErr = nil
	s.mu.Unlock()
	s.replaySpool()
	return nil
}

func encode(batch []*event.Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, ev := range batch {
		if err := enc.Encode(ev); err != nil {
			return nil, fmt.Errorf("encode event: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func (s *Shipper) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(s.cfg.URL, "/")+"/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("ship to %s: %w", s.cfg.URL, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusForbidden {
		// The hub knows us and has decided not to listen. Worth distinguishing
		// from a network fault: retrying will not help, and the operator needs to
		// know this probe has been revoked rather than silently spooling forever.
		return fmt.Errorf("hub rejected this probe (403): %s", strings.TrimSpace(string(payload)))
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return nil
}

// -- spool -------------------------------------------------------------------

// scanSpool builds the in-memory listing once, at construction, recovering
// whatever a previous run left behind. This is the only full enumeration of the
// spool directory; everything after it works from the listing.
//
// A file dropped into the spool by hand after startup is therefore not picked
// up. That was never a supported way to feed the shipper — two writers sharing
// one spool directory would already have double-sent every batch in it.
func (s *Shipper) scanSpool() {
	entries, err := readDir(s.cfg.SpoolDir)
	if err != nil {
		return
	}
	idx := make([]spoolEntry, 0, len(entries))
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// A write that died between CreateTemp and Rename leaves one of these.
		// It holds no deliverable batch, so sweep it rather than let a crash loop
		// fill the disk with debris the size cap never sees.
		if strings.HasPrefix(e.Name(), ".spool-") && strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(filepath.Join(s.cfg.SpoolDir, e.Name()))
			continue
		}
		if !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		idx = append(idx, spoolEntry{
			name:   e.Name(),
			size:   info.Size(),
			events: spoolEventCount(e.Name()),
		})
		total += info.Size()
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].name < idx[j].name })

	s.mu.Lock()
	s.spoolIdx, s.spoolBytes = idx, total
	s.mu.Unlock()
}

func (s *Shipper) spool(body []byte, count int) {
	if s.cfg.SpoolDir == "" {
		s.mu.Lock()
		s.stats.Dropped += int64(count)
		s.mu.Unlock()
		return
	}
	name := fmt.Sprintf("%d-%09d.ndjson", time.Now().UnixNano(), count)
	if err := writeSpoolFile(filepath.Join(s.cfg.SpoolDir, name), body); err != nil {
		s.mu.Lock()
		s.stats.Dropped += int64(count)
		s.mu.Unlock()
		return
	}
	entry := spoolEntry{name: name, size: int64(len(body)), events: int64(count)}

	s.mu.Lock()
	s.stats.Spooled += int64(count)
	// Names embed the wall clock, so an NTP step backwards can mint a name that
	// sorts before its predecessor. Insert in order rather than assume; the
	// common case appends and copies nothing.
	at := sort.Search(len(s.spoolIdx), func(i int) bool { return s.spoolIdx[i].name >= name })
	s.spoolIdx = append(s.spoolIdx, spoolEntry{})
	copy(s.spoolIdx[at+1:], s.spoolIdx[at:])
	s.spoolIdx[at] = entry
	s.spoolBytes += entry.size
	s.mu.Unlock()

	s.trimSpool()
}

// spoolTempPattern names the in-progress write. The suffix keeps it out of the
// ".ndjson" listing, so a torn write is invisible to replay rather than being
// posted as a short batch.
const spoolTempPattern = ".spool-*.tmp"

// writeSpoolFile persists a batch durably and atomically.
//
// os.WriteFile neither fsyncs nor renames, and both matter. Without the fsync a
// spooled batch sits in the page cache and is lost to a power cut; without the
// rename a crash mid-write leaves a *partial* file under its final name, which
// scanSpool lists and replaySpool posts as a truncated NDJSON body with a torn
// last line. Both defeat the reason the spool exists: it is the copy of record
// for exactly the window when the hub cannot be reached, and "the moment the
// network breaks is exactly the moment worth recording".
//
// This is the pattern ioc.writeFileAtomic already argues for, and every durable
// write in the engine — the vector store, the parent store, the IOC bundle —
// follows. The spool was the one that did neither.
//
// It goes one step further than writeFileAtomic and syncs the directory, because
// a rename that has not reached the platter is a batch that vanishes. The IOC
// bundle can afford to skip that: it is derived from an upstream feed and a crash
// simply means rebuilding it. A spooled batch is derived from nothing — it is the
// delivery queue itself, and nothing the shipper can reach can regenerate it.
func writeSpoolFile(name string, body []byte) error {
	dir := filepath.Dir(name)
	tmp, err := os.CreateTemp(dir, spoolTempPattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, name); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir flushes a directory entry so a rename survives a power cut.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// trimSpool enforces the size cap, oldest-first. An unbounded spool turns a hub
// outage into a full disk, which takes down the host it was protecting.
//
// The cost is now proportional to what is evicted rather than to what is
// retained, which is the point: eviction is rare and the retained set is the
// quantity an attacker gets to choose.
func (s *Shipper) trimSpool() {
	limit := int64(s.cfg.SpoolMaxMB) << 20

	s.mu.Lock()
	defer s.mu.Unlock()
	for s.spoolBytes > limit && len(s.spoolIdx) > 0 {
		oldest := s.spoolIdx[0]
		s.spoolIdx = s.spoolIdx[1:]
		s.spoolBytes -= oldest.size

		// Events, not files. This counter used to be incremented by one per
		// evicted file while the no-spool path incremented it by the event count,
		// so the single number reported through -stats mixed two units and
		// under-stated real loss by up to BatchSize — 500x at the default. For a
		// package whose own comment calls silent truncation of security telemetry
		// "its own incident", the figure has to be countable.
		//
		// Counted whether or not the unlink succeeds. A file we have stopped
		// tracking will never be replayed, so it is lost to the hub either way,
		// and the accounting has to say so.
		s.stats.Dropped += oldest.events
		_ = os.Remove(filepath.Join(s.cfg.SpoolDir, oldest.name))
	}
}

// spoolEventCount recovers how many events a spool file holds from its name.
//
// spool() writes "<unixnano>-<count>.ndjson", so the count is already on disk and
// simply was not being read. Falling back to 1 keeps a file written by some other
// version from being counted as zero loss, which would be the one wrong answer
// here: under-reporting is what this is fixing.
func spoolEventCount(name string) int64 {
	base := strings.TrimSuffix(name, ".ndjson")
	dash := strings.LastIndexByte(base, '-')
	if dash < 0 {
		return 1
	}
	n, err := strconv.ParseInt(base[dash+1:], 10, 64)
	if err != nil || n <= 0 {
		return 1
	}
	return n
}

// replaySpool re-sends spooled batches oldest-first, stopping at the first
// failure so ordering is preserved and a still-down hub is not hammered.
func (s *Shipper) replaySpool() {
	if s.cfg.SpoolDir == "" {
		return
	}
	s.mu.Lock()
	queue := append([]spoolEntry(nil), s.spoolIdx...)
	s.mu.Unlock()

	// Only a leading run is retired, so the listing stays in replay order and a
	// batch is never skipped past. The caller holds send, so nothing else removes
	// from the front while this walks it.
	var done int
	var freed, replayed, dropped int64
	for _, e := range queue {
		path := filepath.Join(s.cfg.SpoolDir, e.name)
		body, err := os.ReadFile(path)

		if errors.Is(err, fs.ErrNotExist) {
			// Gone from under us. Nothing to send and nothing to retry, so retire
			// it and count the loss rather than carry an entry that can never
			// leave the queue.
			done++
			freed += e.size
			dropped += e.events
			continue
		}
		// A batch written by a pre-atomic build can already be torn: the process
		// died mid-write and the final line is half a record. Atomic writes stop
		// new ones appearing, but they do not clean up a spool that survived the
		// upgrade, and posting a body with a torn last line hands the hub something
		// it cannot parse. Every complete record ends in '\n' — encode uses
		// json.Encoder — so anything after the last one is a fragment.
		var torn int64
		if err == nil {
			if cut := bytes.LastIndexByte(body, '\n'); cut < 0 {
				body, torn = nil, 1
			} else if cut+1 != len(body) {
				body, torn = body[:cut+1], 1
			}
		}
		if err == nil && len(body) > 0 {
			err = s.post(body)
		}
		if err != nil {
			// A post failure is the ordinary hub-is-down case; any read error that
			// is not "missing" may well be transient. Both leave the file in place
			// and stop. Skipping ahead would break the oldest-first ordering this
			// function promises, and a hub that is still down should not be
			// hammered with the rest of the backlog.
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
			break
		}
		_ = os.Remove(path)
		done++
		freed += e.size
		replayed += int64(bytes.Count(body, []byte("\n")))
		// The fragment is one event at most — it was the last line — and it is
		// unrecoverable, so it is counted rather than silently discarded.
		dropped += torn
	}
	if done == 0 {
		return
	}
	s.mu.Lock()
	s.spoolIdx = s.spoolIdx[done:]
	s.spoolBytes -= freed
	s.stats.Replayed += replayed
	s.stats.Dropped += dropped
	s.mu.Unlock()
}

// -- lifecycle ---------------------------------------------------------------

func (s *Shipper) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.FlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			_ = s.Flush()
		}
	}
}

// Close flushes and stops the background sender.
func (s *Shipper) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	close(s.done)
	s.wg.Wait()
	return s.Flush()
}

// Stats returns a snapshot, including how many batches are still spooled.
func (s *Shipper) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.SpoolFile = len(s.spoolIdx)
	return out
}

// LastError reports the most recent delivery failure, for -stats.
func (s *Shipper) LastError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr == nil {
		return ""
	}
	return s.lastErr.Error()
}
