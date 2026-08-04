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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

	mu      sync.Mutex
	pending []*event.Event
	stats   Stats
	lastErr error
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
}

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

func (s *Shipper) spool(body []byte, count int) {
	if s.cfg.SpoolDir == "" {
		s.mu.Lock()
		s.stats.Dropped += int64(count)
		s.mu.Unlock()
		return
	}
	name := filepath.Join(s.cfg.SpoolDir, fmt.Sprintf("%d-%09d.ndjson", time.Now().UnixNano(), count))
	if err := os.WriteFile(name, body, 0o600); err != nil {
		s.mu.Lock()
		s.stats.Dropped += int64(count)
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.stats.Spooled += int64(count)
	s.mu.Unlock()
	s.trimSpool()
}

// trimSpool enforces the size cap, oldest-first. An unbounded spool turns a hub
// outage into a full disk, which takes down the host it was protecting.
func (s *Shipper) trimSpool() {
	entries, err := os.ReadDir(s.cfg.SpoolDir)
	if err != nil {
		return
	}
	type spooled struct {
		path string
		size int64
	}
	var files []spooled
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, spooled{filepath.Join(s.cfg.SpoolDir, e.Name()), info.Size()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	limit := int64(s.cfg.SpoolMaxMB) << 20
	for total > limit && len(files) > 0 {
		oldest := files[0]
		files = files[1:]
		if os.Remove(oldest.path) == nil {
			total -= oldest.size
			s.mu.Lock()
			s.stats.Dropped++
			s.mu.Unlock()
		}
	}
}

// replaySpool re-sends spooled batches oldest-first, stopping at the first
// failure so ordering is preserved and a still-down hub is not hammered.
func (s *Shipper) replaySpool() {
	if s.cfg.SpoolDir == "" {
		return
	}
	entries, err := os.ReadDir(s.cfg.SpoolDir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".ndjson") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		path := filepath.Join(s.cfg.SpoolDir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := s.post(body); err != nil {
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
			return
		}
		_ = os.Remove(path)
		s.mu.Lock()
		s.stats.Replayed += int64(bytes.Count(body, []byte("\n")))
		s.mu.Unlock()
	}
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
	out := s.stats
	s.mu.Unlock()
	if s.cfg.SpoolDir != "" {
		if entries, err := os.ReadDir(s.cfg.SpoolDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".ndjson") {
					out.SpoolFile++
				}
			}
		}
	}
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
