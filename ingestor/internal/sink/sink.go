// Package sink writes enriched events to their destination. Today that is
// newline-delimited JSON, which the Python engine tails; the interface exists so
// a future Phase can add a Kafka or Unix-socket sink without touching the
// pipeline.
package sink

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
)

// Sink accepts enriched events. Implementations must be safe for a single
// writer goroutine; the pipeline guarantees serialised calls.
type Sink interface {
	Write(ev *event.Event) error
	Flush() error
}

// JSONL emits one compact JSON object per line.
type JSONL struct {
	mu  sync.Mutex
	bw  *bufio.Writer
	enc *json.Encoder
	n   int64
}

// NewJSONL wraps w with a 256 KiB buffer. HTML escaping is disabled so log text
// containing <, > or & stays readable, and so Japanese advisory text is not
// mangled by \u sequences.
func NewJSONL(w io.Writer) *JSONL {
	bw := bufio.NewWriterSize(w, 256*1024)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &JSONL{bw: bw, enc: enc}
}

// Write encodes ev followed by a newline (json.Encoder appends one).
func (j *JSONL) Write(ev *event.Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.enc.Encode(ev); err != nil {
		return err
	}
	j.n++
	return nil
}

// Flush pushes buffered bytes to the underlying writer.
func (j *JSONL) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.bw.Flush()
}

// Count returns how many events have been written.
func (j *JSONL) Count() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.n
}

// Discard is a no-op sink used for benchmarking the parse path in isolation.
type Discard struct{ N int64 }

func (d *Discard) Write(*event.Event) error { d.N++; return nil }
func (d *Discard) Flush() error             { return nil }

// tee fans one event out to several sinks.
type tee struct{ sinks []Sink }

// Tee writes every event to all sinks. Used to keep a local JSONL copy while
// also shipping to a remote hub: a probe that only ships has no record of last
// resort if the hub is down and the spool overflows.
//
// A failure in any sink is reported, but the remaining sinks still receive the
// event — losing the local copy because the network is down would invert the
// point of having both.
func Tee(sinks ...Sink) Sink { return &tee{sinks: sinks} }

func (t *tee) Write(ev *event.Event) error {
	var firstErr error
	for _, s := range t.sinks {
		if err := s.Write(ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *tee) Flush() error {
	var firstErr error
	for _, s := range t.sinks {
		if err := s.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
