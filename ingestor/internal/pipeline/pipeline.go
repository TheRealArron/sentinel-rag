// Package pipeline is the concurrent core of the ingestor.
//
// Shape:
//
//	reader (1 goroutine)  ->  jobs chan  ->  N workers  ->  results chan  ->  collector (1 goroutine)
//	  bounded line read       backpressure    sanitize/parse/enrich          reorder -> correlate -> sink
//
// Two decisions are worth calling out:
//
//  1. Order is restored before correlation. Workers finish out of order, which
//     is fine for independent lines but fatal for stateful detection: a
//     "successful login after N failures" rule needs to see the failures first.
//     The collector holds a small reorder buffer keyed by sequence number, so
//     the correlator always sees the original log order.
//
//  2. Line reading is memory-bounded. A single crafted 1 GB "line" must not be
//     able to allocate 1 GB, so readLine consumes through bufio.ReadSlice and
//     discards past the configured cap rather than accumulating fragments.
package pipeline

import (
	"bufio"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/correlate"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/enrich"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/honeytoken"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sigma"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sink"
)

// Options configures a run.
//
// MinScore drops individual events below the threshold, but correlated incidents
// always pass: filtering is about output volume, and the incidents are the whole
// point of ingesting the noise in the first place. The correlator still observes
// filtered events, so a burst of score-54 failures can still raise a score-88
// incident.
type Options struct {
	Workers            int
	MaxLineLen         int
	MinScore           int
	IncludeRaw         bool
	DisableCorrelation bool
	Correlation        correlate.Config
	// Honeytokens may be nil, which disables deception detection.
	Honeytokens *honeytoken.Set
	// Sigma holds detections transpiled from Sigma YAML. nil disables them.
	Sigma *sigma.Set
}

// Stats is the run summary printed with -stats.
type Stats struct {
	LinesRead     int64         `json:"lines_read"`
	BytesRead     int64         `json:"bytes_read"`
	Emitted       int64         `json:"events_emitted"`
	Filtered      int64         `json:"events_filtered"`
	Incidents     int64         `json:"incidents"`
	Sanitised     int64         `json:"lines_sanitised"`
	Unparsed      int64         `json:"lines_unparsed"`
	Honeytokens   int64         `json:"honeytoken_hits"`
	Duration      time.Duration `json:"duration_ns"`
	LinesPerSec   float64       `json:"lines_per_sec"`
	MaxReorderGap int           `json:"max_reorder_gap"`
}

type job struct {
	seq int64
	raw string
}

type result struct {
	seq int64
	ev  *event.Event
	ts  time.Time
}

// defaultMaxLine matches sanitize.DefaultMaxLen.
const defaultMaxLine = sanitize.DefaultMaxLen

// Run drives the pipeline until r is exhausted or ctx is cancelled.
func Run(ctx context.Context, r io.Reader, out sink.Sink, opts Options) (Stats, error) {
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.MaxLineLen <= 0 {
		opts.MaxLineLen = defaultMaxLine
	}

	start := time.Now()
	var st Stats

	jobs := make(chan job, opts.Workers*64)
	results := make(chan result, opts.Workers*64)

	var readErr, sinkErr error
	// The reader owns these counters exclusively; they are merged into st after
	// readWG.Wait() establishes the happens-before edge. Sharing st directly
	// would race with the collector loop below.
	var linesRead, bytesRead int64

	// ---- reader ----------------------------------------------------------
	var readWG sync.WaitGroup
	readWG.Add(1)
	go func() {
		defer readWG.Done()
		defer close(jobs)
		br := bufio.NewReaderSize(r, 128*1024)
		var seq int64
		for {
			select {
			case <-ctx.Done():
				readErr = ctx.Err()
				return
			default:
			}
			line, n, err := readLine(br, opts.MaxLineLen)
			bytesRead += int64(n)
			if strings.TrimSpace(line) != "" {
				linesRead++
				select {
				case jobs <- job{seq: seq, raw: line}:
					seq++
				case <-ctx.Done():
					readErr = ctx.Err()
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					readErr = err
				}
				return
			}
		}
	}()

	// ---- workers ---------------------------------------------------------
	var workWG sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		workWG.Add(1)
		go func() {
			defer workWG.Done()
			for j := range jobs {
				results <- process(j, opts)
			}
		}()
	}
	go func() {
		workWG.Wait()
		close(results)
	}()

	// ---- collector: reorder, correlate, emit -----------------------------
	var corr *correlate.Correlator
	if !opts.DisableCorrelation {
		corr = correlate.New(opts.Correlation)
	}

	pending := make(map[int64]result)
	var next int64
	emit := func(res result) {
		if res.ev.Sanitized {
			st.Sanitised++
		}
		if !res.ev.ParseOK {
			st.Unparsed++
		}
		if res.ev.Rule == "honeytoken_referenced" {
			st.Honeytokens++
		}
		if res.ev.Score >= opts.MinScore {
			if err := out.Write(res.ev); err != nil && sinkErr == nil {
				sinkErr = err
			}
			st.Emitted++
		} else {
			st.Filtered++
		}
		if corr == nil {
			return
		}
		for _, inc := range corr.Observe(res.ev, res.ts) {
			if err := out.Write(inc); err != nil && sinkErr == nil {
				sinkErr = err
			}
			st.Emitted++
			st.Incidents++
		}
	}

	for res := range results {
		pending[res.seq] = res
		if len(pending) > st.MaxReorderGap {
			st.MaxReorderGap = len(pending)
		}
		for {
			ready, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			emit(ready)
		}
	}
	// Drain anything left (only reachable if the reader aborted mid-stream and
	// some sequence numbers were never produced).
	if len(pending) > 0 {
		seqs := make([]int64, 0, len(pending))
		for s := range pending {
			seqs = append(seqs, s)
		}
		sortInt64(seqs)
		for _, s := range seqs {
			emit(pending[s])
		}
	}

	readWG.Wait()
	st.LinesRead, st.BytesRead = linesRead, bytesRead
	if err := out.Flush(); err != nil && sinkErr == nil {
		sinkErr = err
	}

	st.Duration = time.Since(start)
	if secs := st.Duration.Seconds(); secs > 0 {
		st.LinesPerSec = float64(st.LinesRead) / secs
	}

	if readErr != nil {
		return st, readErr
	}
	return st, sinkErr
}

// process is the per-line work: sanitize -> parse -> enrich. It is pure with
// respect to shared state, which is what makes the worker fan-out safe.
func process(j job, opts Options) result {
	san := sanitize.Line(j.raw, opts.MaxLineLen)
	env := parser.Parse(san.Clean)

	ev := &event.Event{
		Seq:       j.seq,
		RawSHA256: event.Fingerprint(j.raw),
		Host:      sanitize.Field(env.Host, 253),
		Facility:  env.Facility,
		Process:   sanitize.Field(env.Process, 64),
		PID:       env.PID,
		Message:   env.Message,
		Sanitized: san.Modified,
		ParseOK:   env.Format != "raw",
	}
	ev.SetField("format", env.Format)
	if opts.IncludeRaw {
		ev.Raw = san.Clean
	}

	ts := env.Timestamp
	if !env.HasTime {
		ts = event.Now()
		ev.AddTags("no-timestamp")
	}
	ev.Timestamp = ts.UTC().Format(time.RFC3339Nano)
	ev.Stamp()

	enrich.ApplyWithSigma(ev, env, san, opts.Honeytokens, opts.Sigma)
	return result{seq: j.seq, ev: ev, ts: ts}
}

// readLine reads one '\n'-terminated line, keeping at most max bytes and
// discarding the rest. It returns the kept text, the number of bytes consumed
// from the reader, and io.EOF on the final (possibly unterminated) line.
func readLine(br *bufio.Reader, max int) (string, int, error) {
	var b strings.Builder
	consumed := 0
	for {
		frag, err := br.ReadSlice('\n')
		consumed += len(frag)
		if room := max - b.Len(); room > 0 {
			if len(frag) > room {
				b.Write(frag[:room])
			} else {
				b.Write(frag)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // long line: keep draining, keep discarding
		}
		if err != nil {
			if errors.Is(err, io.EOF) && b.Len() == 0 && consumed == 0 {
				return "", 0, io.EOF
			}
			return trimEOL(b.String()), consumed, err
		}
		return trimEOL(b.String()), consumed, nil
	}
}

func trimEOL(s string) string { return strings.TrimRight(s, "\r\n") }

func sortInt64(v []int64) {
	// Insertion sort: this path only runs on abort, with a handful of items.
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}
