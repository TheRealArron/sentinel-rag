package pipeline

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
)

// capture is a Sink that records events in the order the pipeline emitted them.
type capture struct{ events []*event.Event }

func (c *capture) Write(ev *event.Event) error {
	cp := *ev
	c.events = append(c.events, &cp)
	return nil
}
func (c *capture) Flush() error { return nil }

// bruteForceLog is a five-failure burst from one public address followed by a
// success: the narrative the correlator is supposed to recognise.
const bruteForceLog = `Jul 30 05:30:01 sentinel sshd[4001]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
Jul 30 05:30:03 sentinel sshd[4002]: Failed password for invalid user oracle from 203.0.113.45 port 51002 ssh2
Jul 30 05:30:05 sentinel sshd[4003]: Failed password for invalid user test from 203.0.113.45 port 51003 ssh2
Jul 30 05:30:07 sentinel sshd[4004]: Failed password for root from 203.0.113.45 port 51004 ssh2
Jul 30 05:30:09 sentinel sshd[4005]: Failed password for arron from 203.0.113.45 port 51005 ssh2
Jul 30 05:30:11 sentinel sshd[4006]: Accepted password for arron from 203.0.113.45 port 51006 ssh2
Jul 30 05:30:12 sentinel sudo[4100]: arron : TTY=pts/0 ; PWD=/home/arron ; USER=root ; COMMAND=/bin/bash
`

func freezeClock(t *testing.T) {
	t.Helper()
	fixed := time.Date(2026, time.July, 30, 6, 0, 0, 0, time.UTC)
	parser.Now = func() time.Time { return fixed }
	event.Now = func() time.Time { return fixed }
	t.Cleanup(func() {
		parser.Now = func() time.Time { return time.Now() }
		event.Now = func() time.Time { return time.Now().UTC() }
	})
}

func TestRunPreservesLogOrder(t *testing.T) {
	freezeClock(t)
	for _, workers := range []int{1, 2, 8, 64} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			var out capture
			st, err := Run(context.Background(), strings.NewReader(bruteForceLog), &out, Options{Workers: workers})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if st.LinesRead != 7 {
				t.Errorf("LinesRead = %d, want 7", st.LinesRead)
			}
			// Sequence numbers of non-synthetic events must be strictly
			// increasing regardless of how many workers raced.
			last := int64(-1)
			for _, ev := range out.events {
				if ev.Process == "sentinel-correlator" {
					continue
				}
				if ev.Seq <= last {
					t.Fatalf("out-of-order event: seq %d after %d", ev.Seq, last)
				}
				last = ev.Seq
			}
		})
	}
}

func TestRunIsDeterministicAcrossWorkerCounts(t *testing.T) {
	freezeClock(t)
	fingerprint := func(workers int) string {
		var out capture
		if _, err := Run(context.Background(), strings.NewReader(bruteForceLog), &out, Options{Workers: workers}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		var b strings.Builder
		for _, ev := range out.events {
			fmt.Fprintf(&b, "%d|%s|%d|%s|%s\n", ev.Seq, ev.Rule, ev.Score, ev.SourceIP, ev.User)
		}
		return b.String()
	}
	want := fingerprint(1)
	for _, w := range []int{2, 4, 16} {
		if got := fingerprint(w); got != want {
			t.Fatalf("output differs at workers=%d:\n--- 1 worker ---\n%s\n--- %d workers ---\n%s", w, want, w, got)
		}
	}
}

func TestRunDetectsCorrelatedIncidents(t *testing.T) {
	freezeClock(t)
	var out capture
	st, err := Run(context.Background(), strings.NewReader(bruteForceLog), &out, Options{
		Workers: 4,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.Incidents != 2 {
		t.Fatalf("Incidents = %d, want 2 (brute force + compromise)", st.Incidents)
	}

	rules := map[string]bool{}
	for _, ev := range out.events {
		rules[ev.Rule] = true
	}
	for _, want := range []string{
		"ssh_failed_password",
		"ssh_accepted_login",
		"sudo_command_executed",
		"correlated_brute_force",
		"correlated_successful_login_after_bruteforce",
	} {
		if !rules[want] {
			t.Errorf("missing rule %q in output", want)
		}
	}
}

func TestIncidentsAppearAfterTheirTrigger(t *testing.T) {
	freezeClock(t)
	var out capture
	if _, err := Run(context.Background(), strings.NewReader(bruteForceLog), &out, Options{Workers: 8}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	seenFifthFailure := false
	for _, ev := range out.events {
		if ev.Rule == "correlated_brute_force" && !seenFifthFailure {
			t.Fatal("brute-force incident emitted before the fifth failure")
		}
		if ev.SourcePort == 51005 {
			seenFifthFailure = true
		}
	}
	if !seenFifthFailure {
		t.Fatal("fifth failure never emitted")
	}
}

func TestMinScoreFiltersNoiseButKeepsIncidents(t *testing.T) {
	freezeClock(t)
	var out capture
	st, err := Run(context.Background(), strings.NewReader(bruteForceLog), &out, Options{Workers: 2, MinScore: 60})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.Filtered == 0 {
		t.Error("Filtered = 0, expected low-score events to be dropped")
	}
	for _, ev := range out.events {
		if ev.Score < 60 && ev.Process != "sentinel-correlator" {
			t.Errorf("event %q with score %d passed a MinScore of 60", ev.Rule, ev.Score)
		}
	}
	// The correlated incidents must survive the filter: they are the point.
	if st.Incidents != 2 {
		t.Errorf("Incidents = %d, want 2 even with MinScore=60", st.Incidents)
	}
}

func TestRunSkipsBlankLines(t *testing.T) {
	freezeClock(t)
	var out capture
	in := "\n\n   \nJul 30 05:30:01 h sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2\n\n"
	st, err := Run(context.Background(), strings.NewReader(in), &out, Options{Workers: 3})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.LinesRead != 1 || st.Emitted != 1 {
		t.Errorf("LinesRead=%d Emitted=%d, want 1/1", st.LinesRead, st.Emitted)
	}
}

func TestRunHandlesUnterminatedFinalLine(t *testing.T) {
	freezeClock(t)
	var out capture
	in := "Jul 30 05:30:01 h sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2"
	st, err := Run(context.Background(), strings.NewReader(in), &out, Options{Workers: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.LinesRead != 1 {
		t.Fatalf("LinesRead = %d, want 1", st.LinesRead)
	}
	if out.events[0].SourceIP != "203.0.113.1" {
		t.Errorf("SourceIP = %q", out.events[0].SourceIP)
	}
}

func TestReadLineIsMemoryBounded(t *testing.T) {
	// A 4 MiB single line must be capped at MaxLineLen, not accumulated.
	freezeClock(t)
	huge := strings.Repeat("A", 4<<20) + "\n"
	var out capture
	st, err := Run(context.Background(), strings.NewReader(huge+"Jul 30 05:30:01 h sshd[1]: Accepted password for arron from 192.168.1.5 port 22 ssh2\n"),
		&out, Options{Workers: 2, MaxLineLen: 1024, IncludeRaw: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if st.LinesRead != 2 {
		t.Fatalf("LinesRead = %d, want 2", st.LinesRead)
	}
	if got := len(out.events[0].Raw); got > 1024 {
		t.Errorf("raw length = %d, want <= 1024", got)
	}
	// The bytes were still consumed, so the following line parses normally.
	if out.events[1].Rule != "ssh_accepted_login" {
		t.Errorf("line after the huge line did not parse: rule=%q", out.events[1].Rule)
	}
}

func TestRunHonoursContextCancellation(t *testing.T) {
	freezeClock(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out capture
	_, err := Run(ctx, strings.NewReader(bruteForceLog), &out, Options{Workers: 2})
	if err == nil {
		t.Error("expected a context error")
	}
}

func TestFingerprintIsStableAndUnique(t *testing.T) {
	a := event.Fingerprint("line one")
	b := event.Fingerprint("line one")
	c := event.Fingerprint("line two")
	if a != b {
		t.Error("fingerprint is not stable for identical input")
	}
	if a == c {
		t.Error("fingerprint collision for different input")
	}
	if len(a) != 64 {
		t.Errorf("fingerprint length = %d, want 64 hex chars", len(a))
	}
}

func BenchmarkRun(b *testing.B) {
	line := "Jul 30 05:30:12 sentinel sshd[4021]: Failed password for root from 203.0.113.45 port 51234 ssh2\n"
	corpus := strings.Repeat(line, 10000)
	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out capture
		if _, err := Run(context.Background(), strings.NewReader(corpus), &out, Options{Workers: 4}); err != nil {
			b.Fatal(err)
		}
	}
}
