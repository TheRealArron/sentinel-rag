package enrich

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
)

// This file is the Go half of benchmarks/. It exists to answer one question
// honestly: is Go actually faster than Python at this specific workload, or is
// "Python's GIL" a story we tell after the fact?
//
// The Python half (benchmarks/regex_bench.py) runs the same 33 patterns over the
// same generated corpus, so the numbers are comparable. See benchmarks/README.md
// for the results and what they do and do not justify.

// benchCorpus generates realistic sshd/sudo/kernel lines. Seeded so both
// languages see a statistically identical corpus.
func benchCorpus(n int) []string {
	r := rand.New(rand.NewSource(1))
	users := []string{"admin", "oracle", "root", "arron", "test", "ubuntu", "git", "postgres"}
	templates := []string{
		"Failed password for %s from 203.0.%d.%d port %d ssh2",
		"Failed password for invalid user %s from 198.51.%d.%d port %d ssh2",
		"Accepted password for %s from 10.0.%d.%d port %d ssh2",
		"Connection closed by 203.0.%d.%d port %d [preauth]",
		"pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=203.0.%d.%d user=%s",
		"Started Daily apt download activities. %s %d %d %d",
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		switch tmpl := templates[r.Intn(len(templates))]; {
		case strings.Count(tmpl, "%s") == 1 && strings.Count(tmpl, "%d") == 3:
			out[i] = fmt.Sprintf(tmpl, users[r.Intn(len(users))], r.Intn(255), r.Intn(255), 50000+r.Intn(9000))
		case strings.Count(tmpl, "%d") == 3 && strings.Count(tmpl, "%s") == 0:
			out[i] = fmt.Sprintf(tmpl, r.Intn(255), r.Intn(255), 50000+r.Intn(9000))
		default:
			out[i] = fmt.Sprintf(tmpl, r.Intn(255), r.Intn(255), users[r.Intn(len(users))])
		}
	}
	return out
}

// BenchmarkRuleSetSingleThread measures the cost of evaluating every rule
// against every line, with no concurrency. This is the apples-to-apples
// comparison against Python: same patterns, same corpus, one core.
func BenchmarkRuleSetSingleThread(b *testing.B) {
	corpus := benchCorpus(10000)
	rules := Rules()
	b.ResetTimer()
	b.ReportAllocs()

	matches := 0
	for i := 0; i < b.N; i++ {
		for _, line := range corpus {
			for j := range rules {
				if rules[j].Pattern.MatchString(line) {
					matches++
				}
			}
		}
	}
	b.StopTimer()
	perLine := float64(b.Elapsed().Nanoseconds()) / float64(b.N*len(corpus))
	b.ReportMetric(perLine, "ns/line")
	b.ReportMetric(float64(len(rules)), "rules")
}

// Deliberately no BenchmarkRuleSetParallel here. testing.B.RunParallel splits
// b.N across goroutines, so with a whole 10k-line corpus as the unit of work and
// only a handful of iterations there is not enough to distribute, and the
// resulting "2x on 16 cores" is an artefact of the harness rather than a
// property of the code. Concurrency is measured end-to-end instead, on the real
// binary against a 500k-line file — see benchmarks/README.md.

// BenchmarkCatastrophicBacktracking is the finding that actually matters for a
// security tool.
//
// The pattern below is a textbook ReDoS trigger: nested quantifiers over an
// overlapping character class. A backtracking engine (PCRE, Python's re, Java,
// JavaScript, Ruby) explores exponentially many paths on a non-matching input
// and effectively hangs. Go's regexp is RE2 — a DFA/NFA simulation with no
// backtracking — so it is linear in the input length, always.
//
// On a log parser this is not an academic distinction. The input is chosen by a
// remote attacker: they pick the SSH username. If one detection rule in the set
// is backtracking-vulnerable, a single crafted username is a denial of service
// against the entire security monitoring pipeline. RE2 makes that class of bug
// unrepresentable rather than something you have to audit for.
func BenchmarkCatastrophicBacktracking(b *testing.B) {
	evil := regexp.MustCompile(`^(a+)+$`)
	// 40 a's then a b: never matches, and forces maximal backtracking.
	input := strings.Repeat("a", 40) + "b"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evil.MatchString(input)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N), "ns/match")
}

// TestReDoSIsLinearInGo asserts the property rather than just measuring it: as
// the adversarial input doubles, RE2's runtime grows linearly. A backtracking
// engine would grow exponentially and blow the timeout.
func TestReDoSIsLinearInGo(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	evil := regexp.MustCompile(`^(a+)+$`)

	timeFor := func(n int) time.Duration {
		input := strings.Repeat("a", n) + "b"
		start := time.Now()
		for i := 0; i < 200; i++ {
			evil.MatchString(input)
		}
		return time.Since(start) / 200
	}

	small := timeFor(20)
	large := timeFor(2000) // 100x the input

	// Linear would be ~100x. Allow a wide margin for scheduling noise and fixed
	// overhead; the point is that it is nowhere near exponential, which for
	// n=2000 would not terminate before the heat death of the test suite.
	if large > small*5000 {
		t.Fatalf("runtime grew %.0fx for a 100x input (%v -> %v); expected roughly linear",
			float64(large)/float64(small), small, large)
	}
	t.Logf("n=20: %v   n=2000: %v   growth: %.1fx for 100x input",
		small, large, float64(large)/float64(small))
}

// TestDumpBenchCorpus writes the shared corpus so the Python benchmark measures
// byte-identical input. Run with:
//
//	go test ./internal/enrich/ -run TestDumpBenchCorpus -corpus-out=/tmp/corpus.txt
var corpusOut = os.Getenv("SENTINEL_BENCH_CORPUS_OUT")

func TestDumpBenchCorpus(t *testing.T) {
	if corpusOut == "" {
		t.Skip("set SENTINEL_BENCH_CORPUS_OUT to write the shared benchmark corpus")
	}
	if err := os.WriteFile(corpusOut, []byte(strings.Join(benchCorpus(10000), "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote 10000 lines to %s", corpusOut)
}

// BenchmarkApplyWith measures the full enrichment path, which is what the
// surface split changed. BenchmarkRuleSetSingleThread above times the raw regex
// sweep and is deliberately untouched by it — it calls the patterns directly —
// so it cannot answer "what did redaction cost".
//
// Two corpora, because the answer differs by an order of magnitude between them:
//
//	withUser  lines carrying a user/target_user capture. These pay for the
//	          redaction pass, the confirmation re-match, and a strings.Builder.
//	noUser    lines with nothing attacker-chosen to blank. redactUntrusted
//	          returns the input unchanged and confirmAgainstRedacted returns
//	          immediately, so the surface split costs one comparison.
func benchApply(b *testing.B, lines []string) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			san := sanitize.Line(line, 0)
			env := parser.Parse(san.Clean)
			ev := &event.Event{Message: env.Message, Process: env.Process}
			ApplyWith(ev, env, san, Detectors{})
		}
	}
}

func BenchmarkApplyWithUserCapture(b *testing.B) {
	benchApply(b, []string{
		"Jul 30 05:30:12 h sshd[1]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2",
		"Jul 30 05:30:12 h sshd[1]: Accepted password for arron from 203.0.113.45 port 51234 ssh2",
		"Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
	})
}

func BenchmarkApplyNoUserCapture(b *testing.B) {
	benchApply(b, []string{
		"Jul 30 05:30:12 h kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.99 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT=23",
		"Jul 30 05:30:12 h systemd[1]: Started Daily apt download activities.",
		"Jul 30 05:30:12 h chronyd[790]: Selected source 162.159.200.123",
	})
}

// BenchmarkSurfaceSplit isolates exactly the work the fix added, and nothing
// else.
//
// An earlier version of this compared ApplyWith against a bare two-pass match
// and reported the difference as "the cost of redaction". That was wrong: the
// bare match also skipped captures, modifiers, tag merging and scoring, so the
// delta measured most of enrichment. The honest comparison is the same matching
// work with and without the redaction machinery around it.
//
//	baseline  one pass of every rule over the raw message
//	split     the same, plus redactUntrusted, confirmAgainstRedacted, and the
//	          second pass over the redacted text
func BenchmarkSurfaceSplit(b *testing.B) {
	const msg = "Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2"

	b.Run("baseline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = matchRules(msg, "sshd", SurfaceRaw)
			_ = matchRules(msg, "sshd", SurfaceRedacted)
		}
	})

	b.Run("split", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = matchAll(msg, "sshd")
		}
	})

	// The no-user case, where both added steps short-circuit. Paired with its
	// own baseline: it is a different, longer line, so comparing it against the
	// sshd baseline above would measure the line, not the change.
	const noUser = "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.99 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT=23"

	b.Run("no_span_baseline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = matchRules(noUser, "kernel", SurfaceRaw)
			_ = matchRules(noUser, "kernel", SurfaceRedacted)
		}
	})

	b.Run("no_span_split", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = matchAll(noUser, "kernel")
		}
	})
}
