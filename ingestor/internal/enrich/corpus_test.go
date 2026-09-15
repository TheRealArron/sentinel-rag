package enrich

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
)

// The detection corpus answers the question the rest of the suite could not:
// do these rules work?
//
// Before this existed, "33 detection rules" was a count. Nothing said whether a
// rule fired on the attack it was written for, nothing said whether it fired on
// ordinary traffic, and nothing failed when a new rule was added with neither
// property established. The rule set's false-positive profile was unmeasured,
// and an unmeasured false-positive rate on a security tool is not a small gap:
// it is the difference between an alert an operator acts on and one they learn
// to close.
//
// Two files, two questions:
//
//	cases.jsonl   per rule, a line it must catch and a near-miss it must not
//	benign.log    a day of ordinary host traffic that must stay quiet
//
// benign.log is hand-authored rather than produced by
// scripts/generate-baseline-log.py. That generator emits a fixed cast of log
// shapes — cron, sshd, ufw, sudo, sessions — modelled on the same assumptions as
// the rules, so measuring the rules against it is circular. It cannot surface a
// false positive because it never emits a line nobody thought about. The lines
// here are the ones a real Ubuntu box writes and nobody designed a rule around:
// systemd reloading a unit, snapd refreshing, sshd's own debug chatter, fwupd,
// anacron, thermald.

const (
	corpusDir = "testdata/detection"

	// benignScoreFloor is the score at which an event on a benign corpus counts
	// as a false positive. 40 is `warning` — the point at which the dashboard
	// stops treating an event as background and an operator is expected to look.
	benignScoreFloor = 40

	// benignBudget is the number of benign lines still scoring at or above the
	// floor. Committed so a regression fails the build, and meant to go down,
	// never up.
	//
	// It started at 13 and the fixes took it to 1. What is left is one line:
	//
	//   ansible-command: Invoked with _raw_params=curl -fsSL https://get.docker.com | sh
	//
	// That is irreducible with the information available. Configuration
	// management fetching a script and piping it to a shell is byte-for-byte the
	// same operation as a dropper, and the rule sees only the command line — not
	// who scheduled it, not whether the URL is trusted, not whether this host
	// runs Ansible at all. Lowering the score to make it disappear would mean
	// under-reporting a genuine dropper, which is the wrong direction to be
	// wrong in. So it stays, budgeted and named, rather than quietly tuned away.
	benignBudget = 1
)

type detectionCase struct {
	Rule string `json:"rule"`
	Kind string `json:"kind"` // "positive" or "negative"
	Line string `json:"line"`
	Why  string `json:"why"`
	// Verdict names the rule expected to *report* this line when it is not the
	// rule under test. Composition is real: a package install performed through
	// sudo is better reported as the sudo command, which names the actor as well
	// as the change. Declaring it keeps the test pinning actual behaviour
	// instead of being relaxed to accommodate it.
	Verdict string `json:"verdict,omitempty"`
}

func loadCases(t *testing.T) []detectionCase {
	t.Helper()
	fh, err := os.Open(filepath.Join(corpusDir, "cases.jsonl"))
	if err != nil {
		t.Fatalf("open cases: %v", err)
	}
	defer fh.Close()

	var cases []detectionCase
	scanner := bufio.NewScanner(fh)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var c detectionCase
		if err := json.Unmarshal([]byte(text), &c); err != nil {
			t.Fatalf("cases.jsonl:%d: %v", line, err)
		}
		if c.Rule == "" || c.Line == "" || c.Why == "" {
			t.Fatalf("cases.jsonl:%d: rule, line and why are all required", line)
		}
		if c.Kind != "positive" && c.Kind != "negative" {
			t.Fatalf("cases.jsonl:%d: kind must be positive or negative, got %q", line, c.Kind)
		}
		cases = append(cases, c)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read cases: %v", err)
	}
	return cases
}

// firedRules returns every rule that matched a raw syslog line, using the same
// two-pass evaluation the pipeline uses.
func firedRules(t *testing.T, line string) []string {
	t.Helper()
	san := sanitize.Line(line, 0)
	env := parser.Parse(san.Clean)
	matches, _ := matchAll(env.Message, env.Process)
	names := make([]string, 0, len(matches))
	for i := range matches {
		names = append(names, matches[i].rule.Name)
	}
	return names
}

func TestEveryRuleHasAPositiveAndANegativeCase(t *testing.T) {
	// The coverage gate. A rule added without a case it must catch and a case it
	// must not is a rule nobody has shown to work, and it fails here rather than
	// in production.
	positives, negatives := map[string]bool{}, map[string]bool{}
	for _, c := range loadCases(t) {
		if c.Kind == "positive" {
			positives[c.Rule] = true
		} else {
			negatives[c.Rule] = true
		}
	}
	known := map[string]bool{}
	for i := range rules {
		known[rules[i].Name] = true
		if !positives[rules[i].Name] {
			t.Errorf("rule %q has no positive case in %s/cases.jsonl", rules[i].Name, corpusDir)
		}
		if !negatives[rules[i].Name] {
			t.Errorf("rule %q has no near-miss negative case in %s/cases.jsonl", rules[i].Name, corpusDir)
		}
	}
	for name := range positives {
		if !known[name] {
			t.Errorf("cases.jsonl names %q, which is not a rule (renamed or removed?)", name)
		}
	}
}

func TestDetectionCasesHold(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.Kind+"/"+c.Rule, func(t *testing.T) {
			fired := firedRules(t, c.Line)
			matched := false
			for _, name := range fired {
				if name == c.Rule {
					matched = true
					break
				}
			}
			switch c.Kind {
			case "positive":
				if !matched {
					t.Errorf("%s did not fire.\n  line: %s\n  why it should: %s\n  fired instead: %v",
						c.Rule, c.Line, c.Why, fired)
				}
			case "negative":
				if matched {
					t.Errorf("%s fired on a line it should ignore.\n  line: %s\n  why not: %s",
						c.Rule, c.Line, c.Why)
				}
			}
		})
	}
}

func TestPositiveCasesAlsoWinTheVerdict(t *testing.T) {
	// Firing is not the same as being reported. A rule that matches but is
	// always outscored by another rule on its own canonical line is a rule the
	// analyst never sees, and the count of 33 would still include it.
	for _, c := range loadCases(t) {
		if c.Kind != "positive" {
			continue
		}
		t.Run(c.Rule, func(t *testing.T) {
			want := c.Verdict
			if want == "" {
				want = c.Rule
			}
			ev := enrichLine(t, c.Line)
			if ev.Rule != want {
				t.Errorf("verdict went to %q, want %q, on %q's own positive case.\n  line: %s",
					ev.Rule, want, c.Rule, c.Line)
			}
		})
	}
}

func TestBenignCorpusStaysQuiet(t *testing.T) {
	fh, err := os.Open(filepath.Join(corpusDir, "benign.log"))
	if err != nil {
		t.Fatalf("open benign corpus: %v", err)
	}
	defer fh.Close()

	type hit struct {
		lineNo int
		score  int
		rule   string
		line   string
	}
	var hits []hit
	byRule := map[string]int{}

	scanner := bufio.NewScanner(fh)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		ev := enrichLine(t, raw)
		if ev.Score >= benignScoreFloor {
			hits = append(hits, hit{lineNo, ev.Score, ev.Rule, raw})
			byRule[ev.Rule]++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read benign corpus: %v", err)
	}

	if len(hits) > benignBudget {
		names := make([]string, 0, len(byRule))
		for name := range byRule {
			names = append(names, name)
		}
		sort.Strings(names)
		var b strings.Builder
		fmt.Fprintf(&b, "%d benign line(s) scored >= %d (budget %d)\n",
			len(hits), benignScoreFloor, benignBudget)
		fmt.Fprintf(&b, "\nby rule:\n")
		for _, name := range names {
			fmt.Fprintf(&b, "  %-34s %d\n", name, byRule[name])
		}
		fmt.Fprintf(&b, "\nlines:\n")
		for _, h := range hits {
			fmt.Fprintf(&b, "  benign.log:%-4d score=%-3d %-34s %s\n",
				h.lineNo, h.score, h.rule, truncate(h.line, 90))
		}
		t.Error(b.String())
	}

	t.Logf("benign corpus: %d lines, %d scored >= %d", lineNo, len(hits), benignScoreFloor)
}

func TestSSHRulesSurviveTheOpenSSHTagSplit(t *testing.T) {
	// OpenSSH 9.8 (July 2024) split sshd into per-connection `sshd-session` and
	// `sshd-auth` binaries that log under their own syslog tags. Five rules carry
	// Process: ["sshd"], and an exact-equality filter takes all five dark on
	// Ubuntu 24.10+ and Debian 13 — silently, which is what makes it worth a test
	// rather than a note. Nothing on this developer's host emits the new tag yet,
	// so the only thing standing between an OpenSSH upgrade and losing most of
	// the SSH detection is this assertion.
	bodies := []struct {
		body     string
		wantRule string
	}{
		{"Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2", "ssh_failed_password"},
		{"Invalid user oracle from 203.0.113.45 port 51234", "ssh_invalid_user"},
		{"Accepted password for arron from 203.0.113.45 port 51234 ssh2", "ssh_accepted_login"},
		{"error: maximum authentication attempts exceeded for root from 203.0.113.45 port 51234 ssh2 [preauth]", "ssh_max_auth_attempts"},
		{"Connection closed by 203.0.113.45 port 51234 [preauth]", "ssh_preauth_disconnect"},
	}
	for _, tag := range []string{"sshd", "sshd-session", "sshd-auth"} {
		for _, tc := range bodies {
			t.Run(tag+"/"+tc.wantRule, func(t *testing.T) {
				line := fmt.Sprintf("Jul 30 05:30:12 sentinel %s[4021]: %s", tag, tc.body)
				ev := enrichLine(t, line)
				if ev.Rule != tc.wantRule {
					t.Errorf("under tag %q the rule was %q, want %q — the process filter "+
						"stopped matching", tag, ev.Rule, tc.wantRule)
				}
			})
		}
	}

	// The alias must not widen anything else. systemd-resolved is not systemd.
	unrelated := enrichLine(t, "Jul 30 05:30:12 sentinel sshd-nonsense[1]: (root) CMD (/bin/true)")
	if unrelated.Rule == "cron_job_executed" {
		t.Error("an unknown sshd-* tag was folded into a process family it does not belong to")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
