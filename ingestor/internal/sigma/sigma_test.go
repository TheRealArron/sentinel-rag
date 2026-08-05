package sigma

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testEvent is a bare map-backed Event, so these tests exercise the matcher
// without dragging in the enrichment pipeline.
type testEvent map[string]string

func (e testEvent) SigmaField(name string) string { return e[name] }

func writeBundle(t *testing.T, dir, name string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

const oneRule = `{
  "version": 1,
  "generator": "test",
  "rules": [{
    "name": "test_rule", "title": "Test", "category": "authentication",
    "score": 70, "outcome": "failure", "mitre": ["T1110"], "tags": ["brute-force"],
    "processes": ["sshd"], "source": "test.yml", "sigma_id": "abc", "level": "high",
    "predicate": {"op": "match", "field": "message", "match": "contains",
                  "values": ["Failed password"], "cased": false}
  }]
}`

func TestLoadReadsABundle(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "rules.json", oneRule)

	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1", set.Len())
	}
	r := set.Rules()[0]
	if r.Name != "test_rule" || r.Score != 70 || r.SigmaID != "abc" {
		t.Errorf("metadata not carried through: %+v", r)
	}
	if got := set.Summary(); !strings.Contains(got, "high=1") {
		t.Errorf("Summary = %q, want it to mention high=1", got)
	}
}

// A missing rules directory is the normal case for an install with no imported
// rules, and must not be an error.
func TestLoadTreatsAMissingDirectoryAsEmpty(t *testing.T) {
	set, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load of a missing dir returned %v, want nil", err)
	}
	if set.Len() != 0 {
		t.Errorf("Len = %d, want 0", set.Len())
	}
}

// A nil Set must behave like an empty one: the ingestor passes nil when Sigma is
// disabled, and a panic there would take down log ingestion.
func TestNilSetIsInert(t *testing.T) {
	var set *Set
	if set.Len() != 0 || set.Rules() != nil || set.Sources() != nil {
		t.Error("nil Set should look empty")
	}
	if got := set.Match(testEvent{"message": "anything"}, "sshd"); got != nil {
		t.Errorf("nil Set matched: %v", got)
	}
}

// A bundle from a newer transpiler must be refused, not half-understood. Loading
// it while ignoring the constructs this build does not implement would silently
// under-match — the rule would look armed and detect nothing.
func TestLoadRefusesAFutureSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "future.json", strings.Replace(oneRule, `"version": 1`, `"version": 99`, 1))

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted a version 99 bundle")
	}
	if !strings.Contains(err.Error(), "make sigma") {
		t.Errorf("error should tell the operator how to fix it, got: %v", err)
	}
}

func TestLoadRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "odd.json",
		strings.Replace(oneRule, `"op": "match"`, `"op": "match", "timeframe": "5m"`, 1))

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a predicate carrying an unimplemented field")
	}
}

func TestLoadRejectsMalformedRules(t *testing.T) {
	cases := map[string]string{
		"empty name":     strings.Replace(oneRule, `"name": "test_rule"`, `"name": ""`, 1),
		"score over 100": strings.Replace(oneRule, `"score": 70`, `"score": 900`, 1),
		"unknown op":     strings.Replace(oneRule, `"op": "match"`, `"op": "xor"`, 1),
		"bad regex": strings.NewReplacer(
			`"match": "contains"`, `"match": "regex"`,
			`["Failed password"]`, `["a(("]`,
		).Replace(oneRule),
		"no values": strings.Replace(oneRule, `"values": ["Failed password"]`, `"values": []`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeBundle(t, dir, "bad.json", body)
			if _, err := Load(dir); err == nil {
				t.Errorf("Load accepted a bundle with %s", name)
			}
		})
	}
}

func TestProcessFilter(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "rules.json", oneRule)
	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ev := testEvent{"message": "Failed password for root"}
	if set.Match(ev, "sshd") == nil {
		t.Error("rule scoped to sshd did not match an sshd event")
	}
	if set.Match(ev, "SSHD") == nil {
		t.Error("process filter should be case-insensitive")
	}
	if set.Match(ev, "cron") != nil {
		t.Error("rule scoped to sshd matched a cron event")
	}
}

func TestMatchOperators(t *testing.T) {
	cases := []struct {
		name   string
		match  string
		values []string
		cased  bool
		actual string
		want   bool
	}{
		{"contains hit", OpContains, []string{"Failed password"}, false, "x Failed password y", true},
		{"contains miss", OpContains, []string{"Failed password"}, false, "Accepted password", false},
		{"contains folds case", OpContains, []string{"FAILED"}, false, "failed password", true},
		{"cased contains respects case", OpContains, []string{"FAILED"}, true, "failed password", false},
		{"equals is exact", OpEquals, []string{"root"}, false, "root", true},
		{"equals rejects a substring", OpEquals, []string{"root"}, false, "rooted", false},
		{"startswith", OpStartsWith, []string{"/etc/"}, false, "/etc/shadow", true},
		{"startswith miss", OpStartsWith, []string{"/etc/"}, false, "/var/etc/shadow", false},
		{"endswith", OpEndsWith, []string{".pem"}, false, "/root/key.pem", true},
		{"regex", OpRegex, []string{`port \d+`}, false, "from 10.0.0.1 port 22 ssh2", true},
		{"regex folds case by default", OpRegex, []string{`FAILED`}, false, "failed", true},
		{"any value matching is enough", OpContains, []string{"nope", "yes"}, false, "say yes", true},
		{"empty field never matches", OpContains, []string{"x"}, false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Predicate{Op: "match", Field: "message", MatchOp: tc.match, Values: tc.values, Cased: tc.cased}
			if err := compile(&p); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := p.Match(testEvent{"message": tc.actual}); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.actual, got, tc.want)
			}
		})
	}
}

// Sigma's `not` is the reason this is a tree and not a flattened regex: a rule
// that means "failures, but not from loopback" cannot survive being mashed into
// one pattern.
func TestBooleanComposition(t *testing.T) {
	p := Predicate{Op: "and", Children: []Predicate{
		{Op: "match", Field: "message", MatchOp: OpContains, Values: []string{"Failed password"}},
		{Op: "not", Children: []Predicate{
			{Op: "match", Field: "source_ip", MatchOp: OpEquals, Values: []string{"127.0.0.1"}},
		}},
	}}
	if err := compile(&p); err != nil {
		t.Fatalf("compile: %v", err)
	}

	remote := testEvent{"message": "Failed password for root", "source_ip": "203.0.113.9"}
	local := testEvent{"message": "Failed password for root", "source_ip": "127.0.0.1"}
	other := testEvent{"message": "Accepted password for root", "source_ip": "203.0.113.9"}

	if !p.Match(remote) {
		t.Error("remote failure should match")
	}
	if p.Match(local) {
		t.Error("the not-clause should have excluded loopback")
	}
	if p.Match(other) {
		t.Error("a success should not match a failure rule")
	}
}

// Rule order decides which detection wins, so it must not depend on the order
// the filesystem happens to return directory entries in.
func TestLoadOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "z-last.json", strings.Replace(oneRule, `"test_rule"`, `"z_rule"`, 1))
	writeBundle(t, dir, "a-first.json", strings.Replace(oneRule, `"test_rule"`, `"a_rule"`, 1))

	for i := 0; i < 5; i++ {
		set, err := Load(dir)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if set.Rules()[0].Name != "a_rule" || set.Rules()[1].Name != "z_rule" {
			t.Fatalf("rule order is not filename order: %s, %s",
				set.Rules()[0].Name, set.Rules()[1].Name)
		}
	}
}

// ---------------------------------------------------------------------------
// cross-implementation agreement
// ---------------------------------------------------------------------------

// The Python transpiler ships a reference evaluator (sentinel.sigma.evaluate).
// If the two implementations disagree about what a compiled rule means, the
// transpiler is worse than useless: `sentinel sigma` would report a detection as
// working while the ingestor silently interprets it differently.
//
// This test is the Go half of the agreement. The Python half
// (tests/test_sigma.py::test_go_and_python_agree) feeds the identical vectors to
// evaluate(); both read testdata/agreement.json, so neither side can drift
// without the other failing.
func TestAgreesWithThePythonReferenceEvaluator(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "agreement.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []struct {
		Name      string          `json:"name"`
		Predicate json.RawMessage `json:"predicate"`
		Event     testEvent       `json:"event"`
		Want      bool            `json:"want"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) < 10 {
		t.Fatalf("only %d vectors — the agreement suite should be broader", len(vectors))
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			var p Predicate
			dec := json.NewDecoder(strings.NewReader(string(v.Predicate)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("decode predicate: %v", err)
			}
			if err := compile(&p); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := p.Match(v.Event); got != v.Want {
				t.Errorf("Go says %v, Python says %v", got, v.Want)
			}
		})
	}
}

// The bundle the repo actually ships must load with the binary that actually
// ships. This catches a transpiler change that emits something Go cannot read.
func TestTheCommittedBundleLoads(t *testing.T) {
	path := filepath.Join("..", "..", "..", "rules", "external")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("rules/external not built — run `make sigma`")
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("the committed bundle does not load: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("the committed bundle is empty")
	}
	for _, r := range set.Rules() {
		if r.Title == "" || r.Category == "" || r.Level == "" {
			t.Errorf("rule %q is missing display metadata: %+v", r.Name, r)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(oneRule), 0o600); err != nil {
		b.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		b.Fatal(err)
	}
	ev := testEvent{"message": "Failed password for invalid user oracle from 203.0.113.45 port 55021 ssh2"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = set.Match(ev, "sshd")
	}
}
