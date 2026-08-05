package enrich

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sigma"
)

// loadRules builds a one-rule Set at the given score, matching "Failed password".
func loadRules(t *testing.T, score int) *sigma.Set {
	t.Helper()
	dir := t.TempDir()
	body := `{"version":1,"generator":"test","rules":[{
	  "name":"sigma_test","title":"Sigma Test","category":"persistence",
	  "score":` + strconv.Itoa(score) + `,"outcome":"attempt","mitre":["T9999"],
	  "tags":["imported-tag"],"processes":[],"source":"test.yml",
	  "sigma_id":"sid-1","level":"high",
	  "predicate":{"op":"match","field":"message","match":"contains",
	               "values":["Failed password"],"cased":false}}]}`
	if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := sigma.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func enrichSigma(t *testing.T, msg, process string, set *sigma.Set) *event.Event {
	t.Helper()
	ev := &event.Event{Message: msg, Process: process}
	env := parser.Envelope{Message: msg, Process: process, Severity: -1, Format: "rfc3164"}
	ApplyWithSigma(ev, env, sanitize.Result{}, nil, set)
	return ev
}

// The built-in rule for a failed SSH password already matches this line. The
// Sigma rule must still contribute its ATT&CK technique and tags — that
// enrichment is the main reason to import a community ruleset at all.
func TestSigmaAlwaysContributesAttribution(t *testing.T) {
	msg := "Failed password for root from 203.0.113.9 port 22 ssh2"
	ev := enrichSigma(t, msg, "sshd", loadRules(t, 10))

	if !hasTag(ev, "imported-tag") {
		t.Errorf("imported tags were not merged: %v", ev.Tags)
	}
	if !hasMITRE(ev, "T9999") {
		t.Errorf("imported ATT&CK technique was not merged: %v", ev.MITRE)
	}
	if ev.Fields["sigma_rule"] != "sigma_test" || ev.Fields["sigma_id"] != "sid-1" {
		t.Errorf("sigma provenance missing: %v", ev.Fields)
	}
}

// A low-scoring imported rule must not be able to talk the pipeline down from a
// verdict a built-in rule already reached. Import can escalate, never soften.
func TestSigmaCannotDowngradeABuiltinVerdict(t *testing.T) {
	msg := "Failed password for root from 203.0.113.9 port 22 ssh2"
	baseline := enrichSigma(t, msg, "sshd", nil)
	withSigma := enrichSigma(t, msg, "sshd", loadRules(t, 10))

	if withSigma.Score < baseline.Score {
		t.Errorf("sigma lowered the score from %d to %d", baseline.Score, withSigma.Score)
	}
	if withSigma.Rule != baseline.Rule {
		t.Errorf("a lower-scoring sigma rule took over the verdict: %q replaced %q",
			withSigma.Rule, baseline.Rule)
	}
	if withSigma.Category != baseline.Category {
		t.Errorf("category changed to %q", withSigma.Category)
	}
}

// A higher-scoring imported rule should take over, and must record what the
// built-in concluded so the escalation is auditable.
func TestSigmaEscalatesAndPreservesTheBuiltinVerdict(t *testing.T) {
	msg := "Failed password for root from 203.0.113.9 port 22 ssh2"
	baseline := enrichSigma(t, msg, "sshd", nil)
	withSigma := enrichSigma(t, msg, "sshd", loadRules(t, 95))

	if withSigma.Rule != "sigma_test" {
		t.Errorf("higher-scoring sigma rule did not take over: rule=%q", withSigma.Rule)
	}
	if withSigma.Score <= baseline.Score {
		t.Errorf("score did not rise: %d -> %d", baseline.Score, withSigma.Score)
	}
	if withSigma.Fields["builtin_rule"] != baseline.Rule {
		t.Errorf("built-in verdict not preserved: got %q, want %q",
			withSigma.Fields["builtin_rule"], baseline.Rule)
	}
	if withSigma.Category != "persistence" {
		t.Errorf("category not taken from the sigma rule: %q", withSigma.Category)
	}
}

// With no built-in match, the Sigma rule sets the verdict outright.
func TestSigmaSetsTheVerdictWhenNothingBuiltinMatched(t *testing.T) {
	// A line no built-in rule covers, but which the test rule's substring hits.
	msg := "unusual daemon note: Failed password subsystem check"
	ev := enrichSigma(t, msg, "customd", loadRules(t, 66))

	if ev.Rule != "sigma_test" {
		t.Fatalf("sigma did not set the verdict: rule=%q score=%d", ev.Rule, ev.Score)
	}
	if _, ok := ev.Fields["builtin_rule"]; ok {
		t.Error("builtin_rule was recorded even though no built-in matched")
	}
	if ev.Severity != event.SeverityFor(ev.Score) {
		t.Errorf("severity %q does not follow score %d", ev.Severity, ev.Score)
	}
}

// Sigma must be entirely optional: nil is what the ingestor passes when the
// operator has imported nothing, which is the default install.
func TestNilSigmaSetChangesNothing(t *testing.T) {
	msg := "Failed password for root from 203.0.113.9 port 22 ssh2"
	viaApply := &event.Event{Message: msg, Process: "sshd"}
	env := parser.Envelope{Message: msg, Process: "sshd", Severity: -1, Format: "rfc3164"}
	Apply(viaApply, env, sanitize.Result{}, nil)

	viaSigma := enrichSigma(t, msg, "sshd", nil)

	if viaApply.Rule != viaSigma.Rule || viaApply.Score != viaSigma.Score {
		t.Errorf("Apply and ApplyWithSigma(nil) disagree: %q/%d vs %q/%d",
			viaApply.Rule, viaApply.Score, viaSigma.Rule, viaSigma.Score)
	}
}

// Regression: an imported rule must not be able to disable correlation.
//
// Sigma carries no outcome field, so the transpiler guesses one from the rule's
// level. An earlier version assigned that guess unconditionally, overwriting the
// "failure" a built-in rule had read off the log line — and the correlator keys
// brute-force detection on exactly that. Importing a Sigma rule silently turned
// off brute-force and compromise correlation; the sample fixture dropped from 25
// events to 23.
func TestSigmaDoesNotOverwriteADerivedOutcome(t *testing.T) {
	msg := "Failed password for root from 203.0.113.9 port 22 ssh2"
	baseline := enrichSigma(t, msg, "sshd", nil)
	if baseline.Outcome != "failure" {
		t.Fatalf("precondition: built-in outcome = %q, want \"failure\"", baseline.Outcome)
	}

	// Score 95 so the sigma rule wins the verdict — the exact case that broke.
	withSigma := enrichSigma(t, msg, "sshd", loadRules(t, 95))
	if withSigma.Outcome != "failure" {
		t.Errorf("sigma overwrote the derived outcome: %q, want \"failure\"", withSigma.Outcome)
	}
}

// Where nothing derived an outcome, the imported rule's value is the best
// available and should be used.
func TestSigmaSuppliesAnOutcomeWhenNoneWasDerived(t *testing.T) {
	ev := enrichSigma(t, "unusual daemon note: Failed password subsystem check", "customd",
		loadRules(t, 66))
	if ev.Outcome != "attempt" {
		t.Errorf("outcome = %q, want the sigma rule's \"attempt\"", ev.Outcome)
	}
}

// A honeytoken hit outranks everything, including an imported rule that scored
// higher than the built-ins. Deception is the one signal with no benign reading.
func TestHoneytokenStillOverridesSigma(t *testing.T) {
	msg := "Failed password for admin_backup from 203.0.113.9 port 22 ssh2"
	ev := &event.Event{Message: msg, Process: "sshd", User: "admin_backup"}
	env := parser.Envelope{Message: msg, Process: "sshd", Severity: -1, Format: "rfc3164"}
	ApplyWithSigma(ev, env, sanitize.Result{}, honeySet(t), loadRules(t, 95))

	if ev.Rule != "honeytoken_referenced" {
		t.Errorf("sigma displaced the honeytoken verdict: rule=%q", ev.Rule)
	}
	if ev.Score != 100 {
		t.Errorf("score = %d, want 100", ev.Score)
	}
	// The sigma attribution should survive as context on the honeytoken alert.
	if ev.Fields["sigma_rule"] != "sigma_test" {
		t.Errorf("sigma provenance lost: %v", ev.Fields)
	}
}
