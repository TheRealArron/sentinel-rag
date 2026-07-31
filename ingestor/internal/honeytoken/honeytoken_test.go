package honeytoken

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSet(t *testing.T) *Set {
	t.Helper()
	set, err := New(Config{
		Users: []Entry{{Value: "admin_backup", Note: "canary"}, {Value: "svc_deploy"}},
		Paths: []Entry{{Value: "/etc/.backup_credentials"}},
		Hosts: []Entry{{Value: "vault-internal.lan"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return set
}

func TestMatchUsernameExactly(t *testing.T) {
	hits := testSet(t).Match([]string{"admin_backup"}, "Failed password for admin_backup from 203.0.113.45")
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
	if hits[0].Token.Kind != KindUser || hits[0].Field != "user" {
		t.Errorf("kind/field = %s/%s", hits[0].Token.Kind, hits[0].Field)
	}
	if hits[0].Token.Note != "canary" {
		t.Errorf("note = %q", hits[0].Token.Note)
	}
}

func TestMatchIsCaseInsensitiveButRecordsWhatWasSeen(t *testing.T) {
	// An attacker case-varying their wordlist is the same attacker.
	hits := testSet(t).Match([]string{"Admin_Backup"}, "")
	if len(hits) != 1 {
		t.Fatalf("case variant not matched: %+v", hits)
	}
	if hits[0].Observed != "Admin_Backup" {
		t.Errorf("Observed = %q, want the form actually seen", hits[0].Observed)
	}
	if hits[0].Token.Value != "admin_backup" {
		t.Errorf("Token.Value = %q, want the configured form", hits[0].Token.Value)
	}
}

func TestTargetUserIsReportedSeparately(t *testing.T) {
	hits := testSet(t).Match([]string{"alice", "svc_deploy"}, "")
	if len(hits) != 1 || hits[0].Field != "target_user" {
		t.Fatalf("expected one target_user hit, got %+v", hits)
	}
}

func TestNoFalsePositiveOnOrdinaryTraffic(t *testing.T) {
	set := testSet(t)
	// This is the property the whole design rests on: a score of 100 is only
	// defensible if normal activity never produces one.
	for _, line := range []string{
		"Failed password for root from 203.0.113.45 port 51001 ssh2",
		"Accepted publickey for arron from 192.168.1.20 port 51234 ssh2",
		"(root) CMD (/usr/bin/certbot renew --quiet)",
		"pam_unix(sshd:session): session opened for user ubuntu by (uid=0)",
		"arron : TTY=pts/0 ; PWD=/home/arron ; USER=root ; COMMAND=/bin/bash",
		"Started Daily apt download activities.",
		"[UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP DPT=23",
		"new user: name=deploy, UID=1002, GID=1002, home=/home/deploy",
	} {
		if hits := set.Match([]string{"root", "arron"}, line); len(hits) != 0 {
			t.Errorf("false positive on %q: %+v", line, hits)
		}
	}
}

func TestPathTokenMatchesInsideACommand(t *testing.T) {
	hits := testSet(t).Match([]string{"arron"}, "arron : COMMAND=cat /etc/.backup_credentials")
	if len(hits) != 1 || hits[0].Token.Kind != KindPath {
		t.Fatalf("path canary not matched: %+v", hits)
	}
	if hits[0].Field != "message" {
		t.Errorf("Field = %q, want message", hits[0].Field)
	}
}

func TestUsernameInACommandBodyIsCaught(t *testing.T) {
	// "useradd admin_backup" has no identity field to match against, but it is
	// still someone touching the canary.
	hits := testSet(t).Match([]string{""}, "new user: name=admin_backup, UID=1002")
	if len(hits) != 1 || hits[0].Field != "message" {
		t.Fatalf("username in message body not matched: %+v", hits)
	}
}

func TestATokenIsReportedOnceEvenWhenItAppearsTwice(t *testing.T) {
	hits := testSet(t).Match([]string{"admin_backup"}, "Failed password for admin_backup from 1.2.3.4")
	if len(hits) != 1 {
		t.Fatalf("token double-counted: %+v", hits)
	}
}

func TestMultipleTokensAreAllReported(t *testing.T) {
	hits := testSet(t).Match([]string{"admin_backup"}, "cat /etc/.backup_credentials on vault-internal.lan")
	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3: %+v", len(hits), hits)
	}
}

func TestNilSetMatchesNothing(t *testing.T) {
	var set *Set
	if hits := set.Match([]string{"admin_backup"}, "anything"); hits != nil {
		t.Errorf("nil set returned %+v", hits)
	}
	if set.Len() != 0 || set.Summary() == "" {
		t.Error("nil set should be safely inert")
	}
}

func TestShortSubstringTokensAreRejected(t *testing.T) {
	// A 2-character "path" would match constantly and turn the highest-severity
	// detector in the system into noise.
	_, err := New(Config{Paths: []Entry{{Value: "ab"}}})
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("err = %v, want a length complaint", err)
	}
}

func TestDuplicateUsersAreRejected(t *testing.T) {
	_, err := New(Config{Users: []Entry{{Value: "dup"}, {Value: "DUP"}}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate complaint", err)
	}
}

func TestEmptyValueIsRejected(t *testing.T) {
	if _, err := New(Config{Users: []Entry{{Value: "  "}}}); err == nil {
		t.Fatal("expected an error for an empty token")
	}
}

func TestLoadAcceptsBareStringsAndObjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.json")
	os.WriteFile(path, []byte(`{
	  "users": ["plain_string", {"value": "with_note", "note": "why"}],
	  "paths": ["/etc/.decoy_file"]
	}`), 0o600)

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Len() != 3 {
		t.Fatalf("Len = %d, want 3", set.Len())
	}
	if set.Path() != path {
		t.Errorf("Path = %q", set.Path())
	}
	if hits := set.Match([]string{"plain_string"}, ""); len(hits) != 1 {
		t.Error("bare string form did not arm")
	}
	if hits := set.Match([]string{"with_note"}, ""); len(hits) != 1 || hits[0].Token.Note != "why" {
		t.Error("object form did not arm with its note")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	// "user" instead of "users" would otherwise parse into an empty set, and a
	// honeypot that is silently unarmed is worse than none at all.
	dir := t.TempDir()
	path := filepath.Join(dir, "h.json")
	os.WriteFile(path, []byte(`{"user": ["typo"]}`), 0o600)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown key")
	}
}

func TestLoadMissingFileWrapsErrNotExist(t *testing.T) {
	// main.go branches on errors.Is(err, os.ErrNotExist) to tell "optional
	// feature absent" from "operator named a file that is missing". Asserted with
	// errors.Is, matching the caller — os.IsNotExist does not unwrap %w and would
	// pass or fail for the wrong reason.
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestVerifyAgainstPasswdFindsCollisions(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"# a comment\n"+
			"admin_backup:x:1001:1001::/home/admin_backup:/bin/bash\n"+
			"arron:x:1000:1000::/home/arron:/bin/bash\n"), 0o600)

	collisions, err := testSet(t).VerifyAgainstPasswd(passwd)
	if err != nil {
		t.Fatalf("VerifyAgainstPasswd: %v", err)
	}
	if len(collisions) != 1 || collisions[0] != "admin_backup" {
		t.Fatalf("collisions = %v, want [admin_backup]", collisions)
	}
}

func TestVerifyAgainstPasswdCleanWhenNoCollision(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\narron:x:1000:1000::/home/arron:/bin/bash\n"), 0o600)

	collisions, err := testSet(t).VerifyAgainstPasswd(passwd)
	if err != nil || len(collisions) != 0 {
		t.Fatalf("collisions = %v, err = %v", collisions, err)
	}
}

func TestSummaryGroupsByKind(t *testing.T) {
	summary := testSet(t).Summary()
	for _, want := range []string{"user=2", "path=1", "host=1"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q missing %q", summary, want)
		}
	}
}

// BenchmarkMatch justifies running honeytokens alongside the rule engine rather
// than short-circuiting it: if the check costs tens of nanoseconds against the
// rule sweep's ~65 microseconds, the ordering is a non-question.
func BenchmarkMatch(b *testing.B) {
	set, _ := New(Config{
		Users: []Entry{{Value: "admin_backup"}, {Value: "svc_deploy"}, {Value: "backup_operator"}},
		Paths: []Entry{{Value: "/etc/.backup_credentials"}, {Value: "/root/.aws/credentials.bak"}},
	})
	line := "Failed password for root from 203.0.113.45 port 51001 ssh2"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Match([]string{"root", ""}, line)
	}
}
