package correlate

import (
	"testing"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/enrich"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
)

var base = time.Date(2026, time.July, 30, 5, 30, 0, 0, time.UTC)

func failure(ip, user string) *event.Event {
	return &event.Event{
		SourceIP: ip, User: user,
		Category: enrich.CatAuth, Outcome: "failure",
		Rule: "ssh_failed_password", Score: 54,
	}
}

func success(ip, user string) *event.Event {
	return &event.Event{
		SourceIP: ip, User: user,
		Category: enrich.CatAuth, Outcome: "success",
		Rule: "ssh_accepted_login", Score: 26,
	}
}

func TestBruteForceThreshold(t *testing.T) {
	c := New(Config{FailureThreshold: 5, Window: time.Minute, Cooldown: time.Hour})

	for i := 0; i < 4; i++ {
		if inc := c.Observe(failure("203.0.113.45", "admin"), base.Add(time.Duration(i)*time.Second)); len(inc) != 0 {
			t.Fatalf("incident fired early at failure %d", i+1)
		}
	}
	inc := c.Observe(failure("203.0.113.45", "admin"), base.Add(4*time.Second))
	if len(inc) != 1 {
		t.Fatalf("got %d incidents at the threshold, want 1", len(inc))
	}
	got := inc[0]
	if got.Rule != "correlated_brute_force" {
		t.Errorf("Rule = %q", got.Rule)
	}
	if got.Severity != event.SeverityCritical {
		t.Errorf("Severity = %q (score %d), want critical", got.Severity, got.Score)
	}
	if got.Fields["failure_count"] != "5" {
		t.Errorf("failure_count = %q, want 5", got.Fields["failure_count"])
	}
	if got.SourceIP != "203.0.113.45" || got.Process != "sentinel-correlator" {
		t.Errorf("ip/process = %q/%q", got.SourceIP, got.Process)
	}
}

func TestFailuresOutsideWindowDoNotAccumulate(t *testing.T) {
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second, Cooldown: time.Hour})
	// One failure every 30s: never 5 within any 60s window.
	for i := 0; i < 20; i++ {
		if inc := c.Observe(failure("203.0.113.45", "root"), base.Add(time.Duration(i)*30*time.Second)); len(inc) != 0 {
			t.Fatalf("slow drip triggered an incident at attempt %d", i+1)
		}
	}
}

func TestCooldownSuppressesRepeats(t *testing.T) {
	c := New(Config{FailureThreshold: 3, Window: time.Minute, Cooldown: 5 * time.Minute})
	total := 0
	// 30 failures over 90 seconds: many thresholds crossed, one alert allowed.
	for i := 0; i < 30; i++ {
		total += len(c.Observe(failure("203.0.113.45", "root"), base.Add(time.Duration(i)*3*time.Second)))
	}
	if total != 1 {
		t.Errorf("got %d incidents, want 1 (cooldown should suppress the rest)", total)
	}
}

func TestPasswordSprayingRaisesScore(t *testing.T) {
	single := New(Config{FailureThreshold: 3, Window: time.Minute, Cooldown: time.Hour})
	spray := New(Config{FailureThreshold: 3, Window: time.Minute, Cooldown: time.Hour})

	var singleInc, sprayInc *event.Event
	for i, u := range []string{"root", "root", "root"} {
		if got := single.Observe(failure("203.0.113.45", u), base.Add(time.Duration(i)*time.Second)); len(got) == 1 {
			singleInc = got[0]
		}
	}
	for i, u := range []string{"root", "admin", "oracle"} {
		if got := spray.Observe(failure("203.0.113.46", u), base.Add(time.Duration(i)*time.Second)); len(got) == 1 {
			sprayInc = got[0]
		}
	}
	if singleInc == nil || sprayInc == nil {
		t.Fatal("expected both correlators to fire")
	}
	if sprayInc.Score <= singleInc.Score {
		t.Errorf("spray score %d should exceed single-user score %d", sprayInc.Score, singleInc.Score)
	}
	if sprayInc.Fields["targeted_users"] != "admin, oracle, root" {
		t.Errorf("targeted_users = %q", sprayInc.Fields["targeted_users"])
	}
}

func TestSuccessAfterFailuresIsProbableCompromise(t *testing.T) {
	c := New(Config{FailureThreshold: 5, Window: time.Minute, Cooldown: time.Hour})
	for i := 0; i < 3; i++ {
		c.Observe(failure("203.0.113.45", "arron"), base.Add(time.Duration(i)*time.Second))
	}
	inc := c.Observe(success("203.0.113.45", "arron"), base.Add(4*time.Second))
	if len(inc) != 1 {
		t.Fatalf("got %d incidents, want 1", len(inc))
	}
	if inc[0].Rule != "correlated_successful_login_after_bruteforce" {
		t.Fatalf("Rule = %q", inc[0].Rule)
	}
	if inc[0].Score < 90 {
		t.Errorf("Score = %d, want >= 90 for a probable compromise", inc[0].Score)
	}

	// The window is reset, so a second clean login does not re-alert.
	if again := c.Observe(success("203.0.113.45", "arron"), base.Add(10*time.Second)); len(again) != 0 {
		t.Errorf("re-alerted on a subsequent login: %d incidents", len(again))
	}
}

func TestCleanSuccessDoesNotAlert(t *testing.T) {
	c := New(DefaultConfig())
	if inc := c.Observe(success("192.168.1.20", "arron"), base); len(inc) != 0 {
		t.Errorf("clean login produced %d incidents", len(inc))
	}
}

func TestEventsWithoutSourceIPAreIgnored(t *testing.T) {
	c := New(DefaultConfig())
	ev := failure("", "root")
	for i := 0; i < 50; i++ {
		if inc := c.Observe(ev, base.Add(time.Duration(i)*time.Second)); len(inc) != 0 {
			t.Fatal("correlated an event with no source address")
		}
	}
	if len(c.state) != 0 {
		t.Errorf("tracked %d sources for IP-less events, want 0", len(c.state))
	}
}

func TestMemoryIsBoundedUnderSourceAddressFlood(t *testing.T) {
	const max = 100
	c := New(Config{FailureThreshold: 5, Window: time.Minute, Cooldown: time.Hour, MaxTrackedIPs: max})
	for i := 0; i < 10000; i++ {
		ip := ipFor(i)
		c.Observe(failure(ip, "root"), base.Add(time.Duration(i)*time.Millisecond))
		if len(c.state) > max {
			t.Fatalf("tracked %d sources, exceeds cap %d", len(c.state), max)
		}
	}
}

// ipFor generates 10.a.b.c addresses so the flood test uses distinct sources.
func ipFor(i int) string {
	a := (i / 65536) % 256
	b := (i / 256) % 256
	c := i % 256
	return "10." + itoa(a) + "." + itoa(b) + "." + itoa(c)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
