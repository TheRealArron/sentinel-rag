package correlate

import (
	"fmt"
	"strings"
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

// Bounding the number of tracked sources is not the same as bounding memory.
// Both fields below are grown by attacker-supplied input — the SSH username is
// chosen by whoever is connecting — so a single address could previously grow
// the correlator's heap without limit, and MaxTrackedIPs permits 8192 of them.
func TestPerSourceStateIsBounded(t *testing.T) {
	t.Run("distinct usernames cannot grow the heap without limit", func(t *testing.T) {
		c := New(Config{FailureThreshold: 5, Window: time.Hour, Cooldown: time.Hour})
		for i := 0; i < 10000; i++ {
			c.Observe(failure("203.0.113.9", fmt.Sprintf("user%d", i)), base.Add(time.Duration(i)*time.Millisecond))
		}
		st := c.state["203.0.113.9"]
		if got := len(st.users); got > maxUsersPerSource {
			t.Errorf("tracked %d usernames from one source, cap is %d", got, maxUsersPerSource)
		}
		if !st.usersOverflow {
			t.Error("overflow not recorded, so the alert would understate the spread")
		}
		// The alert must say the figure is capped rather than assert a precise
		// count it no longer knows.
		if list := c.userList(st); !strings.Contains(list, "tracking capped") {
			t.Errorf("user list %q does not disclose that tracking was capped", list)
		}
	})

	t.Run("failure timestamps cannot grow the heap without limit", func(t *testing.T) {
		c := New(Config{FailureThreshold: 5, Window: time.Hour, Cooldown: time.Hour})
		for i := 0; i < 10000; i++ {
			c.Observe(failure("203.0.113.9", "root"), base.Add(time.Duration(i)*time.Millisecond))
		}
		st := c.state["203.0.113.9"]
		if got := len(st.failures); got > maxFailuresPerSource {
			t.Errorf("retained %d timestamps from one source, cap is %d", got, maxFailuresPerSource)
		}
		// The running total is a counter, not a collection, so it stays exact.
		if st.totalFails != 10000 {
			t.Errorf("totalFails = %d, want 10000 — the true volume must not be lost", st.totalFails)
		}
		if got := c.failureCount(st); !strings.HasPrefix(got, ">=") {
			t.Errorf("failure_count = %q; a saturated count must read as a floor", got)
		}
	})

	t.Run("a saturated source recovers once its window drains", func(t *testing.T) {
		// Saturation must be a transient state. If it stuck, a source that was
		// once noisy would keep reporting approximate counts forever.
		c := New(Config{FailureThreshold: 5, Window: time.Minute, Cooldown: time.Hour})
		for i := 0; i < 500; i++ {
			c.Observe(failure("203.0.113.9", "root"), base.Add(time.Duration(i)*time.Millisecond))
		}
		st := c.state["203.0.113.9"]
		if !st.saturated {
			t.Fatal("expected saturation after 500 failures inside the window")
		}
		// One more failure, an hour later: everything before it has expired.
		c.Observe(failure("203.0.113.9", "root"), base.Add(time.Hour))
		if st.saturated {
			t.Error("still saturated after the window drained")
		}
		if got := c.failureCount(st); got != "1" {
			t.Errorf("failure_count = %q, want an exact 1 once the window drained", got)
		}
	})
}

// The caps must sit far above every threshold the detection logic reads, or
// bounding memory would silently change verdicts.
func TestCapsDoNotAffectAnyVerdict(t *testing.T) {
	if maxUsersPerSource < 10 {
		t.Errorf("maxUsersPerSource %d is below the 10 users the alert lists", maxUsersPerSource)
	}
	if maxUsersPerSource < 3 {
		t.Errorf("maxUsersPerSource %d is below the spraying threshold of 3", maxUsersPerSource)
	}
	if def := DefaultConfig(); maxFailuresPerSource <= def.FailureThreshold {
		t.Errorf("maxFailuresPerSource %d must exceed the brute-force threshold %d",
			maxFailuresPerSource, def.FailureThreshold)
	}
}
