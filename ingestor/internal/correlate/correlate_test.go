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

// ---------------------------------------------------------------------------
// Clock handling.
//
// prune() derives its cutoff from the timestamp of the arriving event, so the
// window is only as trustworthy as the timestamps in the log. Two ways that went
// wrong, neither of which needed an attacker.
// ---------------------------------------------------------------------------

// freezeIngestClock pins event.Now, which is the reference the correlator
// compares log timestamps against.
func freezeIngestClock(t *testing.T, at time.Time) {
	t.Helper()
	event.Now = func() time.Time { return at }
	t.Cleanup(func() { event.Now = func() time.Time { return time.Now().UTC() } })
}

func TestAFutureTimestampCannotResetTheWindow(t *testing.T) {
	// The evasion: prune() expired everything older than (future - window), so a
	// single line dated ahead of the stream wiped the accumulated failures.
	// Interleaving one every few attempts held the count below the threshold for
	// as long as the attacker cared to keep going.
	freezeIngestClock(t, base.Add(time.Minute))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	for i := 0; i < 4; i++ {
		if got := c.Observe(failure("203.0.113.45", fmt.Sprintf("u%d", i)), base.Add(time.Duration(i)*time.Second)); len(got) != 0 {
			t.Fatalf("unexpected incident at failure %d", i)
		}
	}

	// The fifth failure carries a timestamp an hour into the future. Before the
	// fix, prune() expired all four earlier failures against a cutoff derived
	// from it, leaving a count of one — so this line both failed to complete the
	// burst and destroyed the evidence for it.
	out := c.Observe(failure("203.0.113.45", "skewed"), base.Add(time.Hour))
	if len(out) != 1 || out[0].Rule != "correlated_brute_force" {
		t.Fatalf("a future-dated line reset the window; got %d event(s): %v", len(out), out)
	}
	if out[0].Fields["clock_skew_events"] == "" {
		t.Error("the skew should be reported on the incident, not silently corrected")
	}
	if !hasTag(out[0], "clock-skew") {
		t.Errorf("missing clock-skew tag: %v", out[0].Tags)
	}
}

func TestAnOutOfOrderTimestampDoesNotWidenTheWindow(t *testing.T) {
	// Log order is not timestamp order once two files are concatenated, which is
	// what `make shadow-demo` does and what any multi-host collector does by
	// definition. Winding the window back would retain failures that had already
	// expired and manufacture a burst out of hours of background noise.
	freezeIngestClock(t, base.Add(24*time.Hour))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	// Four failures, then a jump forward well past the window.
	for i := 0; i < 4; i++ {
		c.Observe(failure("203.0.113.45", fmt.Sprintf("u%d", i)), base.Add(time.Duration(i)*time.Second))
	}
	c.Observe(failure("203.0.113.45", "later"), base.Add(10*time.Minute))

	// A straggler arriving late but stamped back inside the original burst must
	// not resurrect it.
	out := c.Observe(failure("203.0.113.45", "straggler"), base.Add(4*time.Second))
	if len(out) != 0 {
		t.Fatalf("an out-of-order timestamp rewound the window and raised %v", out[0].Rule)
	}
}

func TestALegitimateQuietGapStillAdvancesTheWindow(t *testing.T) {
	// The counterweight: clamping must not mistake a genuinely idle source for
	// skew, or failures from hours ago would stay in the window forever.
	freezeIngestClock(t, base.Add(48*time.Hour))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	for i := 0; i < 4; i++ {
		c.Observe(failure("203.0.113.45", fmt.Sprintf("u%d", i)), base.Add(time.Duration(i)*time.Second))
	}
	// Six hours later, four more. Neither burst alone reaches the threshold.
	for i := 0; i < 4; i++ {
		out := c.Observe(failure("203.0.113.45", fmt.Sprintf("v%d", i)), base.Add(6*time.Hour+time.Duration(i)*time.Second))
		if len(out) != 0 {
			t.Fatalf("stale failures from six hours earlier were counted: %v", out[0].Message)
		}
	}
}

// ---------------------------------------------------------------------------
// The compromise verdict, and the account it is about.
// ---------------------------------------------------------------------------

func TestSuccessForATargetedAccountIsACompromise(t *testing.T) {
	freezeIngestClock(t, base.Add(time.Minute))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	for _, user := range []string{"admin", "oracle", "arron"} {
		c.Observe(failure("203.0.113.45", user), base)
	}
	out := c.Observe(success("203.0.113.45", "arron"), base.Add(time.Second))

	if len(out) != 1 || out[0].Rule != "correlated_successful_login_after_bruteforce" {
		t.Fatalf("got %v, want a compromise incident", out)
	}
	if out[0].Score != 97 {
		t.Errorf("Score = %d, want 97", out[0].Score)
	}
	if out[0].Fields["account_was_targeted"] != "true" {
		t.Errorf("account_was_targeted = %q", out[0].Fields["account_was_targeted"])
	}
}

func TestSuccessForAnUntargetedAccountIsNotACompromise(t *testing.T) {
	// The shared-egress false positive. Behind CGNAT or a corporate NAT an
	// attacker's failures and a colleague's login share one address, and this
	// used to score 97 — the number that arms the firewall — on that alone.
	freezeIngestClock(t, base.Add(time.Minute))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	for _, user := range []string{"admin", "oracle", "test"} {
		c.Observe(failure("198.51.100.30", user), base)
	}
	out := c.Observe(success("198.51.100.30", "colleague"), base.Add(time.Second))

	if len(out) != 1 {
		t.Fatalf("the event should still be reported, got %d", len(out))
	}
	inc := out[0]
	if inc.Rule != "correlated_login_from_attacking_source" {
		t.Fatalf("Rule = %q, want correlated_login_from_attacking_source", inc.Rule)
	}
	if inc.Score >= 90 {
		t.Errorf("Score = %d: an untargeted account on a shared address can arm the firewall", inc.Score)
	}
	if inc.Fields["account_was_targeted"] != "false" {
		t.Errorf("account_was_targeted = %q", inc.Fields["account_was_targeted"])
	}
	// Reported, not suppressed: going blind here would be the worse failure.
	if !strings.Contains(inc.Message, "colleague") {
		t.Errorf("the incident should name the account: %q", inc.Message)
	}
}

func TestAnUncertainTargetSetKeepsTheHigherSeverity(t *testing.T) {
	// Once the per-source user cap is reached the tracked set is a sample, so
	// "this account was never targeted" stops being knowable. Downgrading on
	// missing evidence would let an attacker earn the lower score by trying
	// enough usernames.
	freezeIngestClock(t, base.Add(time.Minute))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second})

	for i := 0; i < maxUsersPerSource+5; i++ {
		c.Observe(failure("203.0.113.45", fmt.Sprintf("user%d", i)), base)
	}
	out := c.Observe(success("203.0.113.45", "someone-else"), base.Add(time.Second))

	if len(out) != 1 || out[0].Rule != "correlated_successful_login_after_bruteforce" {
		t.Fatalf("got %v, want the compromise verdict when the target set is capped", out)
	}
	if out[0].Fields["targeted_users_capped"] != "true" {
		t.Error("the incident should record that the target set was a sample")
	}
}

func TestCompromiseHasItsOwnCooldown(t *testing.T) {
	// A busy shared address can log in every few seconds. Without a cooldown
	// each one re-raised the incident for as long as the failure window stayed
	// full — and the brute-force cooldown does not cover this path.
	freezeIngestClock(t, base.Add(time.Minute))
	c := New(Config{FailureThreshold: 5, Window: 60 * time.Second, Cooldown: 5 * time.Minute})

	for _, user := range []string{"admin", "oracle", "arron"} {
		c.Observe(failure("203.0.113.45", user), base)
	}
	if got := c.Observe(success("203.0.113.45", "arron"), base.Add(time.Second)); len(got) != 1 {
		t.Fatalf("first success should raise an incident, got %d", len(got))
	}
	for _, user := range []string{"admin", "oracle", "arron"} {
		c.Observe(failure("203.0.113.45", user), base.Add(2*time.Second))
	}
	if got := c.Observe(success("203.0.113.45", "arron"), base.Add(3*time.Second)); len(got) != 0 {
		t.Errorf("a second success inside the cooldown re-alerted: %v", got[0].Rule)
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
