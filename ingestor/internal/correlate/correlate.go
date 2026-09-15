// Package correlate turns a stream of individual events into incidents.
//
// A single "Failed password" line is noise; the internet knocks on port 22 all
// day. Five failures from one public address inside a minute is a brute-force
// attempt, and a *successful* login from an address that just failed five times
// is a probable compromise. That distinction cannot be made by a stateless
// per-line rule, so it lives here.
//
// The correlator is deliberately single-goroutine and time-ordered: the
// pipeline runs it after the reorder buffer, so state transitions follow log
// order rather than worker-scheduling order. Memory is bounded by MaxTrackedIPs
// with LRU eviction, because an attacker choosing a fresh source address per
// packet must not be able to grow our heap without limit.
package correlate

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/enrich"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
)

// Config tunes incident detection.
//
//	FailureThreshold  authentication failures from one source within Window that
//	                  constitute a brute-force incident
//	Window            sliding window for the threshold
//	Cooldown          minimum gap between repeat incidents for one source, so a
//	                  sustained attack yields one alert per period, not per packet
//	MaxTrackedIPs     upper bound on tracked sources; the oldest are evicted
type Config struct {
	FailureThreshold int
	Window           time.Duration
	Cooldown         time.Duration
	MaxTrackedIPs    int
}

// DefaultConfig reflects what we actually see on a home server exposed to the
// internet: opportunistic scanners try 3-4 credentials and move on, so 5 in a
// minute is a real campaign rather than background radiation.
func DefaultConfig() Config {
	return Config{
		FailureThreshold: 5,
		Window:           60 * time.Second,
		Cooldown:         5 * time.Minute,
		MaxTrackedIPs:    8192,
	}
}

// Per-source caps.
//
// MaxTrackedIPs bounds how many sources are tracked, but said nothing about how
// much state each one may accumulate — and both of the fields below are grown by
// attacker-controlled input. A single address supplying a fresh SSH username per
// attempt could grow `users` without limit, and the sanitiser caps a username at
// 256 bytes, so a sustained attempt from the 8192 permitted sources had no upper
// bound on memory at all. Bounding the outer map while leaving the inner state
// unbounded is not a bound.
//
// Both caps are set well above the values any detection here actually reads:
// spraying is declared at 3 distinct users and the alert lists 10, while the
// brute-force threshold defaults to 5 failures. So saturating either changes no
// verdict — it only makes the reported detail approximate, and only in the case
// where the exact figure has long stopped being interesting.
const (
	maxUsersPerSource    = 64
	maxFailuresPerSource = 128
)

type sourceState struct {
	// failures holds the timestamps of recent authentication failures inside the
	// window. Saturates at maxFailuresPerSource; totalFails stays exact.
	failures  []time.Time
	saturated bool
	// users is the distinct set of accounts this source has targeted, capped at
	// maxUsersPerSource. usersOverflow records that the real set is larger, so
	// the alert can say so rather than quietly understating the spread.
	users         map[string]struct{}
	usersOverflow bool
	lastSeen      time.Time
	lastAlert     time.Time
	// lastCompromise is tracked separately from lastAlert so the brute-force
	// cooldown and the compromise cooldown cannot suppress each other. They
	// describe different findings and an operator wants both.
	lastCompromise time.Time
	// windowAt is the time the sliding window is evaluated at for this source.
	// It only ever moves forward — see windowClock.
	windowAt   time.Time
	skewed     int
	totalFails int
}

// futureTolerance is how far ahead of ingest time a log timestamp may be before
// it stops being trusted to define "now".
//
// A log line describes something that already happened, so a timestamp in the
// future is a clock problem or a crafted line. Either way it must not drive the
// sliding window: prune() derives its cutoff from the timestamp of the arriving
// event, so a single line dated an hour ahead expired *every* real failure and
// silently reset the brute-force counter. Interleaving one such line every four
// attempts kept the count below the threshold indefinitely.
//
// Two minutes absorbs ordinary NTP drift and the timezone rounding in RFC 3164
// timestamps without absorbing anything an attacker could use.
const futureTolerance = 2 * time.Minute

// Correlator holds per-source sliding-window state. Not safe for concurrent use.
type Correlator struct {
	cfg    Config
	state  map[string]*sourceState
	seqGen int64
}

// New returns a Correlator, filling zero-valued config fields with defaults.
func New(cfg Config) *Correlator {
	def := DefaultConfig()
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = def.FailureThreshold
	}
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = def.Cooldown
	}
	if cfg.MaxTrackedIPs <= 0 {
		cfg.MaxTrackedIPs = def.MaxTrackedIPs
	}
	return &Correlator{cfg: cfg, state: make(map[string]*sourceState)}
}

// Observe feeds one event through the correlator and returns any incidents it
// triggered. ts is the event's log timestamp; callers pass the ingest time when
// the line carried none.
func (c *Correlator) Observe(ev *event.Event, ts time.Time) []*event.Event {
	if ev.SourceIP == "" {
		return nil
	}
	st := c.stateFor(ev.SourceIP, ts)
	st.lastSeen = ts
	// Everything below windows against `at`, never against the raw timestamp.
	at := c.windowClock(st, ts)

	var out []*event.Event
	isAuthFailure := ev.Outcome == "failure" &&
		(ev.Category == enrich.CatAuth || ev.Category == enrich.CatPrivilege)

	switch {
	case isAuthFailure:
		st.totalFails++
		// Expire first, then record. The order matters: pruning afterwards would
		// let a buffer still full of *stale* timestamps reject the new one, so a
		// source that saturated once could never register another failure even
		// after its window had completely drained — it would sit at a count of
		// zero while being actively attacked. Trimming first means the cap only
		// ever discards events that are genuinely concurrent.
		c.prune(st, at)
		if len(st.failures) < maxFailuresPerSource {
			st.failures = append(st.failures, at)
		} else {
			st.saturated = true
		}
		if ev.User != "" {
			if _, known := st.users[ev.User]; !known {
				if len(st.users) < maxUsersPerSource {
					st.users[ev.User] = struct{}{}
				} else {
					st.usersOverflow = true
				}
			}
		}
		if len(st.failures) >= c.cfg.FailureThreshold && c.offCooldown(st, at) {
			st.lastAlert = at
			out = append(out, c.bruteForceIncident(ev, st, at))
		}

	case ev.Outcome == "success" && ev.Category == enrich.CatAuth:
		c.prune(st, at)
		// A success on the heels of a failure burst is the signal that matters:
		// the guessing stopped because it worked.
		if len(st.failures) >= c.cfg.FailureThreshold/2+1 && c.offCompromiseCooldown(st, at) {
			st.lastCompromise = at
			out = append(out, c.loginAfterFailures(ev, st, at))
			// Reset the window so the next login is not re-alerted.
			st.failures = nil
		}
	}

	return out
}

func (c *Correlator) stateFor(ip string, ts time.Time) *sourceState {
	if st, ok := c.state[ip]; ok {
		return st
	}
	if len(c.state) >= c.cfg.MaxTrackedIPs {
		c.evictOldest()
	}
	st := &sourceState{users: make(map[string]struct{}, 4), lastSeen: ts}
	c.state[ip] = st
	return st
}

// evictOldest drops the least-recently-seen tenth of tracked sources. Batching
// the eviction keeps the O(n) scan amortised instead of running per insert.
func (c *Correlator) evictOldest() {
	type entry struct {
		ip string
		at time.Time
	}
	entries := make([]entry, 0, len(c.state))
	for ip, st := range c.state {
		entries = append(entries, entry{ip, st.lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	drop := len(entries) / 10
	if drop == 0 {
		drop = 1
	}
	for _, e := range entries[:drop] {
		delete(c.state, e.ip)
	}
}

func (c *Correlator) prune(st *sourceState, now time.Time) {
	cutoff := now.Add(-c.cfg.Window)
	keep := st.failures[:0]
	for _, t := range st.failures {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	st.failures = keep
	// Once the retained timestamps have drained below the cap the source is no
	// longer saturated, so its counts become exact again rather than reporting a
	// floor forever after one busy minute.
	if len(st.failures) < maxFailuresPerSource {
		st.saturated = false
	}
}

func (c *Correlator) offCooldown(st *sourceState, now time.Time) bool {
	return st.lastAlert.IsZero() || now.Sub(st.lastAlert) >= c.cfg.Cooldown
}

// offCompromiseCooldown is the same rule on its own timer. A busy NAT egress
// address can produce a legitimate login every few seconds; without this, each
// one re-raised the incident for as long as the failure window stayed full.
func (c *Correlator) offCompromiseCooldown(st *sourceState, now time.Time) bool {
	return st.lastCompromise.IsZero() || now.Sub(st.lastCompromise) >= c.cfg.Cooldown
}

// windowClock returns the time this source's sliding window is evaluated at.
//
// Two corrections to using the raw log timestamp, both of which were reachable
// without any attacker involvement:
//
//  1. A timestamp beyond futureTolerance ahead of ingest time is not trusted.
//     prune() derives its cutoff from it, so one future-dated line expired every
//     real failure and reset the brute-force counter.
//  2. The clock never runs backwards for a source. Log order is not timestamp
//     order once two files are concatenated — which `make shadow-demo` does, and
//     which any multi-host collector does by definition — and an out-of-order
//     arrival would otherwise widen the window and retain failures that had
//     already expired.
//
// Skew is counted rather than silently corrected, and surfaced on any incident
// the source goes on to raise. "Your clocks disagree" is something an operator
// needs told, not something a detector should quietly paper over.
func (c *Correlator) windowClock(st *sourceState, ts time.Time) time.Time {
	if ts.After(event.Now().Add(futureTolerance)) {
		// Not trusted, and therefore not used to advance anything. Clamping it
		// to the tolerance limit instead was the first attempt and it does not
		// work: with a 60s window and a limit two minutes ahead, the clamped
		// value still expires every genuine failure. A timestamp we have decided
		// not to believe cannot be allowed to define "now" at any magnitude.
		st.skewed++
		if !st.windowAt.IsZero() {
			return st.windowAt
		}
		return event.Now()
	}
	if ts.Before(st.windowAt) {
		return st.windowAt
	}
	st.windowAt = ts
	return ts
}

func (c *Correlator) userList(st *sourceState) string {
	users := make([]string, 0, len(st.users))
	for u := range st.users {
		users = append(users, u)
	}
	sort.Strings(users)
	if len(users) > 10 {
		remainder := fmt.Sprintf("+%d more", len(st.users)-10)
		if st.usersOverflow {
			// The set is capped, so "+54 more" would be a false precision about
			// an attacker who tried thousands of names.
			remainder = fmt.Sprintf("+%d more (tracking capped)", len(st.users)-10)
		}
		users = append(users[:10], remainder)
	}
	return join(users, ", ")
}

// failureCount renders the in-window count, marked as a floor when the per-source
// cap has been reached. Reporting a saturated 128 as though it were exact would
// understate a flood by an arbitrary amount; the true running total is carried
// separately in total_failures_seen and is never capped.
func (c *Correlator) failureCount(st *sourceState) string {
	if st.saturated {
		return fmt.Sprintf(">=%d", len(st.failures))
	}
	return fmt.Sprint(len(st.failures))
}

func (c *Correlator) bruteForceIncident(trigger *event.Event, st *sourceState, ts time.Time) *event.Event {
	msg := fmt.Sprintf(
		"INCIDENT brute-force: %s authentication failures from %s within %s (targeted users: %s)",
		c.failureCount(st), trigger.SourceIP, c.cfg.Window, orNone(c.userList(st)))

	inc := c.newIncident(trigger, ts, msg)
	inc.Rule = "correlated_brute_force"
	inc.Category = enrich.CatAuth
	inc.Outcome = "attempt"
	inc.Score = 82
	if enrich.Scope(trigger.SourceIP) == "public" {
		inc.Score += 6
	}
	if len(st.users) >= 3 {
		inc.Score += 4 // credential spraying across accounts
		inc.AddTags("password-spraying", "パスワードスプレー")
	}
	inc.Severity = event.SeverityFor(inc.Score)
	inc.MITRE = []string{"T1110.001", "T1110.003"}
	inc.AddTags("brute-force", "ブルートフォース", "incident", "インシデント",
		"correlated", "相関検知", enrich.CatAuth)
	if st.skewed > 0 {
		inc.SetField("clock_skew_events", strconv.Itoa(st.skewed))
		inc.AddTags("clock-skew", "時刻ずれ")
	}
	inc.SetField("failure_count", c.failureCount(st))
	inc.SetField("window", c.cfg.Window.String())
	inc.SetField("targeted_users", c.userList(st))
	inc.SetField("total_failures_seen", fmt.Sprint(st.totalFails))
	return inc
}

// loginAfterFailures reports a success from an address that was recently
// failing, at one of two severities.
//
// The original always scored 97 — the number that arms the firewall — on the
// strength of "a success from an address that was also failing". That is a
// false positive with teeth. Behind CGNAT, a corporate egress, or a university
// range, an attacker's failures and a colleague's legitimate login share a
// source address, and the detection wired to the responder was the one treating
// an IP as an identity.
//
// So the account matters. If the successful account is one the source was
// actually guessing at, the guessing stopped because it worked: 97, unchanged.
// If it is an account that was never targeted, the same address did both things
// and the likeliest explanation is a shared egress — reported, because going
// blind here would be worse, but below the score that acts without a human.
//
// The uncertain case is handled explicitly: once maxUsersPerSource is reached
// the tracked set is a sample, so "not targeted" stops being knowable and the
// finding keeps the higher severity rather than being quietly downgraded on
// missing evidence.
func (c *Correlator) loginAfterFailures(trigger *event.Event, st *sourceState, ts time.Time) *event.Event {
	_, targeted := st.users[trigger.User]
	certain := !st.usersOverflow

	var inc *event.Event
	if targeted || !certain {
		inc = c.newIncident(trigger, ts, fmt.Sprintf(
			"INCIDENT probable compromise: successful login for %q from %s after %s recent failures "+
				"against that same account", trigger.User, trigger.SourceIP, c.failureCount(st)))
		inc.Rule = "correlated_successful_login_after_bruteforce"
		inc.Score = 97
		inc.AddTags("account-compromise", "アカウント侵害")
	} else {
		inc = c.newIncident(trigger, ts, fmt.Sprintf(
			"INCIDENT successful login for %q from %s, which was failing against other accounts "+
				"(%s) — shared egress address or credentials obtained elsewhere",
			trigger.User, trigger.SourceIP, c.userList(st)))
		inc.Rule = "correlated_login_from_attacking_source"
		inc.Score = 74
		inc.AddTags("shared-source", "共有送信元", "needs-triage", "要トリアージ")
	}

	inc.Category = enrich.CatAuth
	inc.Outcome = "success"
	inc.Severity = event.SeverityFor(inc.Score)
	inc.MITRE = []string{"T1110.001", "T1078.003"}
	inc.AddTags("incident", "インシデント", "correlated", "相関検知",
		"brute-force", "ブルートフォース", enrich.CatAuth)
	if st.skewed > 0 {
		inc.SetField("clock_skew_events", strconv.Itoa(st.skewed))
		inc.AddTags("clock-skew", "時刻ずれ")
	}
	inc.SetField("preceding_failures", c.failureCount(st))
	inc.SetField("targeted_users", c.userList(st))
	inc.SetField("account_was_targeted", strconv.FormatBool(targeted))
	if !certain {
		inc.SetField("targeted_users_capped", "true")
	}
	return inc
}

// newIncident builds the common shell of a synthetic event. Incidents inherit
// the triggering event's identity fields so the dashboard can link back to the
// raw line that closed the case.
func (c *Correlator) newIncident(trigger *event.Event, ts time.Time, msg string) *event.Event {
	c.seqGen++
	inc := &event.Event{
		Seq:        trigger.Seq,
		RawSHA256:  event.Fingerprint(fmt.Sprintf("incident:%d:%s:%s", c.seqGen, trigger.SourceIP, msg)),
		Timestamp:  ts.UTC().Format(time.RFC3339Nano),
		Host:       trigger.Host,
		Facility:   trigger.Facility,
		Process:    "sentinel-correlator",
		Message:    msg,
		SourceIP:   trigger.SourceIP,
		SourcePort: trigger.SourcePort,
		User:       trigger.User,
		ParseOK:    true,
	}
	inc.SetField("trigger_rule", trigger.Rule)
	inc.SetField("trigger_sha256", trigger.RawSHA256)
	inc.SetField("source_scope", enrich.Scope(trigger.SourceIP))
	inc.Stamp()
	return inc
}

func orNone(s string) string {
	if s == "" {
		return "none recorded"
	}
	return s
}

// join avoids pulling in strings for a single call in this hot-ish path.
func join(parts []string, sep string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	n := len(sep) * (len(parts) - 1)
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	b = append(b, parts[0]...)
	for _, p := range parts[1:] {
		b = append(b, sep...)
		b = append(b, p...)
	}
	return string(b)
}
