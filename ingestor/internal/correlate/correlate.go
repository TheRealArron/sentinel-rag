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
	totalFails    int
}

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
		c.prune(st, ts)
		if len(st.failures) < maxFailuresPerSource {
			st.failures = append(st.failures, ts)
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
		if len(st.failures) >= c.cfg.FailureThreshold && c.offCooldown(st, ts) {
			st.lastAlert = ts
			out = append(out, c.bruteForceIncident(ev, st, ts))
		}

	case ev.Outcome == "success" && ev.Category == enrich.CatAuth:
		c.prune(st, ts)
		// A success on the heels of a failure burst is the signal that matters:
		// the guessing stopped because it worked.
		if len(st.failures) >= c.cfg.FailureThreshold/2+1 {
			out = append(out, c.compromiseIncident(ev, st, ts))
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
	inc.SetField("failure_count", c.failureCount(st))
	inc.SetField("window", c.cfg.Window.String())
	inc.SetField("targeted_users", c.userList(st))
	inc.SetField("total_failures_seen", fmt.Sprint(st.totalFails))
	return inc
}

func (c *Correlator) compromiseIncident(trigger *event.Event, st *sourceState, ts time.Time) *event.Event {
	msg := fmt.Sprintf(
		"INCIDENT probable compromise: successful login for %q from %s after %d recent failures from the same source",
		trigger.User, trigger.SourceIP, len(st.failures))

	inc := c.newIncident(trigger, ts, msg)
	inc.Rule = "correlated_successful_login_after_bruteforce"
	inc.Category = enrich.CatAuth
	inc.Outcome = "success"
	inc.Score = 97
	inc.Severity = event.SeverityFor(inc.Score)
	inc.MITRE = []string{"T1110.001", "T1078.003"}
	inc.AddTags("account-compromise", "アカウント侵害", "incident", "インシデント",
		"correlated", "相関検知", "brute-force", "ブルートフォース", enrich.CatAuth)
	inc.SetField("preceding_failures", c.failureCount(st))
	inc.SetField("targeted_users", c.userList(st))
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
