// Package parser turns a sanitised syslog line into the syslog envelope fields
// of an Event: timestamp, host, process, PID, and message body.
//
// Three wire formats are supported, tried in order of specificity:
//
//	RFC 5424  <34>1 2026-07-30T05:30:00.123+09:00 host app 1234 ID47 - msg
//	ISO-8601  2026-07-30T05:30:00.123456+09:00 host app[1234]: msg
//	RFC 3164  <34>Jul 30 05:30:00 host app[1234]: msg
//
// RFC 3164 omits the year, which is a real operational problem: a December log
// read in January must not be dated eleven months in the future. resolveYear
// handles that rollover explicitly.
package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Envelope is the transport-level part of a log line, before detection logic.
//
// Severity holds the syslog PRI severity (0 emerg .. 7 debug) or -1 when the
// line carried no PRI prefix. Format is one of "rfc5424", "iso8601", "rfc3164",
// or "raw" for a line we could not decompose.
type Envelope struct {
	Timestamp time.Time
	HasTime   bool
	Host      string
	Facility  string
	Severity  int
	Process   string
	PID       int
	Message   string
	Format    string
}

var (
	// <PRI> prefix, optional on file-based logs (rsyslog strips it).
	priRe = regexp.MustCompile(`^<(\d{1,3})>`)

	rfc5424Re = regexp.MustCompile(`^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?:\[[^\]]*\]|-) ?(?P<msg>.*)$`)

	iso8601Re = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) +(?P<rest>.*)$`)

	rfc3164Re = regexp.MustCompile(`^(?P<ts>[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) +(?P<rest>.*)$`)

	// "host app[pid]: message" / "host app: message" / "app[pid]: message"
	tagRe = regexp.MustCompile(`^(?P<tag>[A-Za-z0-9_./\-]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$`)
)

// facilities indexed by syslog facility number (RFC 5424 table 1).
var facilities = [...]string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// Now is indirected for deterministic tests.
var Now = func() time.Time { return time.Now() }

// Parse extracts the syslog envelope. It never fails: an unrecognised line
// becomes Format "raw" with the whole line as Message, because dropping logs is
// worse than under-parsing them.
func Parse(line string) Envelope {
	env := Envelope{Severity: -1, Format: "raw", Message: line}
	rest := line

	if m := priRe.FindStringSubmatch(rest); m != nil {
		if pri, err := strconv.Atoi(m[1]); err == nil && pri <= 191 {
			fac := pri / 8
			env.Severity = pri % 8
			if fac < len(facilities) {
				env.Facility = facilities[fac]
			}
		}
		rest = rest[len(m[0]):]
	}

	if m := rfc5424Re.FindStringSubmatch(rest); m != nil {
		env.Format = "rfc5424"
		if ts, err := parseRFC3339Loose(m[1]); err == nil {
			env.Timestamp, env.HasTime = ts, true
		}
		env.Host = nilDash(m[2])
		env.Process = nilDash(m[3])
		if pid, err := strconv.Atoi(m[4]); err == nil {
			env.PID = pid
		}
		env.Message = m[6]
		return env
	}

	if m := iso8601Re.FindStringSubmatch(rest); m != nil {
		env.Format = "iso8601"
		if ts, err := parseRFC3339Loose(m[1]); err == nil {
			env.Timestamp, env.HasTime = ts, true
		}
		splitHostTag(&env, m[2])
		return env
	}

	if m := rfc3164Re.FindStringSubmatch(rest); m != nil {
		env.Format = "rfc3164"
		if ts, err := parseBSDTime(m[1], Now()); err == nil {
			env.Timestamp, env.HasTime = ts, true
		}
		splitHostTag(&env, m[2])
		return env
	}

	// No timestamp: still try to recover "app[pid]: message".
	if m := tagRe.FindStringSubmatch(rest); m != nil {
		env.Process = m[1]
		if pid, err := strconv.Atoi(m[2]); err == nil {
			env.PID = pid
		}
		env.Message = m[3]
	} else {
		env.Message = rest
	}
	return env
}

// splitHostTag consumes "host app[pid]: msg", tolerating a missing hostname
// (common when reading a container's stdout) by checking whether the first
// token already looks like a tag.
func splitHostTag(env *Envelope, rest string) {
	first, remainder, found := strings.Cut(rest, " ")
	if !found {
		env.Message = rest
		return
	}
	// A leading "app[pid]:" means there is no hostname field.
	if strings.HasSuffix(first, ":") || strings.Contains(first, "[") {
		if m := tagRe.FindStringSubmatch(rest); m != nil {
			env.Process = m[1]
			if pid, err := strconv.Atoi(m[2]); err == nil {
				env.PID = pid
			}
			env.Message = m[3]
			return
		}
	}
	env.Host = first
	if m := tagRe.FindStringSubmatch(remainder); m != nil {
		env.Process = m[1]
		if pid, err := strconv.Atoi(m[2]); err == nil {
			env.PID = pid
		}
		env.Message = m[3]
		return
	}
	env.Message = remainder
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parseRFC3339Loose accepts the RFC3339 variants that real syslog daemons emit,
// including a space date/time separator and a missing zone.
func parseRFC3339Loose(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999Z0700",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	var err error
	var t time.Time
	for _, l := range layouts {
		if t, err = time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, err
}

// parseBSDTime resolves a year-less RFC 3164 timestamp against a reference time.
func parseBSDTime(s string, ref time.Time) (time.Time, error) {
	// "Jul  3" (two spaces) and "Jul 30" must both work.
	t, err := time.Parse("Jan _2 15:04:05", s)
	if err != nil {
		if t, err = time.Parse("Jan 2 15:04:05", s); err != nil {
			return time.Time{}, err
		}
	}
	year := resolveYear(t.Month(), ref)
	return time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, ref.Location()).UTC(), nil
}

// resolveYear picks the year for a year-less month.
//
// A log month more than one month ahead of the reference month belongs to the
// previous year (reading a December log in January); otherwise it is the current
// year. The one-month tolerance absorbs clock skew and timezone offsets without
// mistaking them for a rollover.
func resolveYear(m time.Month, ref time.Time) int {
	delta := int(m) - int(ref.Month())
	if delta > 1 {
		return ref.Year() - 1
	}
	if delta < -10 {
		// Log is January-ish while the reference is still December: the log is
		// from the coming year (host clock slightly ahead of ours).
		return ref.Year() + 1
	}
	return ref.Year()
}
