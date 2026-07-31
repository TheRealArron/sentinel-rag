// Package enrich turns a parsed syslog envelope into a scored, tagged security
// event: it applies the detection rule set, extracts entities (IP, user, port,
// command), and derives a 0-100 risk score.
//
// Design note. Scoring is rule-base plus a small set of explicit modifiers
// rather than an opaque model, because a SOC analyst has to be able to explain
// why an alert fired at 03:00. Every modifier is recorded in the event's
// `fields` map under score_* keys so the reasoning is auditable end to end.
package enrich

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
)

var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
)

// Apply enriches ev in place using the parsed envelope and the sanitised message.
func Apply(ev *event.Event, env parser.Envelope, san sanitize.Result) {
	ev.Category = CatUnknown
	ev.Score = 5

	matched := false
	for i := range rules {
		r := &rules[i]
		if !r.appliesTo(env.Process) {
			continue
		}
		m := r.Pattern.FindStringSubmatch(env.Message)
		if m == nil {
			continue
		}
		if !matched {
			matched = true
			ev.Rule = r.Name
			ev.Category = r.Category
			ev.Score = r.Score
			ev.Outcome = r.Outcome
			ev.MITRE = append(ev.MITRE, r.MITRE...)
			applyCaptures(ev, r.Pattern, m)
		}
		ev.AddTags(r.Tags...)
	}

	// Entity extraction that runs regardless of rule match, so even an
	// unrecognised line is still pivotable by IP in the dashboard.
	if ev.SourceIP == "" {
		ev.SourceIP = firstIP(env.Message)
	}

	applyModifiers(ev, env, san)

	ev.Score = clamp(ev.Score, 0, 100)
	ev.Severity = event.SeverityFor(ev.Score)
	ev.AddTags(ev.Category)
	if ev.SourceIP != "" {
		ev.AddTags("scope:" + scopeOf(ev.SourceIP))
	}
}

// appliesTo enforces a rule's optional process filter, case-insensitively.
func (r *Rule) appliesTo(process string) bool {
	if len(r.Process) == 0 {
		return true
	}
	for _, p := range r.Process {
		if strings.EqualFold(p, process) {
			return true
		}
	}
	return false
}

// applyCaptures copies named capture groups onto the event. Known names map to
// first-class fields; anything else lands in Fields so new rules can add
// context without a schema change.
func applyCaptures(ev *event.Event, re *regexp.Regexp, m []string) {
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" || i >= len(m) || m[i] == "" {
			continue
		}
		v := sanitize.Field(m[i], 256)
		switch name {
		case "user":
			ev.User = v
		case "ip":
			if isIP(v) {
				ev.SourceIP = v
			}
		case "dest_ip":
			if isIP(v) {
				ev.DestIP = v
			}
		case "port":
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
				ev.SourcePort = n
			}
		case "dest_port":
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
				ev.DestPort = n
			}
		default:
			ev.SetField(name, v)
		}
	}
}

// applyModifiers adjusts the base rule score using context. Each adjustment is
// recorded so the final number can be explained.
func applyModifiers(ev *event.Event, env parser.Envelope, san sanitize.Result) {
	add := func(delta int, reason string) {
		if delta == 0 {
			return
		}
		ev.Score += delta
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		ev.SetField("score_"+reason, sign+strconv.Itoa(delta))
	}

	// Internet-facing source addresses matter more than loopback noise.
	if ev.SourceIP != "" {
		switch scopeOf(ev.SourceIP) {
		case "public":
			add(8, "public_source")
		case "loopback":
			add(-8, "loopback_source")
		case "private":
			add(-4, "private_source")
		}
	}

	// Anything touching root is a bigger deal.
	target := ev.Fields["target_user"]
	if strings.EqualFold(ev.User, "root") || strings.EqualFold(target, "root") {
		add(10, "root_involved")
	}

	// Syslog severity emerg/alert/crit from the originating daemon.
	if env.Severity >= 0 && env.Severity <= 2 {
		add(10, "syslog_critical")
		ev.AddTags("syslog-critical")
	}

	// The sanitiser found something that should not be in a log line at all.
	// This is itself a detection: it means someone is probing the logging path.
	if san.HadControl || san.HadEscape || san.HadBidi {
		add(25, "log_injection_indicator")
		ev.Category = CatEvasion
		ev.AddTags("log-injection", "ログインジェクション", "input-sanitised", "入力無害化")
		if ev.Rule == "" {
			ev.Rule = "sanitizer_anomaly"
		}
	}
	if san.HadInvalidUTF8 {
		add(5, "invalid_utf8")
		ev.AddTags("invalid-encoding", "不正エンコーディング")
	}
	if san.Truncated {
		ev.AddTags("truncated", "切り詰め")
	}

	// A line we could not parse at all is worth surfacing at low priority: it is
	// either a new log format or an attempt to evade format-based detection.
	if env.Format == "raw" {
		ev.AddTags("unparsed", "解析不能")
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func firstIP(s string) string {
	if m := ipv4Re.FindString(s); m != "" && isIP(m) {
		return m
	}
	if m := ipv6Re.FindString(s); m != "" && isIP(m) {
		return m
	}
	return ""
}

// scopeOf classifies an address so scoring can weight internet-facing activity
// above internal noise.
func scopeOf(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return "unknown"
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsPrivate():
		return "private"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsMulticast():
		return "multicast"
	default:
		return "public"
	}
}

// Scope is the exported form of scopeOf, used by the correlator and tests.
func Scope(s string) string { return scopeOf(s) }
