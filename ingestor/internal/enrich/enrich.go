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
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/honeytoken"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sigma"
)

var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
)

// Apply enriches ev in place using the parsed envelope and the sanitised message.
// tokens may be nil, in which case honeytoken detection is disabled.
func Apply(ev *event.Event, env parser.Envelope, san sanitize.Result, tokens *honeytoken.Set) {
	ApplyWithSigma(ev, env, san, tokens, nil)
}

// ApplyWithSigma is Apply plus detections transpiled from Sigma YAML.
func ApplyWithSigma(ev *event.Event, env parser.Envelope, san sanitize.Result,
	tokens *honeytoken.Set, sig *sigma.Set) {
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

	applySigma(ev, env, sig, matched)
	applyModifiers(ev, env, san)
	applyHoneytokens(ev, env, tokens)

	ev.Score = clamp(ev.Score, 0, 100)
	ev.Severity = event.SeverityFor(ev.Score)
	ev.AddTags(ev.Category)
	if ev.SourceIP != "" {
		ev.AddTags("scope:" + scopeOf(ev.SourceIP))
	}
}

// applySigma applies the matching transpiled Sigma rule, if any.
//
// The first version of this ran Sigma only when no built-in rule had matched, on
// the theory that the hand-tuned built-ins should win. Testing it end to end
// showed why that is wrong: the built-ins already cover the common SSH and sudo
// lines, so an imported rule was shadowed on essentially every event it was
// written for, and the import silently bought nothing.
//
// So Sigma always runs, and the two sources compose the way a real detection
// stack composes them:
//
//   - Tags and ATT&CK techniques always merge. This is most of the value of the
//     import — a built-in that knows a line is an SSH failure gains T1110.001
//     from the Sigma rule that knows it is brute force.
//   - The verdict (rule name, category, score) is taken over only when nothing
//     built-in matched, or when the Sigma rule scores strictly higher. An
//     imported rule can escalate an event; it cannot quietly downgrade one.
func applySigma(ev *event.Event, env parser.Envelope, sig *sigma.Set, builtinMatched bool) {
	if sig.Len() == 0 {
		return
	}
	rule := sig.Match(ev, env.Process)
	if rule == nil {
		return
	}

	// Attribution always merges: this is what the import is for.
	ev.MITRE = dedupe(append(ev.MITRE, rule.MITRE...))
	ev.AddTags(rule.Tags...)
	ev.SetField("sigma_rule", rule.Name)
	ev.SetField("sigma_title", rule.Title)
	ev.SetField("sigma_source", rule.Source)
	if rule.SigmaID != "" {
		ev.SetField("sigma_id", rule.SigmaID)
	}

	if builtinMatched && rule.Score <= ev.Score {
		return
	}
	if builtinMatched {
		// Preserve what the built-in concluded, so an analyst can see that two
		// independent rules fired and which one set the score.
		ev.SetField("builtin_rule", ev.Rule)
	}
	ev.Rule = rule.Name
	ev.Category = rule.Category
	ev.Score = rule.Score

	// Outcome is deliberately NOT overwritten when the pipeline already derived
	// one. Sigma has no outcome concept, so the transpiler's value is a guess
	// from the rule's level — whereas a built-in rule read success/failure off
	// the log line itself.
	//
	// This is not theoretical. The correlator keys brute-force detection on
	// `outcome == "failure"`, so the first version of this line — an
	// unconditional assignment — let an imported rule silently disable
	// brute-force and compromise correlation. The sample fixture went from 25
	// events to 23 and that is how it was caught.
	if ev.Outcome == "" {
		ev.Outcome = rule.Outcome
	}
}

// applyHoneytokens overrides the rule verdict when a canary is referenced.
//
// This runs *after* the rule engine rather than short-circuiting it, which is
// worth justifying because the obvious design is to check first and skip the
// regexes. Two reasons not to:
//
//  1. The saving is irrelevant. Measured: the honeytoken check is ~500 ns/line
//     (BenchmarkMatch) against ~65,000 ns/line for the 33-rule sweep
//     (benchmarks/), so it is 0.8% of the cost either way — and honeytoken hits
//     are rare by definition, so short-circuiting would optimise the path that
//     almost never runs.
//  2. The context is worth more than the microseconds. Running the rules first
//     means the alert still says *how* the canary was touched — a failed SSH
//     password, a sudo command, a useradd — instead of only that it was. That
//     detail is what an analyst triages on.
//
// So the rules run, then their verdict is overridden.
func applyHoneytokens(ev *event.Event, env parser.Envelope, tokens *honeytoken.Set) {
	if tokens == nil || tokens.Len() == 0 {
		return
	}
	hits := tokens.Match([]string{ev.User, ev.Fields["target_user"]}, env.Message)
	if len(hits) == 0 {
		return
	}

	values := make([]string, 0, len(hits))
	kinds := make([]string, 0, len(hits))
	fields := make([]string, 0, len(hits))
	for _, hit := range hits {
		values = append(values, hit.Token.Value)
		kinds = append(kinds, string(hit.Token.Kind))
		fields = append(fields, hit.Field)
		if hit.Token.Note != "" {
			ev.SetField("honeytoken_note", hit.Token.Note)
		}
	}

	// 100, unconditionally. Not "+40 and hope it clears the threshold": a
	// honeytoken is the one signal in this system with no benign explanation, so
	// it does not compete with the scoring model, it replaces it.
	ev.SetField("score_honeytoken", "=100")
	ev.Score = 100
	ev.Category = CatDeception
	// The matched rule is preserved under trigger_rule so the alert can still say
	// how the canary was touched.
	if ev.Rule != "" {
		ev.SetField("trigger_rule", ev.Rule)
	}
	ev.Rule = "honeytoken_referenced"
	ev.Outcome = "attempt"
	ev.SetField("honeytoken", strings.Join(values, ", "))
	ev.SetField("honeytoken_kind", strings.Join(kinds, ", "))
	ev.SetField("honeytoken_field", strings.Join(fields, ", "))

	// T1087.001 (Account Discovery: Local Account) is the attacker behaviour a
	// username canary catches; T1083 (File and Directory Discovery) is its
	// filesystem equivalent.
	ev.MITRE = append(ev.MITRE, "T1087.001")
	for _, hit := range hits {
		if hit.Token.Kind == honeytoken.KindPath {
			ev.MITRE = append(ev.MITRE, "T1083")
			break
		}
	}
	ev.MITRE = dedupe(ev.MITRE)

	ev.AddTags(
		"honeytoken", "ハニートークン",
		"deception", "デセプション",
		"canary", "カナリア",
		"high-confidence", "高信頼度",
	)
}

func dedupe(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := items[:0]
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
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
