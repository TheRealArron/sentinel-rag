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
	"sort"
	"strconv"
	"strings"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/event"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/honeytoken"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/ioc"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/parser"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sanitize"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sigma"
)

var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
)

// Detectors bundles the optional detection sources. Every field may be nil,
// which disables that detector; the built-in rule set always runs.
//
// This is a struct rather than more parameters because the list had grown by one
// on each phase — honeytokens, then Sigma, then IOC feeds — and a call site
// passing four nils in the right order is a defect waiting to happen. Named
// fields also mean a new detector does not touch existing callers.
type Detectors struct {
	Honeytokens *honeytoken.Set
	Sigma       *sigma.Set
	IOC         *ioc.Feed
}

// Apply enriches ev in place using the parsed envelope and the sanitised
// message, running only the built-in rule set.
func Apply(ev *event.Event, env parser.Envelope, san sanitize.Result) {
	ApplyWith(ev, env, san, Detectors{})
}

// ApplyWith is Apply plus whichever optional detectors are configured.
//
// Rule evaluation runs in two passes, because the rules that can safely read a
// raw log line are also the rules that tell us which spans of it the attacker
// wrote:
//
//  1. SurfaceRaw rules match against the message as logged. Their patterns
//     anchor on daemon-emitted literals, and their `user`/`target_user`
//     captures locate the attacker-chosen spans.
//  2. Those spans are blanked, and SurfaceRedacted rules — the keyword hunts —
//     match against the result. A username of "xmrig" is then just a username.
//
// The verdict goes to the highest-scoring match across both passes, ties broken
// by declaration order. Captures from *every* match are applied, so the entities
// on the event no longer depend on which rule won.
func ApplyWith(ev *event.Event, env parser.Envelope, san sanitize.Result, det Detectors) {
	ev.Category = CatUnknown
	ev.Score = 5

	matches, redacted := matchAll(env.Message, env.Process)
	win := strongest(matches)
	matched := win >= 0

	// Captures first from the losers, then from the winner, so the winning
	// rule's view of the line is authoritative while a lower-precedence match
	// can still supply a field the winner does not capture at all.
	for i := range matches {
		if i != win {
			applyCaptures(ev, matches[i])
		}
	}
	if matched {
		applyCaptures(ev, matches[win])
	}

	// Tags merge in declaration order, unchanged: every matching rule
	// contributes its bilingual pair regardless of which set the verdict.
	for i := range matches {
		ev.AddTags(matches[i].rule.Tags...)
	}

	if matched {
		r := matches[win].rule
		ev.Rule = r.Name
		ev.Category = r.Category
		ev.Score = r.Score
		ev.Outcome = r.Outcome
		ev.MITRE = append(ev.MITRE, r.MITRE...)
	}

	// Entity extraction that runs regardless of rule match, so even an
	// unrecognised line is still pivotable by IP in the dashboard.
	//
	// It reads the *redacted* message. An address inside a username is a string
	// the attacker typed, not the peer sshd was talking to, and taking it as the
	// source address let a remote party stamp an event of their choosing onto an
	// address of their choosing.
	if ev.SourceIP == "" {
		ev.SourceIP = firstIP(redacted)
	}

	applySigma(ev, env, redacted, det.Sigma, matched)
	applyModifiers(ev, env, san)
	// IOC enrichment runs before honeytokens so that an event which is both a
	// canary reference and a feed hit still ends at a flat 100: honeytokens
	// replace the scoring model rather than adding to it.
	applyIOC(ev, redacted, det.IOC)
	applyHoneytokens(ev, env, det.Honeytokens)

	ev.Score = clamp(ev.Score, 0, 100)
	ev.Severity = event.SeverityFor(ev.Score)
	ev.AddTags(ev.Category)
	if ev.SourceIP != "" {
		ev.AddTags("scope:" + scopeOf(ev.SourceIP))
	}
}

// redactedEvent presents an event to the Sigma matcher with the attacker-chosen
// spans of the message blanked out.
//
// An imported rule written as `message|contains: xmrig` has exactly the defect
// the built-in keyword rules had — a username sets the verdict, and Sigma rules
// are allowed to escalate one. Rules that genuinely want to inspect an account
// name should match the `user` field, which is unmodified and is where the
// transpiler's FIELD_MAP points them.
//
// The wrapper lives here rather than in the sigma package on purpose: the
// matcher's own semantics are pinned by the shared Go/Python agreement vectors,
// and this is a decision about what text to hand it, not about how it matches.
type redactedEvent struct {
	*event.Event
	message string
}

func (r redactedEvent) SigmaField(name string) string {
	switch name {
	case "message":
		return r.message
	case "command":
		// event.SigmaField falls back to the raw message when no command was
		// parsed, which would reintroduce the hole through a different field
		// name. A genuinely captured command is returned as-is: it is a record
		// of something the host ran, not a string typed at a login prompt.
		if cmd := r.Event.Fields["command"]; cmd != "" {
			return cmd
		}
		return r.message
	}
	return r.Event.SigmaField(name)
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
func applySigma(ev *event.Event, env parser.Envelope, redacted string, sig *sigma.Set, builtinMatched bool) {
	if sig.Len() == 0 {
		return
	}
	rule := sig.Match(redactedEvent{Event: ev, message: redacted}, env.Process)
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

// iocWeight is the score added for a confirmed indicator, by indicator type.
//
// The three are deliberately not equal, because their evidential value is not
// equal:
//
//   - A file hash identifies the artefact itself. It is immutable, and a
//     SHA-256 on a malware feed means this exact file, not something adjacent to
//     it. Strongest.
//   - A domain is chosen by the operator of the thing it names, so it carries
//     intent, but domains get parked, sinkholed and resold.
//   - An IP is the weakest indicator in common use and is routinely treated as
//     though it were the strongest. Addresses are shared by NAT, CDNs and
//     hosting providers, are reassigned constantly, and a blocklist entry that
//     was accurate last month may now point at a bystander. A hit is worth
//     noting; it is not worth much on its own.
var iocWeight = map[ioc.Type]int{
	ioc.TypeHash:   45,
	ioc.TypeDomain: 35,
	ioc.TypeIP:     25,
}

// iocMaxScore caps an event whose severity comes from a feed hit.
//
// # Why a cap exists at all
//
// The ioc package has no false positives in the sense that matters to it: every
// filter hit is confirmed against the exact store, so a reported indicator is
// genuinely in the feed. That is a narrower guarantee than it sounds. It says
// the *lookup* was right, not that the *feed* was — and feed contents are
// external, mutable, and outside this system's control. A mistaken or poisoned
// entry for a DNS resolver or a CDN address is a normal occurrence in threat
// intelligence, not an exotic attack.
//
// Phase 5 established that a honeytoken is the only signal permitted to reach
// the score that triggers an automated firewall block, precisely because it is
// the only one with no benign explanation and no external dependency. Letting a
// feed hit stack on top of a rule match and cross that line would have quietly
// revoked that property — the auto-blocker would start acting on third-party
// data, and the first sign of trouble would be a blocked upstream resolver.
//
// So the cap is drawn at the *actuating* threshold, not at a severity label. A
// feed hit may take an event all the way to critical severity — a confirmed
// known-malware hash on a root command line is critical, and under-reporting it
// would be its own failure — but it can never reach the score that makes the
// responder act without a human. Blocking still requires a canary or a
// correlated incident, both derived from this host's own observations.
//
// 89 is one below the default SENTINEL_RESPONSE_MIN_SCORE;
// TestIOCCannotReachTheResponseThreshold pins the relationship so a change to
// either number fails loudly rather than silently arming the firewall from a
// third-party feed.
const iocMaxScore = 89

// applyIOC annotates an event with confirmed threat-feed indicators.
//
// Multiple hits take the maximum weight rather than summing. Summing is the
// obvious implementation and it is wrong here: a single outbound connection log
// can legitimately mention a source IP, a destination IP and a hostname, so three
// additive weights would let one ordinary line reach the cap on nothing more
// than a verbose message. The extra hits are still recorded — they are context
// for the analyst — but they do not compound the score.
func applyIOC(ev *event.Event, redacted string, feed *ioc.Feed) {
	if feed == nil || feed.Len() == 0 {
		return
	}
	entities := map[string]string{"source_ip": ev.SourceIP, "dest_ip": ev.DestIP}
	hits, err := feed.Match(entities, redacted)
	if err != nil {
		// The store became unreadable mid-run. Losing enrichment on this event is
		// survivable; dropping the event is not, so the failure is recorded on the
		// event and ingestion continues.
		ev.AddTags("ioc-lookup-error")
		ev.SetField("ioc_error", sanitize.Field(err.Error(), 200))
		return
	}
	if len(hits) == 0 {
		return
	}

	values := make([]string, 0, len(hits))
	types := make([]string, 0, len(hits))
	feeds := make([]string, 0, len(hits))
	fields := make([]string, 0, len(hits))
	best := 0
	for _, hit := range hits {
		values = append(values, hit.Record.Indicator)
		types = append(types, string(hit.Record.Type))
		feeds = append(feeds, hit.Record.Feed)
		fields = append(fields, hit.Candidate.Field)
		if w := iocWeight[hit.Record.Type]; w > best {
			best = w
		}
		if hit.Record.Note != "" {
			ev.SetField("ioc_note", hit.Record.Note)
		}
	}

	before := ev.Score
	ev.Score += best
	ev.SetField("score_ioc", "+"+strconv.Itoa(best))
	if ev.Score > iocMaxScore {
		// The cap stops a feed from *raising* an event to where the responder
		// acts. It must not *lower* one that was already there on this host's
		// own evidence: a reverse shell scores 96 by itself, and clamping that
		// to 89 because a threat feed agreed would disarm the responder for the
		// most serious events in the system — the exact inverse of the intent.
		if before > iocMaxScore {
			ev.Score = before
			ev.SetField("score_ioc", "+0 (already above the feed cap; recorded as context)")
		} else {
			ev.Score = iocMaxScore
			ev.SetField("score_ioc_capped", "="+strconv.Itoa(iocMaxScore))
		}
	}

	// An event that matched no built-in rule is still worth reporting if it
	// touched a known-bad indicator — that is most of the value of a feed. One
	// that did match keeps its verdict, with the indicator as added context,
	// because "failed SSH password from a known C2" is a better alert than
	// "known C2".
	if ev.Rule == "" {
		ev.Rule = "ioc_match"
		ev.Category = CatNetwork
	}
	ev.SetField("ioc", strings.Join(values, ", "))
	ev.SetField("ioc_type", strings.Join(types, ", "))
	ev.SetField("ioc_feed", strings.Join(feeds, ", "))
	ev.SetField("ioc_field", strings.Join(fields, ", "))

	// No ATT&CK technique is attached. A feed hit says an indicator was seen, not
	// what was done with it — the same IP can appear in reconnaissance, C2 or
	// exfiltration — and inventing a technique here would put an unearned
	// attribution into the graph and the analyst's prompt. Where the technique is
	// actually known, the built-in or Sigma rule that matched has already
	// supplied it.
	ev.AddTags(
		"ioc", "侵害指標",
		"threat-intel", "脅威インテリジェンス",
	)
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
// Honeytokens deliberately read the *raw* message. Every other detector is
// handed redacted text because a keyword inside a username is not evidence of
// anything — but a canary username is the exception that proves it. Nothing on
// the host is called `admin_backup`, so a login attempt for `admin_backup` is
// the detection, not a false positive smuggled through a user field.
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

// processAliases maps a syslog tag onto the daemon family a rule's Process
// filter names.
//
// OpenSSH 9.8 (July 2024) split `sshd` into per-connection `sshd-session` and
// `sshd-auth` binaries, which log under their own tags. A rule filtered on
// `sshd` with an exact-equality check therefore stops matching on Ubuntu 24.10+
// and Debian 13 — and stops matching *silently*, which is the part that makes it
// dangerous. Five of the six SSH rules here carry that filter, so the failure
// mode is "most of the SSH detection is off and nothing says so".
//
// An explicit table rather than a prefix or hyphen rule: `systemd-resolved` must
// not be folded into `systemd`, and a rule that widens itself by accident is the
// same class of surprise in the other direction. One entry per real-world split,
// added when a real daemon does it.
var processAliases = map[string]string{
	"sshd-session": "sshd",
	"sshd-auth":    "sshd",
}

// appliesTo enforces a rule's optional process filter, case-insensitively and
// after alias folding.
func (r *Rule) appliesTo(process string) bool {
	if len(r.Process) == 0 {
		return true
	}
	family := process
	if alias, ok := processAliases[strings.ToLower(process)]; ok {
		family = alias
	}
	for _, p := range r.Process {
		if strings.EqualFold(p, process) || strings.EqualFold(p, family) {
			return true
		}
	}
	return false
}

// ruleMatch is one rule firing on one line. It keeps the submatch *offsets*
// rather than the extracted strings, because redaction needs to know where the
// attacker-chosen spans are, not merely what they said.
type ruleMatch struct {
	index int // position in `rules`, for deterministic precedence tie-breaks
	rule  *Rule
	text  string // the text this rule was evaluated against
	loc   []int  // as returned by Regexp.FindStringSubmatchIndex
}

// group returns capture group i, or "" when the group did not participate.
func (m ruleMatch) group(i int) string {
	if 2*i+1 >= len(m.loc) {
		return ""
	}
	lo, hi := m.loc[2*i], m.loc[2*i+1]
	if lo < 0 || hi < lo {
		return ""
	}
	return m.text[lo:hi]
}

// matchAll runs both passes and returns every rule that fired, along with the
// redacted message the second pass and the entity fallbacks were evaluated
// against. Extracted so the detection corpus test can ask "which rules matched
// this line" without reimplementing the two-pass logic and drifting from it.
func matchAll(message, process string) ([]ruleMatch, string) {
	matches := matchRules(message, process, SurfaceRaw)
	redacted := redactUntrusted(message, matches)
	matches = confirmAgainstRedacted(matches, redacted, message)
	return append(matches, matchRules(redacted, process, SurfaceRedacted)...), redacted
}

// matchRules evaluates every rule declaring the given surface against text.
// Results come back in declaration order.
func matchRules(text, process string, surface Surface) []ruleMatch {
	var out []ruleMatch
	for i := range rules {
		r := &rules[i]
		if r.Surface != surface || !r.appliesTo(process) {
			continue
		}
		loc := r.Pattern.FindStringSubmatchIndex(text)
		if loc == nil {
			continue
		}
		out = append(out, ruleMatch{index: i, rule: r, text: text, loc: loc})
	}
	return out
}

// strongest returns the index of the match that sets the verdict, or -1.
//
// Precedence is (highest Score, then earliest declaration). Score is the right
// discriminator because it is already this project's statement of how much a
// detection matters: a reverse shell found inside a sudo command line should
// report as a reverse shell, not as "a sudo command ran". Declaration order
// remains only as a deterministic tie-break, never as the primary rule.
func strongest(matches []ruleMatch) int {
	best := -1
	for i := range matches {
		if best < 0 ||
			matches[i].rule.Score > matches[best].rule.Score ||
			(matches[i].rule.Score == matches[best].rule.Score && matches[i].index < matches[best].index) {
			best = i
		}
	}
	return best
}

// confirmAgainstRedacted drops raw-surface matches that only held because of
// text the attacker supplied.
//
// SurfaceRaw is a claim that a pattern is pinned to daemon-emitted literals, and
// for most rules that claim is true by inspection — but "by inspection" is how
// the original defect survived review, and the claim has to hold for rules
// nobody has written yet. The alternative considered was requiring a Process
// filter on every raw-surface rule. That was rejected: it narrows detection to a
// hardcoded set of syslog tags, which is precisely the failure mode where an
// OpenSSH upgrade renaming `sshd` to `sshd-session` silently takes rules dark.
//
// So the check is behavioural instead of structural. A rule whose match came
// from the daemon's own text still matches once the username is blanked —
// "Failed password for [redacted] from ..." is still a failed password. A rule
// that only matched because the username *was* "victim : user NOT in sudoers"
// has nothing left to match, and is dropped.
//
// Captures still come from the raw match, so the event keeps the real username
// rather than the marker. Only the verdict and tags are affected.
func confirmAgainstRedacted(matches []ruleMatch, redacted, original string) []ruleMatch {
	if redacted == original {
		return matches // nothing was attacker-chosen; nothing to re-check
	}
	kept := matches[:0]
	for _, m := range matches {
		if m.rule.Pattern.MatchString(redacted) {
			kept = append(kept, m)
		}
	}
	return kept
}

// redactionFill replaces an attacker-chosen span. It is a fixed literal rather
// than a same-length run, because nothing downstream of here needs the offsets
// to line up, and a literal is recognisable if it ever surfaces in a debug dump.
const redactionFill = "[redacted]"

// untrustedCapture reports whether a capture group holds a value supplied by the
// remote party rather than described by the host.
//
// `command` is deliberately not in this set. A command line is attacker-
// influenced too, but it is a record of something the host *ran*, and scanning
// it for reverse shells and pipe-to-shell droppers is the entire purpose of the
// free-text rules. The distinction that matters is between a string someone
// typed at a login prompt and a string the machine executed.
func untrustedCapture(name string) bool {
	switch name {
	case "user", "target_user":
		return true
	}
	return false
}

// redactUntrusted blanks the spans that the raw-surface rules identified as
// attacker-chosen, so a keyword rule cannot be made to match inside one.
//
// Redaction is by byte offset, not by string replacement. Replacing every
// occurrence of the captured value would also blank innocent text that happens
// to equal it — a user named "root" would erase "root" from "PWD=/root" — and
// suppressing real detections is the failure mode this change exists to avoid
// creating.
func redactUntrusted(msg string, matches []ruleMatch) string {
	type span struct{ lo, hi int }
	var spans []span
	for _, m := range matches {
		for gi, name := range m.rule.Pattern.SubexpNames() {
			if gi == 0 || !untrustedCapture(name) {
				continue
			}
			lo, hi := m.loc[2*gi], m.loc[2*gi+1]
			if lo >= 0 && hi > lo {
				spans = append(spans, span{lo, hi})
			}
		}
	}
	if len(spans) == 0 {
		return msg
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })

	var b strings.Builder
	b.Grow(len(msg))
	prev := 0
	for _, s := range spans {
		if s.lo < prev {
			s.lo = prev // two rules captured overlapping spans
		}
		if s.hi <= s.lo {
			continue
		}
		b.WriteString(msg[prev:s.lo])
		b.WriteString(redactionFill)
		prev = s.hi
	}
	b.WriteString(msg[prev:])
	return b.String()
}

// applyCaptures copies named capture groups onto the event. Known names map to
// first-class fields; anything else lands in Fields so new rules can add
// context without a schema change.
func applyCaptures(ev *event.Event, m ruleMatch) {
	for i, name := range m.rule.Pattern.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		raw := m.group(i)
		if raw == "" {
			continue
		}
		v := sanitize.Field(raw, 256)
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
