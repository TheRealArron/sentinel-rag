package ioc

import (
	"net"
	"regexp"
	"strings"
)

// Type classifies an indicator. The type is stored alongside each record and
// carried onto the event, because "this IP is on a Tor exit list" and "this
// SHA-256 is a known dropper" warrant very different responses.
type Type string

const (
	TypeIP     Type = "ip"
	TypeDomain Type = "domain"
	TypeHash   Type = "hash"
)

// Candidate is a possible indicator extracted from an event, before any feed
// lookup has happened.
type Candidate struct {
	Value string // normalised, ready to hash and look up
	Type  Type
	Field string // where it came from: "source_ip", "dest_ip", "message"
	Raw   string // the form actually seen, so an alert can quote the log line
}

var (
	candIPv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	candIPv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)

	// Hostname-shaped tokens: at least two labels. The 64-char alternative is
	// listed first so a full SHA-256 is never chopped into a shorter match.
	candHostRe = regexp.MustCompile(
		`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b`)

	// MD5, SHA-1, SHA-256. Ordered longest-first; the word boundaries make the
	// lengths exact, so a 64-character digest cannot match the 32-character
	// alternative.
	candHashRe = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)
)

// NormaliseIP returns the canonical text form of an IP, or "" if it is not one.
//
// Canonicalisation is not cosmetic. A feed may list `2001:db8::1`, `2001:0db8::1`
// or `2001:DB8:0:0:0:0:0:1` for the same address, and a log line may contain a
// fourth spelling. Comparing text without canonicalising means the store and the
// lookup disagree and the indicator silently never fires — the failure mode this
// whole package has to avoid, because it looks exactly like "no threats found".
//
// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is folded to its IPv4 form, matching what
// net.IP.String does and what feeds publish.
func NormaliseIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// NormaliseDomain lowercases and validates a domain name.
//
// # The refusal
//
// Internationalised domains are rejected rather than guessed at. Matching
// `пример.рф` against a feed requires IDNA/Punycode, and correct IDNA is a
// Unicode table problem, not a string transformation — the stdlib has no
// implementation, and this binary parses attacker-controlled input, so pulling
// in golang.org/x/net for it is not a trade worth making (see the package
// comment in honeytoken for the same reasoning about YAML).
//
// The alternative — a half-correct ASCII fold — is worse than refusing. It would
// produce a normalised form that the Python feed compiler would have to
// reproduce exactly, and two independent half-correct IDNA implementations
// agreeing is not something to rely on. So non-ASCII domains are dropped here
// and dropped by the compiler, consistently, and the compiler reports how many
// it skipped rather than passing them through silently.
func NormaliseDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	lower := strings.ToLower(s)
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return ""
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return ""
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return "" // non-ASCII or punctuation: refused, see above
			}
		}
	}
	// A domain whose final label is all digits is a dotted number — an IPv4
	// address or a version string — not a hostname.
	if isAllDigits(labels[len(labels)-1]) {
		return ""
	}
	return lower
}

// NormaliseHash lowercases a hex digest of a recognised length.
func NormaliseHash(s string) string {
	s = strings.TrimSpace(s)
	switch len(s) {
	case 32, 40, 64: // MD5, SHA-1, SHA-256
	default:
		return ""
	}
	lower := strings.ToLower(s)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return lower
}

// Normalise dispatches on type. Used by the loader to canonicalise feed input
// the same way lookups canonicalise log input — the two must not diverge, which
// is why there is one function rather than a copy on each side.
func Normalise(t Type, value string) string {
	switch t {
	case TypeIP:
		return NormaliseIP(value)
	case TypeDomain:
		return NormaliseDomain(value)
	case TypeHash:
		return NormaliseHash(value)
	}
	return ""
}

// ClassifyAndNormalise guesses an indicator's type from its shape and returns
// the canonical form. Feeds that ship untyped indicator lists rely on this.
func ClassifyAndNormalise(value string) (Type, string) {
	if v := NormaliseIP(value); v != "" {
		return TypeIP, v
	}
	if v := NormaliseHash(value); v != "" {
		return TypeHash, v
	}
	if v := NormaliseDomain(value); v != "" {
		return TypeDomain, v
	}
	return "", ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ExtractCandidates pulls every plausible indicator out of an event.
//
// entities are values the parser already extracted and labelled (source IP,
// destination IP); message is free text scanned with the regexes above.
//
// # What is deliberately not scanned
//
// The event's own Host field. Matching the host a log came *from* against a
// domain feed flags your own machine the moment its hostname resembles a feed
// entry, and every event on the box lights up at once. Indicators are about who
// the host talked to, not what it is called.
//
// # On duplicate suppression
//
// The same address usually appears both as a parsed source_ip field and inside
// the message text. Deduplication happens on the normalised value, keeping the
// first (parsed, therefore better-attributed) occurrence, so one event that
// mentions one bad IP produces one hit rather than two.
func ExtractCandidates(entities map[string]string, message string) []Candidate {
	var out []Candidate
	seen := make(map[string]struct{}, 8)

	add := func(t Type, raw, field string) {
		norm := Normalise(t, raw)
		if norm == "" {
			return
		}
		if _, dup := seen[norm]; dup {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, Candidate{Value: norm, Type: t, Field: field, Raw: raw})
	}

	// Parsed entity fields first, so their attribution wins over a message match.
	// Sorted iteration is not needed: source_ip and dest_ip are added explicitly
	// in a fixed order rather than by ranging the map, because map order is
	// randomised and the hit order would otherwise vary run to run — which would
	// make the sample fixture unreproducible.
	for _, field := range []string{"source_ip", "dest_ip"} {
		if v := entities[field]; v != "" {
			add(TypeIP, v, field)
		}
	}

	if message == "" {
		return out
	}
	shape := scanShape(message)
	if shape.hasDot {
		for _, m := range candIPv4Re.FindAllString(message, -1) {
			add(TypeIP, m, "message")
		}
	}
	if shape.hasColon {
		for _, m := range candIPv6Re.FindAllString(message, -1) {
			add(TypeIP, m, "message")
		}
	}
	if shape.hexRun >= 32 {
		for _, m := range candHashRe.FindAllString(message, -1) {
			add(TypeHash, m, "message")
		}
	}
	if shape.hasDot {
		for _, m := range candHostRe.FindAllString(message, -1) {
			add(TypeDomain, m, "message")
		}
	}
	return out
}

// shape holds the cheap facts about a message that decide which of the four
// extraction regexes can possibly match.
type shape struct {
	hasDot   bool
	hasColon bool
	hexRun   int // longest run of hex digits
}

// scanShape gates the extraction regexes behind one linear byte scan.
//
// # Why this exists
//
// Measured, on the UFW line in BenchmarkExtractCandidates: IPv4 5.2 µs, IPv6
// 5.5 µs, hash 8.1 µs, hostname 9.7 µs — about 28 µs of regex per log line,
// against roughly 65 µs for the entire 33-rule detection sweep. Adding that
// unconditionally would have made feed matching nearly half the cost of
// enrichment, which is a strange price for a stage that answers "no" almost
// every time.
//
// It also puts the Bloom filter's contribution in proportion, and the honest
// version of that is worth stating: a filter probe is 114 ns. The filter is not
// what makes this fast — extraction dominates it by two orders of magnitude.
// What the filter buys is memory (32x, measured in TestMemoryFootprintAtFeedScale)
// and the avoidance of a ~30 µs store lookup per candidate. Both real, neither
// the thing a reader would assume from "we put a Bloom filter in front of it".
//
// # Why the gates are sound
//
// Each is a necessary condition of its pattern, not a heuristic:
//
//   - IPv4 and hostname patterns both require a literal '.'.
//   - The IPv6 pattern requires a ':'.
//   - A hash is 32, 40 or 64 consecutive hex characters, so a message whose
//     longest hex run is shorter than 32 cannot contain one.
//
// So a gate can never skip a regex that would have matched.
// TestGatesNeverSkipARealMatch checks that against the ungated path directly,
// because an unsound gate here would drop indicators silently.
func scanShape(s string) shape {
	var sh shape
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.':
			sh.hasDot = true
		case ':':
			sh.hasColon = true
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			run++
			if run > sh.hexRun {
				sh.hexRun = run
			}
		} else {
			run = 0
		}
	}
	return sh
}
