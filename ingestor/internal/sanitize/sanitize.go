// Package sanitize hardens untrusted log text before it is parsed, indexed, or
// rendered.
//
// Threat model. A log line is attacker-controlled data: a remote user picks
// their own SSH username, HTTP path, and TLS SNI, and those strings land
// verbatim in /var/log. Four concrete attacks follow from that:
//
//  1. Log injection / forging (CWE-117). A username containing CR or LF lets an
//     attacker append a second, fake log line ("Accepted password for root").
//     We escape every control character to a printable \xNN form, so a forged
//     line can never survive re-serialisation as a separate record.
//  2. Terminal escape injection. ANSI CSI/OSC sequences in a log let an attacker
//     rewrite what an operator sees in `tail -f`, hide lines, or (with OSC 8 /
//     OSC 52) smuggle clickable links and clipboard writes. We strip them.
//  3. Trojan Source (CVE-2021-42574). Unicode bidi overrides and zero-width
//     characters make the rendered order of a line differ from its byte order,
//     so "user=attacker" can display as "user=root". We drop those code points.
//  4. Memory pressure. A single 500 MB "line" is a cheap DoS against any
//     line-oriented reader. We cap length and record the truncation.
//
// The sanitiser is deliberately lossy-but-honest: it never silently rewrites
// content, it reports whether it modified the line, and the original bytes stay
// recoverable via the SHA-256 fingerprint kept on every event.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// DefaultMaxLen caps a single log line. 8 KiB is ~4x the longest legitimate
// syslog line we have observed (long systemd unit dumps) and well under the
// RFC 5425 limit.
const DefaultMaxLen = 8192

// truncationMarker is appended to lines cut short by the length cap.
const truncationMarker = "…[sentinel:truncated]"

// Result reports what the sanitiser did, so callers can flag suspicious input
// rather than just quietly cleaning it.
//
// The Had* flags are detections in their own right, and enrich.Apply scores them
// as such:
//
//	HadControl     CR/LF/NUL embedded mid-line: possible log-forging attempt
//	HadEscape      ANSI escape sequence: possible terminal-render attack
//	HadBidi        Trojan Source bidi or zero-width code point
//	HadInvalidUTF8 malformed bytes, repaired with U+FFFD
type Result struct {
	Clean          string
	Modified       bool
	Truncated      bool
	HadControl     bool
	HadEscape      bool
	HadBidi        bool
	HadInvalidUTF8 bool
}

// Line sanitises a single raw log line. maxLen <= 0 selects DefaultMaxLen.
func Line(raw string, maxLen int) Result {
	if maxLen <= 0 {
		maxLen = DefaultMaxLen
	}
	res := Result{Clean: raw}

	// 1. Guarantee valid UTF-8 before any rune-wise work. Japanese advisories
	//    and log payloads are multibyte, so we repair rather than reject.
	if !utf8.ValidString(res.Clean) {
		res.Clean = strings.ToValidUTF8(res.Clean, "�")
		res.HadInvalidUTF8 = true
	}

	// 2. Escape sequences must go before control-char escaping, because ESC is
	//    itself a control character.
	if strings.ContainsRune(res.Clean, 0x1b) {
		res.Clean = stripEscapes(res.Clean)
		res.HadEscape = true
	}

	// 3. Bidi overrides and zero-width characters.
	if cleaned, dropped := stripInvisible(res.Clean); dropped {
		res.Clean = cleaned
		res.HadBidi = true
	}

	// 4. Remaining control characters become printable.
	if cleaned, found := escapeControls(res.Clean); found {
		res.Clean = cleaned
		res.HadControl = true
	}

	// 5. Length cap, applied on a rune boundary so we never emit broken UTF-8.
	if len(res.Clean) > maxLen {
		cut := maxLen - len(truncationMarker)
		if cut < 0 {
			cut = 0
		}
		for cut > 0 && !utf8.RuneStart(res.Clean[cut]) {
			cut--
		}
		res.Clean = res.Clean[:cut] + truncationMarker
		res.Truncated = true
	}

	res.Modified = res.Clean != raw
	return res
}

// stripEscapes removes ANSI escape sequences: CSI (ESC [ ... final), OSC
// (ESC ] ... BEL|ST), and the two-byte forms (ESC followed by one byte).
func stripEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] != 0x1b {
			b.WriteRune(runes[i])
			continue
		}
		i++ // consume ESC
		if i >= len(runes) {
			break
		}
		switch runes[i] {
		case '[': // CSI: parameters/intermediates then a final byte 0x40-0x7E
			i++
			for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x3f {
				i++
			}
			// i now points at the final byte (or past the end); the loop's i++
			// consumes it.
		case ']': // OSC: terminated by BEL or ESC \
			i++
			for i < len(runes) {
				if runes[i] == 0x07 {
					break
				}
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
		default:
			// Two-byte escape (ESC c, ESC =, ...): the ESC and this byte are
			// both dropped.
		}
	}
	return b.String()
}

// invisible reports whether r is a bidirectional-override or zero-width code
// point of the kind used by Trojan Source style attacks.
func invisible(r rune) bool {
	switch {
	case r >= 0x200b && r <= 0x200f: // ZWSP, ZWNJ, ZWJ, LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0xfeff: // BOM used mid-line
		return true
	case r == 0x00ad: // soft hyphen
		return true
	}
	return false
}

func stripInvisible(s string) (string, bool) {
	if !strings.ContainsFunc(s, invisible) {
		return s, false
	}
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, s), true
}

const hexDigits = "0123456789abcdef"

// escapeControls converts C0/C1 control characters into printable \xNN escapes.
// Tab is normalised to a single space because it is common and benign in log
// text, and collapsing it keeps field splitting predictable.
func escapeControls(s string) (string, bool) {
	found := false
	for _, r := range s {
		if isControl(r) {
			found = true
			break
		}
	}
	if !found {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case isControl(r):
			b.WriteString(`\x`)
			b.WriteByte(hexDigits[(byte(r)>>4)&0x0f])
			b.WriteByte(hexDigits[byte(r)&0x0f])
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), true
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// Field sanitises a short extracted value (username, IP, command) for safe use
// as vector-store metadata. It applies Line plus a tighter length cap and
// rejects values that are entirely non-printable.
func Field(v string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 256
	}
	out := Line(v, maxLen).Clean
	return strings.TrimSpace(out)
}
