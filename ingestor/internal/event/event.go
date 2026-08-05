// Package event defines the structured log record that the Go ingestor emits
// and the Python AI engine consumes. It is the contract between the two halves
// of Sentinel RAG, so every field is explicitly JSON-tagged and stable.
package event

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Severity labels, ordered. Derived from Score so the two can never disagree.
const (
	SeverityInfo     = "info"
	SeverityNotice   = "notice"
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Event is one normalised log record.
//
// Field groups:
//   - identity:   Seq, RawSHA256, IngestedAt
//   - syslog:     Timestamp, Host, Facility, Process, PID, Message
//   - detection:  Category, Severity, Score, Rule, Outcome, MITRE, Tags
//   - entities:   SourceIP, SourcePort, User, Fields
//   - provenance: Sanitized, ParseOK, Raw
type Event struct {
	Seq        int64  `json:"seq"`
	RawSHA256  string `json:"raw_sha256"`
	IngestedAt string `json:"ingested_at"`

	Timestamp string `json:"timestamp,omitempty"`
	Host      string `json:"host,omitempty"`
	Facility  string `json:"facility,omitempty"`
	Process   string `json:"process,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Message   string `json:"message"`

	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Score    int      `json:"score"`
	Rule     string   `json:"rule,omitempty"`
	Outcome  string   `json:"outcome,omitempty"`
	MITRE    []string `json:"mitre,omitempty"`
	Tags     []string `json:"tags,omitempty"`

	SourceIP   string            `json:"source_ip,omitempty"`
	SourcePort int               `json:"source_port,omitempty"`
	DestIP     string            `json:"dest_ip,omitempty"`
	DestPort   int               `json:"dest_port,omitempty"`
	User       string            `json:"user,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`

	Sanitized bool   `json:"sanitized"`
	ParseOK   bool   `json:"parse_ok"`
	Raw       string `json:"raw,omitempty"`
}

// SeverityFor maps a 0-100 risk score onto a severity label.
func SeverityFor(score int) string {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 40:
		return SeverityWarning
	case score >= 20:
		return SeverityNotice
	default:
		return SeverityInfo
	}
}

// Fingerprint returns the hex SHA-256 of the raw line. The Python side uses it
// as a stable vector-store ID so re-ingesting the same file is idempotent.
func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// SetField stores a key/value pair, allocating the map on first use.
func (e *Event) SetField(k, v string) {
	if v == "" {
		return
	}
	if e.Fields == nil {
		e.Fields = make(map[string]string, 4)
	}
	e.Fields[k] = v
}

// AddTags appends tags, skipping duplicates and empties.
func (e *Event) AddTags(tags ...string) {
	for _, t := range tags {
		if t == "" {
			continue
		}
		dup := false
		for _, have := range e.Tags {
			if have == t {
				dup = true
				break
			}
		}
		if !dup {
			e.Tags = append(e.Tags, t)
		}
	}
}

// Now is indirected so tests can freeze the clock.
var Now = func() time.Time { return time.Now().UTC() }

// Stamp fills IngestedAt with the current UTC time in RFC3339.
func (e *Event) Stamp() {
	e.IngestedAt = Now().Format(time.RFC3339Nano)
}

// SigmaField exposes the normalised fields a transpiled Sigma rule can match on.
// Kept as an explicit switch rather than reflection: the set of matchable fields
// is a contract with the transpiler's FIELD_MAP, and a typo should be a missing
// match rather than a silently empty one.
func (e *Event) SigmaField(name string) string {
	switch name {
	case "message":
		return e.Message
	case "user":
		return e.User
	case "host":
		return e.Host
	case "process":
		return e.Process
	case "source_ip":
		return e.SourceIP
	case "dest_ip":
		return e.DestIP
	case "source_port":
		if e.SourcePort == 0 {
			return ""
		}
		return strconv.Itoa(e.SourcePort)
	case "dest_port":
		if e.DestPort == 0 {
			return ""
		}
		return strconv.Itoa(e.DestPort)
	case "command":
		// Falls back to the message: many syslog lines carry the command inline
		// rather than in a parsed field, and a rule written against `command`
		// should still fire on those.
		if cmd := e.Fields["command"]; cmd != "" {
			return cmd
		}
		return e.Message
	}
	return e.Fields[name]
}
