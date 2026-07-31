// Package honeytoken implements deceptive defence: canary usernames, paths, and
// hostnames that exist nowhere on the system, so any reference to one is
// attacker activity by construction.
//
// # Why this is the highest-signal detector in the system
//
// Every other rule in this ingestor infers intent from behaviour, and behaviour
// is ambiguous. Five failed passwords might be an attack or a backup script with
// a stale credential. A honeytoken has no such ambiguity: nothing on the host
// references `admin_backup`, no legitimate process reads
// `/etc/.backup_credentials`, so a log line containing one is either an attacker
// enumerating accounts or an operator who has forgotten their own decoy. That is
// what makes it the only detector here that can justify a score of 100, and the
// only one that clears the firewall-response threshold on a single event.
//
// # Why a hash set and not a Bloom filter
//
// The obvious pitch is "Bloom filter — O(1) membership, cache-efficient." It is
// the wrong structure here and choosing it would demonstrate the opposite of
// what it is meant to.
//
// A Bloom filter buys *memory* at the cost of *false positives*. It wins when
// storing the set outright hurts: millions of breached-password hashes, a full
// IOC feed. A honeytoken list is 5-50 entries — a few hundred bytes. A Go map is
// a single hash and a pointer chase, has zero false positives, and needs no
// confirmation step.
//
// False positives are exactly what cannot be tolerated at this position in the
// system. This event scores 100 and is the only thing permitted to trigger an
// automated firewall block. "Probably a honeytoken" is not a basis for cutting
// off a network. The Bloom filter belongs in IOC matching, where the candidate
// set is millions of indicators, memory is the binding constraint, and a
// positive can afford a confirmation lookup before it means anything.
//
// # Why JSON and not YAML
//
// The ingestor imports nothing outside the standard library — that is a security
// property on the component that parses attacker-controlled input, not a
// stylistic preference. YAML would mean a third-party parser (or a half-correct
// hand-rolled subset, which is worse). encoding/json is in the standard library
// and the schema here is a list of strings.
package honeytoken

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Kind classifies what a token impersonates. Kinds are matched differently:
// usernames are compared against extracted identity fields, everything else is
// searched for inside the message body.
type Kind string

const (
	KindUser    Kind = "user"
	KindPath    Kind = "path"
	KindHost    Kind = "host"
	KindProcess Kind = "process"
)

// Token is one canary value.
type Token struct {
	Value string
	Kind  Kind
	Note  string
	// lower is Value pre-folded. Matching is case-insensitive, and folding the
	// needle on every line for every token showed up as the dominant cost in
	// BenchmarkMatch; it is a constant, so it is computed once here.
	lower string
}

// Hit records a matched token and where it was seen.
type Hit struct {
	Token    Token
	Field    string // "user", "target_user", "message"
	Observed string // the exact text seen, before case normalisation
}

// Set is an immutable, concurrency-safe collection of tokens. Built once at
// startup and read from every worker goroutine, so it is never mutated after
// Load returns.
type Set struct {
	// Usernames are matched exactly (case-folded) against identity fields the
	// parser already extracted, so a message merely mentioning the word cannot
	// trigger a score-100 event.
	users map[string]Token
	// Paths, hosts, and process names have to be searched for inside the message
	// body, because they appear inside command lines rather than in their own
	// field. Kept as a slice: with a handful of entries a linear scan of
	// strings.Contains beats anything cleverer, and stays predictable.
	substrings []Token
	path       string
}

// Config is the on-disk schema.
//
//	{
//	  "users":     ["admin_backup", {"value": "svc_deploy", "note": "decoy"}],
//	  "paths":     ["/etc/.backup_credentials"],
//	  "hosts":     ["vault-internal"],
//	  "processes": ["backup-agent"]
//	}
//
// Each list accepts either a bare string or an object with a note, so a simple
// list stays simple and an annotated one is still possible.
type Config struct {
	Users     []Entry `json:"users"`
	Paths     []Entry `json:"paths"`
	Hosts     []Entry `json:"hosts"`
	Processes []Entry `json:"processes"`
}

// Entry is one configured token. Exported because Config is part of the public
// API and callers construct it directly in tests and tooling.
type Entry struct {
	Value string `json:"value"`
	Note  string `json:"note"`
}

// UnmarshalJSON accepts "name" or {"value": "name", "note": "..."}.
func (e *Entry) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		e.Value, e.Note = s, ""
		return nil
	}
	var obj struct {
		Value string `json:"value"`
		Note  string `json:"note"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("honeytoken entry must be a string or {\"value\",\"note\"}: %w", err)
	}
	if obj.Value == "" {
		return fmt.Errorf("honeytoken entry has an empty value")
	}
	e.Value, e.Note = obj.Value, obj.Note
	return nil
}

// Load reads a honeytoken config. A nil *Set is valid and matches nothing, so
// callers never need a nil check.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read honeytokens %s: %w", path, err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// Reject unknown fields: a typo like "user" instead of "users" would
	// otherwise silently produce a set with no tokens in it, and a honeypot that
	// silently is not armed is worse than no honeypot.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse honeytokens %s: %w", path, err)
	}
	set, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	set.path = path
	return set, nil
}

// New builds a Set from an already-parsed Config.
func New(cfg Config) (*Set, error) {
	s := &Set{users: make(map[string]Token)}

	add := func(entries []Entry, kind Kind) error {
		for _, e := range entries {
			value := strings.TrimSpace(e.Value)
			if value == "" {
				return fmt.Errorf("empty %s honeytoken", kind)
			}
			tok := Token{Value: value, Kind: kind, Note: e.Note, lower: strings.ToLower(value)}
			if kind == KindUser {
				key := strings.ToLower(value)
				if _, dup := s.users[key]; dup {
					return fmt.Errorf("duplicate user honeytoken %q", value)
				}
				s.users[key] = tok
				continue
			}
			// Substring tokens must be long enough not to appear by accident. A
			// two-character "path" would match constantly and turn the
			// highest-severity detector in the system into pure noise.
			if len(value) < 4 {
				return fmt.Errorf("%s honeytoken %q is too short to match safely (minimum 4 characters)", kind, value)
			}
			s.substrings = append(s.substrings, tok)
		}
		return nil
	}

	if err := add(cfg.Users, KindUser); err != nil {
		return nil, err
	}
	if err := add(cfg.Paths, KindPath); err != nil {
		return nil, err
	}
	if err := add(cfg.Hosts, KindHost); err != nil {
		return nil, err
	}
	if err := add(cfg.Processes, KindProcess); err != nil {
		return nil, err
	}
	return s, nil
}

// Len reports how many tokens are armed.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.users) + len(s.substrings)
}

// Path is the file the set was loaded from, for diagnostics.
func (s *Set) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Match reports every honeytoken referenced by this event.
//
// identities are fields the parser already extracted (user, target user); they
// are compared exactly, case-folded. message is the free text, searched for
// substring tokens.
//
// Case folding on usernames is deliberate. On Linux `Admin_Backup` and
// `admin_backup` are different accounts and neither exists, so both are
// suspicious — but only the exact form is the canary. Folding catches an
// attacker case-varying their wordlist, and Observed keeps the form actually
// seen so the alert is not misleading about what was typed.
func (s *Set) Match(identities []string, message string) []Hit {
	if s == nil || s.Len() == 0 {
		return nil
	}
	var hits []Hit

	for i, identity := range identities {
		if identity == "" {
			continue
		}
		if tok, ok := s.users[strings.ToLower(identity)]; ok {
			field := "user"
			if i > 0 {
				field = "target_user"
			}
			hits = append(hits, Hit{Token: tok, Field: field, Observed: identity})
		}
	}

	if message != "" && len(s.substrings) > 0 {
		lower := strings.ToLower(message)
		for _, tok := range s.substrings {
			if strings.Contains(lower, tok.lower) {
				hits = append(hits, Hit{Token: tok, Field: "message", Observed: tok.Value})
			}
		}
		// A username honeytoken can also show up inside a command line
		// ("useradd admin_backup") rather than in an identity field. Catch that
		// too, but only when it was not already matched as an identity, so one
		// event does not report the same token twice.
		for key, tok := range s.users {
			if strings.Contains(lower, key) && !containsToken(hits, tok.Value) {
				hits = append(hits, Hit{Token: tok, Field: "message", Observed: tok.Value})
			}
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Token.Kind != hits[j].Token.Kind {
			return hits[i].Token.Kind < hits[j].Token.Kind
		}
		return hits[i].Token.Value < hits[j].Token.Value
	})
	return hits
}

func containsToken(hits []Hit, value string) bool {
	for _, h := range hits {
		if h.Token.Value == value {
			return true
		}
	}
	return false
}

// Summary renders the armed tokens for logging, grouped by kind.
func (s *Set) Summary() string {
	if s == nil || s.Len() == 0 {
		return "no honeytokens armed"
	}
	byKind := map[Kind][]string{}
	for _, tok := range s.users {
		byKind[KindUser] = append(byKind[KindUser], tok.Value)
	}
	for _, tok := range s.substrings {
		byKind[tok.Kind] = append(byKind[tok.Kind], tok.Value)
	}
	parts := make([]string, 0, len(byKind))
	for _, kind := range []Kind{KindUser, KindPath, KindHost, KindProcess} {
		values := byKind[kind]
		if len(values) == 0 {
			continue
		}
		sort.Strings(values)
		parts = append(parts, fmt.Sprintf("%s=%d %v", kind, len(values), values))
	}
	return strings.Join(parts, "  ")
}

// VerifyAgainstPasswd checks that no username honeytoken is a real account, and
// returns the colliding names.
//
// This is the failure mode that quietly destroys a honeypot: a canary that
// collides with a real account fires on every legitimate login, the operator
// learns to ignore it, and — because this detector is wired to the firewall —
// a real user can get their own address blocked. Better to refuse to arm.
//
// Run this on the host, not inside the container: a container has its own
// /etc/passwd, so the check would pass vacuously there and prove nothing.
func (s *Set) VerifyAgainstPasswd(passwdPath string) ([]string, error) {
	if s == nil || len(s.users) == 0 {
		return nil, nil
	}
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", passwdPath, err)
	}
	defer f.Close()

	var collisions []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if tok, ok := s.users[strings.ToLower(strings.TrimSpace(name))]; ok {
			collisions = append(collisions, tok.Value)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", passwdPath, err)
	}
	sort.Strings(collisions)
	return collisions, nil
}
