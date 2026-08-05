// Package sigma evaluates Sigma-derived detection rules that were transpiled to
// JSON by the Python engine.
//
// The split is deliberate. Sigma is YAML, and a YAML parser in Go would mean a
// third-party dependency in the one component that has none — the component that
// parses attacker-controlled input and ships FROM scratch. So the Python side
// owns transpilation and emits JSON, which encoding/json reads.
//
// The payoff is that adding a detection is a file, not a rebuild: drop a Sigma
// rule in rules/sigma/, run `make sigma`, restart. No recompile, and the Go
// binary keeps its empty go.mod.
//
// Rules are evaluated as a predicate tree rather than a flattened regex, because
// Sigma's and/or/not do not survive being mashed into one pattern. See
// docs/design/sigma.md.
package sigma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Supported bundle schema version. A bundle from a newer transpiler is refused
// rather than half-understood.
const SchemaVersion = 1

// MatchOp is how a leaf compares its values.
const (
	OpEquals     = "equals"
	OpContains   = "contains"
	OpStartsWith = "startswith"
	OpEndsWith   = "endswith"
	OpRegex      = "regex"
)

// Predicate is one node of a compiled matcher tree.
type Predicate struct {
	Op       string      `json:"op"`
	Children []Predicate `json:"children,omitempty"`
	Field    string      `json:"field,omitempty"`
	MatchOp  string      `json:"match,omitempty"`
	Values   []string    `json:"values,omitempty"`
	Cased    bool        `json:"cased,omitempty"`

	// compiled regexes, built once at load time
	patterns []*regexp.Regexp
	// values pre-folded when the match is case-insensitive
	folded []string
}

// Rule is a transpiled Sigma rule in Sentinel's shape.
type Rule struct {
	Name      string    `json:"name"`
	Title     string    `json:"title"`
	Category  string    `json:"category"`
	Score     int       `json:"score"`
	Outcome   string    `json:"outcome"`
	MITRE     []string  `json:"mitre"`
	Tags      []string  `json:"tags"`
	Processes []string  `json:"processes"`
	Source    string    `json:"source"`
	SigmaID   string    `json:"sigma_id"`
	Level     string    `json:"level"`
	Predicate Predicate `json:"predicate"`
}

// Bundle is the on-disk file the Python transpiler emits.
type Bundle struct {
	Version   int    `json:"version"`
	Generator string `json:"generator"`
	Rules     []Rule `json:"rules"`
}

// Event is the subset of fields a rule can match against. Kept as an explicit
// interface rather than taking *event.Event so this package stays independent of
// the enrichment pipeline and can be tested on its own.
type Event interface {
	SigmaField(name string) string
}

// Set is an immutable, concurrency-safe collection of loaded rules.
type Set struct {
	rules []Rule
	paths []string
}

// Len reports how many rules are armed.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// Rules exposes the loaded rules read-only.
func (s *Set) Rules() []Rule {
	if s == nil {
		return nil
	}
	return s.rules
}

// Sources lists the bundle files that were loaded.
func (s *Set) Sources() []string {
	if s == nil {
		return nil
	}
	return s.paths
}

// Load reads every *.json bundle in dir. A missing directory yields an empty
// set, not an error: external rules are optional.
func Load(dir string) (*Set, error) {
	set := &Set{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return nil, fmt.Errorf("read sigma rules %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	// Sorted so rule order — and therefore first-match-wins — is deterministic
	// across machines and filesystems.
	sortStrings(names)

	for _, name := range names {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var bundle Bundle
		dec := json.NewDecoder(f)
		// Unknown fields are an error: a bundle carrying a construct this build
		// does not implement must fail loudly, not silently under-match.
		dec.DisallowUnknownFields()
		err = dec.Decode(&bundle)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if bundle.Version != SchemaVersion {
			return nil, fmt.Errorf(
				"%s: bundle schema version %d, this build understands %d — "+
					"regenerate with `make sigma`", path, bundle.Version, SchemaVersion)
		}
		for i := range bundle.Rules {
			if err := validate(&bundle.Rules[i], path); err != nil {
				return nil, err
			}
			if err := compile(&bundle.Rules[i].Predicate); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", path, bundle.Rules[i].Name, err)
			}
			set.rules = append(set.rules, bundle.Rules[i])
		}
		set.paths = append(set.paths, path)
	}
	return set, nil
}

func validate(r *Rule, path string) error {
	if r.Name == "" {
		return fmt.Errorf("%s: rule with an empty name", path)
	}
	if r.Score < 0 || r.Score > 100 {
		return fmt.Errorf("%s: rule %q has score %d, want 0-100", path, r.Name, r.Score)
	}
	if r.Predicate.Op == "" {
		return fmt.Errorf("%s: rule %q has no predicate", path, r.Name)
	}
	return nil
}

// compile prepares regexes and case-folded values once, at load, so matching
// never allocates or recompiles on the hot path.
func compile(p *Predicate) error {
	switch p.Op {
	case "and", "or", "not":
		if len(p.Children) == 0 {
			return fmt.Errorf("%s node has no children", p.Op)
		}
		if p.Op == "not" && len(p.Children) != 1 {
			return fmt.Errorf("not node has %d children, want 1", len(p.Children))
		}
		for i := range p.Children {
			if err := compile(&p.Children[i]); err != nil {
				return err
			}
		}
		return nil
	case "match":
		if p.Field == "" {
			return fmt.Errorf("match node has no field")
		}
		if len(p.Values) == 0 {
			return fmt.Errorf("match node on %q has no values", p.Field)
		}
		if p.MatchOp == OpRegex {
			p.patterns = make([]*regexp.Regexp, 0, len(p.Values))
			for _, v := range p.Values {
				expr := v
				if !p.Cased {
					expr = "(?i)" + expr
				}
				re, err := regexp.Compile(expr)
				if err != nil {
					return fmt.Errorf("invalid regex %q: %w", v, err)
				}
				p.patterns = append(p.patterns, re)
			}
			return nil
		}
		if !p.Cased {
			p.folded = make([]string, len(p.Values))
			for i, v := range p.Values {
				p.folded[i] = strings.ToLower(v)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown predicate op %q", p.Op)
	}
}

// Match reports whether ev satisfies p.
func (p *Predicate) Match(ev Event) bool {
	switch p.Op {
	case "and":
		for i := range p.Children {
			if !p.Children[i].Match(ev) {
				return false
			}
		}
		return true
	case "or":
		for i := range p.Children {
			if p.Children[i].Match(ev) {
				return true
			}
		}
		return false
	case "not":
		return !p.Children[0].Match(ev)
	case "match":
		return p.matchLeaf(ev)
	}
	return false
}

func (p *Predicate) matchLeaf(ev Event) bool {
	actual := ev.SigmaField(p.Field)
	if p.MatchOp == OpRegex {
		for _, re := range p.patterns {
			if re.MatchString(actual) {
				return true
			}
		}
		return false
	}

	haystack := actual
	needles := p.Values
	if !p.Cased {
		haystack = strings.ToLower(actual)
		needles = p.folded
	}

	for _, needle := range needles {
		switch p.MatchOp {
		case OpEquals:
			if haystack == needle {
				return true
			}
		case OpContains:
			if strings.Contains(haystack, needle) {
				return true
			}
		case OpStartsWith:
			if strings.HasPrefix(haystack, needle) {
				return true
			}
		case OpEndsWith:
			if strings.HasSuffix(haystack, needle) {
				return true
			}
		}
	}
	return false
}

// AppliesTo enforces a rule's optional process filter, case-insensitively.
func (r *Rule) AppliesTo(process string) bool {
	if len(r.Processes) == 0 {
		return true
	}
	for _, p := range r.Processes {
		if strings.EqualFold(p, process) {
			return true
		}
	}
	return false
}

// Match returns the first rule that fires, or nil. First-match-wins mirrors the
// built-in rule engine, so imported and native rules behave the same way.
func (s *Set) Match(ev Event, process string) *Rule {
	if s == nil {
		return nil
	}
	for i := range s.rules {
		if !s.rules[i].AppliesTo(process) {
			continue
		}
		if s.rules[i].Predicate.Match(ev) {
			return &s.rules[i]
		}
	}
	return nil
}

// Summary renders the loaded rules for the startup banner.
func (s *Set) Summary() string {
	if s.Len() == 0 {
		return "no sigma rules loaded"
	}
	byLevel := map[string]int{}
	for _, r := range s.rules {
		byLevel[r.Level]++
	}
	parts := make([]string, 0, len(byLevel))
	for _, level := range []string{"critical", "high", "medium", "low", "informational"} {
		if n := byLevel[level]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", level, n))
		}
	}
	return fmt.Sprintf("%d rule(s) [%s]", len(s.rules), strings.Join(parts, " "))
}

// sortStrings is an insertion sort: the input is a handful of filenames, and
// this keeps the package free of even a stdlib sort import in the hot path.
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}
