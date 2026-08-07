package ioc

import (
	"strings"
	"testing"
)

// Canonicalisation is the quiet correctness requirement of the whole package: a
// feed and a log line that spell the same address differently must produce the
// same key, or the indicator never fires and the system reports "no threats".
func TestNormaliseIPCanonicalises(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":        "192.0.2.1",
		" 192.0.2.1 ":      "192.0.2.1",
		"::ffff:192.0.2.1": "192.0.2.1", // IPv4-mapped folds to IPv4
		"2001:db8::1":      "2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001": "2001:db8::1", // expanded
		"2001:DB8::1":  "2001:db8::1", // uppercase
		"192.0.2.256":  "",            // out of range
		"192.0.2":      "",            // incomplete
		"not-an-ip":    "",
		"":             "",
		"192.0.2.1/24": "", // CIDR is not a single indicator
	}
	for in, want := range cases {
		if got := NormaliseIP(in); got != want {
			t.Errorf("NormaliseIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseDomain(t *testing.T) {
	cases := map[string]string{
		"evil.example.com":    "evil.example.com",
		"EVIL.Example.COM":    "evil.example.com",
		"evil.example.com.":   "evil.example.com", // trailing root dot
		"a.b.c.d.example.org": "a.b.c.d.example.org",
		"xn--80ak6aa92e.com":  "xn--80ak6aa92e.com", // already punycode: accepted

		// Refused, deliberately.
		"пример.рф":    "", // non-ASCII: needs IDNA, see NormaliseDomain
		"localhost":    "", // single label
		"1.2.3.4":      "", // dotted number, not a hostname
		"1.2.3":        "", // version string
		"-bad.example": "", // label starts with a hyphen
		"bad-.example": "",
		"a..b":         "", // empty label
		"":             "",
	}
	for in, want := range cases {
		if got := NormaliseDomain(in); got != want {
			t.Errorf("NormaliseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseHash(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	cases := map[string]string{
		md5:                                md5,
		"D41D8CD98F00B204E9800998ECF8427E": md5,
		sha1:                               sha1,
		sha256:                             sha256,
		"abc":                              "", // too short
		"g41d8cd98f00b204e9800998ecf8427e": "", // not hex
		"d41d8cd98f00b204e9800998ecf8427":  "", // 31 chars: no such digest
	}
	for in, want := range cases {
		if got := NormaliseHash(in); got != want {
			t.Errorf("NormaliseHash(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyAndNormalise(t *testing.T) {
	cases := []struct {
		in    string
		wantT Type
		wantV string
	}{
		{"192.0.2.1", TypeIP, "192.0.2.1"},
		{"2001:db8::1", TypeIP, "2001:db8::1"},
		{"EVIL.example.com", TypeDomain, "evil.example.com"},
		{"D41D8CD98F00B204E9800998ECF8427E", TypeHash, "d41d8cd98f00b204e9800998ecf8427e"},
		{"garbage here", "", ""},
	}
	for _, tc := range cases {
		gotT, gotV := ClassifyAndNormalise(tc.in)
		if gotT != tc.wantT || gotV != tc.wantV {
			t.Errorf("ClassifyAndNormalise(%q) = (%q, %q), want (%q, %q)",
				tc.in, gotT, gotV, tc.wantT, tc.wantV)
		}
	}
}

func TestExtractCandidates(t *testing.T) {
	entities := map[string]string{"source_ip": "192.0.2.1", "dest_ip": "198.51.100.7"}
	msg := "curl http://evil.example.com/p from 192.0.2.1 dropped " +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got := ExtractCandidates(entities, msg)
	index := map[string]Candidate{}
	for _, c := range got {
		index[c.Value] = c
	}

	// The parsed source_ip also appears in the message; it must be reported once,
	// attributed to the parsed field rather than to the text.
	if c, ok := index["192.0.2.1"]; !ok {
		t.Error("source IP not extracted")
	} else if c.Field != "source_ip" {
		t.Errorf("192.0.2.1 attributed to %q, want source_ip", c.Field)
	}
	count := 0
	for _, c := range got {
		if c.Value == "192.0.2.1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("192.0.2.1 extracted %d times, want 1", count)
	}

	for _, want := range []string{"198.51.100.7", "evil.example.com",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} {
		if _, ok := index[want]; !ok {
			t.Errorf("%q not extracted from %q", want, msg)
		}
	}
	if c := index["evil.example.com"]; c.Type != TypeDomain {
		t.Errorf("evil.example.com typed %q, want domain", c.Type)
	}
}

// A SHA-256 is 64 hex characters and contains no dots, but a careless hash regex
// can chop it into a 32-character prefix and a 32-character suffix, producing two
// indicators that are both wrong.
func TestExtractDoesNotSplitLongDigests(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := ExtractCandidates(nil, "hash="+sha256)
	hashes := 0
	for _, c := range got {
		if c.Type == TypeHash {
			hashes++
			if c.Value != sha256 {
				t.Errorf("extracted %q, want the full digest", c.Value)
			}
		}
	}
	if hashes != 1 {
		t.Errorf("extracted %d hashes from one digest, want 1", hashes)
	}
}

// Ordinary syslog is full of dotted tokens that are not domains. Extracting them
// is not a correctness bug — the store would simply miss — but it is a wasted
// filter probe on every line, so it is worth pinning.
func TestExtractIgnoresNonDomainDottedTokens(t *testing.T) {
	msg := "sshd.service: version 1.2.3 failed, see /etc/ssh/sshd_config line 42"
	for _, c := range ExtractCandidates(nil, msg) {
		if c.Type == TypeDomain && c.Value == "1.2.3" {
			t.Errorf("version string %q extracted as a domain", c.Value)
		}
	}
}

// The extraction regexes are gated behind a cheap byte scan (see scanShape). A
// gate that is merely usually right would drop indicators silently, so this
// compares the gated path against running all four regexes unconditionally over
// a corpus built to sit on every boundary the gates test.
func TestGatesNeverSkipARealMatch(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"

	corpus := []string{
		"",
		"no indicators at all here",
		"Accepted publickey for alice from 10.1.2.3 port 51234 ssh2",
		"connect to 2001:db8::1 port 443",
		"MAC=aa:bb:cc:dd:ee:ff no addresses",
		"hash=" + md5,
		"hash=" + sha1,
		"hash=" + sha256,
		md5 + " " + sha256,
		// 31 hex characters: one short of the shortest digest, so the gate must
		// close and the regex must not have matched anyway.
		"deadbeefdeadbeefdeadbeefdeadbee 10.0.0.1",
		// Exactly 32, the boundary the gate is written against.
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"visit evil.example.com now",
		"curl http://evil.example.com/" + sha256 + " --interface 203.0.113.45",
		"[UFW BLOCK] SRC=203.0.113.45 DST=192.168.1.42 PROTO=TCP SPT=51000 DPT=23",
		"sshd.service: version 1.2.3 failed",
		"::ffff:192.0.2.1 mapped",
		"a.b 1.2 x:y 0123456789abcdef0123456789abcdef",
		"mixed CASE HASH " + strings.ToUpper(md5),
	}

	for _, msg := range corpus {
		gated := ExtractCandidates(nil, msg)
		ungated := extractUngated(msg)
		if !sameCandidates(gated, ungated) {
			t.Errorf("gating changed the result for %q:\n gated:   %v\n ungated: %v",
				msg, values(gated), values(ungated))
		}
	}
}

// extractUngated runs all four regexes with no gating, as the reference.
func extractUngated(message string) []Candidate {
	var out []Candidate
	seen := make(map[string]struct{}, 8)
	add := func(t Type, raw string) {
		norm := Normalise(t, raw)
		if norm == "" {
			return
		}
		if _, dup := seen[norm]; dup {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, Candidate{Value: norm, Type: t, Field: "message", Raw: raw})
	}
	if message == "" {
		return out
	}
	for _, m := range candIPv4Re.FindAllString(message, -1) {
		add(TypeIP, m)
	}
	for _, m := range candIPv6Re.FindAllString(message, -1) {
		add(TypeIP, m)
	}
	for _, m := range candHashRe.FindAllString(message, -1) {
		add(TypeHash, m)
	}
	for _, m := range candHostRe.FindAllString(message, -1) {
		add(TypeDomain, m)
	}
	return out
}

func sameCandidates(a, b []Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, c := range a {
		seen[string(c.Type)+"|"+c.Value]++
	}
	for _, c := range b {
		seen[string(c.Type)+"|"+c.Value]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func values(cs []Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c.Type)+":"+c.Value)
	}
	return out
}

func TestScanShape(t *testing.T) {
	cases := []struct {
		in     string
		dot    bool
		colon  bool
		hexRun int
	}{
		{"", false, false, 0},
		{"zzz", false, false, 0},
		// 'a' and 'e' are hex digits, so ordinary prose has short runs. That is
		// fine — the gate only cares whether a run reaches 32.
		{"plain text", false, false, 1},
		{"10.0.0.1", true, false, 2},
		{"a:b", false, true, 1},
		{"deadbeef", false, false, 8},
		{"zzdeadbeefzz", false, false, 8},
		{"aa:bb:cc", false, true, 2},
		{"x 0123456789abcdef0123456789abcdef y", false, false, 32},
	}
	for _, tc := range cases {
		got := scanShape(tc.in)
		if got.hasDot != tc.dot || got.hasColon != tc.colon || got.hexRun != tc.hexRun {
			t.Errorf("scanShape(%q) = %+v, want dot=%v colon=%v hexRun=%d",
				tc.in, got, tc.dot, tc.colon, tc.hexRun)
		}
	}
}

func TestFeedMatchConfirmsAndCounts(t *testing.T) {
	recs := []Record{
		{Indicator: "198.51.100.7", Type: TypeIP, Feed: "abuse.ch", Note: "C2"},
		{Indicator: "evil.example.com", Type: TypeDomain, Feed: "internal", Note: "phishing"},
	}
	feed, _ := buildTestBundle(t, recs)

	hits, err := feed.Match(map[string]string{"source_ip": "198.51.100.7"},
		"connect to evil.example.com and 192.0.2.99")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
	// Sorted by type then indicator: domain before ip.
	if hits[0].Record.Indicator != "evil.example.com" || hits[0].Record.Feed != "internal" {
		t.Errorf("first hit = %+v", hits[0].Record)
	}
	if hits[1].Record.Indicator != "198.51.100.7" || hits[1].Record.Note != "C2" {
		t.Errorf("second hit = %+v", hits[1].Record)
	}
	if hits[1].Candidate.Field != "source_ip" {
		t.Errorf("IP hit attributed to %q, want source_ip", hits[1].Candidate.Field)
	}

	st := feed.Stats()
	if st.Confirmed != 2 {
		t.Errorf("Confirmed = %d, want 2", st.Confirmed)
	}
	if st.Candidates < 3 {
		t.Errorf("Candidates = %d, want at least 3", st.Candidates)
	}
	if st.LookupErrors != 0 {
		t.Errorf("LookupErrors = %d, want 0", st.LookupErrors)
	}
}

// A clean event must not reach the disk at all: that is the entire performance
// argument for the prefilter.
func TestFeedMatchOnCleanEventTouchesNoDisk(t *testing.T) {
	feed, _ := buildTestBundle(t, []Record{
		{Indicator: "198.51.100.7", Type: TypeIP, Feed: "f"},
	})
	hits, err := feed.Match(map[string]string{"source_ip": "10.1.2.3"},
		"Accepted publickey for alice from 10.1.2.3 port 51234")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("clean event produced %d hits", len(hits))
	}
	if st := feed.Stats(); st.BloomHits != 0 {
		t.Errorf("BloomHits = %d on a clean event — the prefilter let a candidate through to disk",
			st.BloomHits)
	}
}

func TestNilFeedIsSafe(t *testing.T) {
	var f *Feed
	hits, err := f.Match(map[string]string{"source_ip": "10.0.0.1"}, "anything")
	if err != nil || hits != nil {
		t.Errorf("nil feed returned hits=%v err=%v", hits, err)
	}
	if f.Len() != 0 {
		t.Error("nil feed reported indicators")
	}
	if f.Summary() == "" {
		t.Error("nil feed has no summary string")
	}
	if err := f.Close(); err != nil {
		t.Errorf("closing a nil feed: %v", err)
	}
}
