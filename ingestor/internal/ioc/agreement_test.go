package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// This is the Go half of the cross-language agreement. The Python half is
// engine/tests/test_ioc.py; both read testdata/agreement.json, which is
// generated from the Python implementation by scripts/gen-ioc-vectors.py, so
// neither side can drift without a test going red.
//
// The failure this guards against is the worst kind available in this design.
// Python builds the bundle and Go reads it; if they disagree about one hash bit,
// the filter rejects every candidate. The ingestor starts cleanly, reports the
// right indicator count, and silently never matches anything. Each codebase
// remains internally consistent, so no test on either side alone would notice.

type agreement struct {
	Salt1 string `json:"salt1"`
	Salt2 string `json:"salt2"`

	HashVectors []struct {
		Key    string `json:"key"`
		FNV1a  string `json:"fnv1a"`
		FMix64 string `json:"fmix64"`
		H1     string `json:"h1"`
		H2     string `json:"h2"`
	} `json:"hash_vectors"`

	SizeVectors []struct {
		N int     `json:"n"`
		P float64 `json:"p"`
		M string  `json:"m"`
		K uint32  `json:"k"`
	} `json:"size_vectors"`

	ProbeVectors []struct {
		Key  string   `json:"key"`
		M    string   `json:"m"`
		Bits []string `json:"bits"`
	} `json:"probe_vectors"`

	NormaliseVectors []struct {
		Type       string `json:"type"`
		In         string `json:"in"`
		Out        string `json:"out"`
		Classified string `json:"classified"`
	} `json:"normalise_vectors"`

	Bundle struct {
		Indicators []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
			Feed  string `json:"feed"`
			Note  string `json:"note"`
		} `json:"indicators"`
		FPR         float64 `json:"fpr"`
		BloomHex    string  `json:"bloom_hex"`
		BloomSHA256 string  `json:"bloom_sha256"`
		Store       string  `json:"store"`
	} `json:"bundle"`
}

func loadAgreement(t *testing.T) agreement {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "agreement.json"))
	if err != nil {
		t.Fatalf("read agreement vectors (run scripts/gen-ioc-vectors.py): %v", err)
	}
	var a agreement
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("parse agreement vectors: %v", err)
	}
	return a
}

func mustU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad uint64 %q in vectors: %v", s, err)
	}
	return v
}

// The salts are half the interop contract: changing either silently invalidates
// every bundle ever built, so they are pinned rather than merely shared.
func TestSaltsAgree(t *testing.T) {
	a := loadAgreement(t)
	if got := mustU64(t, a.Salt1); got != DefaultSalt1 {
		t.Errorf("DefaultSalt1 = %#x, Python uses %#x", DefaultSalt1, got)
	}
	if got := mustU64(t, a.Salt2); got != DefaultSalt2 {
		t.Errorf("DefaultSalt2 = %#x, Python uses %#x", DefaultSalt2, got)
	}
}

func TestBloomAgreementVectors(t *testing.T) {
	a := loadAgreement(t)
	if len(a.HashVectors) < 8 {
		t.Fatalf("only %d hash vectors — the agreement suite should be broader",
			len(a.HashVectors))
	}
	for _, v := range a.HashVectors {
		if got := fnv1a(v.Key); got != mustU64(t, v.FNV1a) {
			t.Errorf("fnv1a(%q) = %d, Python says %s", v.Key, got, v.FNV1a)
		}
		if got := fmix64(fnv1a(v.Key)); got != mustU64(t, v.FMix64) {
			t.Errorf("fmix64(fnv1a(%q)) = %d, Python says %s", v.Key, got, v.FMix64)
		}
		h1, h2 := hashes(v.Key, DefaultSalt1, DefaultSalt2)
		if h1 != mustU64(t, v.H1) {
			t.Errorf("h1(%q) = %d, Python says %s", v.Key, h1, v.H1)
		}
		if h2 != mustU64(t, v.H2) {
			t.Errorf("h2(%q) = %d, Python says %s", v.Key, h2, v.H2)
		}
	}
}

// Sizing must agree exactly, not approximately. Go rounds halves away from zero
// and Python's built-in round() rounds them to even, so an exact .5 would give
// the two sides different k and therefore incompatible filters. The Python
// implementation uses floor(x+0.5) for that reason; this is what checks it.
func TestSizingAgreementVectors(t *testing.T) {
	a := loadAgreement(t)
	for _, v := range a.SizeVectors {
		m, k, err := SizeFor(uint64(v.N), v.P)
		if err != nil {
			t.Errorf("SizeFor(%d, %g): %v", v.N, v.P, err)
			continue
		}
		if m != mustU64(t, v.M) || k != v.K {
			t.Errorf("SizeFor(%d, %g) = (m=%d, k=%d), Python says (m=%s, k=%d)",
				v.N, v.P, m, k, v.M, v.K)
		}
	}
}

func TestProbeAgreementVectors(t *testing.T) {
	a := loadAgreement(t)
	for _, v := range a.ProbeVectors {
		m := mustU64(t, v.M)
		h1, h2 := hashes(v.Key, DefaultSalt1, DefaultSalt2)
		for i, want := range v.Bits {
			got := probe(h1, h2, uint32(i), m)
			if got != mustU64(t, want) {
				t.Errorf("probe(%q, i=%d, m=%d) = %d, Python says %s",
					v.Key, i, m, got, want)
			}
		}
	}
}

// Normalisation runs on both sides — the compiler canonicalises feed entries,
// the ingestor canonicalises log entries — so a divergence means the store is
// keyed on one spelling and looked up by another.
func TestNormalisationAgreementVectors(t *testing.T) {
	a := loadAgreement(t)
	for _, v := range a.NormaliseVectors {
		var got string
		switch v.Type {
		case "ip":
			got = NormaliseIP(v.In)
		case "domain":
			got = NormaliseDomain(v.In)
		case "hash":
			got = NormaliseHash(v.In)
		case "classify":
			var kind Type
			kind, got = ClassifyAndNormalise(v.In)
			if string(kind) != v.Classified {
				t.Errorf("ClassifyAndNormalise(%q) typed %q, Python says %q",
					v.In, kind, v.Classified)
			}
		default:
			t.Fatalf("unknown vector type %q", v.Type)
		}
		if got != v.Out {
			t.Errorf("normalise %s(%q) = %q, Python says %q", v.Type, v.In, got, v.Out)
		}
	}
}

// The end-to-end check: Go rebuilds the same bundle from the same indicators and
// the bytes must be identical. This is what catches a header-layout or
// byte-order mistake that the per-function vectors would miss.
func TestBundleBytesAgree(t *testing.T) {
	a := loadAgreement(t)

	b, err := New(uint64(len(a.Bundle.Indicators)), a.Bundle.FPR, DefaultSalt1, DefaultSalt2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recs := make([]Record, 0, len(a.Bundle.Indicators))
	for _, i := range a.Bundle.Indicators {
		b.Add(i.Value)
		recs = append(recs, Record{
			Indicator: i.Value, Type: Type(i.Type), Feed: i.Feed, Note: i.Note,
		})
	}
	blob, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	wantHex := a.Bundle.BloomHex
	if got := hex.EncodeToString(blob); got != wantHex {
		t.Errorf("bloom bytes differ.\n go:     %s\n python: %s", got, wantHex)
	}
	sum := sha256.Sum256(blob)
	if got := hex.EncodeToString(sum[:]); got != a.Bundle.BloomSHA256 {
		t.Errorf("bloom sha256 = %s, Python says %s", got, a.Bundle.BloomSHA256)
	}

	// The store is text, so compare it directly rather than by digest: a
	// mismatch should show which record and which column.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "s")
	prepared, err := prepare(recs)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := writeStore(storePath, prepared); err != nil {
		t.Fatalf("writeStore: %v", err)
	}
	got, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != a.Bundle.Store {
		t.Errorf("store contents differ.\n go:\n%s\n python:\n%s", got, a.Bundle.Store)
	}

	// And the filter Python built must actually answer Go's queries — the
	// property all of the above exists to protect.
	parsed, err := UnmarshalBloom(blob)
	if err != nil {
		t.Fatalf("UnmarshalBloom: %v", err)
	}
	for _, i := range a.Bundle.Indicators {
		if !parsed.MayContain(i.Value) {
			t.Errorf("filter built by Python rejects %q, which it contains", i.Value)
		}
	}
}
