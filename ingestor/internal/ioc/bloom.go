// Package ioc matches log events against threat-intelligence indicators at feed
// scale: millions of IPs, domains, and file hashes pulled from external sources.
//
// # Why a Bloom filter here, when Phase 5 argued against one
//
// The honeytoken package deliberately rejects a Bloom filter, and the reasoning
// there is still correct: a 5-50 entry canary list fits in a few hundred bytes,
// so a probabilistic structure buys nothing and costs correctness on the one
// detector permitted to trigger a firewall block.
//
// Everything about this position is different. An IOC feed is millions of
// indicators, not dozens, and the memory is real. Measured rather than estimated
// (TestMemoryFootprintAtFeedScale, and docs/design/ioc.md):
//
//	1,000,000 indicators
//	  as a Go map:       73.9 MiB resident   (77 bytes each: text, headers, buckets)
//	  as a Bloom filter:  2.3 MiB resident   (19.2 bits each, 13 probes)
//
// That is 32x, and it scales linearly — the aggregated feed sets this is aimed
// at run to several million indicators, where the map side passes a third of a
// gigabyte. On a home server also holding an embedding model in RAM, that is the
// binding constraint.
//
// # The part that makes the false positives acceptable
//
// A Bloom filter alone would be unusable here for exactly the reason Phase 5
// gives: a probabilistic "probably an IOC" is not something to alert a human on,
// let alone act on. So the filter is not the answer, it is the *prefilter*:
//
//	candidate --> Bloom filter (RAM, ~11 MB) --> miss: definitively not an IOC, stop
//	                    |
//	                  hit (real or false)
//	                    v
//	              sorted store (disk) --> binary search --> exact verdict
//
// The Bloom filter can only produce false positives, never false negatives, so a
// miss is a *proof* of absence and costs one cache-resident probe. That is the
// ~99.99% case, and it never touches the disk. A hit is a maybe, and is resolved
// by an exact lookup against the sorted store before it is allowed to mean
// anything. The output of the package therefore has zero false positives — the
// same correctness property honeytokens have — while the resident memory is
// proportional to bits-per-key rather than bytes-per-key.
//
// This is the trade Phase 5 said it was deferring, and it only pays because the
// confirmation step exists. A Bloom filter in front of an in-memory exact set
// would be pure overhead: if the exact set is resident anyway, the filter saves
// no memory and adds a hash. The confirmation store is on disk for that reason,
// not incidentally.
//
// # Why the sizing is explicit rather than "big enough"
//
// A Bloom filter that is quietly overloaded does not fail, it degrades: the
// false-positive rate climbs, every candidate starts reaching the disk, and the
// only symptom is that ingestion got slower. Load reports the filter's estimated
// FPR at its actual fill level so that degradation is visible rather than
// inferred, and the ingestor prints it at startup.
package ioc

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"math"
)

// bloomMagic identifies the serialised filter. The trailing digit is the format
// version and is checked separately, so a future format change fails loudly on
// an old reader instead of being interpreted as garbage bits.
const bloomMagic = "SENTBLM1"

// bloomVersion is the on-disk format version.
const bloomVersion = uint32(1)

// bloomHeaderLen is the fixed-size header preceding the bit array:
// magic(8) + version(4) + k(4) + m(8) + n(8) + salt1(8) + salt2(8) + crc32(4).
const bloomHeaderLen = 8 + 4 + 4 + 8 + 8 + 8 + 8 + 4

// Default sizing parameters. DefaultFPR is the target false-positive rate of the
// prefilter — not of the package, which has none, because every filter hit is
// confirmed against the exact store.
//
// 1e-4 is chosen against the cost of being wrong, which here is one disk seek
// rather than one bad alert. At 1e-4 a million benign candidates produce ~100
// unnecessary lookups, which is free; pushing to 1e-6 would cost 50% more memory
// to avoid seeks that were never the bottleneck. See docs/design/ioc.md.
const DefaultFPR = 1e-4

// Default salts for the compiled bundle.
//
// These are the splitmix64 mixing constants, used here simply as two fixed,
// well-distributed 64-bit values — nothing about the filter needs them to be
// secret or unpredictable, only stable. Stability is the actual requirement:
// they are half of the interop contract with the Python feed compiler, and
// changing either one silently invalidates every bundle ever built. Both are
// odd, so DefaultSalt2 already satisfies the constraint normaliseSalt2 enforces.
const (
	DefaultSalt1 = uint64(0x9e3779b97f4a7c15)
	DefaultSalt2 = uint64(0xbf58476d1ce4e5b9)
)

// maxBloomBits caps a single filter at 2 Gib (256 MiB of bits). A feed large
// enough to need more than that has outgrown a single-node design, and the cap
// turns a nonsensical size parameter into an error at build time rather than an
// allocation failure at startup.
const maxBloomBits = uint64(1) << 31

// Bloom is an immutable Bloom filter. Built once (by the Python feed compiler,
// or by New in tests), read from every worker goroutine, never mutated after
// construction — which is what makes it safe to share without a lock.
type Bloom struct {
	bits  []byte
	m     uint64 // bit count; not necessarily a multiple of 8
	k     uint32 // probes per key
	n     uint64 // keys inserted, for the fill report
	salt1 uint64
	salt2 uint64
}

// SizeFor returns the bit count m and probe count k minimising memory for n
// keys at target false-positive rate p, by the standard result
//
//	m = -n·ln(p) / (ln2)²        k = (m/n)·ln2
//
// n is clamped to at least 1: a zero-key filter still needs a bit to probe, and
// returning m=0 would make every lookup a division by zero rather than an
// obvious empty filter.
func SizeFor(n uint64, p float64) (m uint64, k uint32, err error) {
	if p <= 0 || p >= 1 {
		return 0, 0, fmt.Errorf("target false-positive rate must be in (0,1), got %g", p)
	}
	if n == 0 {
		n = 1
	}
	ln2 := math.Ln2
	mf := -float64(n) * math.Log(p) / (ln2 * ln2)
	if mf > float64(maxBloomBits) {
		return 0, 0, fmt.Errorf(
			"filter for %d indicators at p=%g needs %.0f bits, over the %d-bit cap",
			n, p, mf, maxBloomBits)
	}
	m = uint64(math.Ceil(mf))
	if m < 8 {
		m = 8
	}
	kf := math.Round(float64(m) / float64(n) * ln2)
	if kf < 1 {
		kf = 1
	}
	// Cap k. Beyond ~30 probes the marginal FPR gain is negligible and each probe
	// is an independent cache miss, so an absurd p would otherwise trade real
	// throughput for imaginary accuracy.
	if kf > 30 {
		kf = 30
	}
	return m, uint32(kf), nil
}

// New builds an empty filter sized for n keys at target rate p.
func New(n uint64, p float64, salt1, salt2 uint64) (*Bloom, error) {
	m, k, err := SizeFor(n, p)
	if err != nil {
		return nil, err
	}
	return &Bloom{
		bits:  make([]byte, (m+7)/8),
		m:     m,
		k:     k,
		salt1: salt1,
		salt2: normaliseSalt2(salt2),
	}, nil
}

// normaliseSalt2 forces the configured second salt odd.
//
// Double hashing derives probe i as h1 + i·h2 (mod m). An even stride shares a
// factor with an even m, so the probe sequence cycles early and a nominally
// k-probe filter sets fewer than k distinct bits — degrading the true
// false-positive rate without changing anything observable about the structure.
//
// The stride that actually matters is the post-finaliser value, and hashes()
// forces that odd; this function keeps the *stored* salt odd as well, so the
// format carries a checkable invariant. UnmarshalBloom rejects an even salt2 on
// that basis, which is what makes a filter written by some future third
// implementation fail loudly rather than quietly perform worse than its header
// claims.
//
// Oddness is a mitigation, not a proof of coprimality: m is derived from the
// feed size rather than rounded to a power of two, because rounding up would
// cost up to 2x the memory that is this package's entire justification. The
// resulting rate is therefore measured rather than argued — see
// TestObservedFPRMatchesTarget, which is the test that caught the original
// hashing being seventeen times worse than advertised.
func normaliseSalt2(s uint64) uint64 { return s | 1 }

// Add inserts a key. Not safe for concurrent use; filters are built single
// threaded and only then shared.
func (b *Bloom) Add(key string) {
	h1, h2 := hashes(key, b.salt1, b.salt2)
	for i := uint32(0); i < b.k; i++ {
		pos := probe(h1, h2, i, b.m)
		b.bits[pos>>3] |= 1 << (pos & 7)
	}
	b.n++
}

// MayContain reports whether key might be present. A false return is definitive:
// the key was never added. A true return needs confirmation against the exact
// store.
//
// The early return on the first clear bit is what makes the common case cheap.
// At optimal loading roughly half the bits are set, so a key that was never
// added exits after ~2 probes on average rather than all k.
func (b *Bloom) MayContain(key string) bool {
	if b == nil || b.m == 0 {
		return false
	}
	h1, h2 := hashes(key, b.salt1, b.salt2)
	for i := uint32(0); i < b.k; i++ {
		pos := probe(h1, h2, i, b.m)
		if b.bits[pos>>3]&(1<<(pos&7)) == 0 {
			return false
		}
	}
	return true
}

// probe returns the bit index of the i-th probe for a key hashed to (h1,h2).
//
// Kirsch-Mitzenmacher: k independent hashes are not needed, two suffice, because
// h1 + i·h2 is as good as independent hashing for Bloom-filter purposes. That
// matters at k=13 — it is the difference between two hash computations over the
// key and thirteen.
//
// The addition is deliberately allowed to wrap: uint64 overflow is defined in
// Go, and wrapping is uniform modulo 2^64, so it does not bias the probe
// distribution. The Python builder relies on this and masks to 64 bits to match.
func probe(h1, h2 uint64, i uint32, m uint64) uint64 {
	return (h1 + uint64(i)*h2) % m
}

// hashes derives the two base hashes for a key: one pass of FNV-1a over the key,
// then two independent finalisers.
//
// FNV-1a is used rather than a stronger function for a specific reason: this
// hash has to be reimplemented exactly by the Python feed compiler, because a
// builder and a reader that disagree on one bit produce a filter that matches
// nothing and reports no error. FNV-1a is eight lines in any language and has no
// tuning parameters to get wrong, which makes cross-language agreement testable
// rather than hopeful (see TestBloomAgreementVectors).
//
// # Why the finaliser is not optional
//
// The first version of this salted FNV directly — fnv1a(salt1||key) and
// fnv1a(salt2||key) — on the reasoning that Bloom filters need uniformity rather
// than cryptographic strength, which is true. It was still wrong, and
// TestObservedFPRMatchesTarget is what caught it: the measured false-positive
// rate came out at 1.7e-2 against a 1e-3 target, seventeen times worse than the
// header advertised.
//
// The cause is FNV-1a's avalanche in the low bits. Its round is h = (h XOR b) *
// prime, and multiplication never propagates information downward — bit 0 of the
// product depends only on bit 0 of the operands. So the bottom bits of an FNV
// hash are close to a plain XOR of the input's bottom bits, and two FNV hashes
// over the same key with different prefixes stay strongly correlated there.
// Since the probe index is (h1 + i·h2) mod m and m is even, the modulo reads
// exactly those correlated low bits, and the k probes collapse toward each
// other: a nominally 10-probe filter was setting far fewer than 10 distinct
// bits per key.
//
// Nothing about that failure is visible from the structure. The filter still has
// no false negatives, still round-trips, still reports a healthy EstimatedFPR
// from its header arithmetic — it is simply worse than it claims, and only a
// measurement notices. That is the whole argument for benchmarks/ applied to a
// data structure.
//
// The fix is to run each hash through the murmur3 64-bit finaliser, which is a
// bijection built from shift-XOR and multiply specifically to avalanche high
// bits down into low ones. Salting then happens by XOR before the finaliser
// rather than by prefixing bytes, which also means the key is hashed once
// instead of twice.
func hashes(key string, salt1, salt2 uint64) (uint64, uint64) {
	h := fnv1a(key)
	// salt2's oddness is re-established after mixing: normaliseSalt2 forces the
	// configured salt odd, but the finaliser does not preserve parity, so the
	// value that actually drives the probe stride is forced odd here.
	return fmix64(h ^ salt1), fmix64(h^salt2) | 1
}

// fnv1a is stock FNV-1a 64 over the key.
func fnv1a(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}

// fmix64 is the murmur3 finaliser: a bijection on uint64 with full avalanche.
// The constants are murmur3's and are not tunable — the Python compiler
// transcribes them exactly, masking to 64 bits since Python integers do not
// wrap.
func fmix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// Len reports the number of keys inserted.
func (b *Bloom) Len() uint64 {
	if b == nil {
		return 0
	}
	return b.n
}

// Bits reports the filter's size in bits.
func (b *Bloom) Bits() uint64 {
	if b == nil {
		return 0
	}
	return b.m
}

// Probes reports k.
func (b *Bloom) Probes() uint32 {
	if b == nil {
		return 0
	}
	return b.k
}

// EstimatedFPR returns the false-positive rate implied by the filter's actual
// fill, (1 - e^(-kn/m))^k.
//
// This uses the recorded key count rather than counting set bits: at 96 million
// bits, popcounting the array on every startup is real work to answer a question
// the header already knows. The two agree except for a filter built by a broken
// writer, which the CRC catches first.
func (b *Bloom) EstimatedFPR() float64 {
	if b == nil || b.m == 0 || b.n == 0 {
		return 0
	}
	exp := -float64(b.k) * float64(b.n) / float64(b.m)
	return math.Pow(1-math.Exp(exp), float64(b.k))
}

// MarshalBinary serialises the filter: fixed header, then the bit array.
//
// The CRC covers the bit array only. A truncated or corrupted filter is the
// failure mode worth catching here, because it does not announce itself — a
// filter with a zeroed tail still answers every query, just with silently more
// false positives on some keys and false *negatives* on others, which would make
// the ingestor miss indicators it was told it had.
func (b *Bloom) MarshalBinary() ([]byte, error) {
	out := make([]byte, bloomHeaderLen+len(b.bits))
	copy(out[0:8], bloomMagic)
	binary.LittleEndian.PutUint32(out[8:12], bloomVersion)
	binary.LittleEndian.PutUint32(out[12:16], b.k)
	binary.LittleEndian.PutUint64(out[16:24], b.m)
	binary.LittleEndian.PutUint64(out[24:32], b.n)
	binary.LittleEndian.PutUint64(out[32:40], b.salt1)
	binary.LittleEndian.PutUint64(out[40:48], b.salt2)
	binary.LittleEndian.PutUint32(out[48:52], crc32.ChecksumIEEE(b.bits))
	copy(out[bloomHeaderLen:], b.bits)
	return out, nil
}

// UnmarshalBloom parses a serialised filter, verifying magic, version, declared
// length and checksum before returning it.
func UnmarshalBloom(data []byte) (*Bloom, error) {
	if len(data) < bloomHeaderLen {
		return nil, fmt.Errorf("bloom filter truncated: %d bytes, need at least %d",
			len(data), bloomHeaderLen)
	}
	if string(data[0:8]) != bloomMagic {
		return nil, fmt.Errorf("not a sentinel bloom filter (bad magic %q)", data[0:8])
	}
	version := binary.LittleEndian.Uint32(data[8:12])
	if version != bloomVersion {
		return nil, fmt.Errorf("bloom filter format version %d, this build understands %d",
			version, bloomVersion)
	}
	b := &Bloom{
		k:     binary.LittleEndian.Uint32(data[12:16]),
		m:     binary.LittleEndian.Uint64(data[16:24]),
		n:     binary.LittleEndian.Uint64(data[24:32]),
		salt1: binary.LittleEndian.Uint64(data[32:40]),
		salt2: binary.LittleEndian.Uint64(data[40:48]),
	}
	want := binary.LittleEndian.Uint32(data[48:52])

	if b.m == 0 {
		return nil, fmt.Errorf("bloom filter declares zero bits")
	}
	if b.m > maxBloomBits {
		return nil, fmt.Errorf("bloom filter declares %d bits, over the %d-bit cap", b.m, maxBloomBits)
	}
	if b.k == 0 {
		return nil, fmt.Errorf("bloom filter declares zero probes")
	}
	// salt2 must be odd; see normaliseSalt2. A writer that skipped that step
	// produces a filter whose real FPR is worse than its header claims, so it is
	// rejected rather than quietly used.
	if b.salt2&1 == 0 {
		return nil, fmt.Errorf("bloom filter salt2 is even, which degrades the probe sequence")
	}
	wantBytes := int((b.m + 7) / 8)
	body := data[bloomHeaderLen:]
	if len(body) != wantBytes {
		return nil, fmt.Errorf("bloom filter body is %d bytes, header declares %d bits (%d bytes)",
			len(body), b.m, wantBytes)
	}
	if got := crc32.ChecksumIEEE(body); got != want {
		return nil, fmt.Errorf("bloom filter checksum mismatch: got %08x, want %08x", got, want)
	}
	b.bits = body
	return b, nil
}
