package ioc

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// storeHeaderPrefix marks the store's self-describing first line.
const storeHeaderPrefix = "#sentinel-ioc-store"

// storeVersion is the store format version.
const storeVersion = 1

// maxRecordLen caps a single record. A corrupt or truncated store must not be
// able to make a lookup allocate without bound, and no legitimate record is
// close to this: the longest indicator is a 64-character SHA-256 and the rest is
// short metadata.
const maxRecordLen = 4096

// readChunk is the granularity of the scan reads inside a binary-search step.
// Sized to sit inside one page, since the cost being managed here is page faults
// rather than syscalls.
const readChunk = 512

// Record is one confirmed indicator.
type Record struct {
	Indicator string // normalised: lowercase domain, canonical IP, lowercase hex digest
	Type      Type
	Feed      string // which feed asserted it, so an analyst can judge the source
	Note      string
}

// Store is the exact confirmation tier: a sorted, newline-delimited file that is
// binary-searched on demand and never read into memory.
//
// # Why a file and not a map
//
// This is the half of the design that makes the Bloom filter worth having. A
// Bloom filter in front of an in-memory exact set saves nothing — if the set is
// resident anyway, the filter is a pure addition. Keeping the exact data on disk
// is what converts the filter's probabilistic answer into a memory saving:
// millions of indicators cost ~11 MB of resident bits plus whatever the page
// cache decides to keep, instead of hundreds of megabytes of Go strings and map
// buckets.
//
// The access pattern is what makes it affordable. The Bloom filter answers
// ~99.99% of candidates without a lookup, so the disk is touched roughly once
// per ten thousand log lines, and the top few levels of the binary search stay
// in page cache because every search visits them.
//
// # Why binary search over lines, and not an index
//
// A sorted text file needs no side index: the ordering *is* the index. That
// keeps the artefact greppable and diffable — an operator can `grep` a store to
// answer "is this IP in my feeds" without any Sentinel tooling, and a feed
// rebuild produces a readable diff rather than an opaque blob. An offset table
// would buy one seek per lookup at the cost of that, on a path that is already
// off the hot path by construction.
type Store struct {
	f     *os.File
	size  int64
	path  string
	count int64
}

// OpenStore opens a sorted indicator store and validates its header.
//
// Header validation is not ceremony. A store that is unsorted, or sorted by a
// different collation than the lookup uses, does not fail — it returns "not
// found" for indicators it contains, which is a detection system silently
// missing the threats it was configured to catch. The header records that the
// writer intended this collation, and TestStoreOrderingMatchesWriter checks the
// two agree.
func OpenStore(path string) (*Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ioc store %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat ioc store %s: %w", path, err)
	}
	s := &Store{f: f, size: fi.Size(), path: path}

	if s.size == 0 {
		f.Close()
		return nil, fmt.Errorf("ioc store %s is empty", path)
	}
	// Every record must be newline-terminated, because the binary search locates
	// record boundaries by scanning for '\n'. A missing final newline would make
	// the last record unreachable — the one bug in this design that produces a
	// wrong answer rather than an error.
	var last [1]byte
	if _, err := f.ReadAt(last[:], s.size-1); err != nil {
		f.Close()
		return nil, fmt.Errorf("read ioc store %s: %w", path, err)
	}
	if last[0] != '\n' {
		f.Close()
		return nil, fmt.Errorf("ioc store %s does not end with a newline, so its last record is unreachable", path)
	}

	header, _, err := s.readLineAt(0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read ioc store header %s: %w", path, err)
	}
	if err := s.parseHeader(header); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// parseHeader reads `#sentinel-ioc-store v1 count=N`.
//
// The header is a comment line rather than a binary preamble so the file stays a
// text file end to end. It needs no special handling during the search: '#'
// (0x23) sorts below every byte a normalised indicator can begin with — digits
// for IPv4, ':' for IPv6, lowercase hex and letters for hashes and domains — so
// the header is simply the smallest record and every search steps over it.
// TestHeaderSortsBeforeEveryIndicator pins that assumption, because it is an
// ordering coupling that would otherwise be invisible.
func (s *Store) parseHeader(line string) error {
	if !strings.HasPrefix(line, storeHeaderPrefix) {
		return fmt.Errorf("missing %s header (first line was %.60q)", storeHeaderPrefix, line)
	}
	fields := strings.Fields(line)
	var sawVersion bool
	for _, f := range fields[1:] {
		switch {
		case strings.HasPrefix(f, "v"):
			v, err := strconv.Atoi(strings.TrimPrefix(f, "v"))
			if err != nil {
				return fmt.Errorf("unparseable store version %q", f)
			}
			if v != storeVersion {
				return fmt.Errorf("store format version %d, this build understands %d", v, storeVersion)
			}
			sawVersion = true
		case strings.HasPrefix(f, "count="):
			n, err := strconv.ParseInt(strings.TrimPrefix(f, "count="), 10, 64)
			if err != nil {
				return fmt.Errorf("unparseable store count %q", f)
			}
			s.count = n
		}
	}
	if !sawVersion {
		return fmt.Errorf("store header declares no version")
	}
	return nil
}

// Close releases the file handle.
func (s *Store) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f.Close()
}

// Path is the file the store was opened from, for diagnostics.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Count is the indicator count declared by the header.
func (s *Store) Count() int64 {
	if s == nil {
		return 0
	}
	return s.count
}

// Lookup resolves a candidate against the store exactly.
//
// Safe for concurrent use: every read goes through ReadAt, which takes its own
// offset rather than sharing the file's. This matters — the pipeline fans out to
// one goroutine per CPU and they all confirm against the same store, so a
// Seek-then-Read implementation would interleave offsets between goroutines and
// return records belonging to another worker's query. Nothing about that failure
// looks like a bug at the call site: it produces plausible, wrong indicators.
func (s *Store) Lookup(key string) (Record, bool, error) {
	if s == nil || s.f == nil || key == "" {
		return Record{}, false, nil
	}
	off, err := s.findFirst(key)
	if err != nil {
		return Record{}, false, err
	}
	if off >= s.size {
		return Record{}, false, nil
	}
	line, _, err := s.readLineAt(off)
	if err != nil {
		return Record{}, false, err
	}
	rec, ok := parseRecord(line)
	if !ok || rec.Indicator != key {
		return Record{}, false, nil
	}
	return rec, true, nil
}

// findFirst returns the offset of the first record whose indicator is >= key,
// or s.size if every record sorts below it.
//
// Binary search over variable-length lines cannot bisect on record index, so it
// bisects on *byte* offset and snaps to the next record boundary. The subtlety
// is the case where the probed half contains no boundary at all — a single
// record longer than the remaining span — which is handled by discarding the
// upper half rather than looping on the same midpoint.
func (s *Store) findFirst(key string) (int64, error) {
	lo, hi := int64(0), s.size
	for lo < hi {
		mid := lo + (hi-lo)/2
		start, err := s.lineStartAtOrAfter(mid)
		if err != nil {
			return 0, err
		}
		if start >= hi {
			// No record begins in [mid, hi). Any record still in range must begin
			// below mid, so narrow from the top. mid < hi holds by construction,
			// so hi strictly decreases and the loop terminates.
			hi = mid
			continue
		}
		line, next, err := s.readLineAt(start)
		if err != nil {
			return 0, err
		}
		if indicatorOf(line) < key {
			lo = next
		} else {
			hi = start
		}
	}
	return lo, nil
}

// lineStartAtOrAfter returns the offset of the first record beginning at or
// after off, or s.size if there is none.
func (s *Store) lineStartAtOrAfter(off int64) (int64, error) {
	if off <= 0 {
		return 0, nil
	}
	// Start one byte back: if off itself is a record start, the byte before it is
	// the '\n' that ends the previous record, and scanning finds it immediately.
	pos := off - 1
	buf := make([]byte, readChunk)
	for pos < s.size {
		n, err := s.f.ReadAt(buf, pos)
		if n > 0 {
			if i := indexByte(buf[:n], '\n'); i >= 0 {
				return pos + int64(i) + 1, nil
			}
			pos += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("scan ioc store %s: %w", s.path, err)
		}
	}
	return s.size, nil
}

// readLineAt reads the record beginning at off, returning it without its
// newline and the offset of the next record.
func (s *Store) readLineAt(off int64) (string, int64, error) {
	var sb strings.Builder
	buf := make([]byte, readChunk)
	pos := off
	for pos < s.size {
		n, err := s.f.ReadAt(buf, pos)
		if n > 0 {
			chunk := buf[:n]
			if i := indexByte(chunk, '\n'); i >= 0 {
				sb.Write(chunk[:i])
				return sb.String(), pos + int64(i) + 1, nil
			}
			if sb.Len()+n > maxRecordLen {
				return "", 0, fmt.Errorf("ioc store %s has a record over %d bytes at offset %d",
					s.path, maxRecordLen, off)
			}
			sb.Write(chunk)
			pos += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", 0, fmt.Errorf("read ioc store %s: %w", s.path, err)
		}
	}
	// Reachable only past the final newline, which OpenStore has already
	// verified exists.
	return sb.String(), s.size, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// indicatorOf returns a record's key without allocating the rest of it, which
// matters because findFirst calls it once per binary-search step.
func indicatorOf(line string) string {
	if i := strings.IndexByte(line, '\t'); i >= 0 {
		return line[:i]
	}
	return line
}

// parseRecord splits `indicator\ttype\tfeed\tnote`. Trailing fields are
// optional so a minimal store — indicators and nothing else — is still valid.
func parseRecord(line string) (Record, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return Record{}, false
	}
	parts := strings.Split(line, "\t")
	rec := Record{Indicator: parts[0]}
	if rec.Indicator == "" {
		return Record{}, false
	}
	if len(parts) > 1 {
		rec.Type = Type(parts[1])
	}
	if len(parts) > 2 {
		rec.Feed = parts[2]
	}
	if len(parts) > 3 {
		rec.Note = parts[3]
	}
	return rec, true
}
