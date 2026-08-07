package ioc

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Build compiles records into a matched bloom/store pair.
//
// This is the reference implementation of the bundle format. The Python feed
// compiler produces the same bytes from the same input — that is not a
// convenience, it is the interop contract, and it is pinned by the shared vector
// suite (TestBloomAgreementVectors and engine/tests/test_ioc.py). A builder and
// a reader that disagree on one hash bit produce a filter that matches nothing
// and reports no error, so "the two implementations agree" has to be a test
// rather than an intention.
//
// Records are normalised, deduplicated and sorted here rather than trusted from
// the caller, because the binary search's correctness depends on the ordering
// and an unsorted store fails by returning "not found" for indicators it holds.
func Build(bloomPath, storePath string, recs []Record, fpr float64, salt1, salt2 uint64) error {
	clean, err := prepare(recs)
	if err != nil {
		return err
	}

	b, err := New(uint64(len(clean)), fpr, salt1, salt2)
	if err != nil {
		return err
	}
	for _, r := range clean {
		b.Add(r.Indicator)
	}

	if err := writeStore(storePath, clean); err != nil {
		return err
	}
	blob, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(bloomPath, blob); err != nil {
		return fmt.Errorf("write ioc bloom %s: %w", bloomPath, err)
	}
	return nil
}

// prepare normalises, drops unusable records, deduplicates and sorts.
func prepare(recs []Record) ([]Record, error) {
	out := make([]Record, 0, len(recs))
	seen := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		t, value := r.Type, r.Indicator
		var norm string
		if t == "" {
			t, norm = ClassifyAndNormalise(value)
		} else {
			norm = Normalise(t, value)
		}
		if norm == "" {
			continue // unclassifiable or refused (see NormaliseDomain)
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		// Tabs and newlines would corrupt the record framing. Metadata comes from
		// external feeds, so it is sanitised rather than assumed well-formed.
		out = append(out, Record{
			Indicator: norm,
			Type:      t,
			Feed:      sanitiseField(r.Feed),
			Note:      sanitiseField(r.Note),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable indicators after normalisation")
	}
	// Byte order, matching the comparison findFirst uses. Sorting by anything
	// else — case-insensitive, locale-aware — would break the search on exactly
	// the records where the two collations disagree.
	sort.Slice(out, func(i, j int) bool { return out[i].Indicator < out[j].Indicator })
	return out, nil
}

func sanitiseField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}

// writeStore emits the header and the sorted records.
func writeStore(path string, recs []Record) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s v%d count=%d\n", storeHeaderPrefix, storeVersion, len(recs))
	for _, r := range recs {
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\n", r.Indicator, r.Type, r.Feed, r.Note)
	}
	if err := writeFileAtomic(path, []byte(sb.String())); err != nil {
		return fmt.Errorf("write ioc store %s: %w", path, err)
	}
	return nil
}

// writeFileAtomic writes via a temporary file and renames into place.
//
// The ingestor loads this bundle at startup and a rebuild can happen while one
// is running. A partially written store is not a parse error — it is a *shorter*
// sorted file, which loads cleanly and silently lacks the indicators that had
// not been written yet. Rename is atomic within a directory, so a reader sees
// either the old bundle or the new one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ioc-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// Flush to disk before the rename: the rename is atomic with respect to other
	// processes, but not with respect to a power cut, which could otherwise leave
	// the new name pointing at unwritten blocks.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
