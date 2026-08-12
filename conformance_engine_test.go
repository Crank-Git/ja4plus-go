//go:build conformance

package ja4plus

import (
	"slices"
	"strings"
)

// The comparison engine of the conformance suite. It holds FR-conformance-16 through
// FR-conformance-19, and it holds FR-reference-25 and FR-reference-26.
//
// The engine compares two maps of values. It reads no file and it decodes no packet, so a
// test proves every case with a fixture. `conformance_test.go` fills the two maps from the
// corpus.
//
// The engine stays in the test build. It reads `deviationEntry`, which `deviations_test.go`
// defines, and `v1.0.0` freezes the exported API of the library.

// conformanceKey names one comparison. It writes the register key form of
// `testdata/README.md`, so that an entry of `testdata/deviations.json` names a comparison
// the suite makes.
type conformanceKey struct {
	// Capture is the file name of the capture, such as `tls12.pcap`.
	Capture string
	// Stream names the stream or the frame that carries the value.
	Stream string
	// Method names the JA4+ method, such as `JA4S`.
	Method string
}

// String returns the key in the register form `<capture>/<stream>/<method>`.
func (k conformanceKey) String() string {
	return k.Capture + "/" + k.Stream + "/" + k.Method
}

// conformanceDeviationKind names which of the three differences a comparison found.
// The report prints the value, so each one reads as a sentence.
type conformanceDeviationKind string

const (
	// conformanceExtraValue holds FR-conformance-17.
	conformanceExtraValue conformanceDeviationKind = "the library produces a value the vector does not hold"
	// conformanceAbsentValue holds FR-conformance-18.
	conformanceAbsentValue conformanceDeviationKind = "the vector holds a value the library does not produce"
	// conformanceChangedValue holds FR-conformance-19.
	conformanceChangedValue conformanceDeviationKind = "the two values differ"
)

// conformanceDeviation is one difference between the library and a FoxIO vector.
type conformanceDeviation struct {
	// Key names the capture, the stream and the method.
	Key conformanceKey
	// Kind names which of the three differences the comparison found.
	Kind conformanceDeviationKind
	// Expected is the value the vector holds. An extra value holds the empty string here.
	Expected string
	// Produced is the value the library produces. An absent value holds the empty string
	// here.
	Produced string
	// Accepted is true when the register names this comparison. FR-reference-25 expects
	// such a comparison to differ, so an accepted deviation is a recorded ruling.
	Accepted bool
}

// conformanceStaleEntry is one register entry whose recorded `ours` value differs from the
// value the run produces. #307 states the defect it reports.
//
// A register entry records the two values that the maintainer ruled on. A later change
// moves the value this library produces, and the entry then accepts a comparison it does
// not describe. FR-reference-26 never reaches such an entry, because the two values still
// differ.
type conformanceStaleEntry struct {
	// Key names the comparison the register entry accepts.
	Key conformanceKey
	// Recorded is the `ours` value of the register entry.
	Recorded string
	// Produced is the value the run produces. It is the empty string when the library
	// produces no value for the key.
	Produced string
}

// conformanceOrphanEntry is one register entry whose key no comparison of the run reaches.
// #328 states the defect it reports.
//
// A register entry names a comparison. A renamed method key, a dropped capture or a moved
// stream name each stop the run from making that comparison. The entry then accepts a
// difference that no comparison of the run reports. FR-reference-26 never reaches such an
// entry, and #307 never reaches it either, because both checks read the compared keys
// alone.
type conformanceOrphanEntry struct {
	// Key names the comparison the register entry accepts.
	Key conformanceKey
	// Recorded is the `ours` value of the register entry.
	Recorded string
}

// conformanceComparison holds the outcome of one comparison run.
type conformanceComparison struct {
	// Matches counts the comparisons where the two values are equal and the register
	// names neither.
	Matches int
	// Matched names every comparison that Matches counts, sorted by key. The report reads
	// it, because a count alone cannot say which method of which capture matched.
	Matched []conformanceKey
	// Deviations holds every difference, sorted by key.
	Deviations []conformanceDeviation
	// Closed names every comparison that the register names and that now matches.
	// FR-reference-26 fails the suite for each one.
	Closed []conformanceKey
	// Stale holds every register entry whose recorded value the run no longer produces,
	// sorted by key. #307 fails the suite for each one.
	Stale []conformanceStaleEntry
	// Reached names every register key that this comparison reaches, sorted by key. It holds
	// FR-conformance-33h. The run subtracts the reached keys from the register, and each key
	// that remains names an orphan entry.
	Reached []conformanceKey
}

// compareConformance returns the comparison of the produced values with the vector values.
//
// The comparison is an exact string match, so a case change and a whitespace change are
// both deviations. It never trims, lowercases or sorts a value.
//
// The register maps a key to the entry that accepts the difference. A key the register
// names produces an accepted deviation when the two values differ, and a closed entry when
// the two values are equal. A nil register accepts nothing.
//
// A key the register names produces a stale entry when the recorded `ours` value differs
// from the produced value. A stale entry stands beside a match, a deviation and a closed
// entry, and it replaces none of them.
//
// A key the register names also reaches `Reached`. The comparison reads one capture and one
// vector set, so it sees one part of the register. `conformanceOrphanEntries` reads the
// reached keys of the whole run.
func compareConformance(
	produced map[conformanceKey]string,
	expected map[conformanceKey]string,
	register map[conformanceKey]deviationEntry,
) conformanceComparison {
	var result conformanceComparison

	for _, key := range conformanceComparedKeys(produced, expected) {
		producedValue, libraryHolds := produced[key]
		expectedValue, vectorHolds := expected[key]
		entry, registered := register[key]

		// #328 records the key before the branches below. A closed entry and a stale entry
		// each name a key the run reaches, so the record stands outside every branch.
		if registered {
			result.Reached = append(result.Reached, key)
		}

		// #307 reads the recorded value of the entry, and never its presence alone. The
		// check stands outside the two branches below, because a stale record is a defect of
		// the register and it says nothing about the comparison.
		//
		// The check reads `producedValue` and never `libraryHolds`. A key the library
		// produces no value for reads the empty string, and a capability decline records the
		// empty string, so the two agree. This holds because no fingerprinter of this project
		// returns an empty value without an error.
		if registered && entry.Ours != producedValue {
			result.Stale = append(result.Stale, conformanceStaleEntry{
				Key:      key,
				Recorded: entry.Ours,
				Produced: producedValue,
			})
		}

		if libraryHolds && vectorHolds && producedValue == expectedValue {
			if registered {
				result.Closed = append(result.Closed, key)

				continue
			}

			result.Matches++
			result.Matched = append(result.Matched, key)

			continue
		}

		deviation := conformanceDeviation{
			Key:      key,
			Kind:     conformanceChangedValue,
			Expected: expectedValue,
			Produced: producedValue,
			Accepted: registered,
		}

		switch {
		case !vectorHolds:
			deviation.Kind = conformanceExtraValue
		case !libraryHolds:
			deviation.Kind = conformanceAbsentValue
		}

		result.Deviations = append(result.Deviations, deviation)
	}

	return result
}

// conformanceOrphanEntries returns one entry for each register key that the reached set does
// not hold, sorted by key. It holds FR-conformance-33i.
//
// The caller passes the reached keys of the whole run, and never of one comparison. One
// comparison reads one capture and one vector set, so a key it does not reach is a key
// another comparison of the run reaches.
func conformanceOrphanEntries(
	register map[conformanceKey]deviationEntry,
	reached map[conformanceKey]bool,
) []conformanceOrphanEntry {
	var entries []conformanceOrphanEntry

	for key, entry := range register {
		if reached[key] {
			continue
		}

		entries = append(entries, conformanceOrphanEntry{Key: key, Recorded: entry.Ours})
	}

	// A range over a map orders nothing, and an unordered report changes on every run.
	slices.SortFunc(entries, func(first, second conformanceOrphanEntry) int {
		return strings.Compare(first.Key.String(), second.Key.String())
	})

	return entries
}

// conformanceComparedKeys returns every key of the two maps, sorted.
// A range over a map orders nothing, and an unordered report changes on every run.
func conformanceComparedKeys(produced, expected map[conformanceKey]string) []conformanceKey {
	seen := make(map[conformanceKey]struct{}, len(produced)+len(expected))

	for key := range produced {
		seen[key] = struct{}{}
	}

	for key := range expected {
		seen[key] = struct{}{}
	}

	keys := make([]conformanceKey, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}

	slices.SortFunc(keys, func(first, second conformanceKey) int {
		return strings.Compare(first.String(), second.String())
	})

	return keys
}
