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

// conformanceComparison holds the outcome of one comparison run.
type conformanceComparison struct {
	// Matches counts the comparisons where the two values are equal and the register
	// names neither.
	Matches int
	// Deviations holds every difference, sorted by key.
	Deviations []conformanceDeviation
	// Closed names every comparison that the register names and that now matches.
	// FR-reference-26 fails the suite for each one.
	Closed []conformanceKey
}

// compareConformance returns the comparison of the produced values with the vector values.
//
// The comparison is an exact string match, so a case change and a whitespace change are
// both deviations. It never trims, lowercases or sorts a value.
//
// The register maps a key to the entry that accepts the difference. A key the register
// names produces an accepted deviation when the two values differ, and a closed entry when
// the two values are equal. A nil register accepts nothing.
func compareConformance(
	produced map[conformanceKey]string,
	expected map[conformanceKey]string,
	register map[conformanceKey]deviationEntry,
) conformanceComparison {
	var result conformanceComparison

	for _, key := range conformanceComparedKeys(produced, expected) {
		producedValue, libraryHolds := produced[key]
		expectedValue, vectorHolds := expected[key]
		_, registered := register[key]

		if libraryHolds && vectorHolds && producedValue == expectedValue {
			if registered {
				result.Closed = append(result.Closed, key)

				continue
			}

			result.Matches++

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
