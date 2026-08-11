//go:build conformance

package ja4plus

import (
	"testing"
)

// These tests hold FR-conformance-16 through FR-conformance-19, FR-reference-25 and
// FR-reference-26. They run over fixture values, because a corpus comparison proves the
// engine only where the corpus reaches the case. The register is empty today, so a
// fixture register is the only way to exercise the two reference requirements.
//
// `.claude/rules/rulings.md` reserves a register entry to the maintainer. These fixtures
// live in the test and reach `testdata/deviations.json` never.

// oneConformanceKey returns the key of one comparison the fixtures use.
func oneConformanceKey(method string) conformanceKey {
	return conformanceKey{Capture: "tls12.pcap", Stream: "1", Method: method}
}

func TestTheComparisonReportsAMatchWhenTheTwoValuesAreEqual(t *testing.T) {
	key := oneConformanceKey("JA4")
	value := "t13d1715h2_5b57614c22b0_3d5424432f57"

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		nil,
	)

	if result.Matches != 1 {
		t.Errorf("the comparison reports %d matches, and the two values are equal", result.Matches)
	}

	if len(result.Deviations) != 0 {
		t.Errorf("the comparison reports %d deviations, and the two values are equal", len(result.Deviations))
	}
}

// FR-conformance-17 makes an extra fingerprint a deviation.
func TestTheComparisonReportsADeviationWhenTheLibraryProducesAValueTheVectorLacks(t *testing.T) {
	key := oneConformanceKey("JA4T")

	result := compareConformance(
		map[conformanceKey]string{key: "8192_2-1-3-1-1-4_1460_8"},
		map[conformanceKey]string{},
		nil,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the library produces one extra value", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceExtraValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-17 names %q", deviation.Kind, conformanceExtraValue)
	}

	if deviation.Produced != "8192_2-1-3-1-1-4_1460_8" {
		t.Errorf("the deviation holds the produced value %q, and the library produced `8192_2-1-3-1-1-4_1460_8`", deviation.Produced)
	}

	if deviation.Expected != "" {
		t.Errorf("the deviation holds the expected value %q, and the vector holds no value", deviation.Expected)
	}
}

// FR-conformance-18 makes an absent fingerprint a deviation.
func TestTheComparisonReportsADeviationWhenTheVectorHoldsAValueTheLibraryLacks(t *testing.T) {
	key := oneConformanceKey("JA4S")

	result := compareConformance(
		map[conformanceKey]string{},
		map[conformanceKey]string{key: "t130200_1301_a56c5b993250"},
		nil,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the vector holds one value the library lacks", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceAbsentValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-18 names %q", deviation.Kind, conformanceAbsentValue)
	}

	if deviation.Expected != "t130200_1301_a56c5b993250" {
		t.Errorf("the deviation holds the expected value %q, and the vector holds `t130200_1301_a56c5b993250`", deviation.Expected)
	}

	if deviation.Produced != "" {
		t.Errorf("the deviation holds the produced value %q, and the library produced no value", deviation.Produced)
	}
}

// FR-conformance-19 makes one character a deviation. The acceptance criteria name a
// fingerprint that a test changes by one character, and this test holds that case.
func TestTheComparisonReportsADeviationWhenTheTwoValuesDifferByOneCharacter(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f58"},
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f57"},
		nil,
	)

	if result.Matches != 0 {
		t.Errorf("the comparison reports %d matches, and the two values differ by one character", result.Matches)
	}

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the two values differ by one character", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceChangedValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-19 names %q", deviation.Kind, conformanceChangedValue)
	}

	// FR-conformance-32 requires both values, and #35 writes them into the report.
	if deviation.Expected != "t13d1715h2_5b57614c22b0_3d5424432f57" || deviation.Produced != "t13d1715h2_5b57614c22b0_3d5424432f58" {
		t.Errorf("the deviation holds the expected value %q and the produced value %q", deviation.Expected, deviation.Produced)
	}
}

// FR-conformance-16 compares as an exact string match. A comparison that trims, lowercases
// or sorts a value reports a match this project does not hold.
func TestTheComparisonReportsADeviationForACaseChangeAndForAWhitespaceChange(t *testing.T) {
	cases := []struct {
		name     string
		produced string
		expected string
	}{
		{"the case differs", "T13D1715H2_5B57614C22B0_3D5424432F57", "t13d1715h2_5b57614c22b0_3d5424432f57"},
		{"a trailing space is present", "t13d1715h2_5b57614c22b0_3d5424432f57 ", "t13d1715h2_5b57614c22b0_3d5424432f57"},
		{"a leading space is present", " t13d1715h2_5b57614c22b0_3d5424432f57", "t13d1715h2_5b57614c22b0_3d5424432f57"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key := oneConformanceKey("JA4")

			result := compareConformance(
				map[conformanceKey]string{key: testCase.produced},
				map[conformanceKey]string{key: testCase.expected},
				nil,
			)

			if result.Matches != 0 {
				t.Errorf("the comparison reports a match where %s, and FR-conformance-16 requires an exact string match", testCase.name)
			}
		})
	}
}

// FR-reference-25 expects the comparison the register names to differ. An accepted
// deviation is a recorded ruling, and it is not a failure.
func TestTheComparisonAcceptsADeviationTheRegisterNames(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the two values differ", len(result.Deviations))
	}

	if !result.Deviations[0].Accepted {
		t.Errorf("the comparison reports an unaccepted deviation, and the register names the comparison %q", key)
	}

	if len(result.Closed) != 0 {
		t.Errorf("the comparison reports %d closed entries, and the comparison still differs", len(result.Closed))
	}
}

// FR-reference-26 fails the suite when a comparison the register names now matches. A
// closed deviation that sits in the register unnoticed hides a repair.
func TestTheComparisonReportsAClosedEntryWhenARegisteredComparisonMatches(t *testing.T) {
	key := oneConformanceKey("JA4L-S")
	value := "6252_58"

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: value, Theirs: value, Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the register names one comparison that now matches", len(result.Closed))
	}

	if result.Closed[0] != key {
		t.Errorf("the comparison reports the closed entry %q, and the register names %q", result.Closed[0], key)
	}

	// A closed entry is a failure, so it must never count as a match that the summary
	// reports as healthy.
	if result.Matches != 0 {
		t.Errorf("the comparison counts %d matches, and a closed register entry is a failure", result.Matches)
	}
}

// The engine sorts its deviations, so a report and a failure message read the same on
// every run. A range over a map orders nothing.
func TestTheComparisonSortsTheDeviationsByKey(t *testing.T) {
	produced := map[conformanceKey]string{
		{Capture: "b.pcap", Stream: "1", Method: "JA4"}:  "b1",
		{Capture: "a.pcap", Stream: "2", Method: "JA4"}:  "a2",
		{Capture: "a.pcap", Stream: "1", Method: "JA4S"}: "a1s",
		{Capture: "a.pcap", Stream: "1", Method: "JA4"}:  "a1",
	}

	result := compareConformance(produced, map[conformanceKey]string{}, nil)

	wanted := []string{
		"a.pcap/1/JA4",
		"a.pcap/1/JA4S",
		"a.pcap/2/JA4",
		"b.pcap/1/JA4",
	}

	if len(result.Deviations) != len(wanted) {
		t.Fatalf("the comparison reports %d deviations, and the fixture holds %d", len(result.Deviations), len(wanted))
	}

	for index, key := range wanted {
		if got := result.Deviations[index].Key.String(); got != key {
			t.Errorf("deviation %d holds the key %q, and the sorted order names %q", index, got, key)
		}
	}
}

func TestTheConformanceKeyWritesTheRegisterKeyForm(t *testing.T) {
	// `testdata/README.md` states the form `<capture>/<stream>/<method>`, and
	// `checkDeviationKey` holds it. A key the register cannot name is a key that
	// FR-reference-25 cannot reach.
	key := conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4L-S"}

	if key.String() != "ssh2.pcapng/15/JA4L-S" {
		t.Fatalf("the key writes %q, and the register form is `ssh2.pcapng/15/JA4L-S`", key.String())
	}

	if err := checkDeviationKey(key.String()); err != nil {
		t.Errorf("the register reader rejects the key %q: %v", key.String(), err)
	}
}
