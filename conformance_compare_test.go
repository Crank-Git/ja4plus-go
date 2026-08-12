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

// #307 states that a register entry records a value the run no longer produces. The entry
// then accepts a comparison it does not describe, and FR-reference-26 never fires, because
// the two values still differ.
func TestTheComparisonReportsAStaleEntryWhenTheRunNoLongerProducesTheRecordedValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_57"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the run produces `6252_57` where the register records `6252_58`",
			len(result.Stale))
	}

	stale := result.Stale[0]

	if stale.Key != key {
		t.Errorf("the comparison reports the stale entry %q, and the register names %q", stale.Key, key)
	}

	if stale.Recorded != "6252_58" || stale.Produced != "6252_57" {
		t.Errorf("the stale entry records %q and produces %q, and the fixture holds `6252_58` and `6252_57`",
			stale.Recorded, stale.Produced)
	}

	// The entry still accepts the deviation. A stale record is a defect of the register,
	// and it never turns a ruling into an unaccepted deviation.
	if len(result.Deviations) != 1 || !result.Deviations[0].Accepted {
		t.Errorf("the comparison reports %d deviations, and the register names the comparison %q",
			len(result.Deviations), key)
	}
}

// An entry the run still reaches is not stale. A check that reported one on every entry
// would fail every run and gate nothing.
func TestTheComparisonReportsNoStaleEntryWhenTheRunProducesTheRecordedValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the run produces the recorded value `6252_58`",
			len(result.Stale))
	}
}

// A capability decline records the empty string, because the library produces no value.
// The library that starts to produce one makes that record wrong.
func TestTheComparisonReportsAStaleEntryWhenTheLibraryProducesAValueACapabilityDeclineDenies(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Capability: true, Ours: "", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the entry records no value where the run produces `6252_58`",
			len(result.Stale))
	}

	if result.Stale[0].Recorded != "" || result.Stale[0].Produced != "6252_58" {
		t.Errorf("the stale entry records %q and produces %q, and the fixture holds the empty string and `6252_58`",
			result.Stale[0].Recorded, result.Stale[0].Produced)
	}
}

// A capability decline that still holds produces no value, and the empty record matches it.
func TestTheComparisonReportsNoStaleEntryWhenACapabilityDeclineStillProducesNoValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Capability: true, Ours: "", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the library produces no value for the key %q",
			len(result.Stale), key)
	}
}

// One entry carries two defects when the run reaches the vector value and the entry records
// a third value. The suite then prints one message for each, and neither one replaces the
// other.
func TestTheComparisonReportsAClosedEntryAndAStaleEntryForOneRegisterKey(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_59"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the run produces the vector value `6252_59`",
			len(result.Closed))
	}

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the entry records `6252_58` where the run produces `6252_59`",
			len(result.Stale))
	}

	if result.Matches != 0 {
		t.Errorf("the comparison counts %d matches, and the register names the comparison %q", result.Matches, key)
	}
}

// The register names no comparison the run makes, so no stale entry can stand. A nil
// register accepts nothing, and it must report nothing.
func TestTheComparisonReportsNoStaleEntryWhenTheRegisterNamesNoComparison(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f58"},
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f57"},
		nil,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the register names no comparison", len(result.Stale))
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

// #328 states that the stale check of #307 visits only the keys the run reaches. A register
// entry whose key neither map holds reaches no comparison, so the comparison names the keys
// it reaches and the run subtracts them from the register.
func TestTheComparisonNamesEveryRegisterKeyItReaches(t *testing.T) {
	reached := oneConformanceKey("JA4")
	absent := oneConformanceKey("JA4S")

	register := map[conformanceKey]deviationEntry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		absent:  {Key: absent.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{reached: "ours"},
		map[conformanceKey]string{reached: "theirs"},
		register,
	)

	if len(result.Reached) != 1 {
		t.Fatalf("the comparison names %d reached register keys, and it compares the one key %q",
			len(result.Reached), reached)
	}

	if result.Reached[0] != reached {
		t.Errorf("the comparison names the reached key %q, and it compares %q", result.Reached[0], reached)
	}
}

// A key that the register does not name measures nothing about the register, so the
// comparison names it nowhere.
func TestTheComparisonNamesNoReachedKeyThatTheRegisterDoesNotHold(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "value"},
		map[conformanceKey]string{key: "value"},
		nil,
	)

	if len(result.Reached) != 0 {
		t.Errorf("the comparison names %d reached register keys, and the register holds none", len(result.Reached))
	}
}

// A closed entry names a key the run reaches. An orphan check that counted it as unreached
// would report an orphan the register does not hold.
func TestTheComparisonNamesAReachedKeyForAClosedEntry(t *testing.T) {
	key := oneConformanceKey("JA4")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "value", Theirs: "value", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "value"},
		map[conformanceKey]string{key: "value"},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the two values are equal", len(result.Closed))
	}

	if len(result.Reached) != 1 || result.Reached[0] != key {
		t.Errorf("the comparison names %d reached register keys, and it compares the closed key %q",
			len(result.Reached), key)
	}
}

// #328 states the orphan entry. The run reaches the key of one entry and no key of the
// other, so the second entry is an orphan entry.
func TestTheOrphanEntriesNameEveryRegisterKeyTheRunNeverReaches(t *testing.T) {
	reached := oneConformanceKey("JA4")
	orphan := oneConformanceKey("JA4S")

	register := map[conformanceKey]deviationEntry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		orphan:  {Key: orphan.String(), Ours: "recorded", Theirs: "theirs", Ruling: "#20"},
	}

	entries := conformanceOrphanEntries(register, map[conformanceKey]bool{reached: true})

	if len(entries) != 1 {
		t.Fatalf("the run reports %d orphan entries, and it reaches the key of one of the two entries", len(entries))
	}

	if entries[0].Key != orphan {
		t.Errorf("the run reports the orphan entry %q, and it reaches no key of %q", entries[0].Key, orphan)
	}

	if entries[0].Recorded != "recorded" {
		t.Errorf("the orphan entry records %q, and the register entry holds `recorded`", entries[0].Recorded)
	}
}

// An orphan check that fired on a reached key would fail every run and gate nothing.
func TestTheOrphanEntriesNameNoRegisterKeyTheRunReaches(t *testing.T) {
	key := oneConformanceKey("JA4")

	register := map[conformanceKey]deviationEntry{
		key: {Key: key.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	}

	entries := conformanceOrphanEntries(register, map[conformanceKey]bool{key: true})

	if len(entries) != 0 {
		t.Errorf("the run reports %d orphan entries, and it reaches the key of the one entry", len(entries))
	}
}

// A range over the register orders nothing, and an unordered report changes on every run.
func TestTheOrphanEntriesSortTheEntriesByKey(t *testing.T) {
	first := conformanceKey{Capture: "dhcp.pcapng", Stream: "1", Method: "JA4D"}
	second := conformanceKey{Capture: "tls12.pcap", Stream: "1", Method: "JA4"}

	register := map[conformanceKey]deviationEntry{
		second: {Key: second.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		first:  {Key: first.String(), Ours: "ours", Theirs: "theirs", Ruling: "#20"},
	}

	entries := conformanceOrphanEntries(register, nil)

	if len(entries) != 2 {
		t.Fatalf("the run reports %d orphan entries, and it reaches no key of the two entries", len(entries))
	}

	if entries[0].Key != first || entries[1].Key != second {
		t.Errorf("the run reports the orphan entries %q and %q, and the sorted order names `dhcp.pcapng` first",
			entries[0].Key, entries[1].Key)
	}
}
