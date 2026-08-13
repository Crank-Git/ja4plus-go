//go:build conformance

package ja4plus

import (
	"os"
	"strings"
	"testing"
)

// These tests hold FR-conformance-27 through FR-conformance-33.
//
// They run over fixture values, because the corpus reaches only the cases the corpus
// holds. `conformance_report_test.go` holds the renderer, and `conformance_test.go` fills
// it from the corpus.

// oneConformanceReport returns a report over one capture, one match and one deviation.
func oneConformanceReport() *conformanceReport {
	report := newConformanceReport("27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8")
	report.readCapture("tls12.pcap")

	report.recordComparison("tls12.pcap", "per-stream", conformanceComparison{
		Matches: 1,
		Matched: []conformanceKey{{Capture: "tls12.pcap", Stream: "0", Method: "JA4.1"}},
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: "JA4_o.1"},
			Kind:     conformanceAbsentValue,
			Expected: "t13d1715h2_5b234860e130_014157ec0da2",
		}},
	})

	return report
}

// conformanceRowOf returns the row of one capture and one method.
func conformanceRowOf(t *testing.T, report *conformanceReport, capture, method string) conformanceReportRow {
	t.Helper()

	for _, row := range report.rows() {
		if row.Capture == capture && row.Method == method {
			return row
		}
	}

	t.Fatalf("the report holds no row for the capture %q and the method %q", capture, method)

	return conformanceReportRow{}
}

// The raw form of a method is a form of that method, and never a method of its own. The
// `## Terms` table of `docs/specs/spec.md` names eleven methods, and `raw form` names
// `JA4_r` as a form of JA4.
func TestTheReportReadsARawFormKeyAsItsMethod(t *testing.T) {
	cases := map[string]string{
		"JA4.1":     "JA4",
		"JA4_r.1":   "JA4",
		"JA4_o.1":   "JA4",
		"JA4_ro.1":  "JA4",
		"JA4S":      "JA4S",
		"JA4S_r.2":  "JA4S",
		"JA4H_ro.3": "JA4H",
		"JA4X_r":    "JA4X",
		"JA4SSH.11": "JA4SSH",
		"JA4T.1":    "JA4T",
		"JA4TS.1":   "JA4TS",
		"JA4D.1":    "JA4D",
		// The per-stream vector names the two JA4L methods `JA4L-C` and `JA4L-S`, and the
		// per-packet vector names them `ja4.ja4l` and `ja4.ja4ls`.
		"JA4L-C":  "JA4L",
		"JA4L-S":  "JA4LS",
		"JA4L.1":  "JA4L",
		"JA4LS.1": "JA4LS",
	}

	for key, wanted := range cases {
		t.Run(key, func(t *testing.T) {
			method, err := conformanceReportMethodOf(key)
			if err != nil {
				t.Fatalf("the report rejects the key %q: %v", key, err)
			}

			if method != wanted {
				t.Errorf("the report reads the key %q as the method %q, and it names %q", key, method, wanted)
			}
		})
	}
}

// A key the report cannot place is a defect of the harness. A silent drop would lose a
// comparison from the table that FR-conformance-28 states.
func TestTheReportRejectsAMethodKeyItDoesNotRecognize(t *testing.T) {
	if _, err := conformanceReportMethodOf("JA4TScan.1"); err == nil {
		t.Error("the report reads the key `JA4TScan.1`, and this project implements no such method")
	}
}

// FR-conformance-28 holds one row for each capture and each method.
func TestTheReportHoldsOneRowForEachCaptureAndEachMethod(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("tls12.pcap")
	report.readCapture("dhcp.pcapng")

	rows := report.rows()

	wanted := 2 * len(conformanceReportMethods)
	if len(rows) != wanted {
		t.Fatalf("the report holds %d rows, and 2 captures times %d methods make %d",
			len(rows), len(conformanceReportMethods), wanted)
	}

	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		key := row.Capture + "/" + row.Method
		if seen[key] {
			t.Errorf("the report holds the row %q twice", key)
		}

		seen[key] = true
	}
}

// FR-conformance-29 records `match`, `deviation` or `not applicable` in each row.
func TestTheReportRecordsOneOfTheThreeResultsInEachRow(t *testing.T) {
	report := oneConformanceReport()

	held := map[conformanceReportResult]bool{
		conformanceReportMatch:         true,
		conformanceReportDeviation:     true,
		conformanceReportNotApplicable: true,
	}

	for _, row := range report.rows() {
		if !held[row.Result] {
			t.Errorf("the row %s/%s records the result %q, and FR-conformance-29 names three",
				row.Capture, row.Method, row.Result)
		}
	}
}

// FR-conformance-33 records `not applicable` only when the vector holds no value for the
// method on the capture. A comparison that fails is a deviation, and never `not
// applicable`.
func TestTheReportRecordsNotApplicableOnlyWhereNoVectorHoldsAValue(t *testing.T) {
	report := oneConformanceReport()

	// The fixture compares JA4 on the capture, and the comparison holds one match and one
	// deviation. A deviation outranks a match, because a row that reads `match` while a
	// deviation stands hides the deviation.
	if row := conformanceRowOf(t, report, "tls12.pcap", "JA4"); row.Result != conformanceReportDeviation {
		t.Errorf("the JA4 row records %q, and the comparison holds one deviation", row.Result)
	}

	// No vector of the fixture holds a JA4SSH value, so the row records `not applicable`.
	if row := conformanceRowOf(t, report, "tls12.pcap", "JA4SSH"); row.Result != conformanceReportNotApplicable {
		t.Errorf("the JA4SSH row records %q, and no vector holds a JA4SSH value", row.Result)
	}
}

// A row that holds every match and no deviation records `match`.
func TestTheReportRecordsAMatchWhereEveryComparisonMatches(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("dhcp.pcapng")
	report.recordComparison("dhcp.pcapng", "per-packet", conformanceComparison{
		Matches: 2,
		Matched: []conformanceKey{
			{Capture: "dhcp.pcapng", Stream: "1", Method: "JA4D.1"},
			{Capture: "dhcp.pcapng", Stream: "2", Method: "JA4D.1"},
		},
	})

	row := conformanceRowOf(t, report, "dhcp.pcapng", "JA4D")

	if row.Result != conformanceReportMatch {
		t.Errorf("the JA4D row records %q, and the two comparisons match", row.Result)
	}

	if row.Matches != 2 || row.Deviations != 0 {
		t.Errorf("the JA4D row counts %d matches and %d deviations, and the comparison holds 2 and 0",
			row.Matches, row.Deviations)
	}

	if row.Set != "per-packet" {
		t.Errorf("the JA4D row names the vector set %q, and the per-packet vector holds the value", row.Set)
	}
}

// A `not applicable` row states why the suite compares nothing. A reader who meets an
// empty row cannot tell an absent vector from a defect of the harness.
func TestTheReportStatesTheReasonOfEachNotApplicableRow(t *testing.T) {
	report := oneConformanceReport()

	for _, row := range report.rows() {
		if row.Result == conformanceReportNotApplicable && row.Reason == "" {
			t.Errorf("the row %s/%s records `not applicable` and states no reason", row.Capture, row.Method)
		}
	}
}

// FoxIO marks one capture `notest`, and the suite compares no value on it. Every row of
// that capture names the marker as the reason.
func TestTheReportNamesTheNotestMarkerAsTheReasonOfADeclinedCapture(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.declineCapture("dtls-udp.notest.cap", conformanceReportNotestReason)

	row := conformanceRowOf(t, report, "dtls-udp.notest.cap", "JA4")

	if row.Result != conformanceReportNotApplicable {
		t.Errorf("the row records %q, and FoxIO marks the capture `notest`", row.Result)
	}

	if !strings.Contains(row.Reason, "notest") {
		t.Errorf("the row states the reason %q, and it does not name the marker", row.Reason)
	}
}

// FR-conformance-30 names the fetched FoxIO commit.
func TestTheReportNamesTheFetchedFoxIOCommit(t *testing.T) {
	commit := "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

	if text := oneConformanceReport().render(); !strings.Contains(text, commit) {
		t.Errorf("the report does not name the fetched FoxIO commit %s", commit)
	}
}

// FR-conformance-31 names the count of captures, the count of matches and the count of
// deviations.
func TestTheReportNamesTheCountOfCapturesMatchesAndDeviations(t *testing.T) {
	text := oneConformanceReport().render()

	for _, line := range []string{
		"| Captures | 1 |",
		"| Matches | 1 |",
		"| Deviations | 1 |",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("the report holds no summary line %q", line)
		}
	}
}

// FR-conformance-32 records the expected value and the produced value of each deviation.
func TestTheReportWritesTheExpectedValueAndTheProducedValueOfEachDeviation(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordComparison("ssh2.pcapng", "per-packet", conformanceComparison{
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.1"},
			Kind:     conformanceChangedValue,
			Expected: "c36s36_c55s53_c14s14",
			Produced: "c36s36_c55s53_c13s14",
		}},
	})

	text := report.render()

	for _, value := range []string{"c36s36_c55s53_c14s14", "c36s36_c55s53_c13s14"} {
		if !strings.Contains(text, value) {
			t.Errorf("the report does not hold the value %q", value)
		}
	}
}

// The report is tracked in git, so its size lands in every future diff. The corpus reports
// 3431 deviations at the pinned commit. The three SSH captures carry more than half of
// them. The report therefore holds at most `conformanceReportSampleLimit` deviation rows
// for one capture, one method and one vector set. It states the full count of the group.
// `conformance.log` holds every deviation, and the CI job uploads it.
func TestTheReportBoundsTheDeviationRowsOfOneGroup(t *testing.T) {
	deviations := make([]conformanceDeviation, 0, 10)

	for index := range 10 {
		deviations = append(deviations, conformanceDeviation{
			Key:      conformanceKey{Capture: "ssh-r.pcap", Stream: "0", Method: conformanceMethodOccurrence("JA4SSH", index+1)},
			Kind:     conformanceAbsentValue,
			Expected: "c36s36_c55s53_c14s14",
		})
	}

	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh-r.pcap")
	report.recordComparison("ssh-r.pcap", "per-stream", conformanceComparison{Deviations: deviations})

	groups := report.deviationGroups()
	if len(groups) != 1 {
		t.Fatalf("the report holds %d deviation groups, and the fixture holds one", len(groups))
	}

	if groups[0].Count != 10 {
		t.Errorf("the group counts %d deviations, and the fixture holds 10", groups[0].Count)
	}

	if len(groups[0].Samples) != conformanceReportSampleLimit {
		t.Errorf("the group holds %d deviation rows, and the report bounds a group at %d",
			len(groups[0].Samples), conformanceReportSampleLimit)
	}

	// A reader must find the deviations the report leaves out.
	if !strings.Contains(report.render(), "conformance.log") {
		t.Error("the report does not name `conformance.log`, which holds every deviation")
	}
}

// A report that changes between two runs over one corpus fills every future diff with
// noise. A range over a map orders nothing, so the renderer sorts every table.
func TestTheReportRendersTheSameTextForTheSameRun(t *testing.T) {
	if first, second := oneConformanceReport().render(), oneConformanceReport().render(); first != second {
		t.Error("the report renders two different texts for one run")
	}
}

// The engine counts a match, and the report needs the key of each one to place it in a
// row.
func TestTheComparisonNamesEveryKeyThatMatches(t *testing.T) {
	key := oneConformanceKey("JA4")
	value := "t13d1715h2_5b57614c22b0_3d5424432f57"

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		nil,
	)

	if len(result.Matched) != 1 || result.Matched[0] != key {
		t.Fatalf("the comparison names %v as the keys that match, and the fixture holds %q", result.Matched, key)
	}
}

// #307 makes a stale register entry a fourth kind. The report names the key, the recorded
// value and the produced value, so a reader repairs the entry without a rerun.
func TestTheReportNamesEveryStaleRegisterEntry(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordComparison("ssh2.pcapng", "per-packet", conformanceComparison{
		Stale: []conformanceStaleEntry{{
			Key:      conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.1"},
			Recorded: "c36s36_c55s53_c14s14",
			Produced: "c36s36_c55s53_c13s14",
		}},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Stale register entries",
		"| Stale register entries | 1 |",
		"ssh2.pcapng/15/JA4SSH.1",
		"c36s36_c55s53_c14s14",
		"c36s36_c55s53_c13s14",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report collects a stale entry in the order the run reaches each capture, and it sorts
// the section by key. An unsorted section changes on a run that reads the captures in
// another order.
func TestTheReportSortsTheStaleRegisterEntriesByKey(t *testing.T) {
	report := newConformanceReport("27f0cbf")

	for _, capture := range []string{"tls12.pcap", "dhcp.pcapng"} {
		report.readCapture(capture)
		report.recordComparison(capture, "per-stream", conformanceComparison{
			Stale: []conformanceStaleEntry{{
				Key:      conformanceKey{Capture: capture, Stream: "1", Method: "JA4"},
				Recorded: "recorded-" + capture,
				Produced: "produced-" + capture,
			}},
		})
	}

	text := report.render()

	first := strings.Index(text, "`dhcp.pcapng/1/JA4`")
	second := strings.Index(text, "`tls12.pcap/1/JA4`")

	if first < 0 || second < 0 {
		t.Fatalf("the report holds %d stale rows, and the fixture holds 2", len(report.stale))
	}

	if first > second {
		t.Errorf("the report writes `tls12.pcap/1/JA4` before `dhcp.pcapng/1/JA4`, and the sorted order names `dhcp.pcapng` first")
	}
}

// A run that reaches every recorded value states that result. A section a reader finds
// empty says nothing about the register.
func TestTheReportStatesThatARunReportsNoStaleRegisterEntry(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Stale register entries | 0 |",
		"The run reports no stale register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// #328 makes an orphan register entry a fifth kind. The report names the key and the
// recorded value, so a reader repairs the entry without a rerun.
func TestTheReportNamesEveryOrphanRegisterEntry(t *testing.T) {
	orphan := conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.9"}

	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordOrphans(map[conformanceKey]deviationEntry{
		orphan: {Key: orphan.String(), Ours: "c36s36_c55s53_c14s14", Theirs: "c36s36_c55s53_c13s14", Ruling: "#19"},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Orphan register entries",
		"| Orphan register entries | 1 |",
		"ssh2.pcapng/15/JA4SSH.9",
		"c36s36_c55s53_c14s14",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report subtracts the keys of every comparison from the register. An entry whose key
// one comparison reaches is no orphan entry.
func TestTheReportNamesNoOrphanEntryForAKeyAComparisonReaches(t *testing.T) {
	reached := conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: "JA4_o.1"}

	report := oneConformanceReport()
	report.recordComparison("tls12.pcap", "per-stream", conformanceComparison{Reached: []conformanceKey{reached}})
	report.recordOrphans(map[conformanceKey]deviationEntry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	})

	text := report.render()

	for _, wanted := range []string{
		"| Orphan register entries | 0 |",
		"The run reports no orphan register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// A run that reaches every register key states that result. A section a reader finds empty
// says nothing about the register.
func TestTheReportStatesThatARunReportsNoOrphanRegisterEntry(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Orphan register entries | 0 |",
		"The run reports no orphan register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report is tracked, and FR-conformance-27 rewrites it on every run. This test reads
// the tracked file and proves its path and its shape. `TestConformance` fails the run when
// the write itself fails, and the two checks together hold FR-conformance-27.
func TestTheTrackedConformanceReportHoldsTheReportShape(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	content, err := os.ReadFile(conformanceReportPath)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceReportPath, err)
	}

	text := string(content)

	for _, wanted := range []string{"# FoxIO conformance report", "| Captures |", "## Results"} {
		if !strings.Contains(text, wanted) {
			t.Errorf("%s does not hold %q", conformanceReportPath, wanted)
		}
	}
}

// FR-conformance-33q names the count of uncovered values, and FR-conformance-33s states the
// count of each capture, each vector set and each method. A reader therefore reads the count
// of one method without a rerun.
func TestTheReportStatesTheUncoveredValueCountOfEachMethod(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("https-connect.pcap")
	report.recordComparison("https-connect.pcap", conformanceReportPacketSet, conformanceComparison{
		Uncovered: []conformanceUncoveredValue{
			{Key: conformanceKey{Capture: "https-connect.pcap", Stream: "3", Method: "JA4L.1"}, Produced: "45_64"},
			{
				Key:      conformanceKey{Capture: "https-connect.pcap", Stream: "5", Method: "JA4LS.1"},
				Produced: "13532_57",
				Accepted: true,
			},
		},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Uncovered values",
		"| Unaccepted uncovered values | 1 |",
		"| Accepted uncovered values | 1 |",
		"https-connect.pcap/3/JA4L.1",
		"https-connect.pcap/5/JA4LS.1",
		"45_64",
		"13532_57",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// FR-conformance-33t states the result of every run. A section a reader finds empty says
// nothing about the coverage of the corpus.
func TestTheReportStatesThatARunReportsNoUncoveredValue(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Unaccepted uncovered values | 0 |",
		"| Accepted uncovered values | 0 |",
		"The run reports no uncovered value.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// FR-conformance-33r counts an accepted uncovered value apart from an accepted deviation,
// because an uncovered value is neither a match nor a deviation. The register holds one entry
// for each accepted comparison, so the two counts add up to the register key count.
func TestTheReportCountsAnAcceptedUncoveredValueApartFromAnAcceptedDeviation(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("tls-handshake.pcapng")
	report.recordComparison("tls-handshake.pcapng", conformanceReportStreamSet, conformanceComparison{
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "tls-handshake.pcapng", Stream: "0", Method: "JA4S"},
			Kind:     conformanceChangedValue,
			Expected: "t120300_c030_4e8089b5d0f3",
			Produced: "t120300_c030_4e8089b5d0f4",
			Accepted: true,
		}},
		Uncovered: []conformanceUncoveredValue{{
			Key:      conformanceKey{Capture: "tls-handshake.pcapng", Stream: "0", Method: "JA4L-S"},
			Produced: "13532_57",
			Accepted: true,
		}},
	})

	text := report.render()

	for _, wanted := range []string{
		"| Accepted deviations | 1 |",
		"| Accepted uncovered values | 1 |",
		"| Accepted comparisons | 2 |",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// An uncovered value reaches no row of the result table. The vector file holds no value for
// the method, and FR-conformance-33 records `not applicable` for that cell.
func TestTheReportRecordsNotApplicableForAMethodThatReachesUncoveredValuesAlone(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("https-connect.pcap")
	report.recordComparison("https-connect.pcap", conformanceReportPacketSet, conformanceComparison{
		Uncovered: []conformanceUncoveredValue{
			{Key: conformanceKey{Capture: "https-connect.pcap", Stream: "3", Method: "JA4L.1"}, Produced: "45_64"},
		},
	})

	row := conformanceRowOf(t, report, "https-connect.pcap", "JA4L")

	if row.Result != conformanceReportNotApplicable {
		t.Errorf("the row records %q, and the vector file holds no value for the method", row.Result)
	}

	if row.Deviations != 0 {
		t.Errorf("the row counts %d deviations, and an uncovered value is no deviation", row.Deviations)
	}
}
