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
