//go:build conformance

package ja4plus

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// The report of the conformance suite. It holds FR-conformance-27 through
// FR-conformance-33.
//
// The renderer reads the comparisons that `compareConformance` returns and writes
// `docs/audit/conformance.md`. It reads no file and it decodes no packet, so a fixture
// proves every case without the corpus. `conformance_test.go` fills it from the corpus,
// and `conformance_report_check_test.go` holds the tests.
//
// # Why the report samples the deviations
//
// The report is tracked in git, so every row of it lands in each future diff. The corpus
// at the pinned commit reports 3431 deviations. The three SSH captures carry 1808 of them.
// A table of 3431 rows costs about 420 KB. It also hides the 159 deviations where the two
// values differ. 2025 rows where the library produces a value the vector does not hold
// stand in front of them.
//
// The report therefore holds the count of every group and at most
// `conformanceReportSampleLimit` rows of it. `conformance.log` holds every deviation. The
// `Run the conformance suite` step of `.github/workflows/ci.yml` writes that log. The
// `Upload the conformance log` step of that file uploads it. No measurement is lost.
//
// The renderer stays in the test build. `v1.0.0` freezes the exported API of the library,
// and a measurement of the library is no part of that API.

// conformanceReportPath names the report that FR-conformance-27 writes on every run.
const conformanceReportPath = "docs/audit/conformance.md"

// conformanceReportSampleLimit bounds the deviation rows that the report holds for one
// capture, one method and one vector set.
const conformanceReportSampleLimit = 3

// conformanceReportStreamSet and conformanceReportPacketSet name the two vector sets.
const (
	conformanceReportStreamSet = "per-stream"
	conformanceReportPacketSet = "per-packet"
)

// conformanceReportNotestReason states why the suite compares no value on a capture that
// FoxIO marks `notest`.
const conformanceReportNotestReason = "FoxIO marks the capture `notest`, so the suite compares no value on it."

// conformanceReportNoVectorReason states why the suite compares no value on a capture that
// no vector reaches.
const conformanceReportNoVectorReason = "No vector of the corpus holds a value for the capture."

// conformanceReportNoValueReason states why one method of one capture reaches no
// comparison.
const conformanceReportNoValueReason = "No vector of the corpus holds a value for the method on the capture."

// conformanceReportSharedFieldReason states why JA4D6 reaches no row of its own name.
//
// FoxIO writes both JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25
// makes the per-packet adapter authoritative for the two. The corpus therefore holds no
// value under a JA4D6 name, and `conformance_test.go` compares a JA4D6 value under the
// method JA4D.
const conformanceReportSharedFieldReason = "FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, " +
	"and FR-conformance-25 compares the two under JA4D."

// conformanceReportMethods names the eleven methods this project implements, in the order
// the report prints them. `docs/specs/spec.md` `## Terms` defines the word `method`, and
// the twelfth FoxIO method is JA4TScan, which `Non-goals` declines.
var conformanceReportMethods = []string{
	"JA4", "JA4S", "JA4H", "JA4X", "JA4SSH",
	"JA4L", "JA4LS", "JA4T", "JA4TS", "JA4D", "JA4D6",
}

// conformanceReportResult names one of the three results that FR-conformance-29 states.
type conformanceReportResult string

const (
	conformanceReportMatch         conformanceReportResult = "match"
	conformanceReportDeviation     conformanceReportResult = "deviation"
	conformanceReportNotApplicable conformanceReportResult = "not applicable"
)

// conformanceReportRow is one row of the result table. FR-conformance-28 holds one row for
// each capture and each method.
type conformanceReportRow struct {
	// Capture is the file name of the capture.
	Capture string
	// Method is one of the eleven methods this project implements.
	Method string
	// Set names the vector sets that hold a value for the row.
	Set string
	// Result is `match`, `deviation` or `not applicable`.
	Result conformanceReportResult
	// Matches counts the comparisons of the row that match.
	Matches int
	// Deviations counts the comparisons of the row that differ, accepted and unaccepted.
	Deviations int
	// Reason states why the row records `not applicable`. It is empty on every other row.
	Reason string
}

// conformanceReportGroup holds the deviations of one capture, one method and one vector
// set.
type conformanceReportGroup struct {
	// Capture, Method and Set name the group.
	Capture string
	Method  string
	Set     string
	// Count is the number of deviations of the group.
	Count int
	// Samples holds at most `conformanceReportSampleLimit` of them, sorted by key.
	Samples []conformanceDeviation
}

// conformanceReportCell names one capture and one method.
type conformanceReportCell struct {
	Capture string
	Method  string
}

// conformanceReportGroupKey names one capture, one method and one vector set.
type conformanceReportGroupKey struct {
	Capture string
	Method  string
	Set     string
}

// conformanceReportCount counts the comparisons of one capture and one method.
type conformanceReportCount struct {
	Matches    int
	Deviations int
	Accepted   int
	Sets       map[string]bool
}

// conformanceReportSetTotals counts the outcome of one vector set.
type conformanceReportSetTotals struct {
	Matches    int
	Deviations int
	Accepted   int
	Stale      int
}

// conformanceReport collects the outcome of one conformance run and renders it.
//
// The suite calls `readCapture` for each capture it reads, `recordComparison` for each
// comparison it makes, and `declineCapture` for each capture it compares nothing on.
type conformanceReport struct {
	// commit is the FoxIO commit that `make corpus` fetched.
	commit string
	// captures names every capture the suite read.
	captures []string
	// declined maps a capture to why the suite compares no value on it.
	declined map[string]string
	// counts maps a capture and a method to its comparison counts.
	counts map[conformanceReportCell]conformanceReportCount
	// groups maps a capture, a method and a vector set to its deviations.
	groups map[conformanceReportGroupKey]*conformanceReportGroup
	// sets counts the outcome of each vector set.
	sets map[string]conformanceReportSetTotals
	// stale holds every register entry the run no longer reaches, in the key order the
	// engine writes.
	stale []conformanceStaleEntry
	// reached names every register key that a comparison of the run reaches. #328 subtracts
	// it from the register.
	reached map[conformanceKey]bool
	// orphan holds every register entry that no comparison of the run reaches, sorted by
	// key. `recordOrphans` fills it.
	orphan []conformanceOrphanEntry
	// err holds the first method key the report could not place.
	err error
}

// newConformanceReport returns an empty report for the corpus at the commit.
func newConformanceReport(commit string) *conformanceReport {
	return &conformanceReport{
		commit:   commit,
		declined: make(map[string]string),
		counts:   make(map[conformanceReportCell]conformanceReportCount),
		groups:   make(map[conformanceReportGroupKey]*conformanceReportGroup),
		sets:     make(map[string]conformanceReportSetTotals),
		reached:  make(map[conformanceKey]bool),
	}
}

// readCapture records that the suite read the capture.
// FR-conformance-28 holds one row for each capture, so a capture the suite compares
// nothing on still reaches the table.
func (r *conformanceReport) readCapture(capture string) {
	if !slices.Contains(r.captures, capture) {
		r.captures = append(r.captures, capture)
	}
}

// declineCapture records that the suite compares no value on the capture, and why.
func (r *conformanceReport) declineCapture(capture, reason string) {
	r.readCapture(capture)
	r.declined[capture] = reason
}

// recordComparison adds one comparison of one capture and one vector set to the report.
//
// A method key that the report cannot place is a defect of the harness. It is never a
// deviation of the library. The report holds the first such key, and `Err` returns it. A
// caller then fails the run, rather than write a table that drops a comparison.
func (r *conformanceReport) recordComparison(capture, set string, comparison conformanceComparison) {
	r.readCapture(capture)

	setTotals := r.sets[set]

	for _, key := range comparison.Matched {
		method, err := conformanceReportMethodOf(key.Method)
		if err != nil {
			r.hold(err)

			continue
		}

		count := r.count(capture, method, set)
		count.Matches++
		r.counts[conformanceReportCell{Capture: capture, Method: method}] = count
		setTotals.Matches++
	}

	for _, deviation := range comparison.Deviations {
		method, err := conformanceReportMethodOf(deviation.Key.Method)
		if err != nil {
			r.hold(err)

			continue
		}

		count := r.count(capture, method, set)
		count.Deviations++

		if deviation.Accepted {
			count.Accepted++
			setTotals.Accepted++
		} else {
			setTotals.Deviations++
		}

		r.counts[conformanceReportCell{Capture: capture, Method: method}] = count
		r.addDeviation(capture, method, set, deviation)
	}

	// A stale entry names a register entry rather than a comparison, so it reaches no row
	// of the result table. #307 gives it a section of its own.
	r.stale = append(r.stale, comparison.Stale...)
	setTotals.Stale += len(comparison.Stale)

	// #328 collects the reached keys of every comparison. The report counts the orphan
	// entries on its own, and `conformance_test.go` compares the result with its own count.
	for _, key := range comparison.Reached {
		r.reached[key] = true
	}

	r.sets[set] = setTotals
}

// recordOrphans records every register entry that no comparison of the run reaches.
// It holds FR-conformance-33i.
//
// The caller calls it once, after the last comparison. A caller that calls it earlier
// reports an orphan entry for each comparison the run has not yet made.
func (r *conformanceReport) recordOrphans(register map[conformanceKey]deviationEntry) {
	r.orphan = conformanceOrphanEntries(register, r.reached)
}

// hold records the first error the report met.
func (r *conformanceReport) hold(err error) {
	if r.err == nil {
		r.err = err
	}
}

// Err returns the first method key the report could not place, and nil when it placed
// every key.
func (r *conformanceReport) Err() error {
	return r.err
}

// count returns the counts of one capture and one method, with the vector set recorded.
func (r *conformanceReport) count(capture, method, set string) conformanceReportCount {
	cell := conformanceReportCell{Capture: capture, Method: method}

	count, held := r.counts[cell]
	if !held {
		count.Sets = make(map[string]bool)
	}

	count.Sets[set] = true

	return count
}

// addDeviation adds one deviation to its group, and keeps at most the sample limit.
func (r *conformanceReport) addDeviation(capture, method, set string, deviation conformanceDeviation) {
	key := conformanceReportGroupKey{Capture: capture, Method: method, Set: set}

	group, held := r.groups[key]
	if !held {
		group = &conformanceReportGroup{Capture: capture, Method: method, Set: set}
		r.groups[key] = group
	}

	group.Count++

	if len(group.Samples) < conformanceReportSampleLimit {
		group.Samples = append(group.Samples, deviation)
	}
}

// conformanceReportMethodOf returns the method that one comparison key names.
//
// The key carries the vector key form, so it holds an occurrence number, a raw-form suffix,
// or the JA4L label the per-stream vector writes. A raw form is a form of its method, and
// never a method of its own, so `JA4H_ro.3` names the method JA4H.
//
// It returns an error for a key that names none of the eleven methods.
func conformanceReportMethodOf(key string) (string, error) {
	method, _, held := strings.Cut(key, ".")
	if !held {
		method = key
	}

	// The per-stream vector names the two JA4L methods `JA4L-C` and `JA4L-S`.
	// `conformance_adapters_test.go` reads the label from the library output form.
	switch method {
	case "JA4L-C":
		return "JA4L", nil
	case "JA4L-S":
		return "JA4LS", nil
	}

	// `_ro` ends with `_o`, so the longer suffix comes first.
	for _, suffix := range []string{"_ro", "_r", "_o"} {
		if base, cut := strings.CutSuffix(method, suffix); cut {
			method = base

			break
		}
	}

	if !slices.Contains(conformanceReportMethods, method) {
		return "", fmt.Errorf(
			"the comparison key %q names the method %q, and this project implements none of that name", key, method)
	}

	return method, nil
}

// rows returns one row for each capture and each method, sorted by capture and then by the
// order of `conformanceReportMethods`. It holds FR-conformance-28, FR-conformance-29 and
// FR-conformance-33.
func (r *conformanceReport) rows() []conformanceReportRow {
	captures := slices.Clone(r.captures)
	slices.Sort(captures)

	rows := make([]conformanceReportRow, 0, len(captures)*len(conformanceReportMethods))

	for _, capture := range captures {
		for _, method := range conformanceReportMethods {
			rows = append(rows, r.row(capture, method))
		}
	}

	return rows
}

// row returns the row of one capture and one method.
//
// A deviation outranks a match, because a row that reads `match` while a deviation stands
// hides the deviation. FR-conformance-33 records `not applicable` only where no vector
// holds a value, so a row reaches that result only where the suite compared nothing.
func (r *conformanceReport) row(capture, method string) conformanceReportRow {
	count := r.counts[conformanceReportCell{Capture: capture, Method: method}]

	row := conformanceReportRow{
		Capture:    capture,
		Method:     method,
		Set:        "—",
		Result:     conformanceReportNotApplicable,
		Matches:    count.Matches,
		Deviations: count.Deviations,
	}

	switch {
	case count.Deviations > 0:
		row.Result = conformanceReportDeviation
	case count.Matches > 0:
		row.Result = conformanceReportMatch
	case r.declined[capture] != "":
		row.Reason = r.declined[capture]
	case method == "JA4D6":
		row.Reason = conformanceReportSharedFieldReason
	default:
		row.Reason = conformanceReportNoValueReason
	}

	if len(count.Sets) > 0 {
		sets := make([]string, 0, len(count.Sets))
		for set := range count.Sets {
			sets = append(sets, set)
		}

		slices.Sort(sets)
		row.Set = strings.Join(sets, " and ")
	}

	return row
}

// deviationGroups returns every deviation group, sorted by capture, then vector set, then
// method.
func (r *conformanceReport) deviationGroups() []conformanceReportGroup {
	groups := make([]conformanceReportGroup, 0, len(r.groups))
	for _, group := range r.groups {
		groups = append(groups, *group)
	}

	slices.SortFunc(groups, func(first, second conformanceReportGroup) int {
		return strings.Compare(
			first.Capture+"\x00"+first.Set+"\x00"+first.Method,
			second.Capture+"\x00"+second.Set+"\x00"+second.Method,
		)
	})

	return groups
}

// conformanceReportCounts counts the whole run.
type conformanceReportCounts struct {
	Captures      int
	Compared      int
	NotApplicable int
	Matches       int
	Deviations    int
	Accepted      int
	Stale         int
	Orphan        int
}

// totals counts the whole run from the comparisons the report holds.
//
// The report counts the run on its own, and `conformance_test.go` compares the result with
// `conformanceRunTotals`. Two counts that must agree catch a renderer that drops a
// comparison, which one count cannot.
func (r *conformanceReport) totals() conformanceReportCounts {
	totals := conformanceReportCounts{Captures: len(r.captures), Orphan: len(r.orphan)}

	for _, set := range r.sets {
		totals.Matches += set.Matches
		totals.Deviations += set.Deviations
		totals.Accepted += set.Accepted
		totals.Stale += set.Stale
	}

	compared := make(map[string]bool, len(r.captures))
	for cell := range r.counts {
		compared[cell.Capture] = true
	}

	totals.Compared = len(compared)
	totals.NotApplicable = totals.Captures - totals.Compared

	return totals
}

// render returns the whole report as Markdown.
//
// Every table is sorted, so two runs over one corpus render one text. An unsorted table
// changes on every run and fills each future diff with noise.
func (r *conformanceReport) render() string {
	var out strings.Builder

	r.renderHead(&out)
	r.renderSummary(&out)
	r.renderDeviations(&out)
	r.renderStale(&out)
	r.renderOrphans(&out)
	r.renderResults(&out)

	return out.String()
}

// renderHead writes the title and the commit. It holds FR-conformance-30.
func (r *conformanceReport) renderHead(out *strings.Builder) {
	out.WriteString("# FoxIO conformance report\n\n")
	out.WriteString("`make conformance` writes this file on every run. Never edit it by hand.\n\n")
	fmt.Fprintf(out, "The corpus holds the FoxIO commit `%s`.\n\n", r.commit)
	out.WriteString("`docs/specs/features/04-conformance-harness.md` states the requirements this report holds.\n\n")
}

// renderSummary writes the counts. It holds FR-conformance-31.
func (r *conformanceReport) renderSummary(out *strings.Builder) {
	totals := r.totals()

	out.WriteString("## Summary\n\n")
	out.WriteString("| Measure | Count |\n|---|---|\n")
	fmt.Fprintf(out, "| Captures | %d |\n", totals.Captures)
	fmt.Fprintf(out, "| Matches | %d |\n", totals.Matches)
	fmt.Fprintf(out, "| Deviations | %d |\n", totals.Deviations)
	fmt.Fprintf(out, "| Accepted deviations | %d |\n", totals.Accepted)
	fmt.Fprintf(out, "| Stale register entries | %d |\n", totals.Stale)
	fmt.Fprintf(out, "| Orphan register entries | %d |\n", totals.Orphan)
	fmt.Fprintf(out, "| Captures the suite compared | %d |\n", totals.Compared)
	fmt.Fprintf(out, "| Captures the suite compared nothing on | %d |\n\n", totals.NotApplicable)

	out.WriteString("The two vector sets cover different methods, so the report counts each one on its own.\n\n")
	out.WriteString("| Vector set | Matches | Deviations | Accepted deviations |\n|---|---|---|---|\n")

	for _, set := range []string{conformanceReportStreamSet, conformanceReportPacketSet} {
		counts := r.sets[set]
		fmt.Fprintf(out, "| %s | %d | %d | %d |\n", set, counts.Matches, counts.Deviations, counts.Accepted)
	}

	out.WriteString("\nAn accepted deviation is an entry of `testdata/deviations.json`, which records a ruling.\n\n")
}

// renderDeviations writes the deviation table. It holds FR-conformance-32.
func (r *conformanceReport) renderDeviations(out *strings.Builder) {
	groups := r.deviationGroups()

	out.WriteString("## Deviations\n\n")

	if len(groups) == 0 {
		out.WriteString("The run reports no deviation.\n\n")

		return
	}

	fmt.Fprintf(out, "The run reports %d deviations in %d groups. One group is one capture, one method and one "+
		"vector set.\n\n", r.totals().Deviations+r.totals().Accepted, len(groups))
	fmt.Fprintf(out, "This file is tracked in git, so the table holds at most %d deviations of each group. "+
		"The `Deviations` column counts the whole group.\n", conformanceReportSampleLimit)
	out.WriteString("`conformance.log` holds every deviation, `make conformance` writes it in CI, and the " +
		"conformance job uploads it as an artifact.\n\n")

	out.WriteString("| Capture | Vector set | Method | Deviations | Comparison | Difference | Expected | Produced |\n")
	out.WriteString("|---|---|---|---|---|---|---|---|\n")

	for _, group := range groups {
		for _, deviation := range group.Samples {
			accepted := ""
			if deviation.Accepted {
				accepted = " (accepted)"
			}

			fmt.Fprintf(out, "| `%s` | %s | %s | %d | `%s` | %s%s | %s | %s |\n",
				group.Capture, group.Set, group.Method, group.Count, deviation.Key,
				deviation.Kind, accepted,
				conformanceReportValue(deviation.Expected), conformanceReportValue(deviation.Produced))
		}
	}

	out.WriteString("\n")
}

// renderStale writes the stale register entries. It holds #307.
//
// The section states the result of every run, and never of a failed run alone. A reader who
// finds no section cannot tell a healthy register from a renderer that dropped one.
func (r *conformanceReport) renderStale(out *strings.Builder) {
	out.WriteString("## Stale register entries\n\n")
	out.WriteString("An entry of `testdata/deviations.json` records the value this library produced when the " +
		"maintainer ruled. A later change moves that value, and the entry then accepts a comparison it does not " +
		"describe.\n\n")

	if len(r.stale) == 0 {
		out.WriteString("The run reports no stale register entry.\n\n")

		return
	}

	entries := slices.Clone(r.stale)
	slices.SortStableFunc(entries, func(first, second conformanceStaleEntry) int {
		return strings.Compare(first.Key.String(), second.Key.String())
	})

	out.WriteString("| Comparison | Recorded | Produced |\n|---|---|---|\n")

	for _, entry := range entries {
		fmt.Fprintf(out, "| `%s` | %s | %s |\n",
			entry.Key, conformanceReportValue(entry.Recorded), conformanceReportValue(entry.Produced))
	}

	out.WriteString("\n")
}

// renderOrphans writes the orphan register entries. It holds FR-conformance-33m,
// FR-conformance-33n and FR-conformance-33o, and #328 states the defect it reports.
//
// The section states the result of every run, and never of a failed run alone. A reader who
// finds no section cannot tell a healthy register from a renderer that dropped one.
//
// The row holds no produced value. No comparison of the run reaches the key, so the run
// produces nothing to print.
func (r *conformanceReport) renderOrphans(out *strings.Builder) {
	out.WriteString("## Orphan register entries\n\n")
	out.WriteString("An entry of `testdata/deviations.json` names one comparison. No comparison of the run reaches " +
		"the key of an entry below, so the entry accepts a difference the run never measures.\n\n")

	if len(r.orphan) == 0 {
		out.WriteString("The run reports no orphan register entry.\n\n")

		return
	}

	out.WriteString("| Comparison | Recorded |\n|---|---|\n")

	for _, entry := range r.orphan {
		fmt.Fprintf(out, "| `%s` | %s |\n", entry.Key, conformanceReportValue(entry.Recorded))
	}

	out.WriteString("\n")
}

// renderResults writes the result table. It holds FR-conformance-28, FR-conformance-29 and
// FR-conformance-33.
func (r *conformanceReport) renderResults(out *strings.Builder) {
	out.WriteString("## Results\n\n")
	out.WriteString("The table holds one row for each capture and each method. A row records `not applicable` " +
		"only where no vector of the corpus holds a value for that method on that capture.\n\n")
	out.WriteString("| Capture | Method | Vector set | Result | Matches | Deviations | Reason |\n")
	out.WriteString("|---|---|---|---|---|---|---|\n")

	for _, row := range r.rows() {
		reason := row.Reason
		if reason == "" {
			reason = "—"
		}

		fmt.Fprintf(out, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			row.Capture, row.Method, row.Set, row.Result,
			strconv.Itoa(row.Matches), strconv.Itoa(row.Deviations), reason)
	}
}

// conformanceReportValue returns one fingerprint value as a table cell.
//
// An extra value holds no expected value, and an absent value holds no produced value.
// FR-conformance-16 compares as an exact string match, so the cell reproduces the value
// without a change. A code span holds it, so a reader never reads it as Markdown.
func conformanceReportValue(value string) string {
	if value == "" {
		return "(none)"
	}

	return "`" + value + "`"
}

// conformanceWriteReport writes the report to `docs/audit/conformance.md`.
// It holds FR-conformance-27.
func conformanceWriteReport(report *conformanceReport) error {
	if err := report.Err(); err != nil {
		return err
	}

	// The report is tracked in git and a reader opens it, so it carries the file mode of a
	// tracked document.
	if err := os.WriteFile(conformanceReportPath, []byte(report.render()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", conformanceReportPath, err)
	}

	return nil
}
