package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// report returns one report text with the rows the caller names.
//
// The header holds the `Swept path` row that `internal/mutationreport` renders, so a case
// reads the same shape the tracked report holds.
func report(swept string, rows ...string) string {
	return "# Mutation report — 2026-08-14 — `" + swept + "`\n\n" +
		"## The run\n\n" +
		"| Field | Value |\n|---|---|\n" +
		"| Tool | `gremlins` |\n" +
		"| Swept path | `" + swept + "` |\n\n" +
		"## Every mutation\n\n" +
		"| File | Line | Column | Type | Verdict |\n|---|---|---|---|---|\n" +
		strings.Join(rows, "\n") + "\n"
}

// row returns one row of the `## Every mutation` table.
func row(file string, line, column int, kind, verdict string) string {
	return "| `" + file + "` | " + strconv.Itoa(line) + " | " + strconv.Itoa(column) + " | `" + kind + "` | `" + verdict + "` |"
}

// TestTheParserReadsEveryMutationRow holds the row format that `internal/mutationreport`
// renders. A verdict carries a space, and a parser that read one word would drop
// `NOT COVERED` and `TIMED OUT`.
func TestTheParserReadsEveryMutationRow(t *testing.T) {
	text := report("./internal/parser",
		row("internal/parser/http.go", 177, 12, "CONDITIONALS_BOUNDARY", "LIVED"),
		row("internal/parser/http.go", 177, 12, "CONDITIONALS_NEGATION", "KILLED"),
		row("internal/parser/quic.go", 52, 9, "ARITHMETIC_BASE", "NOT COVERED"),
		row("internal/parser/tls.go", 61, 3, "INVERT_NEGATIVES", "TIMED OUT"),
	)

	found, err := parseMutations(text)
	if err != nil {
		t.Fatalf("parse the report: %v", err)
	}

	if len(found) != 4 {
		t.Fatalf("the parser read %d row(s) of a report that holds 4", len(found))
	}

	if found[0].File != "internal/parser/http.go" || found[0].Line != 177 || found[0].Column != 12 {
		t.Errorf("the parser read the first row as %+v", found[0])
	}

	if found[2].Verdict != "NOT COVERED" {
		t.Errorf("the parser read a verdict of %q, and the row states NOT COVERED", found[2].Verdict)
	}

	if found[3].Verdict != "TIMED OUT" {
		t.Errorf("the parser read a verdict of %q, and the row states TIMED OUT", found[3].Verdict)
	}
}

// TestTheParserRejectsAReportThatHoldsNoRow holds the trap of the whole detector.
//
// `internal/mutationreport` owns the report format. A later change to that format would
// leave the pattern matching nothing, and a command that then reported zero new mutations
// would report success on every night.
func TestTheParserRejectsAReportThatHoldsNoRow(t *testing.T) {
	if _, err := parseMutations("# Mutation report\n\nNo table here.\n"); err == nil {
		t.Error("the parser accepted a report that holds no mutation row")
	}

	// A moved format is the case this guard exists for. The row below carries a sixth
	// column, which the pattern does not read.
	moved := "| `a.go` | 1 | 2 | `ARITHMETIC_BASE` | `LIVED` | extra |\n"
	if _, err := parseMutations(moved); err == nil {
		t.Error("the parser accepted a row of a format it does not read")
	}
}

// TestTheSweptPathReaderReadsTheRunTable holds the row that names the path of the baseline.
func TestTheSweptPathReaderReadsTheRunTable(t *testing.T) {
	found, err := sweptPath(report("./internal/parser", row("a.go", 1, 2, "ARITHMETIC_BASE", "LIVED")))
	if err != nil {
		t.Fatalf("read the swept path: %v", err)
	}

	if found != "./internal/parser" {
		t.Errorf("the reader read the swept path as %q", found)
	}

	if _, err := sweptPath("# Mutation report\n\nNo run table.\n"); err == nil {
		t.Error("the reader accepted a report that holds no Swept path row")
	}
}

// TestANewLivedMutationIsReported holds FR-mutation-18. A mutation that the baseline never
// held and that the sweep reports as `LIVED` needs a settlement.
func TestANewLivedMutationIsReported(t *testing.T) {
	baseline := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "LIVED"},
	}
	current := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "LIVED"},
		{File: "a.go", Line: 20, Column: 5, Type: "CONDITIONALS_BOUNDARY", Verdict: "LIVED"},
	}

	found := newUnsettled(baseline, current)
	if len(found) != 1 {
		t.Fatalf("the comparison found %d mutation(s), and one is new: %+v", len(found), found)
	}

	if found[0].Line != 20 {
		t.Errorf("the comparison named the mutation at line %d, and the new one sits at line 20", found[0].Line)
	}
}

// TestAMutationThatStopsBeingKilledIsReported holds the regression that FR-mutation-18
// exists to catch. A test that stops asserting on a line turns a `KILLED` mutation into a
// `LIVED` one, and the coordinates do not move.
func TestAMutationThatStopsBeingKilledIsReported(t *testing.T) {
	baseline := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "KILLED"},
	}
	current := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "LIVED"},
	}

	if found := newUnsettled(baseline, current); len(found) != 1 {
		t.Errorf("the comparison found %d mutation(s), and a killed mutation that now lives is new", len(found))
	}
}

// TestANewTimedOutMutationIsReported holds the edge case of
// `docs/specs/features/15-mutation-sweep.md`, which states
// `The verdict is `TIMED OUT`. It is settled like a `LIVED` mutation.`
//
// **This is the case that the `mutants_total` field of `gremlins` v0.6.0 hides.** #91
// measured it on 2026-08-14: `fileReport` at `internal/report/report.go:178` sums the
// lived, the killed and the not-viable mutations alone, so a detector built on that total
// counts no timed-out mutation at all.
func TestANewTimedOutMutationIsReported(t *testing.T) {
	baseline := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "KILLED"},
	}
	current := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "TIMED OUT"},
	}

	found := newUnsettled(baseline, current)
	if len(found) != 1 {
		t.Fatalf("the comparison found %d mutation(s), and a new TIMED OUT mutation needs a settlement", len(found))
	}

	if found[0].Verdict != "TIMED OUT" {
		t.Errorf("the comparison named a verdict of %q", found[0].Verdict)
	}
}

// TestANotCoveredMutationIsNoNewMutation holds the edge case that sends an uncovered line
// to the coverage floor rather than to a settlement. `.coverage-floor` guards that gap, and
// an issue for each uncovered line would repeat it.
func TestANotCoveredMutationIsNoNewMutation(t *testing.T) {
	current := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "NOT COVERED"},
		{File: "a.go", Line: 11, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "NOT VIABLE"},
	}

	if found := newUnsettled(nil, current); len(found) != 0 {
		t.Errorf("the comparison found %d mutation(s), and neither verdict needs a settlement: %+v", len(found), found)
	}
}

// TestAMutationTypeSeparatesTwoMutationsOfOneLine holds the fourth identity field. Two
// mutators reach one line and one column, and the report of 2026-08-14 holds many such
// pairs. A comparison that read three fields would hide one of the pair.
func TestAMutationTypeSeparatesTwoMutationsOfOneLine(t *testing.T) {
	baseline := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "CONDITIONALS_NEGATION", Verdict: "LIVED"},
	}
	current := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "CONDITIONALS_NEGATION", Verdict: "LIVED"},
		{File: "a.go", Line: 10, Column: 2, Type: "CONDITIONALS_BOUNDARY", Verdict: "LIVED"},
	}

	found := newUnsettled(baseline, current)
	if len(found) != 1 || found[0].Type != "CONDITIONALS_BOUNDARY" {
		t.Errorf("the comparison found %+v, and the boundary mutator is the new one", found)
	}
}

// TestAnEditAboveAMutationMakesItReadAsNew records the limit of the identity, and it does
// not repair it.
//
// The identity is the file, the line, the column and the mutator type. An inserted line
// moves the line number of every mutation below it, so the comparison reads a moved
// mutation as new.
//
// **The failure is one-sided.** The comparison over-reports and it never under-reports, so
// no real regression escapes. FR-mutation-19 keeps the sweep off the merge path, and
// `.github/workflows/mutation.yml` opens one issue for one run. So the cost of the limit is
// one issue that a reader closes.
func TestAnEditAboveAMutationMakesItReadAsNew(t *testing.T) {
	baseline := []mutation{
		{File: "a.go", Line: 10, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "LIVED"},
	}
	// One inserted line above the mutation moves it to line 11, and nothing else changed.
	current := []mutation{
		{File: "a.go", Line: 11, Column: 2, Type: "ARITHMETIC_BASE", Verdict: "LIVED"},
	}

	if found := newUnsettled(baseline, current); len(found) != 1 {
		t.Errorf("the comparison found %d mutation(s), and this case records that a line shift reads as one new mutation", len(found))
	}
}

// TestTheBaselineModeNamesTheLastReport holds the baseline rule. `reportName` of
// `internal/mutationreport` leads each name with the UTC calendar day, so a plain sort
// orders the reports by date.
func TestTheBaselineModeNamesTheLastReport(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "2026-08-01-internal-parser.md"), report("./internal/parser", row("a.go", 1, 2, "ARITHMETIC_BASE", "LIVED")))
	write(t, filepath.Join(dir, "2026-08-14-ja4db.md"), report("./ja4db", row("b.go", 3, 4, "ARITHMETIC_BASE", "LIVED")))

	output, err := run(dir, "", "", "")
	if err != nil {
		t.Fatalf("the baseline mode failed: %v", err)
	}

	if !strings.Contains(output, "swept-path=./ja4db\n") {
		t.Errorf("the baseline mode named no swept path of the last report:\n%s", output)
	}

	if !strings.Contains(output, "2026-08-14-ja4db.md") {
		t.Errorf("the baseline mode named the wrong report:\n%s", output)
	}
}

// TestTheBaselineModeRejectsAnEmptyDirectory holds the second trap. A run that compared
// against no baseline would report every mutation of the tree as new.
func TestTheBaselineModeRejectsAnEmptyDirectory(t *testing.T) {
	if _, err := run(t.TempDir(), "", "", ""); err == nil {
		t.Error("the baseline mode accepted a directory that holds no report")
	}
}

// TestTheCompareModeWritesTheIssueBody holds the body that FR-mutation-18 sends to
// `gh issue create`.
func TestTheCompareModeWritesTheIssueBody(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.md")
	current := filepath.Join(dir, "current.md")
	body := filepath.Join(dir, "body.md")

	write(t, baseline, report("./internal/parser", row("internal/parser/http.go", 177, 12, "CONDITIONALS_BOUNDARY", "LIVED")))
	write(t, current, report("./internal/parser",
		row("internal/parser/http.go", 177, 12, "CONDITIONALS_BOUNDARY", "LIVED"),
		row("internal/parser/quic.go", 52, 9, "ARITHMETIC_BASE", "LIVED"),
	))

	output, err := run(dir, baseline, current, body)
	if err != nil {
		t.Fatalf("the compare mode failed: %v", err)
	}

	if output != "new-lived=1\n" {
		t.Errorf("the compare mode printed %q, and one mutation is new", output)
	}

	text := read(t, body)
	if !strings.Contains(text, "`internal/parser/quic.go` | 52 | 9 | `ARITHMETIC_BASE` | `LIVED`") {
		t.Errorf("the body names no new mutation:\n%s", text)
	}

	if strings.Contains(text, "internal/parser/http.go") {
		t.Errorf("the body names a mutation that the baseline already settles:\n%s", text)
	}

	if !strings.Contains(text, "moves that mutation to a new line number") {
		t.Errorf("the body records no line-shift limit, and a reader would read every row as a regression:\n%s", text)
	}
}

// TestTheCompareModeWritesNoBodyWithoutANewMutation holds the quiet night. The workflow
// opens an issue only when the count is above zero, and a body written for a clean sweep
// would be a body nobody reads.
func TestTheCompareModeWritesNoBodyWithoutANewMutation(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.md")
	current := filepath.Join(dir, "current.md")
	body := filepath.Join(dir, "body.md")

	text := report("./internal/parser", row("internal/parser/http.go", 177, 12, "CONDITIONALS_BOUNDARY", "LIVED"))
	write(t, baseline, text)
	write(t, current, text)

	output, err := run(dir, baseline, current, body)
	if err != nil {
		t.Fatalf("the compare mode failed: %v", err)
	}

	if output != "new-lived=0\n" {
		t.Errorf("the compare mode printed %q, and no mutation is new", output)
	}

	if _, err := os.Stat(body); !os.IsNotExist(err) {
		t.Errorf("the compare mode wrote a body for a sweep that found nothing")
	}
}

// TestTheCompareModeRejectsAnAbsentBaseline holds the flag contract.
func TestTheCompareModeRejectsAnAbsentBaseline(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current.md")
	write(t, current, report("./internal/parser", row("a.go", 1, 2, "ARITHMETIC_BASE", "LIVED")))

	if _, err := run(dir, "", current, ""); err == nil {
		t.Error("the compare mode accepted no baseline report")
	}

	if _, err := run(dir, filepath.Join(dir, "absent.md"), current, ""); err == nil {
		t.Error("the compare mode accepted a baseline path that names no file")
	}
}

// TestTheCompareModeReadsTheTrackedReport holds the format against the file that #91
// committed. A case that read a report this file builds would pass after
// `internal/mutationreport` moved the format.
func TestTheCompareModeReadsTheTrackedReport(t *testing.T) {
	const tracked = "../../docs/mutation_reports/2026-08-14-internal-parser.md"

	text := read(t, tracked)

	found, err := parseMutations(text)
	if err != nil {
		t.Fatalf("parse the tracked report: %v", err)
	}

	// `CLAUDE.md` states the measurement of 2026-08-14: 882 mutations of `./internal/parser`.
	if len(found) != 882 {
		t.Errorf("the parser read %d row(s) of the tracked report, and the sweep of 2026-08-14 applied 882", len(found))
	}

	counts := map[string]int{}
	for _, m := range found {
		counts[m.Verdict]++
	}

	// **Each count below comes from the verdict of each mutation, and from no total.**
	for verdict, want := range map[string]int{
		"KILLED":      493,
		"LIVED":       223,
		"NOT COVERED": 162,
		"TIMED OUT":   4,
	} {
		if counts[verdict] != want {
			t.Errorf("the parser counted %d %s mutation(s) of the tracked report, and the sweep of 2026-08-14 reported %d", counts[verdict], verdict, want)
		}
	}

	// The tracked report is its own baseline, so it names nothing new.
	if unsettled := newUnsettled(found, found); len(unsettled) != 0 {
		t.Errorf("the tracked report names %d new mutation(s) against itself", len(unsettled))
	}

	swept, err := sweptPath(text)
	if err != nil {
		t.Fatalf("read the swept path of the tracked report: %v", err)
	}
	if swept != "./internal/parser" {
		t.Errorf("the tracked report names the swept path %q", swept)
	}
}

func write(t *testing.T, path, text string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(raw)
}
