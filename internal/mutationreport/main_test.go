package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleJSON is the shape that `gremlins unleash --output` writes.
//
// The field names come from `OutputResult`, `OutputFile` and `Mutation` in
// `internal/report/internal/structure.go` of `gremlins` v0.6.0. The two files sit in the
// order that reverses the sorted order, so a test can prove the sort.
const sampleJSON = `{
  "go_module": "github.com/Crank-Git/ja4plus-go",
  "files": [
    {"file_name": "internal/parser/tls.go", "mutations": [
      {"type": "CONDITIONALS_BOUNDARY", "status": "LIVED", "line": 40, "column": 3},
      {"type": "ARITHMETIC_BASE", "status": "TIMED OUT", "line": 12, "column": 9}
    ]},
    {"file_name": "internal/dbcache/cache.go", "mutations": [
      {"type": "INVERT_NEGATIVES", "status": "KILLED", "line": 7, "column": 2},
      {"type": "INVERT_LOGICAL", "status": "NOT COVERED", "line": 7, "column": 1},
      {"type": "INCREMENT_DECREMENT", "status": "NOT VIABLE", "line": 99, "column": 4}
    ]}
  ],
  "test_efficacy": 50.0,
  "mutations_coverage": 66.67,
  "mutants_total": 3,
  "mutants_killed": 1,
  "mutants_lived": 1,
  "mutants_not_viable": 1,
  "mutants_not_covered": 1,
  "elapsed_time": 167.4,
  "mutator_statistics": {"invert_negatives": 1}
}`

// sampleInput returns the parsed sample with the metadata that the Makefile supplies.
func sampleInput(t *testing.T) reportInput {
	t.Helper()
	result, err := parse([]byte(sampleJSON))
	if err != nil {
		t.Fatalf("parse the sample: %v", err)
	}

	return reportInput{
		result:      result,
		toolVersion: "v0.6.0",
		date:        "2026-08-14",
		packages:    "./internal/parser",
		excluded:    "`cmd/` and `examples/`",
	}
}

// TestTheReportNamesEveryMutationWithItsFileLineAndVerdict holds FR-mutation-7.
func TestTheReportNamesEveryMutationWithItsFileLineAndVerdict(t *testing.T) {
	report := render(sampleInput(t))

	for _, row := range []string{
		"| `internal/dbcache/cache.go` | 7 | 1 | `INVERT_LOGICAL` | `NOT COVERED` |",
		"| `internal/dbcache/cache.go` | 7 | 2 | `INVERT_NEGATIVES` | `KILLED` |",
		"| `internal/dbcache/cache.go` | 99 | 4 | `INCREMENT_DECREMENT` | `NOT VIABLE` |",
		"| `internal/parser/tls.go` | 12 | 9 | `ARITHMETIC_BASE` | `TIMED OUT` |",
		"| `internal/parser/tls.go` | 40 | 3 | `CONDITIONALS_BOUNDARY` | `LIVED` |",
	} {
		if !strings.Contains(report, row) {
			t.Errorf("the report holds no row for %q", row)
		}
	}
}

// TestTheReportRecordsTheToolVersionAndTheDate holds FR-mutation-9.
func TestTheReportRecordsTheToolVersionAndTheDate(t *testing.T) {
	report := render(sampleInput(t))

	if !strings.Contains(report, "| Tool version | `v0.6.0` |") {
		t.Error("the report records no tool version, and the JSON of gremlins holds none")
	}
	if !strings.Contains(report, "| Date, UTC | 2026-08-14 |") {
		t.Error("the report records no date, and the JSON of gremlins holds none")
	}
}

// TestTheReportPrintsEveryVerdictThatTheToolEmits holds FR-mutation-8.
//
// FR-mutation-8 names five verdicts. `Status.String` in `internal/mutator/mutator.go` of
// `gremlins` v0.6.0 returns seven strings, and this test holds all seven. A verdict with no
// row would drop a mutation from the counts without a failure.
func TestTheReportPrintsEveryVerdictThatTheToolEmits(t *testing.T) {
	report := render(sampleInput(t))

	for _, verdict := range []string{
		"KILLED", "LIVED", "NOT COVERED", "TIMED OUT", "NOT VIABLE", "SKIPPED", "RUNNABLE",
	} {
		if !strings.Contains(report, "| `"+verdict+"` |") {
			t.Errorf("the verdict table holds no row for %s", verdict)
		}
	}
}

// TestTheReportCountsEveryVerdictFromTheMutationEntries holds the reading that the
// top-level counts of the JSON answer a different question.
//
// `fileReport` in `internal/report/report.go` of `gremlins` v0.6.0 sets
// `MutantsTotal: r.lived + r.killed + r.notViable`. The sample states `"mutants_total": 3`
// and it holds 5 mutations, so a report that read the top-level field would lose two.
func TestTheReportCountsEveryVerdictFromTheMutationEntries(t *testing.T) {
	report := render(sampleInput(t))

	for _, row := range []string{
		"| `KILLED` | 1 |",
		"| `LIVED` | 1 |",
		"| `NOT COVERED` | 1 |",
		"| `TIMED OUT` | 1 |",
		"| `NOT VIABLE` | 1 |",
		"| `SKIPPED` | 0 |",
		"| `RUNNABLE` | 0 |",
		"| **Total** | **5** |",
	} {
		if !strings.Contains(report, row) {
			t.Errorf("the verdict counts hold no %q", row)
		}
	}
}

// TestTheReportStatesTheLivedCountBeforeTheTable holds the plan of #91: the `LIVED` count
// sizes the settlement work of FR-mutation-11, so a reader must reach it without a search.
func TestTheReportStatesTheLivedCountBeforeTheTable(t *testing.T) {
	report := render(sampleInput(t))

	statement := strings.Index(report, "**LIVED: 1.**")
	if statement < 0 {
		t.Fatal("the report states no LIVED count in bold")
	}
	if table := strings.Index(report, "## Every mutation"); table < statement {
		t.Error("the LIVED count sits after the mutation table, so a reader must search for it")
	}
}

// TestTheReportSortsEveryMutation holds FR-mutation-10.
//
// `fileReport` in `internal/report/report.go` of `gremlins` v0.6.0 ranges over a Go map, so
// two runs over one tree write two orders. A tracked file that reorders on every sweep
// produces a diff that states no change of verdict.
func TestTheReportSortsEveryMutation(t *testing.T) {
	ordered := rows(sampleInput(t).result)

	want := []string{
		"internal/dbcache/cache.go:7:1",
		"internal/dbcache/cache.go:7:2",
		"internal/dbcache/cache.go:99:4",
		"internal/parser/tls.go:12:9",
		"internal/parser/tls.go:40:3",
	}
	if len(ordered) != len(want) {
		t.Fatalf("the sort returned %d rows, and the sample holds %d", len(ordered), len(want))
	}
	for index, row := range ordered {
		got := fmt.Sprintf("%s:%d:%d", row.file, row.Line, row.Column)
		if got != want[index] {
			t.Errorf("row %d is %s, and the sorted order states %s", index, got, want[index])
		}
	}
}

// TestTheReportNamesTheSweptPathAndTheExclusions holds the edge case of the feature file:
// the report records which packages the sweep read and which it did not.
func TestTheReportNamesTheSweptPathAndTheExclusions(t *testing.T) {
	report := render(sampleInput(t))

	if !strings.Contains(report, "| Swept path | `./internal/parser` |") {
		t.Error("the report names no swept path, so a reader cannot tell what it measures")
	}
	if !strings.Contains(report, "| Paths the sweep excludes | `cmd/` and `examples/` |") {
		t.Error("the report names no excluded path")
	}
	if !strings.Contains(report, "unmeasured rather than effective") {
		t.Error("the report does not state that an unswept package is unmeasured")
	}
}

// TestTheReportNameLeadsWithTheDate holds the file naming of `docs/mutation_reports/`.
func TestTheReportNameLeadsWithTheDate(t *testing.T) {
	for _, test := range []struct{ packages, want string }{
		{"./internal/parser", "2026-08-14-internal-parser.md"},
		{".", "2026-08-14-all.md"},
		{"./ja4db", "2026-08-14-ja4db.md"},
	} {
		if got := reportName("2026-08-14", test.packages); got != test.want {
			t.Errorf("reportName for %q returned %q, and the naming states %q", test.packages, got, test.want)
		}
	}
}

// TestTheCommandWritesOneReportAndPrintsItsPath holds FR-mutation-6.
func TestTheCommandWritesOneReportAndPrintsItsPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sweep.json")
	if err := os.WriteFile(input, []byte(sampleJSON), 0o600); err != nil {
		t.Fatalf("write the sample: %v", err)
	}

	out := filepath.Join(dir, "mutation_reports")
	err := run(input, out, reportInput{
		toolVersion: "v0.6.0", date: "2026-08-14", packages: "./internal/parser", excluded: "`cmd/`",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	written, err := os.ReadFile(filepath.Join(out, "2026-08-14-internal-parser.md"))
	if err != nil {
		t.Fatalf("the command wrote no report: %v", err)
	}
	if !strings.Contains(string(written), "# Mutation report — 2026-08-14 — `./internal/parser`") {
		t.Error("the written report holds no title")
	}
}

// TestTheCommandFailsOnAnEmptySweep holds the case that costs the most to miss: a report
// that states zero mutations reads as a clean sweep.
func TestTheCommandFailsOnAnEmptySweep(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(input, []byte(`{"go_module":"m","files":[]}`), 0o600); err != nil {
		t.Fatalf("write the sample: %v", err)
	}

	if err := run(input, dir, reportInput{}); err == nil {
		t.Error("the command accepted a sweep that applied no mutation")
	}
}

// TestTheCommandFailsOnAnAbsentInput holds the two early exits of run.
func TestTheCommandFailsOnAnAbsentInput(t *testing.T) {
	if err := run("", t.TempDir(), reportInput{}); err == nil {
		t.Error("the command accepted an empty -input")
	}
	if err := run(filepath.Join(t.TempDir(), "absent.json"), t.TempDir(), reportInput{}); err == nil {
		t.Error("the command accepted an absent -input file")
	}
}

// TestTheCommandFailsOnMalformedJSON holds the parse step.
func TestTheCommandFailsOnMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(input, []byte("{"), 0o600); err != nil {
		t.Fatalf("write the sample: %v", err)
	}

	if err := run(input, dir, reportInput{}); err == nil {
		t.Error("the command accepted a malformed sweep output")
	}
}
