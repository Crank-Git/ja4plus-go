// Command mutationreport renders the JSON output of `gremlins` as a tracked report.
//
// `make mutate` runs it after the sweep. It reads the file that `gremlins unleash
// --output` writes, and it writes one markdown report under `docs/mutation_reports/`.
//
// Epic 15 (#89) owns the sweep, and #91 built this command.
// `docs/specs/features/15-mutation-sweep.md` holds FR-mutation-6 through FR-mutation-10.
//
// # Why a renderer exists at all
//
// The JSON of `gremlins` v0.6.0 answers FR-mutation-7 and it answers neither FR-mutation-9
// nor FR-mutation-10.
//
//   - It records no tool version and no date. `OutputResult` in
//     `internal/report/internal/structure.go` of `gremlins` v0.6.0 holds 9 fields, and no
//     one of them names either. FR-mutation-9 needs both, so this command adds them.
//   - It orders the `files` array from a Go map. `fileReport` in `internal/report/report.go`
//     ranges over `r.files`, so two runs over one tree write two orders. A tracked file that
//     reorders on every sweep produces a diff that states nothing, so this command sorts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// gremlinsResult is the subset of the `gremlins` JSON that the report reads.
//
// The field names come from `OutputResult` in `internal/report/internal/structure.go` of
// `gremlins` v0.6.0. Read at the pinned version in the module cache on 2026-08-14.
type gremlinsResult struct {
	GoModule          string         `json:"go_module"`
	Files             []gremlinsFile `json:"files"`
	TestEfficacy      float64        `json:"test_efficacy"`
	MutationsCoverage float64        `json:"mutations_coverage"`
	MutantsTotal      int            `json:"mutants_total"`
	ElapsedTime       float64        `json:"elapsed_time"`
}

type gremlinsFile struct {
	Filename  string             `json:"file_name"`
	Mutations []gremlinsMutation `json:"mutations"`
}

type gremlinsMutation struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// verdictOrder lists every status that `gremlins` v0.6.0 emits, in the order the report
// prints them.
//
// `Status.String` in `internal/mutator/mutator.go` of `gremlins` v0.6.0 returns exactly
// these seven strings. **FR-mutation-8 names five of them.** `RUNNABLE` is the dry-run
// verdict that `Engine.mutationStatus` sets, and `SKIPPED` marks a mutation outside a
// configured diff. Neither one reaches a full sweep of this repository, and the report
// carries a row for each so that a later `gremlins` release cannot drop a mutation into a
// verdict the report does not print.
var verdictOrder = []string{
	"KILLED",
	"LIVED",
	"NOT COVERED",
	"TIMED OUT",
	"NOT VIABLE",
	"SKIPPED",
	"RUNNABLE",
}

// reportInput carries every value the report states that the JSON does not hold.
type reportInput struct {
	result      gremlinsResult
	toolVersion string
	date        string
	packages    string
	excluded    string
}

func main() {
	input := flag.String("input", "", "the JSON file that `gremlins unleash --output` wrote")
	dir := flag.String("dir", "docs/mutation_reports", "the directory that receives the report")
	toolVersion := flag.String("tool-version", "", "the pinned `gremlins` version, for FR-mutation-9")
	packages := flag.String("packages", "", "the path argument that the sweep passed to `gremlins unleash`")
	excluded := flag.String("excluded", "", "the paths that `.gremlins.yaml` holds back from the sweep")
	date := flag.String("date", time.Now().UTC().Format(dateLayout), "the UTC calendar day of the sweep")
	flag.Parse()

	if err := run(*input, *dir, reportInput{
		toolVersion: *toolVersion,
		date:        *date,
		packages:    *packages,
		excluded:    *excluded,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "mutationreport: %v\n", err)
		os.Exit(1)
	}
}

// dateLayout is the UTC calendar day form that this repository writes everywhere.
const dateLayout = "2006-01-02"

// run reads the sweep output and writes one report. It returns the error of the first step
// that fails, and it writes no file after a failure.
func run(input, dir string, meta reportInput) error {
	if input == "" {
		return fmt.Errorf("no -input file")
	}
	raw, err := os.ReadFile(input) //nolint:gosec // The path comes from the Makefile.
	if err != nil {
		return fmt.Errorf("read %s: %w", input, err)
	}
	if meta.result, err = parse(raw); err != nil {
		return fmt.Errorf("read %s: %w", input, err)
	}

	path := filepath.Join(dir, reportName(meta.date, meta.packages))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(render(meta)), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Println(path)

	return nil
}

// parse returns the sweep result that one `gremlins` output file holds.
//
// It rejects a result that holds no file. `gremlins` prints `No results to report.` and
// writes no output file when it applies no mutation, so an empty `files` array names a
// sweep that measured nothing. A report of zero mutations reads as a clean sweep, which is
// the most expensive mistake this command can make.
func parse(raw []byte) (gremlinsResult, error) {
	var result gremlinsResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("parse the gremlins output: %w", err)
	}
	if len(result.Files) == 0 {
		return result, fmt.Errorf("the gremlins output holds no file, so the sweep applied no mutation")
	}

	return result, nil
}

// reportName returns the file name of one sweep: the UTC day, then the swept path.
//
// The day leads the name so that a plain sort of the directory reads as a history, and
// acceptance criterion 3 of the feature file can name "the most recent report".
func reportName(date, packages string) string {
	slug := strings.TrimPrefix(packages, "./")
	slug = strings.Trim(slug, "./")
	if slug == "" {
		slug = "all"
	}
	slug = strings.ReplaceAll(slug, "/", "-")

	return fmt.Sprintf("%s-%s.md", date, slug)
}

// mutationRow is one mutation of the report, with the file that holds it.
type mutationRow struct {
	file string
	gremlinsMutation
}

// rows returns every mutation of the result in one deterministic order.
//
// `gremlins` writes the `files` array from a Go map, so its order changes between two runs
// over one tree. This report is tracked in git under FR-mutation-10, so an unsorted report
// would produce a diff on every sweep that changes no verdict.
func rows(result gremlinsResult) []mutationRow {
	var out []mutationRow
	for _, file := range result.Files {
		for _, mutation := range file.Mutations {
			out = append(out, mutationRow{file: file.Filename, gremlinsMutation: mutation})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Column != out[j].Column {
			return out[i].Column < out[j].Column
		}

		return out[i].Type < out[j].Type
	})

	return out
}

// countVerdicts returns the count of each verdict, read from the mutation entries.
//
// **The top-level counts of the JSON do not answer this.** `fileReport` in
// `internal/report/report.go` of `gremlins` v0.6.0 sets
// `MutantsTotal: r.lived + r.killed + r.notViable`, so `mutants_total` excludes every
// `NOT COVERED` and every `TIMED OUT` mutation. The JSON carries no timed-out count and no
// skipped count at all. The `status` field of each mutation carries every verdict, so the
// report counts from there.
func countVerdicts(rows []mutationRow) map[string]int {
	counts := make(map[string]int, len(verdictOrder))
	for _, row := range rows {
		counts[row.Status]++
	}

	return counts
}

// render returns the whole report as markdown.
func render(meta reportInput) string {
	all := rows(meta.result)
	counts := countVerdicts(all)

	var b strings.Builder
	fmt.Fprintf(&b, "# Mutation report — %s — `%s`\n\n", meta.date, meta.packages)
	b.WriteString("<!-- This file is generated. `make mutate` writes it. Do not edit it by hand. -->\n\n")
	b.WriteString("**A mutation that survives names a test that runs a line and asserts nothing about it.**\n")
	b.WriteString("It is not always a defect. `docs/specs/features/15-mutation-sweep.md` holds the requirements,\n")
	b.WriteString("and FR-mutation-11 states that every `LIVED` mutation is settled.\n\n")

	fmt.Fprintf(&b, "## The run\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Tool | `gremlins` |\n")
	fmt.Fprintf(&b, "| Tool version | `%s` |\n", meta.toolVersion)
	fmt.Fprintf(&b, "| Date, UTC | %s |\n", meta.date)
	fmt.Fprintf(&b, "| Go module | `%s` |\n", meta.result.GoModule)
	fmt.Fprintf(&b, "| Swept path | `%s` |\n", meta.packages)
	fmt.Fprintf(&b, "| Paths the sweep excludes | %s |\n", meta.excluded)
	fmt.Fprintf(&b, "| Elapsed | %.0f s |\n", meta.result.ElapsedTime)
	fmt.Fprintf(&b, "| Test efficacy | %.2f%% |\n", meta.result.TestEfficacy)
	fmt.Fprintf(&b, "| Mutation coverage | %.2f%% |\n\n", meta.result.MutationsCoverage)

	b.WriteString("**The sweep reads the swept path alone.** `gremlins unleash <path>` reads the whole\n")
	b.WriteString("directory tree under the path, and it reads no package outside that tree. A package that\n")
	b.WriteString("the `Swept path` row does not cover holds no row of this report, and its tests are\n")
	b.WriteString("unmeasured rather than effective.\n\n")

	fmt.Fprintf(&b, "## The verdict counts\n\n")
	fmt.Fprintf(&b, "**LIVED: %d.** That count sizes the settlement work of FR-mutation-11.\n\n", counts["LIVED"])
	b.WriteString("| Verdict | Count | What it means |\n|---|---|---|\n")
	for _, verdict := range verdictOrder {
		fmt.Fprintf(&b, "| `%s` | %d | %s |\n", verdict, counts[verdict], verdictMeaning[verdict])
	}
	fmt.Fprintf(&b, "| **Total** | **%d** | Every mutation the tool applied. |\n\n", len(all))

	b.WriteString("**`mutants_total` of the JSON is not the total above.** `fileReport` in\n")
	b.WriteString("`internal/report/report.go` of `gremlins` v0.6.0 sets it to the killed, lived and\n")
	fmt.Fprintf(&b, "not-viable count alone, so it reports %d here. This report counts every mutation entry.\n\n",
		meta.result.MutantsTotal)

	fmt.Fprintf(&b, "## Every mutation\n\n")
	b.WriteString("| File | Line | Column | Mutation | Verdict |\n|---|---|---|---|---|\n")
	for _, row := range all {
		fmt.Fprintf(&b, "| `%s` | %d | %d | `%s` | `%s` |\n",
			row.file, row.Line, row.Column, row.Type, row.Status)
	}

	return b.String()
}

// verdictMeaning states what each verdict of `gremlins` v0.6.0 means.
//
// Each sentence reads `internal/mutator/mutator.go` and `internal/engine/` of `gremlins`
// v0.6.0, and none of them reads the tool's website.
var verdictMeaning = map[string]string{
	"KILLED":      "A test failed, so the suite catches the change. `go test` exited 1.",
	"LIVED":       "Every test passed, so no test asserts on the change. FR-mutation-11 settles it.",
	"NOT COVERED": "No test reaches the line, so the tool ran nothing.",
	"TIMED OUT":   "The suite did not finish, and FR-mutation-11 settles it like a `LIVED` mutation.",
	"NOT VIABLE":  "The mutated package did not compile. `go test` exited 2. No settlement is needed.",
	"SKIPPED":     "The mutation sits outside the configured diff. This repository configures none.",
	"RUNNABLE":    "A dry run identified the mutation and ran no test. `make mutate` performs no dry run.",
}
