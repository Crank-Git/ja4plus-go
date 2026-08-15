// Command mutationdiff compares two mutation reports and names every new unsettled mutation.
//
// `.github/workflows/mutation.yml` runs it on a schedule. Epic 15 (#89) owns the sweep, and
// #93 built this command. `docs/specs/features/15-mutation-sweep.md` holds FR-mutation-17
// through FR-mutation-20.
//
// # The one defect this command exists to avoid
//
// **This command counts a verdict from the verdict of each mutation, and never from a
// total.** #91 measured the reason on 2026-08-14. `fileReport` at
// `internal/report/report.go:178` of `gremlins` v0.6.0 sets `mutants_total` to the sum of
// the lived, the killed and the not-viable mutations alone. It reported 716 where the
// swept path holds 882. **A detector that reads a total therefore misses every `TIMED OUT`
// mutation and every `NOT COVERED` mutation**, and a new `TIMED OUT` mutation would open no
// issue.
//
// So this command reads the per-mutation rows of a report, and it reads no count row.
//
// # Two modes, and one baseline rule
//
// The workflow needs the swept path of the baseline before it sweeps, and it needs the
// comparison after. Each mode prints `key=value` lines, which a step appends to
// `$GITHUB_OUTPUT`.
//
//	mutationdiff -dir docs/mutation_reports
//	  baseline=docs/mutation_reports/2026-08-14-internal-parser.md
//	  swept-path=./internal/parser
//
//	mutationdiff -baseline <report> -current <report> -body <path>
//	  new-lived=3
//
// **The current sweep reads the swept path of the baseline, and never a path this file
// names.** A sweep of a wider path would report every mutation of every package the
// baseline never measured as new.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	dir := flag.String("dir", "docs/mutation_reports", "the directory that holds the tracked reports")
	baseline := flag.String("baseline", "", "the tracked report of the last sweep")
	current := flag.String("current", "", "the report that the scheduled sweep wrote")
	body := flag.String("body", "", "the file that receives the issue body")
	flag.Parse()

	output, err := run(*dir, *baseline, *current, *body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutationdiff: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(output)
}

// run performs one mode and returns the `key=value` lines that the mode prints.
//
// It selects the baseline mode when the caller names no current report. It returns an error
// for every failure, and it writes the body file only when the comparison finds a mutation.
func run(dir, baseline, current, body string) (string, error) {
	if current == "" {
		return baselineMode(dir)
	}
	if baseline == "" {
		return "", fmt.Errorf("no -baseline report")
	}

	return compareMode(baseline, current, body)
}

// baselineMode names the tracked report of the last sweep and the path that sweep read.
func baselineMode(dir string) (string, error) {
	path, err := latestReport(dir)
	if err != nil {
		return "", err
	}
	text, err := readReport(path)
	if err != nil {
		return "", err
	}
	swept, err := sweptPath(text)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	return fmt.Sprintf("baseline=%s\nswept-path=%s\n", filepath.ToSlash(path), swept), nil
}

// compareMode names every mutation of the current report that the baseline does not settle.
func compareMode(baseline, current, body string) (string, error) {
	baselineText, err := readReport(baseline)
	if err != nil {
		return "", err
	}
	currentText, err := readReport(current)
	if err != nil {
		return "", err
	}

	baselineMutations, err := parseMutations(baselineText)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", baseline, err)
	}
	currentMutations, err := parseMutations(currentText)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", current, err)
	}

	found := newUnsettled(baselineMutations, currentMutations)

	if body != "" && len(found) > 0 {
		swept, err := sweptPath(currentText)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", current, err)
		}
		text := renderBody(filepath.ToSlash(baseline), swept, found)
		if err := os.WriteFile(body, []byte(text), 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", body, err)
		}
	}

	return fmt.Sprintf("new-lived=%d\n", len(found)), nil
}

// mutation is one row of the `## Every mutation` table of a report.
//
// The four identity fields are the file, the line, the column and the mutator type. The
// report table holds each one, and `## How a mutation is identified` of the doc comment of
// newUnsettled states what that identity does not survive.
type mutation struct {
	File    string
	Line    int
	Column  int
	Type    string
	Verdict string
}

// key returns the identity of one mutation across two reports.
func (m mutation) key() mutation {
	m.Verdict = ""

	return m
}

// unsettledVerdicts names each verdict that FR-mutation-11 reads.
//
// **FR-mutation-11 settles a `LIVED` mutation on code that can move a fingerprint value,
// and it counts every other one.** The maintainer ruled that boundary on 2026-08-14, and
// #634 carries the amendment. **A report states no fingerprint risk**, so this map keeps
// both verdicts and a person applies the boundary to each row the comparison reports.
//
// **FR-mutation-18 names `LIVED`, and the edge-case table of
// `docs/specs/features/15-mutation-sweep.md` adds `TIMED OUT`.** That table states it
// verbatim: `The verdict is `TIMED OUT`. It is settled like a `LIVED` mutation.` So a
// detector that reads `LIVED` alone leaves a mutation that needs a settlement unreported.
//
// `NOT COVERED` is not here. The same table sends that gap to the coverage floor of
// `docs/specs/features/07-supply-chain.md`, and `.coverage-floor` already guards it.
var unsettledVerdicts = map[string]bool{
	"LIVED":     true,
	"TIMED OUT": true,
}

// newUnsettled returns every mutation of the current report that needs a settlement and
// that the baseline does not already carry with the same need.
//
// A mutation that the baseline reports as `KILLED` and the current report reports as
// `LIVED` is new, because a test stopped asserting on the line. A mutation that the
// baseline never held is new too.
//
// # How a mutation is identified
//
// The identity is the file, the line, the column and the mutator type. The report table
// holds those four, and it holds nothing else that separates two mutations of one line.
//
// **That identity does not survive an unrelated edit above the mutation.** An inserted line
// moves every line number below it, so every mutation below such an edit reads as new.
//
// **The failure is one-sided, and that is why this project accepts it.** A line shift makes
// this command over-report, and it never makes it under-report: a real new `LIVED` mutation
// carries coordinates the baseline cannot hold, whichever way the file moved. FR-mutation-19
// keeps the sweep off the merge path, so an over-report costs a reader one issue and it
// blocks nothing.
//
// `.github/workflows/mutation.yml` bounds that cost. It opens one issue for one run and it
// dedupes by title, so a shifted file produces one issue and never one for each mutation.
func newUnsettled(baseline, current []mutation) []mutation {
	settled := make(map[mutation]bool, len(baseline))
	for _, m := range baseline {
		if unsettledVerdicts[m.Verdict] {
			settled[m.key()] = true
		}
	}

	found := []mutation{}
	for _, m := range current {
		if unsettledVerdicts[m.Verdict] && !settled[m.key()] {
			found = append(found, m)
		}
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		if found[i].Line != found[j].Line {
			return found[i].Line < found[j].Line
		}
		if found[i].Column != found[j].Column {
			return found[i].Column < found[j].Column
		}

		return found[i].Type < found[j].Type
	})

	return found
}

// mutationRow reads one row of the `## Every mutation` table that `internal/mutationreport`
// renders.
//
// The five cells are the file, the line, the column, the mutator type and the verdict. A
// verdict carries a space, so the pattern reads a character class and never one word.
var mutationRow = regexp.MustCompile("(?m)^\\| `([^`]+)` \\| (\\d+) \\| (\\d+) \\| `([A-Z_]+)` \\| `([A-Z ]+)` \\|$")

// sweptPathRow reads the `Swept path` row of the `## The run` table.
var sweptPathRow = regexp.MustCompile("(?m)^\\| Swept path \\| `([^`]+)` \\|$")

// parseMutations returns every mutation row of one report.
//
// **It rejects a report that holds no row.** `internal/mutationreport` owns the report
// format, and a later change to that format would leave this pattern matching nothing. A
// command that then reported zero new mutations would be a detector that detects nothing,
// and it would report success on every night.
func parseMutations(text string) ([]mutation, error) {
	rows := mutationRow.FindAllStringSubmatch(text, -1)
	if len(rows) == 0 {
		return nil, fmt.Errorf("the report holds no mutation row, so the table format moved or the sweep measured nothing")
	}

	found := make([]mutation, 0, len(rows))
	for _, row := range rows {
		line, err := strconv.Atoi(row[2])
		if err != nil {
			return nil, fmt.Errorf("read the line of %s: %w", row[1], err)
		}
		column, err := strconv.Atoi(row[3])
		if err != nil {
			return nil, fmt.Errorf("read the column of %s: %w", row[1], err)
		}

		found = append(found, mutation{
			File:    row[1],
			Line:    line,
			Column:  column,
			Type:    row[4],
			Verdict: row[5],
		})
	}

	return found, nil
}

// sweptPath returns the path that one report records under the `Swept path` row.
//
// It rejects a report that holds no such row, for the reason that parseMutations states.
func sweptPath(text string) (string, error) {
	row := sweptPathRow.FindStringSubmatch(text)
	if row == nil {
		return "", fmt.Errorf("the report holds no Swept path row, so the sweep path is unknown")
	}

	return row[1], nil
}

// latestReport returns the tracked report of the last sweep.
//
// `reportName` of `internal/mutationreport` leads each name with the UTC calendar day, so a
// plain sort of the directory orders the reports by date. This function takes the last name
// of that order.
//
// It rejects an empty directory, because a comparison against no baseline reports every
// mutation of the tree as new.
func latestReport(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dir, err)
	}

	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("%s holds no report, so this run has no baseline", dir)
	}
	sort.Strings(names)

	return filepath.Join(dir, names[len(names)-1]), nil
}

// readReport returns the text of one report file.
func readReport(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // The path comes from the workflow and from the report directory.
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	return string(raw), nil
}

// renderBody returns the issue body that FR-mutation-18 needs.
//
// The body names the baseline it compared against, so a reader can reproduce the
// comparison. It names the line-shift limit, because a burst of rows after an unrelated
// edit is the expected shape of a false report.
func renderBody(baseline, swept string, found []mutation) string {
	var out strings.Builder

	fmt.Fprintf(&out, "The scheduled mutation sweep of `%s` found %d mutation(s) that the last tracked sweep does not settle.\n\n", swept, len(found))
	fmt.Fprintf(&out, "FR-mutation-18 opens this issue. FR-mutation-11 settles each row below on code that\n")
	fmt.Fprintf(&out, "can move a fingerprint value, and it counts every other row. FR-mutation-12 states that\n")
	fmt.Fprintf(&out, "a settlement is an added assertion or a recorded reason.\n\n")

	fmt.Fprintf(&out, "| Baseline | `%s` |\n|---|---|\n| Swept path | `%s` |\n\n", baseline, swept)

	out.WriteString("## The mutations\n\n")
	out.WriteString("| File | Line | Column | Type | Verdict |\n|---|---|---|---|---|\n")
	for _, m := range found {
		fmt.Fprintf(&out, "| `%s` | %d | %d | `%s` | `%s` |\n", m.File, m.Line, m.Column, m.Type, m.Verdict)
	}

	out.WriteString("\n## Read the line shift before you settle a row\n\n")
	out.WriteString("A mutation is identified by its file, its line, its column and its mutator type.\n")
	out.WriteString("**An inserted line above a mutation moves that mutation to a new line number**, and\n")
	out.WriteString("this comparison then reads it as new. A run that reports many rows across one file\n")
	out.WriteString("is the expected shape of that shift, and it is not a regression of the tests.\n\n")
	out.WriteString("Commit a fresh report under `docs/mutation_reports/` to move the baseline forward.\n")
	out.WriteString("`docs/specs/features/15-mutation-sweep.md` holds the requirements.\n")

	return out.String()
}
