package ja4plus

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The `## [Unreleased]` preamble of `CHANGELOG.md` states four whole-tree counts, and three
// consecutive batches left them stale. #270 holds the first instance, round 32 of the
// `## Changelog` of `docs/specs/spec.md` holds the second, and #306 holds the third. Every
// member moves a whole-tree count by a slice, and no member owned the paragraph.
//
// These tests add a failure, and they read no exit status of the conformance run. The suite
// exits 2 on the current corpus, because it reports a deviation. A guard that read that exit
// status would report success where the run reports a deviation. #201 records the same trap
// in the `make docs` target.
//
// These tests read `docs/audit/conformance.md` and never the corpus. The suite rewrites that
// report on every run, and `.github/workflows/ci.yml` fails the job when the tracked report
// and the run disagree. #227 built that step, and `conformance_report_freshness_test.go`
// holds it. The tracked report therefore states the counts the current tree produces. These
// tests need no corpus, and they skip for no reason.
//
// These tests read the summary totals of the report, and never its deviation table. #303
// reports that two runs of one commit produce different deviation keys for
// `http-empty-useragent.pcap`. The totals hold across those two runs, so that defect moves
// no count these tests read.
//
// Each identifier below carries the `changelog` prefix. `conformance_report_test.go` declares
// `conformanceReportCount` for another purpose, under the `conformance` build tag. An
// untagged build hides that collision, and `make conformance` then reports it as a build
// failure.

// changelogFile is the path of the changelog, relative to the package directory.
const changelogFile = "CHANGELOG.md"

// changelogUnreleasedHeading names the section that holds the preamble.
const changelogUnreleasedHeading = "## [Unreleased]"

// changelogRunSentence reads the four counts of the preamble. The paragraph wraps, so the
// caller collapses each run of whitespace to one space before it matches.
var changelogRunSentence = regexp.MustCompile(
	`A run on the current tree reports ([0-9]+) matches, ([0-9]+) deviations, ([0-9]+) accepted deviations and ([0-9]+) register keys\.`)

// changelogRulingSentence reads one ruling of the preamble enumeration. It matches
// `Issue #42 put 248 entries` and `issue #197 put 14 more`.
var changelogRulingSentence = regexp.MustCompile(`(?i)issue #([0-9]+) put ([0-9]+) `)

// changelogReportSummaryRow reads one row of the report summary table.
var changelogReportSummaryRow = regexp.MustCompile(`(?m)^\| ([^|]+?) +\| ([0-9]+) \|$`)

// changelogUnreleasedPreamble returns the first paragraph of the `## [Unreleased]` section,
// with each run of whitespace collapsed to one space. It fails the test when the changelog
// holds no such section.
func changelogUnreleasedPreamble(t *testing.T) string {
	t.Helper()

	changelog := readRepoFile(t, changelogFile)

	start := strings.Index(changelog, changelogUnreleasedHeading)
	if start < 0 {
		t.Fatalf("%s holds no %q section", changelogFile, changelogUnreleasedHeading)
	}

	body := strings.TrimLeft(changelog[start+len(changelogUnreleasedHeading):], "\n")

	// The preamble ends at the first blank line. A later paragraph of the section records
	// the measurement of one batch, and those counts name their own base rather than the
	// current tree.
	if end := strings.Index(body, "\n\n"); end >= 0 {
		body = body[:end]
	}

	return strings.Join(strings.Fields(body), " ")
}

// changelogReportSummary returns the count that the summary table of the tracked report
// gives each measure. It fails the test when the report holds no summary table.
func changelogReportSummary(t *testing.T) map[string]int {
	t.Helper()

	report := readRepoFile(t, conformanceReportPathFromSource(t))

	counts := make(map[string]int)

	for _, row := range changelogReportSummaryRow.FindAllStringSubmatch(report, -1) {
		count, err := strconv.Atoi(row[2])
		if err != nil {
			t.Fatalf("the report row %q holds no number: %v", row[0], err)
		}

		// The report holds a second table below the summary, and its rows carry four
		// columns. This pattern matches a two-column row alone, and the first table the
		// report writes is the summary. A later table that repeats a measure name must not
		// replace the summary count.
		if _, held := counts[row[1]]; !held {
			counts[row[1]] = count
		}
	}

	if len(counts) == 0 {
		t.Fatalf("%s holds no summary table", conformanceReportPathFromSource(t))
	}

	return counts
}

// changelogReportSummaryCount returns the summary count of the measure. It fails the test when
// the summary table holds no row of that name.
func changelogReportSummaryCount(t *testing.T, counts map[string]int, measure string) int {
	t.Helper()

	count, held := counts[measure]
	if !held {
		t.Fatalf("the summary table of %s holds no %q row", conformanceReportPathFromSource(t), measure)
	}

	return count
}

func TestTheChangelogPreambleStatesTheCountsTheTreeProduces(t *testing.T) {
	preamble := changelogUnreleasedPreamble(t)

	stated := changelogRunSentence.FindStringSubmatch(preamble)
	if stated == nil {
		t.Fatalf("the %s preamble of %s states no run sentence:\n%s",
			changelogUnreleasedHeading, changelogFile, preamble)
	}

	summary := changelogReportSummary(t)

	// The register key count reads the tracked register, and the accepted deviation count
	// reads the report. The two answer different questions: the register names a comparison
	// that the suite may no longer reach, and the report counts the comparisons the run
	// matched to an entry.
	for _, measure := range []struct {
		name  string
		group int
		want  int
	}{
		{"matches", 1, changelogReportSummaryCount(t, summary, "Matches")},
		{"deviations", 2, changelogReportSummaryCount(t, summary, "Deviations")},
		{"accepted deviations", 3, changelogReportSummaryCount(t, summary, "Accepted deviations")},
		{"register keys", 4, len(readDeviationRegister(t))},
	} {
		count, err := strconv.Atoi(stated[measure.group])
		if err != nil {
			t.Fatalf("the preamble states %q for the %s: %v", stated[measure.group], measure.name, err)
		}

		if count != measure.want {
			t.Errorf("the %s preamble of %s states %d %s, and the tree reports %d",
				changelogUnreleasedHeading, changelogFile, count, measure.name, measure.want)
		}
	}
}

func TestTheChangelogPreambleEnumeratesEveryRulingOfTheRegister(t *testing.T) {
	preamble := changelogUnreleasedPreamble(t)

	stated := make(map[string]int)

	for _, sentence := range changelogRulingSentence.FindAllStringSubmatch(preamble, -1) {
		count, err := strconv.Atoi(sentence[2])
		if err != nil {
			t.Fatalf("the preamble states %q for issue #%s: %v", sentence[2], sentence[1], err)
		}

		stated["#"+sentence[1]] = count
	}

	held := make(map[string]int)
	for _, entry := range readDeviationRegister(t) {
		held[entry.Ruling]++
	}

	for ruling, count := range held {
		if stated[ruling] != count {
			t.Errorf("the %s preamble of %s gives the ruling %s %d entries, and the register holds %d",
				changelogUnreleasedHeading, changelogFile, ruling, stated[ruling], count)
		}
	}

	// A ruling that the register no longer holds must leave the paragraph too. A stale
	// sentence names a number that no file produces.
	for ruling := range stated {
		if _, reached := held[ruling]; !reached {
			t.Errorf("the %s preamble of %s names the ruling %s, and the register holds no entry under it",
				changelogUnreleasedHeading, changelogFile, ruling)
		}
	}
}

func TestTheChangelogPreambleEnumerationAddsUpToTheRegisterKeyCount(t *testing.T) {
	preamble := changelogUnreleasedPreamble(t)

	stated := changelogRunSentence.FindStringSubmatch(preamble)
	if stated == nil {
		t.Fatalf("the %s preamble of %s states no run sentence:\n%s",
			changelogUnreleasedHeading, changelogFile, preamble)
	}

	keys, err := strconv.Atoi(stated[4])
	if err != nil {
		t.Fatalf("the preamble states %q register keys: %v", stated[4], err)
	}

	// This check reads the paragraph alone, so it fails on arithmetic that the register
	// happens to satisfy. The enumeration read `150 + 35 + 13 + 4` against 203 keys for four
	// batches, and 202 is not 203. #306 records that defect.
	sum := 0

	for _, sentence := range changelogRulingSentence.FindAllStringSubmatch(preamble, -1) {
		count, convErr := strconv.Atoi(sentence[2])
		if convErr != nil {
			t.Fatalf("the preamble states %q for issue #%s: %v", sentence[2], sentence[1], convErr)
		}

		sum += count
	}

	if sum != keys {
		t.Errorf("the %s preamble of %s enumerates %d entries, and it states %d register keys",
			changelogUnreleasedHeading, changelogFile, sum, keys)
	}
}
