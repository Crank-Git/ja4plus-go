//go:build prerelease

package ja4plus

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/repofile"
)

// The release gate case of `docs/specs/features/16-pre-release-validation.md`.
//
// FR-prerelease-26 through FR-prerelease-30 stand at the release gate. Each one reads a
// fact that the maintainer must know before it promotes the release.
//
// **The maintainer amended FR-prerelease-26 on 2026-08-15 UTC**, and #633 applied it. The
// run now reads the tag under test, and the promotion waits on the result. **The four other
// requirements of this slice read the tracked tree**, so each one holds before the tag and
// after it.
//
// **Three of the five run today, and two of them read something the tree does not hold.**
// #94 records the maintainer ruling of 2026-08-14: each member writes its case against
// `v0.3.0` and enumerates the expected failures. The doc comment of each case below names
// what it reads, and it names the issue that turns a failure green.

// prereleaseConformanceReport holds the measurement that `make conformance` writes.
const prereleaseConformanceReport = "docs/audit/conformance.md"

// prereleaseConformanceSuite holds the gate that fails the suite on a closed entry.
const prereleaseConformanceSuite = "conformance_test.go"

// documentationSiteAddress names the host that serves the documentation site.
//
// The case dials it before it reads the link, and the two outcomes mean two things.
//
//   - The host accepts a connection and answers with an error status. The link does not
//     resolve, and the case fails.
//   - The host accepts no connection. The case could not check, and it skips.
const documentationSiteAddress = "crank-git.github.io:443"

// prereleaseSummaryRow returns the count that one row of the report summary states.
//
// It fails the test when the report holds no such row. A release gate that read an absent
// row would pass on a report that measures nothing.
func prereleaseSummaryRow(t *testing.T, report, measure string) int {
	t.Helper()

	pattern := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(measure) + ` \| (\d+) \|$`)

	match := pattern.FindStringSubmatch(report)
	if match == nil {
		t.Fatalf("%s holds no summary row named %q", prereleaseConformanceReport, measure)
	}

	count := 0
	if _, err := fmt.Sscanf(match[1], "%d", &count); err != nil {
		t.Fatalf("the %q row states %q, and the row states a count: %v", measure, match[1], err)
	}

	return count
}

// TestTheReleaseGateRunsAgainstTheTagUnderTest holds FR-prerelease-26.
//
// The requirement states that `make prerelease` runs against the tag under test, and that
// the maintainer promotes the release only when every case passes or carries a recorded
// reason. **The maintainer ruled that amendment on 2026-08-15 UTC**, at
// https://github.com/Crank-Git/ja4plus-go/issues/633#issuecomment-5299776974, and #633
// applied it. **#633 is the reversal path.**
//
// The pre-amendment requirement stated that `make prerelease` passes before the maintainer
// creates the tag. That named a moment at which no tag exists, so this case could read
// none and it asserted nothing.
//
// This case reads two facts. The run names a tag, and the download directory holds the
// published checksum file of that tag. **A run that reads no published release proves
// nothing about the artifact the maintainer promotes**, so a summary that reported it as a
// pass would report a gate that gates nothing.
//
// **This case verifies no digest.** `TestEveryPublishedChecksumVerifies` holds
// FR-prerelease-22 and compares every digest. This case reads the presence of the file,
// which is the evidence that the maintainer pushed the tag and that GoReleaser published
// it.
//
// **This case runs no command.** `make prerelease` runs this file, so a case that ran the
// target would call itself without a bound.
//
// **This case is red until Epic 10 ships a tag under test.** #100 cuts that tag and #593
// holds the `LICENSE` half. That red is the state of the repository, and it is never a
// regression of this case.
func TestTheReleaseGateRunsAgainstTheTagUnderTest(t *testing.T) {
	directory, tag := releaseUnderTest(t)

	path := filepath.Join(directory, releaseChecksumFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the release of tag %s holds no %s in %s, so this run reads no published release: %v",
			tag, releaseChecksumFile, directory, err)
	}
}

// TestTheRegisterHoldsNoEntryWhoseComparisonNowMatches holds FR-prerelease-27.
//
// **The conformance suite already holds this gate, and this case writes no second
// comparison.** `compareConformance` records a closed entry when the register names a key
// and the two values are now equal, and `conformance_test.go` fails the suite for each one.
// A second comparison here would read the corpus, and it would drift from the first.
//
// So this case reads two things the suite leaves behind.
//
//  1. The report that `make conformance` writes. It states the stale count and the orphan
//     count, and a release carries neither.
//  2. The source of the suite, which must still hold the closed-entry gate. A commit that
//     removed that loop would leave a closed entry unreported, and the report states no
//     closed count.
//
// **The report publishes no closed count, and `conformanceSetTotals` counts one.** So the
// closed gate reaches the reader as a failing suite alone. #99 records that gap.
//
// This case reads a tracked file, so it needs no corpus and it reads no tag.
func TestTheRegisterHoldsNoEntryWhoseComparisonNowMatches(t *testing.T) {
	report := readRepoFile(t, prereleaseConformanceReport)

	if stale := prereleaseSummaryRow(t, report, "Stale register entries"); stale != 0 {
		t.Errorf("%s reports %d stale register entries, and a release carries none",
			prereleaseConformanceReport, stale)
	}

	if orphan := prereleaseSummaryRow(t, report, "Orphan register entries"); orphan != 0 {
		t.Errorf("%s reports %d orphan register entries, and a release carries none",
			prereleaseConformanceReport, orphan)
	}

	suite := readRepoFile(t, prereleaseConformanceSuite)
	if !strings.Contains(suite, "range comparison.Closed") {
		t.Errorf("%s holds no loop over the closed entries, so a register entry whose "+
			"comparison now matches reaches no report", prereleaseConformanceSuite)
	}
}

// mutationReportDirectory holds the tracked report of each mutation sweep.
const mutationReportDirectory = "docs/mutation_reports"

// mutationSettlementDirectory holds one settlement record for each tracked report.
const mutationSettlementDirectory = "docs/mutation_settlements"

// mutationRuleSentence is the amended FR-mutation-11, verbatim.
//
// The maintainer ruled the boundary on 2026-08-14, and #634 carried the amendment into
// `docs/specs/features/15-mutation-sweep.md`, `docs/mutation_sweep.md` and the settlement
// record. `.claude/rules/ste.md` `## What is verbatim, and never rewritten` binds this
// sentence, so a reworded copy here would read no record of the tree.
const mutationRuleSentence = "A LIVED mutation on code that can move a fingerprint value " +
	"is settled. Every other LIVED mutation is counted and recorded."

// mutationSettledVerdicts names each verdict that FR-mutation-11 reads.
//
// `unsettledVerdicts` in `internal/mutationdiff/main.go` names the same two, and the
// edge-case table of `docs/specs/features/15-mutation-sweep.md` states the reason for the
// second one: `The verdict is `TIMED OUT`. FR-mutation-11 reads it like a `LIVED`
// mutation.` **A case that read `LIVED` alone would leave four mutations of the tracked
// sweep unread.**
//
// `NOT COVERED` is not here. The same table sends that gap to `.coverage-floor`.
var mutationSettledVerdicts = []string{"LIVED", "TIMED OUT"}

// mutationVerdictRow returns the pattern that reads the count of one verdict.
//
// The report and the settlement record each state the count in a table, and the two tables
// differ in their emphasis and in their column count. So the pattern reads a backtick and
// an asterisk around each cell, and it reads the first two columns alone.
func mutationVerdictRow(verdict string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\| *[*` + "`" + `]*` + regexp.QuoteMeta(verdict) +
		`[*` + "`" + `]* *\| *\**(\d+)\** *\|`)
}

// mutationVerdictCount returns the count that one document states for one verdict.
//
// It fails the test when the document states no such row. A gate that read an absent row as
// zero would report agreement between two documents that measure different sweeps.
func mutationVerdictCount(t *testing.T, path, text, verdict string) int {
	t.Helper()

	match := mutationVerdictRow(verdict).FindStringSubmatch(text)
	if match == nil {
		t.Fatalf("%s states no count for the %s verdict, and FR-mutation-11 reads that verdict",
			path, verdict)
	}

	count, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("the %s row of %s states %q, and the row states a count: %v",
			verdict, path, match[1], err)
	}

	return count
}

// mostRecentMutationReport returns the tracked report of the most recent sweep.
//
// **It runs `mutationdiff`, and it repeats no rule of that command.** `latestReport` in
// `internal/mutationdiff/main.go` decides which report is the most recent one, and
// `.github/workflows/mutation.yml` reads the same answer from the same command. A second
// copy of that rule here would let the nightly comparison and the release gate name two
// different sweeps.
func mostRecentMutationReport(t *testing.T) string {
	t.Helper()

	output, err := exec.Command("go", "run", "./internal/mutationdiff",
		"-dir", mutationReportDirectory).Output()
	if err != nil {
		// `main` of `internal/mutationdiff` writes the reason to standard error and it
		// exits 1, so `%v` alone reports `exit status 1` and it drops the reason.
		reason := ""
		exit := &exec.ExitError{}
		if errors.As(err, &exit) {
			reason = strings.TrimSpace(string(exit.Stderr))
		}

		t.Fatalf("name the report of the most recent sweep: %v: %s", err, reason)
	}

	for _, line := range strings.Split(string(output), "\n") {
		if path, found := strings.CutPrefix(line, "baseline="); found {
			return path
		}
	}

	t.Fatalf("mutationdiff printed no baseline line over %s: %q", mutationReportDirectory, output)

	return ""
}

// TestEveryLivedMutationOfTheMostRecentSweepIsSettled holds FR-prerelease-28.
//
// The requirement states that the most recent sweep records every `LIVED` mutation as
// settled or as counted. **The maintainer amended FR-mutation-11 on 2026-08-14**, #634
// applied the amendment, and #642 aligned FR-prerelease-28 with it. **#642 is the reversal
// path.**
//
// The pre-amendment rule asked for a settlement for each of the 223 `LIVED` mutations of
// the tracked sweep, and the tracked record settles ten of them. So a case that demanded a
// settlement for every one would read the record as incomplete work rather than as the
// answer the maintainer ruled.
//
// **No test decides the fingerprint risk of a mutation, because that reading is a person's
// work.** `docs/mutation_settlements/2026-08-14-internal-parser.md` states the three tests
// that a reader applies, and the record of that reading is the settlement document. This
// case therefore holds the one property a machine can hold: **the record covers the sweep
// that the tree holds today.**
//
// It reads four facts.
//
//  1. The most recent report carries a settlement record of the same name. A sweep with no
//     record settles nothing at all.
//  2. The record quotes the amended FR-mutation-11. A record written under the replaced
//     rule states a disposition the maintainer no longer asks for.
//  3. The record states the same count as the report, for each verdict that
//     FR-mutation-11 reads. **This is the check that a later sweep fails.** A fresh report
//     beside a stale record reports two counts, and the release then carries mutations
//     that no reader has read.
//  4. The record holds both dispositions of the amended rule. A record with no counted
//     remainder states nothing about the mutations outside the fingerprint boundary.
//
// **This case reads the count table of the report, and it parses no mutation row.**
// `countVerdicts` in `internal/mutationreport/main.go` builds that table from the rows
// themselves, so the count is a per-mutation count. **It is never the `mutants_total` field
// of the tool**, which #91 measured at 716 against a true total of 882 on 2026-08-14.
func TestEveryLivedMutationOfTheMostRecentSweepIsSettled(t *testing.T) {
	report := mostRecentMutationReport(t)
	settlement := filepath.Join(mutationSettlementDirectory, filepath.Base(report))

	if _, err := os.Stat(settlement); err != nil {
		t.Fatalf("the sweep of %s carries no settlement record at %s, so no mutation of "+
			"the most recent sweep is settled: %v", report, settlement, err)
	}

	record := readRepoFile(t, settlement)

	if !strings.Contains(record, mutationRuleSentence) {
		t.Errorf("%s quotes no amended FR-mutation-11, so it records a disposition under "+
			"the replaced rule. The amended rule reads %q", settlement, mutationRuleSentence)
	}

	reportText := readRepoFile(t, report)
	for _, verdict := range mutationSettledVerdicts {
		swept := mutationVerdictCount(t, report, reportText, verdict)
		recorded := mutationVerdictCount(t, settlement, record, verdict)

		if swept != recorded {
			t.Errorf("%s reports %d mutations with the verdict %s, and %s records %d. "+
				"The record reads an earlier sweep, so the release carries mutations that "+
				"no reader has read", report, swept, verdict, settlement, recorded)
		}
	}

	for _, disposition := range []string{"## The settlements", "## The counted remainder"} {
		if !strings.Contains(record, disposition) {
			t.Errorf("%s holds no %q section, and the amended FR-mutation-11 states two "+
				"dispositions", settlement, disposition)
		}
	}
}

// TestNoTrackedDocumentStatesAForbiddenMethodCount holds FR-prerelease-29.
//
// **`TestMethodCountAppliesElevenToMethodsAndTenToFingerprinters` holds the same rule, and
// this case reads the files that guard cannot reach.** `methodCountDocuments` walks the
// directory tree and it reads four file kinds: no extension, `.md`, `.html` and `.go`. So a
// tracked file of any other kind states a method count that no guard reads. `mkdocs.yml`
// carries `site_description`, which the published site prints, and the walk reads no
// `.yml` file.
//
// **This case reads the complement of that walk, and it duplicates no pattern.** It applies
// `methodCountForbiddenForms` and `methodCountIsQuoted`, which the ordinary guard owns. A
// second copy of the two forms would drift from the first, and one copy cannot.
//
// A later commit that widens `methodCountExtensions` narrows this case by the same amount,
// because the case reads what the map does not name.
//
// The file set comes from `git ls-files`, so it names a tracked file and never a build
// artifact. FR-prerelease-29 states the tracked set.
func TestNoTrackedDocumentStatesAForbiddenMethodCount(t *testing.T) {
	for _, path := range prereleaseTrackedFiles(t) {
		if methodCountExtensions[filepath.Ext(path)] && !prereleasePathIsSkipped(path) {
			// The ordinary guard reads this file, and one guard is enough.
			continue
		}

		text, readable := prereleaseTextFile(t, path)
		if !readable {
			continue
		}

		text = methodCountMaskHistory(path, text)

		for _, form := range methodCountForbiddenForms {
			for _, position := range form.pattern.FindAllStringIndex(text, -1) {
				if methodCountIsQuoted(text, position[0], position[1]) {
					continue
				}

				line := 1 + strings.Count(text[:position[0]], "\n")
				t.Errorf("%s:%d states %q, and %s: %s",
					path, line, text[position[0]:position[1]],
					"docs/specs/features/12-ja4ls.md forbids the form", form.reason)
			}
		}
	}
}

// prereleaseTrackedFiles returns the path of every file that git tracks.
//
// It fails the test when the command fails, because a release gate that read an empty set
// would report a clean tree on every repository.
func prereleaseTrackedFiles(t *testing.T) []string {
	t.Helper()

	output, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("list the tracked files: %v", err)
	}

	paths := []string{}
	for _, path := range strings.Split(string(output), "\x00") {
		if path != "" {
			paths = append(paths, path)
		}
	}

	if len(paths) == 0 {
		t.Fatal("git tracks no file, and this case would then read nothing")
	}

	return paths
}

// prereleasePathIsSkipped reports whether the ordinary method-count walk skips the path.
//
// The walk skips a directory by name. So a tracked file under one of them reaches no
// guard, whatever its extension.
//
// **`assets` is the one skipped directory that git tracks**, and `assets/logo.png` is the
// one file it holds today. A later `assets/README.md` would reach this case and no other,
// because the walk skips the directory and the ordinary guard reads no file of it.
func prereleasePathIsSkipped(path string) bool {
	slashed := filepath.ToSlash(path)

	for directory := range methodCountSkipDirs {
		if slashed == directory || strings.HasPrefix(slashed, directory+"/") {
			return true
		}
	}

	return false
}

// prereleaseTextFile returns the text of the file, and whether the file holds text.
//
// A file that holds a zero byte is not a document, and `assets/logo.png` is the one such
// tracked file today. The case reads no byte of it.
func prereleaseTextFile(t *testing.T, path string) (string, bool) {
	t.Helper()

	text := readRepoFile(t, path)
	if strings.ContainsRune(text, 0) {
		return "", false
	}

	return text, true
}

// TestTheReadmeLinksToTheDocumentationSiteAndTheLinkResolves holds FR-prerelease-30.
//
// **`TestTheSiteURLAndTheReadmeLinkNameOneAddress` already holds the link itself**, under
// FR-documentation-38 and FR-documentation-39. This case holds the half no ordinary test
// can hold: the link resolves.
//
// **The link does not resolve today, and the cause is recorded rather than unknown.**
// `.github/workflows/docs.yml` publishes the site on a push to `master`, and it states the
// consequence: `A push to a branch other than master reaches no job of this file.` Epic 14
// merges to `dev`, so the site publishes when `dev` reaches `master`. A measurement on
// 2026-08-14 read status 404.
//
// **This case reaches the network, and it never passes when it could not check.** It dials
// the site host first. A host that accepts no connection makes the case skip, and the skip
// message states that it checked nothing. A host that answers with an error status makes
// the case fail, because the host then resolves and the site does not.
func TestTheReadmeLinksToTheDocumentationSiteAndTheLinkResolves(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, repofile.DocumentationSiteURL) {
		t.Fatalf("README.md names no link to %s", repofile.DocumentationSiteURL)
	}

	if networkIsAbsent(documentationSiteAddress) {
		t.Skipf("this case checked no link: it reached no connection to %s",
			documentationSiteAddress)
	}

	// The rule of `.claude/rules/external-apis.md` binds every call: the client carries a
	// timeout, it verifies the server certificate, and it bounds the response body.
	client := &http.Client{Timeout: 30 * time.Second}

	response, err := client.Get(repofile.DocumentationSiteURL)
	if err != nil {
		t.Fatalf("the link %s does not resolve: %v", repofile.DocumentationSiteURL, err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		t.Errorf("the link %s answers with status %d, and the release needs status %d. "+
			"`.github/workflows/docs.yml` publishes the site on a push to `master`, and "+
			"this work stands on `dev`",
			repofile.DocumentationSiteURL, response.StatusCode, http.StatusOK)
	}
}
