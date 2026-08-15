//go:build prerelease

package ja4plus

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The release gate case of `docs/specs/features/16-pre-release-validation.md`.
//
// FR-prerelease-26 through FR-prerelease-30 stand between the last commit and the tag. Each
// one reads a fact that the maintainer must know before the release.
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

// TestThePrereleaseTargetPassesBeforeTheTag records FR-prerelease-26, and it asserts
// nothing.
//
// **FR-prerelease-26 and the maintainer ruling of 2026-08-14 disagree, and this case
// resolves neither.** The requirement states that `make prerelease` passes before the
// maintainer creates the tag. The ruling on #94 states that each case runs against `v0.3.0`
// and that several of them fail until Epic 10 ships a tag. So `make prerelease` does not
// pass today, by that ruling.
//
// **The question belongs to the maintainer**, and #99 returns it. It is a scope question,
// and it is never a ruling about a fingerprint value.
//
// **This case runs no command.** `make prerelease` runs this file, so a case that ran the
// target would call itself without a bound.
//
// The registry row of FR-prerelease-26 reads `proves: false` until the maintainer answers.
// **The tree holds this case, and the row states that the case asserts nothing.** The Epic
// 16 round renamed the field from `built` on 2026-08-14, because a summary that called this
// case `absent` stated something the binary disproves.
func TestThePrereleaseTargetPassesBeforeTheTag(t *testing.T) {
	t.Skip("this case asserts nothing about FR-prerelease-26: the requirement and the " +
		"maintainer ruling of 2026-08-14 on #94 disagree, and #99 returns the question")
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

// TestEveryLivedMutationOfTheMostRecentSweepIsSettled records FR-prerelease-28.
//
// **This case reads a report that the tree does not hold, and Epic 15 produces one.** #90
// builds the mutation sweep on `epic/89-mutation-sweep`, which is a different integration
// branch. No line of that work stands on this branch, and no line of it stands on `dev`.
//
// **`make mutate` is the discriminator, and this case invents no report path.** The target
// is absent today, so the sweep runs nowhere and the case skips. When Epic 15 lands the
// target, this case fails and it names the work that completes it. A case that named a path
// nobody has written would pass on a tree that holds no sweep.
//
// #89 is the epic that turns this case green.
func TestEveryLivedMutationOfTheMostRecentSweepIsSettled(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !regexp.MustCompile(`(?m)^mutate:`).MatchString(makefile) {
		t.Skip("this case checked no mutation: the Makefile defines no mutate target, so " +
			"the tree holds no sweep and no report. Epic #89 builds the sweep, and #90 " +
			"adds the target")
	}

	t.Error("the Makefile now defines the mutate target, and this case still reads no " +
		"report of the most recent sweep. Complete it against the report that #90 writes")
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
	if !strings.Contains(readme, documentationSiteURL) {
		t.Fatalf("README.md names no link to %s", documentationSiteURL)
	}

	if networkIsAbsent(documentationSiteAddress) {
		t.Skipf("this case checked no link: it reached no connection to %s",
			documentationSiteAddress)
	}

	// The rule of `.claude/rules/external-apis.md` binds every call: the client carries a
	// timeout, it verifies the server certificate, and it bounds the response body.
	client := &http.Client{Timeout: 30 * time.Second}

	response, err := client.Get(documentationSiteURL)
	if err != nil {
		t.Fatalf("the link %s does not resolve: %v", documentationSiteURL, err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		t.Errorf("the link %s answers with status %d, and the release needs status %d. "+
			"`.github/workflows/docs.yml` publishes the site on a push to `master`, and "+
			"this work stands on `dev`",
			documentationSiteURL, response.StatusCode, http.StatusOK)
	}
}
