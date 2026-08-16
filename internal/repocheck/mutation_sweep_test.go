package repocheck

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests hold the mutation sweep harness of Epic 15 (#89), which #90 built.
// No Go code reads the harness at run time, so a later edit could drop it without a
// failure. These tests are that failure.
//
// `docs/specs/features/15-mutation-sweep.md` holds FR-mutation-1 through FR-mutation-5.

// TestTheMakefileRunsTheMutationTool holds FR-mutation-1 and FR-mutation-3.
func TestTheMakefileRunsTheMutationTool(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !regexp.MustCompile(`(?m)^mutate:\s*$`).MatchString(makefile) {
		t.Error("the Makefile holds no mutate recipe, so make mutate exits 2")
	}

	if !strings.Contains(makefile, "gremlins unleash") {
		t.Error("the mutate recipe runs no gremlins unleash, so it sweeps nothing")
	}
}

// TestTheMutateTargetIsPhony holds the `.PHONY` entry of the `mutate` target.
//
// A target that `.PHONY` does not name stops when a file of that name exists. `make docs`
// carries the measured case, because `docs/` is a directory of this repository.
//
// The reading for `mutate`: the repository root holds no path named `mutate`, so the trap
// that `make docs` hits does not apply today. The entry still guards the target. A later
// change that adds such a path makes `make mutate` print
// `make: Nothing to be done for 'mutate'.` and exit 0 without a sweep. The second assertion
// below holds the reading, and it fails when the path appears.
func TestTheMutateTargetIsPhony(t *testing.T) {
	phony := regexp.MustCompile(`(?m)^\.PHONY:(.*)$`).FindStringSubmatch(readRepoFile(t, "Makefile"))
	if phony == nil {
		t.Fatal("the Makefile states no .PHONY line")
	}

	if !strings.Contains(" "+strings.TrimSpace(phony[1])+" ", " mutate ") {
		t.Error("the .PHONY line names no mutate target")
	}

	if _, err := os.Stat("mutate"); err == nil {
		t.Error("the repository root now holds a path named mutate, so the reading of this test is stale")
	}
}

// TestTheMakefilePinsTheMutationToolVersion holds FR-mutation-2.
//
// FR-mutation-2 permits the pin in `.gremlins.yaml` or in the `Makefile`. The pin lives in
// the `Makefile`, because the documented `gremlins` configuration schema holds no version
// key. Verified against <https://gremlins.dev/latest/usage/configuration/>, retrieved
// 2026-08-14.
func TestTheMakefilePinsTheMutationToolVersion(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	pin := regexp.MustCompile(`(?m)^GREMLINS_VERSION \?= (v[0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(makefile)
	if pin == nil {
		t.Fatal("the Makefile states no GREMLINS_VERSION pin")
	}

	if !strings.Contains(makefile, "gremlins@$(GREMLINS_VERSION)") {
		t.Errorf("the pin is %s, and no install command reads it, so the pin binds nothing", pin[1])
	}
}

// TestTheMutateTargetSweepsOnePackage holds FR-mutation-5.
//
// `?=` sets the variable only when the environment and the command line state none, so
// `make mutate PKG=./internal/parser` overrides the named set of FR-mutation-4.
func TestTheMutateTargetSweepsOnePackage(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !regexp.MustCompile(`(?m)^PKG \?= `).MatchString(makefile) {
		t.Error("the Makefile does not set PKG with ?=, so a command line cannot override it")
	}

	if !strings.Contains(makefile, "unleash $(PKG)") {
		t.Error("the mutate recipe does not pass PKG to gremlins, so PKG selects nothing")
	}
}

// TestTheMutationConfigurationRaisesTheTimeoutCoefficient holds the measured configuration
// of `.gremlins.yaml`.
//
// `gremlins` estimates the timeout of one mutation from a `go test` run. The Go build cache
// serves that run, so the estimate collapses to the cache-hit time.
//
// At the default coefficient of 3, every one of the 16 mutations of `internal/dbcache`
// reported `TIMED OUT`, measured on 2026-08-14. `./ja4db` settles at 120, and 240 reports
// the verdicts that 120 reports.
func TestTheMutationConfigurationRaisesTheTimeoutCoefficient(t *testing.T) {
	config := readRepoFile(t, ".gremlins.yaml")

	if !regexp.MustCompile(`(?m)^\s+timeout-coefficient: 120$`).MatchString(config) {
		t.Error("the configuration does not set timeout-coefficient to 120, so a fast suite reports a false TIMED OUT")
	}
}

// mutationReportDir is the directory that FR-mutation-6 names.
const mutationReportDir = "docs/mutation_reports"

// TestTheMutateTargetWritesAReport holds FR-mutation-6.
//
// `gremlins` writes the machine-readable half, and `internal/mutationreport` renders the
// tracked half. Both steps must stay in the recipe: a sweep with no render writes no report,
// and a render with no sweep reads a stale file.
func TestTheMutateTargetWritesAReport(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !strings.Contains(makefile, "unleash $(PKG) --output $(MUTATION_JSON)") {
		t.Error("the mutate recipe passes no --output to gremlins, so it writes no machine-readable result")
	}
	if !strings.Contains(makefile, "go run ./internal/mutationreport") {
		t.Error("the mutate recipe runs no renderer, so it writes no report to docs/mutation_reports/")
	}
	if !strings.Contains(makefile, "MUTATION_REPORT_DIR ?= "+mutationReportDir) {
		t.Errorf("the mutate recipe does not send the report to %s, which FR-mutation-6 names", mutationReportDir)
	}
}

// TestTheMutationReportNamesEveryExcludedPath holds the edge case of
// `docs/specs/features/15-mutation-sweep.md` that names an unswept package.
//
// The report states which paths the sweep does not read. That sentence comes from
// `MUTATION_EXCLUDED` of the `Makefile`, and the sweep reads `.gremlins.yaml`. Two sources
// state one fact, so this test fails when they disagree.
func TestTheMutationReportNamesEveryExcludedPath(t *testing.T) {
	excluded := regexp.MustCompile(`(?m)^MUTATION_EXCLUDED \?= (.*)$`).FindStringSubmatch(readRepoFile(t, "Makefile"))
	if excluded == nil {
		t.Fatal("the Makefile states no MUTATION_EXCLUDED value, so the report names no excluded path")
	}

	config := readRepoFile(t, ".gremlins.yaml")
	patterns := regexp.MustCompile(`(?m)^\s+- '\^([^']+)'$`).FindAllStringSubmatch(config, -1)
	if len(patterns) == 0 {
		t.Fatal(".gremlins.yaml states no exclude-files pattern, so this guard reads nothing")
	}

	for _, pattern := range patterns {
		if !strings.Contains(excluded[1], "`"+pattern[1]+"`") {
			t.Errorf("the exclude-files list holds %q, and MUTATION_EXCLUDED does not name it: %q",
				pattern[1], excluded[1])
		}
	}
}

// TestTheMutationReportIsTracked holds FR-mutation-10.
//
// A git worktree checks out a tracked file alone, so a report this test reads inside a
// worktree is a report that git tracks. The second assertion holds the developer checkout,
// where an untracked file is present all the same.
func TestTheMutationReportIsTracked(t *testing.T) {
	entries, err := os.ReadDir(mutationReportDir)
	if err != nil {
		t.Fatalf("%s is absent, and FR-mutation-6 names it: %v", mutationReportDir, err)
	}

	reports := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			reports++
		}
	}
	if reports == 0 {
		t.Errorf("%s holds no report, so FR-mutation-10 tracks nothing", mutationReportDir)
	}

	// The comment of `.gitignore` names the directory, so this guard reads a pattern alone.
	for number, line := range strings.Split(readRepoFile(t, ".gitignore"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "mutation_reports") {
			t.Errorf(".gitignore:%d ignores the report, and FR-mutation-10 tracks it: %q", number+1, line)
		}
	}
}

// TestTheMutationReportRecordsEveryRequiredField holds FR-mutation-7, FR-mutation-8 and
// FR-mutation-9 against the committed artifact rather than against the renderer.
//
// The renderer has its own tests in `internal/mutationreport`. This test reads what the
// sweep actually wrote, so a recipe that drops a flag fails here.
func TestTheMutationReportRecordsEveryRequiredField(t *testing.T) {
	report := readRepoFile(t, latestMutationReport(t))

	// FR-mutation-9. The date is the UTC calendar day, as every date of this repository is.
	if !regexp.MustCompile(`(?m)^\| Tool version \| ` + "`" + `v[0-9]+\.[0-9]+\.[0-9]+` + "`" + ` \|$`).MatchString(report) {
		t.Error("the report records no tool version")
	}
	if !regexp.MustCompile(`(?m)^\| Date, UTC \| [0-9]{4}-[0-9]{2}-[0-9]{2} \|$`).MatchString(report) {
		t.Error("the report records no date")
	}

	// FR-mutation-8 names five verdicts, and `gremlins` v0.6.0 emits seven. The report
	// prints a row for every one.
	for _, verdict := range []string{
		"KILLED", "LIVED", "NOT COVERED", "TIMED OUT", "NOT VIABLE", "SKIPPED", "RUNNABLE",
	} {
		if !strings.Contains(report, "| `"+verdict+"` |") {
			t.Errorf("the report holds no count row for the verdict %s", verdict)
		}
	}

	// FR-mutation-7. One row for each mutation: the file, the line and the verdict.
	rows := regexp.MustCompile("(?m)^\\| `[^`]+\\.go` \\| [0-9]+ \\| [0-9]+ \\| `[A-Z_]+` \\| `[A-Z ]+` \\|$")
	if found := len(rows.FindAllString(report, -1)); found == 0 {
		t.Error("the report names no mutation, so FR-mutation-7 reads nothing")
	}
}

// latestMutationReport returns the report that sorts last. The file name leads with the UTC
// day, so the last name is the most recent sweep.
func latestMutationReport(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir(mutationReportDir)
	if err != nil {
		t.Fatalf("read %s: %v", mutationReportDir, err)
	}

	latest := ""
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") && entry.Name() > latest {
			latest = entry.Name()
		}
	}
	if latest == "" {
		t.Fatalf("%s holds no report", mutationReportDir)
	}

	return mutationReportDir + "/" + latest
}

// TestTheSiteExcludesTheMutationReports holds the site half of FR-mutation-6.
//
// A report holds one table row for each mutation, and `make mutate` writes one report for
// each sweep. A published report that no `nav` entry names reaches
// `validation.nav.omitted_files: warn`, and `strict` turns that warning into a failed build.
//
// `TestEveryExcludedDirectoryReachesTheSiteConfig` in `mkdocs_config_test.go` asserts the
// same pattern shape, and the two tests guard different things. That test reads
// `excludedDocumentationDirs`, so it holds `mkdocs.yml` against the list and it holds the
// list against nothing. This test names `mutation_reports` as a literal, so it survives an
// edit that drops the name from the list. Without this test one edit that removes the name
// from both `excludedDocumentationDirs` and `mkdocs.yml` leaves every test green, and
// `make docs` then fails on the first sweep. The cross-member review of Epic 15 asked which
// test the tree keeps, and it keeps both for this reason.
func TestTheSiteExcludesTheMutationReports(t *testing.T) {
	if !regexp.MustCompile(`(?m)^\s+/mutation_reports/\s*$`).MatchString(readRepoFile(t, "mkdocs.yml")) {
		t.Error("exclude_docs of mkdocs.yml names no /mutation_reports/ pattern, so make docs fails on the first sweep")
	}
}

// TestTheMutationConfigurationExcludesTheCommandLineProgram holds
// `docs/specs/features/15-mutation-sweep.md` `## Out of scope`, which declines a sweep of
// `cmd/ja4plus`.
//
// The path argument of `gremlins unleash` reads a whole directory tree, so the default
// `PKG` of `.` reaches `cmd/` without this list.
func TestTheMutationConfigurationExcludesTheCommandLineProgram(t *testing.T) {
	config := readRepoFile(t, ".gremlins.yaml")

	for _, pattern := range []string{"'^cmd/'", "'^examples/'"} {
		if !strings.Contains(config, pattern) {
			t.Errorf("the exclude-files list does not hold %s", pattern)
		}
	}
}
