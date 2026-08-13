package ja4plus

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The repository harness is a build gate, and no Go code reads it at run time.
// These tests hold the gate, so that a later edit cannot drop it without a failure.

// readRepoFile returns the content of a file in the repository root.
// It fails the test when the file is absent.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// TestGoModDeclaresGo124 holds the Go 1.24 language version that FR-foundation-1 names.
// The citation named FR-foundation-2 until 2026-08-13. That requirement now names the
// toolchain of the workflow, and FR-foundation-1 names this directive.
// `github.com/gopacket/gopacket@v1.6.1` states `go 1.24.0` in its own `go.mod`, so the
// toolchain writes that longer form here and it refuses `go 1.24`. #438 measured it.
// Go states that the two forms name one language version:
// `1.21, 1.21rc2, and 1.21.3 all implement language version 1.21`.
// The pattern accepts each 1.24 release, and it still fails for `go 1.25`.
func TestGoModDeclaresGo124(t *testing.T) {
	goMod := readRepoFile(t, "go.mod")

	if !regexp.MustCompile(`(?m)^go 1\.24(\.\d+)?$`).MatchString(goMod) {
		t.Errorf("go.mod does not declare the Go 1.24 language version:\n%s", goMod)
	}
}

// goToolchainRange is the Go version range that every workflow of this repository names.
// FR-foundation-2 states the range, and the comment above `jobs:` of
// `.github/workflows/ci.yml` states why it is a range rather than a bare major version.
//
// **This constant is the one source of truth for the pair of workflows.** #473 read the
// alternatives and declined each one. `actions/setup-go` names `go.mod`, `go.work`,
// `.go-version` and `.tool-versions` for its `go-version-file` input, and its README
// states no range support for a file. `go.mod` states a language version, and #438 bars a
// move of it. A repository variable lives outside the tree, so no test reads it and no
// pull request reviews it. The three tests below read this constant instead, so a
// workflow that drifts from the pair fails a test in the tree.
// **The range moved from `~1.26.5` to `~1.26.6` on 2026-08-13**, and a new advisory moved
// it. The `vuln` job passed on go1.26.5 at commit `83f2127`, and it failed on the same
// toolchain at commit `7210e80` about one hour later. No line of this repository changed
// between the two runs. The comment above the `vuln` job of `.github/workflows/ci.yml`
// states that property, and it states why a red `vuln` job is not a regression by default.
const goToolchainRange = "~1.26.6"

// TestCIWorkflowTestsGo126Only holds the one Go version that FR-foundation-2 names.
// The test named Go 1.24 until 2026-08-13, and comment 5286440152 of #65 holds the
// amendment. Issue #65 is the reversal path.
//
// The range excludes go1.26.0 through go1.26.5, because GO-2026-5856 names a fix at
// 1.26.5 and four later advisories each name a fix at 1.26.6. `actions/setup-go` reads the
// tool cache of the runner before it reads the release list, so a bare `1.26` can resolve
// to a toolchain that this gate fails.
func TestCIWorkflowTestsGo126Only(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	matrix := regexp.MustCompile(`(?m)^ *go-version: \[(.*)\]$`).FindStringSubmatch(workflow)
	if matrix == nil {
		t.Fatalf(".github/workflows/ci.yml holds no go-version matrix")
	}

	if matrix[1] != "'"+goToolchainRange+"'" {
		t.Errorf("the go-version matrix is [%s], and FR-foundation-2 names Go 1.26 only", matrix[1])
	}
}

// TestCIWorkflowNamesOneGoVersion holds every job of the workflow at the version that
// FR-foundation-2 names. The `vuln` job of #65 reports the standard library of the Go
// version on the PATH, so a job that names a second version measures an artifact this
// workflow never produces.
func TestCIWorkflowNamesOneGoVersion(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	versions := regexp.MustCompile(`(?m)^ *go-version: '(.*)'$`).FindAllStringSubmatch(workflow, -1)
	if versions == nil {
		t.Fatalf(".github/workflows/ci.yml holds no literal go-version input")
	}

	for _, version := range versions {
		if version[1] != goToolchainRange {
			t.Errorf("a job names go-version %q, and FR-foundation-2 names Go 1.26 only", version[1])
		}
	}
}

func TestCIWorkflowPinsTheLinterVersion(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	pin := regexp.MustCompile(`(?m)^ *version: (v\d+\.\d+\.\d+)$`)
	if !pin.MatchString(workflow) {
		t.Errorf("the golangci-lint version is not a released version number:\n%s", workflow)
	}
}

// A pull request into `dev` must start the workflow. Pull request #107 added the filter,
// and FR-foundation-14 depends on it.
func TestCIWorkflowRunsOnAPullRequestIntoDev(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	branches := regexp.MustCompile(`(?m)^ *branches: \[(.*)\]$`).FindAllStringSubmatch(workflow, -1)
	if len(branches) < 2 {
		t.Fatalf(".github/workflows/ci.yml holds fewer than two branch filters")
	}

	if !strings.Contains(branches[1][1], "dev") {
		t.Errorf("the pull request branch filter is [%s], and it does not name dev", branches[1][1])
	}
}

// makefileRecipe returns the recipe of a target in the `Makefile`.
// It fails the test when the `Makefile` holds no such target.
//
// A recipe line starts with a tab, so the first line without one ends the recipe.
func makefileRecipe(t *testing.T, target string) string {
	t.Helper()

	recipe := []string{}
	found := false

	for _, line := range strings.Split(readRepoFile(t, "Makefile"), "\n") {
		if !found {
			found = strings.HasPrefix(line, target+":")
			continue
		}

		if !strings.HasPrefix(line, "\t") {
			break
		}

		recipe = append(recipe, line)
	}

	if !found {
		t.Fatalf("the Makefile holds no %s target", target)
	}

	return strings.Join(recipe, "\n")
}

// A target that `.PHONY` does not name stops when a file of that name exists.
// FR-foundation-15 through FR-foundation-18 add four such targets.
func TestMakefileDeclaresEveryNewTargetPhony(t *testing.T) {
	phony := regexp.MustCompile(`(?m)^\.PHONY: (.*)$`).FindStringSubmatch(readRepoFile(t, "Makefile"))
	if phony == nil {
		t.Fatalf("the Makefile holds no .PHONY line")
	}

	names := strings.Fields(phony[1])
	for _, target := range []string{"corpus", "conformance", "cover", "fuzz"} {
		if !slices.Contains(names, target) {
			t.Errorf(".PHONY names [%s], and it does not name %s", phony[1], target)
		}
	}
}

// FR-foundation-15 names the corpus fetch script. The script is idempotent and it names
// the network on a failure, so the target adds nothing of its own.
func TestMakefileCorpusTargetRunsTheFetchScript(t *testing.T) {
	recipe := makefileRecipe(t, "corpus")

	if !strings.Contains(recipe, "scripts/fetch-corpus.sh") {
		t.Errorf("the corpus recipe does not run scripts/fetch-corpus.sh:\n%s", recipe)
	}
}

// FR-conformance-10 builds the suite only with the `conformance` build tag, and Epic 4
// adds the suite. FR-foundation-16 adds the target that runs it.
func TestMakefileConformanceTargetSelectsTheConformanceBuildTag(t *testing.T) {
	recipe := makefileRecipe(t, "conformance")

	if !strings.Contains(recipe, "-tags conformance") {
		t.Errorf("the conformance recipe does not select the conformance build tag:\n%s", recipe)
	}

	// The suite writes `docs/audit/conformance.md`, and a cached result writes nothing.
	if !strings.Contains(recipe, "-count=1") {
		t.Errorf("the conformance recipe does not defeat the test cache:\n%s", recipe)
	}

	// FR-conformance-11 skips with a message that names `make corpus`, and `go test`
	// prints a skip message only with `-v`.
	if !strings.Contains(recipe, " -v ") {
		t.Errorf("the conformance recipe does not print the skip message:\n%s", recipe)
	}
}

// FR-foundation-17 reports total statement coverage. `go tool cover -func` writes the
// total on its last line.
func TestMakefileCoverTargetReportsTheTotalStatementCoverage(t *testing.T) {
	recipe := makefileRecipe(t, "cover")

	if !strings.Contains(recipe, "-coverprofile=") {
		t.Errorf("the cover recipe writes no coverage profile:\n%s", recipe)
	}

	if !strings.Contains(recipe, "go tool cover -func=") {
		t.Errorf("the cover recipe does not report the total:\n%s", recipe)
	}
}

// FR-foundation-18 runs each fuzz target for 30 seconds. `go test` fuzzes one target for
// each run, so the recipe lists the targets and runs each one.
func TestMakefileFuzzTargetRunsEachTargetFor30Seconds(t *testing.T) {
	recipe := makefileRecipe(t, "fuzz")

	if !strings.Contains(recipe, "-list") {
		t.Errorf("the fuzz recipe lists no fuzz target:\n%s", recipe)
	}

	if !strings.Contains(recipe, "-fuzztime") {
		t.Errorf("the fuzz recipe bounds no fuzz run:\n%s", recipe)
	}

	if !strings.Contains(recipe, "30s") {
		t.Errorf("the fuzz recipe does not run a target for 30 seconds:\n%s", recipe)
	}

	// FR-fuzz-26 fails the run when a target finds a crash. The recipe runs the targets
	// in a loop, and a loop without this exit reports success after a crash.
	if !strings.Contains(recipe, "|| exit 1") {
		t.Errorf("the fuzz recipe does not stop on a failed run:\n%s", recipe)
	}
}

// FR-foundation-19 and FR-foundation-20 measure the benchmarks. A unit test in the same
// package spawns `bash`, `curl` and `tar`, and one test resolves a reserved name, so a
// recipe without a `-run` filter measures the benchmarks and runs those tests too.
func TestMakefileBenchTargetRunsNoUnitTest(t *testing.T) {
	recipe := makefileRecipe(t, "bench")

	if !strings.Contains(recipe, "-bench=.") {
		t.Errorf("the bench recipe runs no benchmark:\n%s", recipe)
	}

	if !strings.Contains(recipe, "-benchmem") {
		t.Errorf("the bench recipe reports no allocation count:\n%s", recipe)
	}

	// `make` reads `$$` as one dollar sign, so the recipe passes `-run '^$'` to `go test`.
	// That pattern matches no test name. The `fuzz` target uses the same form.
	if !strings.Contains(recipe, `-run '^$$'`) {
		t.Errorf("the bench recipe does not hold the unit tests back:\n%s", recipe)
	}
}

// FR-foundation-3 requires the name of every enabled linter. `default: none` disables the
// implicit set, so the enable list is the whole set.
func TestGolangciConfigNamesEveryEnabledLinter(t *testing.T) {
	config := readRepoFile(t, ".golangci.yml")

	if !strings.Contains(config, `version: "2"`) {
		t.Errorf(".golangci.yml does not declare the version 2 format")
	}

	if !strings.Contains(config, "  default: none") {
		t.Errorf(".golangci.yml does not set `default: none`, so it names no complete linter set")
	}

	enabled := regexp.MustCompile(`(?ms)^  enable:\n((?:    - \w+\n)+)`).FindStringSubmatch(config)
	if enabled == nil {
		t.Fatalf(".golangci.yml names no enabled linter")
	}

	if strings.Count(enabled[1], "- ") < 5 {
		t.Errorf(".golangci.yml enables fewer than five linters:\n%s", enabled[1])
	}
}

// TestReleaseWorkflowNamesTheGoToolchainRange holds the release workflow at the range that
// every job of `.github/workflows/ci.yml` names. This test owns
// `.github/workflows/release.yml`, and `TestCIWorkflowNamesOneGoVersion` above owns
// `.github/workflows/ci.yml`. Neither test reads the file of the other.
//
// The test named Go 1.24 until 2026-08-13, and it cited the module floor. #473 measured
// that the two files then held different Go versions: CI proved that the library calls no
// vulnerable function, and this workflow built the artifact that calls nine of them.
// `go.mod` states a language version rather than a toolchain, so the module floor decides
// no toolchain here. Issue #473 is the reversal path.
//
// **No pull request runs the release workflow**, because a tag push is its only trigger.
// So this test is the one check that reads the version before a tag does.
func TestReleaseWorkflowNamesTheGoToolchainRange(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/release.yml")

	versions := regexp.MustCompile(`(?m)^ *go-version: '(.*)'$`).FindAllStringSubmatch(workflow, -1)
	if versions == nil {
		t.Fatalf(".github/workflows/release.yml names no Go version")
	}

	for _, version := range versions {
		if version[1] != goToolchainRange {
			t.Errorf("the release workflow builds on Go %q, and the workflows name %q",
				version[1], goToolchainRange)
		}
	}
}
