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

func TestGoModDeclaresGo124(t *testing.T) {
	goMod := readRepoFile(t, "go.mod")

	if !regexp.MustCompile(`(?m)^go 1\.24$`).MatchString(goMod) {
		t.Errorf("go.mod does not declare `go 1.24`:\n%s", goMod)
	}
}

func TestCIWorkflowTestsGo124Only(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	matrix := regexp.MustCompile(`(?m)^ *go-version: \[(.*)\]$`).FindStringSubmatch(workflow)
	if matrix == nil {
		t.Fatalf(".github/workflows/ci.yml holds no go-version matrix")
	}

	if matrix[1] != "'1.24'" {
		t.Errorf("the go-version matrix is [%s], and FR-foundation-2 names Go 1.24 only", matrix[1])
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

// The release workflow builds every artifact, so it must hold the same Go version as the
// module floor. A lower version fails the release and not the pull request.
func TestReleaseWorkflowBuildsOnGo124(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/release.yml")

	version := regexp.MustCompile(`(?m)^ *go-version: '(.*)'$`).FindStringSubmatch(workflow)
	if version == nil {
		t.Fatalf(".github/workflows/release.yml names no Go version")
	}

	if version[1] != "1.24" {
		t.Errorf("the release workflow builds on Go %s, and the module floor is 1.24", version[1])
	}
}
