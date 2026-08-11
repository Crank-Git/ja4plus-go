package ja4plus

import (
	"os"
	"regexp"
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
