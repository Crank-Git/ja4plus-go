package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// These tests hold FR-release-35c of `docs/specs/features/10-release.md`, which states
// that every artifact is built with `CGO_ENABLED=0`. `CLAUDE.md` `## Stack` states the
// same rule in prose.
//
// Issue #583 measured that the tree did not hold the rule. The workflow set `GOOS` and
// `GOARCH` alone, and the job runs on `ubuntu-latest`. `GOOS=linux GOARCH=amd64` is that
// runner's native pair, so the Go command took the native default of `CGO_ENABLED=1` for
// one build of five. That artifact linked glibc dynamically where the other four are
// static, and a user on a musl distribution or in a `scratch` container met the
// difference.
//
// The project manager took answer 1 of #583 on 2026-08-14: the workflow sets the
// variable, and the prose rule stays. **Issue #583 is the reversal path.** A maintainer
// who prefers answer 2 says so there, and a later member changes the sentence rather than
// the workflow.
//
// **No pull request runs the release workflow**, because a tag push is its only trigger.
// So these tests are the one check that reads the build before a tag does.
//
// The shape follows `go_toolchain_statement_test.go`, which guards the other build claim
// of this repository. Both read a workflow file as text, because no test of this module
// parses YAML and the module depends on no YAML package.

// releaseWorkflowPath names the workflow that builds every released binary.
const releaseWorkflowPath = ".github/workflows/release.yml"

// releaseBuildStepName names the one step that builds a release artifact.
const releaseBuildStepName = "Build binaries"

// releaseBuildPlatforms names the five platforms that FR-release-35b requires.
var releaseBuildPlatforms = []string{
	"GOOS=linux GOARCH=amd64",
	"GOOS=linux GOARCH=arm64",
	"GOOS=darwin GOARCH=amd64",
	"GOOS=darwin GOARCH=arm64",
	"GOOS=windows GOARCH=amd64",
}

// cgoDisabled matches the mapping key that sets the variable to zero.
//
// It accepts a quoted value and a bare one, because YAML reads `0` as a number and
// GitHub Actions converts it to the string `0`. It rejects any other value, so an edit to
// `CGO_ENABLED: 1` fails rather than passes on the key alone.
var cgoDisabled = regexp.MustCompile(`(?m)^\s*CGO_ENABLED:\s*["']?0["']?\s*$`)

// cgoAnyValue matches the mapping key at any value, so a test can find a setting that
// sits outside the build step.
var cgoAnyValue = regexp.MustCompile(`(?m)^\s*CGO_ENABLED:\s*\S+\s*$`)

// releaseArtifactBuild matches a build command that writes an artifact into `dist/`.
var releaseArtifactBuild = regexp.MustCompile(`(?m)^.*go build .*-o dist/.*$`)

// releaseWorkflowStep returns the lines of one named step of the release workflow.
//
// The block starts at the `- name:` line of the step and it ends before the next step. A
// step of this file starts at six spaces, because `steps:` sits at four.
//
// It fails the test when no step carries the name, because a renamed step silently empties
// every assertion that reads the block.
func releaseWorkflowStep(t *testing.T, name string) string {
	t.Helper()

	const stepPrefix = "      - "

	lines := strings.Split(readRepoFile(t, releaseWorkflowPath), "\n")

	start := -1
	for index, line := range lines {
		if line == stepPrefix+"name: "+name {
			start = index
			break
		}
	}

	if start < 0 {
		t.Fatalf("%s holds no step named %q, and these tests read that step", releaseWorkflowPath, name)
	}

	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], stepPrefix) {
			end = index
			break
		}
	}

	return strings.Join(lines[start:end], "\n")
}

// FR-release-35c. A released binary that links the C name resolver reads `nsswitch.conf`
// and the glibc modules of the machine that runs it, and a static binary does not.
func TestTheReleaseBuildStepSetsCgoEnabledToZero(t *testing.T) {
	step := releaseWorkflowStep(t, releaseBuildStepName)

	if !cgoDisabled.MatchString(step) {
		t.Errorf("the %q step of %s does not set CGO_ENABLED to 0, and FR-release-35c requires it",
			releaseBuildStepName, releaseWorkflowPath)
	}
}

// FR-release-35b and FR-release-35c. A build that sits outside the step reads no step
// environment, so it takes the Go default and the guard above passes without covering it.
//
// The assertion reads every artifact build of the whole file rather than the step alone.
// A guard that reads the step alone guards nothing: a sixth build appended after the step
// would pass it.
func TestEveryReleaseArtifactIsBuiltInsideTheStepThatDisablesCgo(t *testing.T) {
	workflow := readRepoFile(t, releaseWorkflowPath)
	step := releaseWorkflowStep(t, releaseBuildStepName)

	builds := releaseArtifactBuild.FindAllString(workflow, -1)
	if len(builds) != len(releaseBuildPlatforms) {
		t.Fatalf("%s holds %d artifact builds, and FR-release-35b names %d",
			releaseWorkflowPath, len(builds), len(releaseBuildPlatforms))
	}

	for _, build := range builds {
		if !strings.Contains(step, build) {
			t.Errorf("this build sits outside the %q step, so it reads no CGO_ENABLED setting:\n%s",
				releaseBuildStepName, build)
		}
	}

	for _, platform := range releaseBuildPlatforms {
		if !strings.Contains(step, platform) {
			t.Errorf("the %q step builds no %s artifact, and FR-release-35b names that platform",
				releaseBuildStepName, platform)
		}
	}
}

// FR-release-35c. The setting is a step environment and never a job environment, because
// the `Run tests` step runs `go test -race` on the same runner and the race detector needs
// cgo there.
//
// Measured on 2026-08-14 for the runner's platform:
//
//	$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -race -o /dev/null ./cmd/ja4plus
//	go: -race requires cgo
//
// So a job-level setting turns the release red at the test step, and it never reaches the
// build it was written for. This test holds the shape that the measurement chose.
//
// Verified against <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions>,
// retrieved 2026-08-14. It states the precedence: `When more than one environment variable
// is defined with the same name, GitHub uses the most specific variable. For example, an
// environment variable defined in a step will override job and workflow environment
// variables with the same name, while the step executes.`
func TestNoReleaseSettingOutsideTheBuildStepDisablesCgo(t *testing.T) {
	workflow := readRepoFile(t, releaseWorkflowPath)
	step := releaseWorkflowStep(t, releaseBuildStepName)

	// The assertion counts the settings rather than searching the step for each one. A
	// job-level `CGO_ENABLED: "0"` and the step-level one differ by indentation alone, so
	// a substring search of the step finds the step's own line and reports nothing.
	inFile := len(cgoAnyValue.FindAllString(workflow, -1))
	inStep := len(cgoAnyValue.FindAllString(step, -1))

	if inFile != inStep {
		t.Errorf("%s holds %d CGO_ENABLED settings and the %q step holds %d, so %d of them reach the race detector of the test step",
			releaseWorkflowPath, inFile, releaseBuildStepName, inStep, inFile-inStep)
	}
}
