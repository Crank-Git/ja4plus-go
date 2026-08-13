package ja4plus

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The coverage floor is a build gate, and no Go code reads it at run time. These tests
// hold the gate, so that a later edit cannot drop it without a failure.

// TestTheRepositoryHoldsACoverageFloorFile holds FR-supply-30. The tree held no such file
// until #68 created it on 2026-08-13, and step 5 of the `## A change is done when` list in
// `CLAUDE.md` was unrunnable until then.
func TestTheRepositoryHoldsACoverageFloorFile(t *testing.T) {
	floor := strings.TrimSpace(readRepoFile(t, ".coverage-floor"))

	if floor == "" {
		t.Fatalf(".coverage-floor holds no value")
	}
}

// TestTheCoverageFloorIsOneNumber holds the shape that the CI coverage job reads.
// The job passes the value to `awk` as a number, and a second line or a unit sign makes
// that comparison read something the file never states.
func TestTheCoverageFloorIsOneNumber(t *testing.T) {
	content := readRepoFile(t, ".coverage-floor")
	floor := strings.TrimSpace(content)

	if strings.ContainsAny(floor, " \t\n") {
		t.Fatalf(".coverage-floor holds more than one value: %q", content)
	}

	value, err := strconv.ParseFloat(floor, 64)
	if err != nil {
		t.Fatalf(".coverage-floor holds %q, and the CI job reads a number: %v", floor, err)
	}

	if value < 0 || value > 100 {
		t.Errorf(".coverage-floor holds %v, and a statement coverage is 0 through 100", value)
	}
}

// TestTheCoverageJobReadsTheFloorFile holds FR-supply-17. A job that measures the coverage
// and reads no floor gates nothing.
func TestTheCoverageJobReadsTheFloorFile(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	if !strings.Contains(workflow, "\n  coverage:\n") {
		t.Fatalf(".github/workflows/ci.yml holds no coverage job")
	}

	if !strings.Contains(workflow, "< .coverage-floor") {
		t.Errorf("the coverage job reads no value from .coverage-floor")
	}
}

// TestTheCoverageJobRunsTheCoverTarget holds FR-supply-16. FR-foundation-17 holds the
// measurement command in the `cover` target, so the job and a developer measure one
// command.
func TestTheCoverageJobRunsTheCoverTarget(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	if !strings.Contains(workflow, "make cover") {
		t.Errorf("the coverage job does not run the cover target")
	}
}

// TestTheCoverageJobPublishesABuildSummary holds FR-supply-20. The build summary is the
// one reader-facing output of this workflow.
func TestTheCoverageJobPublishesABuildSummary(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	if !strings.Contains(workflow, `echo "## Coverage"`) {
		t.Errorf("the coverage job writes no Coverage section to the build summary")
	}
}

// TestTheCIWorkflowGrantsNoJobLevelPermission holds FR-supply-15. The workflow-level block
// gives every job `contents: read`, and a job-level block can only widen it.
//
// FR-supply-19 raises the floor from a person's commit for this reason. A run that
// rewrites the tracked file needs `contents: write`.
func TestTheCIWorkflowGrantsNoJobLevelPermission(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	blocks := regexp.MustCompile(`(?m)^ *permissions:`).FindAllString(workflow, -1)
	if len(blocks) != 1 {
		t.Fatalf(".github/workflows/ci.yml holds %d permissions blocks, and FR-supply-15 names one", len(blocks))
	}

	if blocks[0] != "permissions:" {
		t.Errorf("the one permissions block is indented as %q, so it sits inside a job", blocks[0])
	}
}
