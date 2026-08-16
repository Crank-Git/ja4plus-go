package repocheck

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The coverage floor is a build gate, and no Go code reads it at run time. These tests
// hold the gate, so that a later edit cannot drop it without a failure.

// TestTheRepositoryHoldsACoverageFloorFile holds FR-supply-30. The tree held no such file
// until #68 created it on 2026-08-13. Step 5 of the `## A change is done when` list in
// `CLAUDE.md` was unrunnable until then.
func TestTheRepositoryHoldsACoverageFloorFile(t *testing.T) {
	floor := strings.TrimSpace(readRepoFile(t, ".coverage-floor"))

	if floor == "" {
		t.Fatalf(".coverage-floor holds no value")
	}
}

// TestTheCoverageFloorIsOneNumber holds the shape that the CI coverage job reads.
// The job passes the value to `awk` as a number. A second line or a unit sign makes that
// comparison read something the file never states.
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

// workflowJobCommands returns the lines of one job of a workflow, without a comment line
// and without a blank line.
//
// A test that reads the whole file passes on a comment that holds the phrase, and a
// comment runs no command. Each phrase this file holds appears in a comment of the
// coverage job too, so a test that reads the file measures the prose rather than the job.
//
// The job ends at the next key of the same indent, and the last job of the file ends at
// the end of the file.
func workflowJobCommands(t *testing.T, path string, job string) string {
	t.Helper()

	commands := []string{}
	found := false

	for _, line := range strings.Split(readRepoFile(t, path), "\n") {
		if !found {
			found = line == "  "+job+":"
			continue
		}

		if regexp.MustCompile(`^  \S`).MatchString(line) && !strings.HasPrefix(line, "  #") {
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		commands = append(commands, line)
	}

	if !found {
		t.Fatalf("%s holds no %s job", path, job)
	}

	return strings.Join(commands, "\n")
}

// TestTheCoverageJobReadsTheFloorFile holds FR-supply-17. A job that measures the coverage
// and reads no floor gates nothing.
//
// The test reads the failing branch too. A job that reads the file and never exits on a
// low total reports a number, and it gates nothing.
func TestTheCoverageJobReadsTheFloorFile(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "coverage")

	if !strings.Contains(commands, "< .coverage-floor") {
		t.Errorf("the coverage job reads no value from .coverage-floor:\n%s", commands)
	}

	if !strings.Contains(commands, "the coverage fell below the floor") {
		t.Errorf("the coverage job names no total below the floor:\n%s", commands)
	}

	if !strings.Contains(commands, "exit 1") {
		t.Errorf("the coverage job exits 0 on every total, so it gates nothing:\n%s", commands)
	}
}

// TestTheCoverageJobRunsTheCoverTarget holds FR-supply-16. FR-foundation-17 holds the
// measurement command in the `cover` target, so the job and a developer measure one
// command.
func TestTheCoverageJobRunsTheCoverTarget(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "coverage")

	if !strings.Contains(commands, "make cover") {
		t.Errorf("the coverage job does not run the cover target:\n%s", commands)
	}
}

// TestTheCoverageJobFetchesTheCorpus holds the environment that `.coverage-floor`
// describes. `make cover` reads the FoxIO corpus, and `.gitignore` holds the corpus out of
// the tree, so one command reports two numbers.
//
// The measurement on 2026-08-13, at commit `83f2127` and at commit `7210e80`: `make cover`
// reports 75.0 percent with the corpus and 74.4 percent without it. #68 measured 75.0 with
// the corpus, the coverage job fetched no corpus, and the first full run of Epic 7 failed
// on that difference.
//
// A later edit that drops these steps lowers the total by 0.6 points, and the floor
// comparison then reports a defect of the tests that the tree does not hold.
func TestTheCoverageJobFetchesTheCorpus(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "coverage")

	if !strings.Contains(commands, "make corpus") {
		t.Errorf("the coverage job fetches no corpus, so it measures 0.6 points low:\n%s", commands)
	}

	if !strings.Contains(commands, "testdata/foxio.pin") {
		t.Errorf("the coverage job reads no corpus pin, so it caches no corpus:\n%s", commands)
	}

	if !strings.Contains(commands, "foxio-corpus-") {
		t.Errorf("the coverage job names no corpus cache key, so every run downloads the archive:\n%s", commands)
	}

	if !strings.Contains(commands, "holds no capture") {
		t.Errorf("the coverage job reports no absent corpus, so a failed fetch names the wrong repair:\n%s", commands)
	}
}

// TestTheCoverageJobPublishesABuildSummary holds FR-supply-20. The build summary is the
// one reader-facing output of this workflow.
//
// The test reads the redirection too. A step that writes the heading to standard output
// reaches no reader of the pull request.
func TestTheCoverageJobPublishesABuildSummary(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "coverage")

	if !strings.Contains(commands, `echo "## Coverage"`) {
		t.Errorf("the coverage job writes no Coverage heading:\n%s", commands)
	}

	if !strings.Contains(commands, `>> "$GITHUB_STEP_SUMMARY"`) {
		t.Errorf("the coverage job writes no build summary:\n%s", commands)
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
