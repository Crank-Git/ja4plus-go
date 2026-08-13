package ja4plus

import (
	"strings"
	"testing"
)

// The benchmark job of `.github/workflows/ci.yml` is a build gate, and no Go code reads it
// at run time. These tests hold FR-supply-21 through FR-supply-24, so that a later edit
// cannot drop a step without a failure.
//
// `workflowJobCommands` of `coverage_floor_test.go` reads the job without its comment
// lines. Every phrase below therefore reads a command, and never the prose above it.
//
// **FR-supply-23 asks for a pull-request comment, and no test below holds one.** #69 read
// the requirement against FR-supply-15 and reported the tension. A comment needs
// `pull-requests: write`, `TestTheCIWorkflowGrantsNoJobLevelPermission` of
// `coverage_floor_test.go` refuses a job-level block, and the documentation states that a
// pull request from a fork gets a read-only token whatever the block says. The maintainer
// decides, and issue #69 is the reversal path.

// TestTheBenchmarkJobRunsTheBenchTarget holds FR-supply-21. FR-foundation-19 and
// FR-foundation-20 hold the command in the `bench` target, so the job and a developer
// measure one command.
//
// FR-supply-21 names `go test -bench=. -benchmem ./...`, and the target adds `-run '^$'`.
// `TestMakefileBenchTargetRunsNoUnitTest` of `foundation_test.go` states why: a unit test
// of this package spawns `bash`, `curl` and `tar`. This job measures two commits, so the
// literal command would run the whole suite twice.
func TestTheBenchmarkJobRunsTheBenchTarget(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	if !strings.Contains(commands, "make bench") {
		t.Errorf("the benchmark job does not measure the head:\n%s", commands)
	}

	if !strings.Contains(commands, "make -C base bench") {
		t.Errorf("the benchmark job does not measure the base checkout:\n%s", commands)
	}
}

// TestTheBenchmarkJobMeasuresTheBaseBranch holds FR-supply-22. This repository stores no
// benchmark result, so a job that measures the head alone compares nothing.
//
// The documentation states that `github.base_ref` names `The base_ref or target branch of
// the pull request in a workflow run.`
func TestTheBenchmarkJobMeasuresTheBaseBranch(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	if !strings.Contains(commands, "ref: ${{ github.base_ref }}") {
		t.Errorf("the benchmark job checks out no base branch:\n%s", commands)
	}

	if !strings.Contains(commands, "path: base") {
		t.Errorf("the benchmark job places the base checkout over the head checkout:\n%s", commands)
	}
}

// TestTheBenchmarkJobWarnsAboveTwentyPercent holds FR-supply-23 as far as this workflow
// reaches it. The job marks a benchmark more than 20 percent slower than the base branch,
// and it prints one warning annotation.
//
// A threshold of `1.20` marks a change above 20 percent, and it leaves a change of exactly
// 20 percent alone. The measurement on 2026-08-13, against a base of 8439 ns/op: a head of
// 10126 ns/op wrote `+19.99 percent` and no warning, and a head of 10127 ns/op wrote
// `+20.00 percent **slower**` and one warning.
func TestTheBenchmarkJobWarnsAboveTwentyPercent(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	if !strings.Contains(commands, "threshold=1.20") {
		t.Errorf("the benchmark job names no 20 percent threshold:\n%s", commands)
	}

	if !strings.Contains(commands, "::warning title=Benchmark regression::") {
		t.Errorf("the benchmark job warns on no regression:\n%s", commands)
	}
}

// TestTheBenchmarkJobPublishesABuildSummary holds the one reader-facing output of this
// job. A step that writes the table to standard output reaches no reader of the pull
// request.
func TestTheBenchmarkJobPublishesABuildSummary(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	if !strings.Contains(commands, `echo "## Benchmarks"`) {
		t.Errorf("the benchmark job writes no Benchmarks heading:\n%s", commands)
	}

	if !strings.Contains(commands, `>> "$GITHUB_STEP_SUMMARY"`) {
		t.Errorf("the benchmark job writes no build summary:\n%s", commands)
	}
}

// TestTheBenchmarkJobReportsTheHeadWithoutABase holds the edge case that
// `docs/specs/features/07-supply-chain.md` states: `The benchmark comparison has no base
// result. | The job posts the head results and does not warn.`
//
// A push to `main` or to `master` reaches no base branch, so this path runs on every push.
func TestTheBenchmarkJobReportsTheHeadWithoutABase(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	if !strings.Contains(commands, "This run measured no base result, so it reports the head results alone.") {
		t.Errorf("the benchmark job reports no head result without a base:\n%s", commands)
	}
}

// TestTheBenchmarkJobFailsNoBuild holds FR-supply-24. Runner variance produces a false
// regression, so a benchmark warns and it never blocks.
//
// The test reads two things. Each `make` call holds its exit status back, and no command
// of the job exits with a status above 0. The measurement on 2026-08-13 ran the compare
// step under `bash -e` against eight cases, and every one exited 0.
func TestTheBenchmarkJobFailsNoBuild(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "benchmark")

	for _, line := range strings.Split(commands, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "make ") && !strings.Contains(trimmed, "|| status=$?") {
			t.Errorf("a benchmark step fails the build on a benchmark failure: %q", trimmed)
		}

		for _, status := range []string{"exit 1", "exit 2", "exit 3"} {
			if strings.Contains(trimmed, status) {
				t.Errorf("the benchmark job holds %q, and FR-supply-24 fails no build: %q", status, trimmed)
			}
		}
	}
}

// TestTheBenchmarkJobRunsAfterTheCoverageJob holds the file order that #68 left. A later
// member appends its job beside the last one, and a reader of the file reads the jobs in
// the order the epic built them.
func TestTheBenchmarkJobRunsAfterTheCoverageJob(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	coverage := strings.Index(workflow, "\n  coverage:\n")
	if coverage < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no coverage job")
	}

	benchmark := strings.Index(workflow, "\n  benchmark:\n")
	if benchmark < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no benchmark job")
	}

	if benchmark < coverage {
		t.Errorf("the benchmark job sits above the coverage job, and #68 placed coverage last")
	}
}
