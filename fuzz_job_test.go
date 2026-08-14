package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// The two fuzz jobs are build gates, and no Go code reads either one at run time. The tests
// below hold FR-fuzz-25 through FR-fuzz-29, so that a later edit cannot drop a step without
// a failure. #47 added them on 2026-08-14.
//
// `workflowJobCommands` of `coverage_floor_test.go` reads a job without its comment lines.
// Every phrase below therefore reads a command, and never the prose above it.
//
// **No test below runs either workflow.** A workflow runs on a runner, and this suite runs
// on a developer machine.
//
// **No test below holds FR-fuzz-30, and no test of this repository holds it.** That
// requirement states that `go test ./...` replays every seed input with no fuzz time, and
// the run itself is the proof: `go test` starts one subtest for each seed of each target.
// A run on 2026-08-14 reported 91 passing seed subtests over the 15 targets, at exit 0.
// `fuzz_seed_corpus_test.go` reads the content of each seed, which is a different question.

// nightlyFuzzWorkflow names the file that FR-fuzz-27 names.
const nightlyFuzzWorkflow = ".github/workflows/fuzz.yml"

// TestThePullRequestFuzzJobRunsTheFuzzTarget holds FR-fuzz-25 and FR-fuzz-26.
//
// `make fuzz` runs each target for 30 seconds, and it exits 1 on the first target that
// fails. So the job holds both requirements in one command, and the `Makefile` states the
// fuzz time once for the job and for a developer.
func TestThePullRequestFuzzJobRunsTheFuzzTarget(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "fuzz")

	if !strings.Contains(commands, "make fuzz") {
		t.Errorf("the fuzz job of the CI workflow runs no fuzz target:\n%s", commands)
	}
}

// TestTheFuzzTargetRunsEachTargetForThirtySeconds holds the fuzz time of FR-fuzz-25. The
// job runs `make fuzz`, so the recipe carries the number.
func TestTheFuzzTargetRunsEachTargetForThirtySeconds(t *testing.T) {
	recipe := makefileRecipe(t, "fuzz")

	if !strings.Contains(recipe, "-fuzztime 30s") {
		t.Errorf("the fuzz target does not run each target for 30 seconds:\n%s", recipe)
	}
}

// TestThePullRequestFuzzJobAddsNoTrigger holds the batch model of this project. This
// project runs CI once for each batch: a member pull request targets an integration
// branch, and it carries `[skip ci]`. A trigger inside the fuzz job would start the job on
// a member pull request, and it would spend a runner for each member.
//
// The job therefore names no `on:` key of its own, and the two triggers at the head of the
// file reach it.
func TestThePullRequestFuzzJobAddsNoTrigger(t *testing.T) {
	commands := workflowJobCommands(t, ".github/workflows/ci.yml", "fuzz")

	// The pattern reads a mapping key, and `runs-on:` therefore reads as no trigger.
	trigger := regexp.MustCompile(`(?m)^ *(on|pull_request|push|schedule):`)
	if match := trigger.FindString(commands); match != "" {
		t.Errorf("the fuzz job of the CI workflow holds %q, and the file states the triggers:\n%s", strings.TrimSpace(match), commands)
	}
}

// workflowWithoutComments returns the workflow with every comment line removed.
//
// A comment of this repository quotes the command it explains, so a test that reads the
// whole file reads the prose too. `TestNoWorkflowSetsTheSeedGenerationVariable` measured
// that: the comment above the refusal step names `JA4PLUS_SEEDGEN=1`, and the file assigns
// nothing.
func workflowWithoutComments(t *testing.T, path string) string {
	t.Helper()

	lines := []string{}
	for _, line := range strings.Split(readRepoFile(t, path), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

// TestNoWorkflowSetsTheSeedGenerationVariable holds the trap that #46 recorded.
//
// `JA4PLUS_SEEDGEN=1` turns the seed corpus guard from a comparison into a write. A
// workflow that sets it rewrites every seed to match the code, and the guard then reports
// success whatever the code does. An engineer sets the variable by hand after a deliberate
// change to a seed.
//
// The test reads an assignment and a YAML mapping key. It does not read
// `"${JA4PLUS_SEEDGEN:-}"`, which is the refusal step below.
func TestNoWorkflowSetsTheSeedGenerationVariable(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", nightlyFuzzWorkflow} {
		workflow := workflowWithoutComments(t, path)

		if strings.Contains(workflow, "JA4PLUS_SEEDGEN=") {
			t.Errorf("%s assigns JA4PLUS_SEEDGEN, and the seed corpus guard then writes rather than compares", path)
		}

		if regexp.MustCompile(`(?m)^ *JA4PLUS_SEEDGEN:`).MatchString(workflow) {
			t.Errorf("%s holds JA4PLUS_SEEDGEN as an environment key, and the seed corpus guard then writes rather than compares", path)
		}
	}
}

// TestEachFuzzJobRefusesASeedCorpusWrite holds the second half of the trap. An absent
// assignment proves what the file states, and it proves nothing about the runner. Each job
// therefore reads the environment and exits when the variable carries a value.
func TestEachFuzzJobRefusesASeedCorpusWrite(t *testing.T) {
	jobs := map[string]string{
		".github/workflows/ci.yml": "fuzz",
		nightlyFuzzWorkflow:        "fuzz",
	}

	for path, job := range jobs {
		commands := workflowJobCommands(t, path, job)

		if !strings.Contains(commands, `if [ -n "${JA4PLUS_SEEDGEN:-}" ]; then`) {
			t.Errorf("the %s job of %s does not refuse a seed corpus write:\n%s", job, path, commands)
		}
	}
}

// TestTheNightlyFuzzWorkflowRunsOnASchedule holds FR-fuzz-27.
//
// The documentation states that a scheduled workflow runs on the default branch alone:
// `Scheduled workflows run on the latest commit on the default branch.` So no run starts
// until this file reaches `master`.
func TestTheNightlyFuzzWorkflowRunsOnASchedule(t *testing.T) {
	workflow := readRepoFile(t, nightlyFuzzWorkflow)

	if !strings.Contains(workflow, "  schedule:\n") {
		t.Fatalf("%s holds no schedule trigger", nightlyFuzzWorkflow)
	}

	if !regexp.MustCompile(`(?m)^ *- cron: '[^']+'$`).MatchString(workflow) {
		t.Errorf("%s holds no cron expression", nightlyFuzzWorkflow)
	}
}

// TestTheNightlyFuzzWorkflowRunsEachTargetForTenMinutes holds the fuzz time of FR-fuzz-27.
//
// **`-timeout 0` is load-bearing.** `go help testflag` states `-timeout d ... The default
// is 10 minutes (10m).`, so a 10-minute fuzz run under the default timeout panics before
// the run ends.
func TestTheNightlyFuzzWorkflowRunsEachTargetForTenMinutes(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "fuzz")

	if !strings.Contains(commands, "-fuzztime 10m") {
		t.Errorf("the nightly job does not run a target for 10 minutes:\n%s", commands)
	}

	if !strings.Contains(commands, "-timeout 0") {
		t.Errorf("the nightly job keeps the 10-minute default test timeout, which ends a 10-minute fuzz run:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowReadsEveryTargetFromTheTree holds the coverage of FR-fuzz-27.
// A hard-coded list of targets leaves a later target unfuzzed, and no check reports it.
func TestTheNightlyFuzzWorkflowReadsEveryTargetFromTheTree(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "targets")

	if !strings.Contains(commands, `go test -list '^Fuzz'`) {
		t.Errorf("the nightly workflow does not read the target list from the tree:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowDeclaresTheIssuePermission holds the edge case that
// `docs/specs/features/06-fuzz-testing.md` names: the nightly job runs on a repository with
// no open-issue permission. FR-fuzz-28 needs the scope, and the documentation states
// `If you specify the access for any of these permissions, all of those that are not
// specified are set to none.`
func TestTheNightlyFuzzWorkflowDeclaresTheIssuePermission(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "fuzz")

	if !strings.Contains(commands, "issues: write") {
		t.Errorf("the nightly fuzz job declares no issues: write permission:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowWidensNoOtherJob holds the write scope to the one job that
// needs it. The `targets` job lists names, and a list needs no write scope.
func TestTheNightlyFuzzWorkflowWidensNoOtherJob(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "targets")

	if strings.Contains(commands, "permissions:") {
		t.Errorf("the targets job declares a permissions block, and it writes nothing:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowOpensAnIssueForACrashAlone holds FR-fuzz-28, and it holds the
// separation that issue #568 earned.
//
// **A timeout is not a crash.** A stalled target leaves no input file, so the classify step
// reads the tree rather than the exit status alone. An issue for each stalled night is a
// false report.
func TestTheNightlyFuzzWorkflowOpensAnIssueForACrashAlone(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "fuzz")

	if !strings.Contains(commands, "gh issue create") {
		t.Errorf("the nightly fuzz job opens no issue:\n%s", commands)
	}

	if !strings.Contains(commands, "if: steps.classify.outputs.kind == 'crash'") {
		t.Errorf("the nightly fuzz job does not hold the issue back to a crash:\n%s", commands)
	}

	if !strings.Contains(commands, "git ls-files --others") {
		t.Errorf("the nightly fuzz job reads no input file, so it cannot separate a crash from a stall:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowAttachesTheCrashingInput holds FR-fuzz-29.
//
// The body carries the input as base64, because a crashing input is attacker-controlled and
// a Markdown code fence ends at a line of three backticks. The base64 alphabet holds no
// backtick. The artifact carries the same input and the whole log.
func TestTheNightlyFuzzWorkflowAttachesTheCrashingInput(t *testing.T) {
	commands := workflowJobCommands(t, nightlyFuzzWorkflow, "fuzz")

	if !strings.Contains(commands, `base64 < "$CRASHER"`) {
		t.Errorf("the nightly fuzz job writes no crashing input into the issue body:\n%s", commands)
	}

	if !strings.Contains(commands, "uses: actions/upload-artifact@") {
		t.Errorf("the nightly fuzz job uploads no report:\n%s", commands)
	}
}

// TestTheNightlyFuzzWorkflowPassesNoTemplateToAShell holds the injection rule for this
// file. A value that a template writes into a command reaches the shell as code, and a
// value that an `env:` key carries reaches it as data.
func TestTheNightlyFuzzWorkflowPassesNoTemplateToAShell(t *testing.T) {
	workflow := readRepoFile(t, nightlyFuzzWorkflow)

	inRun := false
	for _, line := range strings.Split(workflow, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "run: |") {
			inRun = true
			continue
		}

		// A key at the step level ends the script block. Every script line of this file
		// carries more indentation than its key.
		if inRun && trimmed != "" && !strings.HasPrefix(line, "          ") {
			inRun = false
		}

		if inRun && strings.Contains(line, "${{") {
			t.Errorf("a run script holds a template, which reaches the shell as code: %q", trimmed)
		}
	}
}

// TestTheNightlyFuzzWorkflowNamesTheGoToolchainRange holds FR-foundation-2 for the file
// that #47 added. `TestCIWorkflowNamesOneGoVersion` of `foundation_test.go` owns
// `.github/workflows/ci.yml`, and `TestReleaseWorkflowNamesTheGoToolchainRange` owns
// `.github/workflows/release.yml`. No test reads the file of another test.
func TestTheNightlyFuzzWorkflowNamesTheGoToolchainRange(t *testing.T) {
	workflow := readRepoFile(t, nightlyFuzzWorkflow)

	versions := regexp.MustCompile(`(?m)^ *go-version: '(.*)'$`).FindAllStringSubmatch(workflow, -1)
	if versions == nil {
		t.Fatalf("%s holds no literal go-version input", nightlyFuzzWorkflow)
	}

	for _, version := range versions {
		if version[1] != goToolchainRange {
			t.Errorf("a job of %s names go-version %q, and FR-foundation-2 names one range", nightlyFuzzWorkflow, version[1])
		}
	}
}

// TestTheNightlyFuzzWorkflowPinsEveryAction holds FR-supply-12 for the file that #47 added.
// A tag moves and a commit hash does not.
func TestTheNightlyFuzzWorkflowPinsEveryAction(t *testing.T) {
	workflow := readRepoFile(t, nightlyFuzzWorkflow)

	// A pinned reference carries a trailing comment that names the version, so the pattern
	// reads the reference and it stops at the space before that comment.
	uses := regexp.MustCompile(`(?m)^ *(?:- )?uses: (\S+)`).FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatalf("%s names no action", nightlyFuzzWorkflow)
	}

	pinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, reference := range uses {
		if !pinned.MatchString(reference[1]) {
			t.Errorf("the action reference %q names no 40-character commit hash", reference[1])
		}
	}
}
