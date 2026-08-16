package repocheck

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The scheduled mutation sweep is a build gate, and no Go code reads it at run time. The
// cases below hold FR-mutation-17 through FR-mutation-20 of
// `docs/specs/features/15-mutation-sweep.md`, so that a later edit cannot drop a step
// without a failure. #93 added them on 2026-08-14.
//
// **Each reader below is a function of text, and a case feeds it a defeated workflow.** A
// guard that reads the tracked file alone proves that the file passes it today, and it
// proves nothing about what the guard rejects. Batch #342 found a guard of that shape, and
// `.claude/rules/cross-member-review.md` category 6 names it: a named guard that guards
// nothing.
//
// **No case below runs the workflow.** A workflow runs on a runner, and this suite runs on
// a developer machine.

// mutationWorkflow names the file that FR-mutation-17 needs.
const mutationWorkflow = ".github/workflows/mutation.yml"

// preReleaseFeatureFile is the file that FR-mutation-20 names.
const preReleaseFeatureFile = "docs/specs/features/16-pre-release-validation.md"

// workflowTriggers returns every trigger key that one workflow names under `on:`.
//
// The reader takes the text rather than a path, so a case can feed it a defeated workflow.
// It reads a key at two spaces of indentation, because a workflow of this repository writes
// the `on:` mapping at the top level.
func workflowTriggers(text string) []string {
	found := []string{}
	inOn := false

	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line == "on:" {
			inOn = true

			continue
		}
		// A key at the top level ends the `on:` mapping.
		if inOn && line != "" && !strings.HasPrefix(line, " ") {
			inOn = false
		}
		if !inOn {
			continue
		}

		key := regexp.MustCompile(`^  ([a-z_]+):`).FindStringSubmatch(line)
		if key != nil {
			found = append(found, key[1])
		}
	}

	sort.Strings(found)

	return found
}

// TestTheTriggerReaderReportsAPullRequestTrigger proves that workflowTriggers can fail.
//
// The text below is the tracked workflow with one trigger added. A reader that returned the
// same answer for both texts would hold FR-mutation-17 and FR-mutation-19 without reading
// anything.
func TestTheTriggerReaderReportsAPullRequestTrigger(t *testing.T) {
	defeated := "name: x\n" +
		"on:\n" +
		"  schedule:\n" +
		"    - cron: '47 3 * * *'\n" +
		"  pull_request:\n" +
		"  workflow_dispatch:\n" +
		"jobs:\n" +
		"  sweep:\n" +
		"    runs-on: ubuntu-latest\n"

	found := strings.Join(workflowTriggers(defeated), ",")
	if found != "pull_request,schedule,workflow_dispatch" {
		t.Errorf("the trigger reader read %q of the defeated workflow, and it reads three triggers", found)
	}

	// The reader stops at the top-level key, so a job name is no trigger.
	if strings.Contains(found, "jobs") || strings.Contains(found, "sweep") {
		t.Errorf("the trigger reader read a job name as a trigger: %q", found)
	}
}

// TestTheMutationWorkflowRunsOnAScheduleAndOnNoPullRequest holds FR-mutation-17 and
// FR-mutation-19.
//
// A `pull_request` trigger or a `push` trigger would put a 60-minute sweep on the merge
// path, and `CLAUDE.md` states that `make mutate` gates nothing.
func TestTheMutationWorkflowRunsOnAScheduleAndOnNoPullRequest(t *testing.T) {
	triggers := workflowTriggers(readRepoFile(t, mutationWorkflow))

	held := map[string]bool{}
	for _, trigger := range triggers {
		held[trigger] = true
	}

	if !held["schedule"] {
		t.Errorf("%s names no schedule trigger, and FR-mutation-17 needs one: %v", mutationWorkflow, triggers)
	}

	for _, forbidden := range []string{"pull_request", "pull_request_target", "push", "merge_group"} {
		if held[forbidden] {
			t.Errorf("%s names the %s trigger, and FR-mutation-19 keeps the sweep off the merge path", mutationWorkflow, forbidden)
		}
	}

	if !regexp.MustCompile(`(?m)^ *- cron: '[^']+'$`).MatchString(readRepoFile(t, mutationWorkflow)) {
		t.Errorf("%s holds no cron expression, so the schedule trigger starts no run", mutationWorkflow)
	}
}

// TestNoWorkflowRunsTheMutationSweepOnAPullRequest holds FR-mutation-19 across every
// workflow.
//
// The case above reads one file, and this one reads the complement. A second workflow that
// ran `make mutate` on a pull request would break FR-mutation-19, and no case that names
// one file would report it.
func TestNoWorkflowRunsTheMutationSweepOnAPullRequest(t *testing.T) {
	// `readRepoFile` reads a relative path, so this suite runs at the repository root.
	entries, err := os.ReadDir(".github/workflows")
	if err != nil {
		t.Fatalf("read the workflow directory: %v", err)
	}

	read := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		read++

		path := ".github/workflows/" + entry.Name()
		text := workflowWithoutComments(t, path)
		if !strings.Contains(text, "make mutate") {
			continue
		}

		for _, trigger := range workflowTriggers(text) {
			if trigger == "pull_request" || trigger == "pull_request_target" || trigger == "push" || trigger == "merge_group" {
				t.Errorf("%s runs the mutation sweep and it names the %s trigger, and FR-mutation-19 keeps the sweep off the merge path", path, trigger)
			}
		}
	}

	// An empty walk would report a clean tree on every repository.
	if read == 0 {
		t.Fatal("the walk read no workflow, so this case checked nothing")
	}
}

// TestTheContinuousIntegrationWorkflowRunsNoMutationSweep holds the second half of
// FR-mutation-19. `.github/workflows/ci.yml` holds every required check of a pull request,
// so a `make mutate` there would gate a merge whatever the trigger states.
func TestTheContinuousIntegrationWorkflowRunsNoMutationSweep(t *testing.T) {
	workflow := workflowWithoutComments(t, ".github/workflows/ci.yml")

	if strings.Contains(workflow, "make mutate") {
		t.Errorf(".github/workflows/ci.yml runs the mutation sweep, and FR-mutation-19 states that the sweep does not block a merge")
	}

	if strings.Contains(workflow, "gremlins") {
		t.Errorf(".github/workflows/ci.yml names the mutation tool, and FR-mutation-19 states that the sweep does not block a merge")
	}
}

// TestTheChangeIsDoneStepsNameNoMutationSweep holds FR-mutation-19 for the developer gate.
//
// `CLAUDE.md` `## A change is done when` names the steps that a change meets before it
// lands. A `make mutate` step there would gate every change on a sweep that takes 20
// minutes, and `CLAUDE.md` states that the target gates nothing.
func TestTheChangeIsDoneStepsNameNoMutationSweep(t *testing.T) {
	text := readRepoFile(t, "CLAUDE.md")

	start := strings.Index(text, "## A change is done when")
	if start < 0 {
		t.Fatal("CLAUDE.md holds no `## A change is done when` section")
	}

	section := text[start:]
	if end := strings.Index(section[1:], "\n## "); end >= 0 {
		section = section[:end+1]
	}

	if strings.Contains(section, "make mutate") {
		t.Errorf("`## A change is done when` of CLAUDE.md names `make mutate`, and FR-mutation-19 states that the sweep does not block a merge")
	}
}

// mutationIssueDefects returns each defect of the issue path that FR-mutation-18 needs.
//
// The reader takes the text rather than a path, so TestTheIssueReaderReportsADefeatedWorkflow
// can feed it a workflow with the issue step removed.
//
// **The caller passes the job without its comment lines, and never the whole file.** A
// comment of this repository quotes the command it explains, so this reader found every
// phrase in the prose of a workflow whose issue step was deleted. A first draft of this
// guard read the whole file and it reported no defect, measured on 2026-08-14.
func mutationIssueDefects(text string) []string {
	defects := []string{}

	checks := []struct {
		phrase string
		defect string
	}{
		{"gh issue create", "the workflow opens no issue, and FR-mutation-18 opens one"},
		{"go run ./internal/mutationdiff", "the workflow runs no comparison, so it cannot name a new mutation"},
		{"if: steps.compare.outputs.new-lived != '0'", "the workflow does not hold the issue back to a run that found a mutation"},
		{"issues: write", "the job declares no issue permission, so `gh issue create` fails"},
		{"GH_TOKEN:", "the issue step carries no token, so `gh` cannot authenticate"},
	}

	for _, check := range checks {
		if !strings.Contains(text, check.phrase) {
			defects = append(defects, check.defect)
		}
	}

	return defects
}

// TestTheIssueReaderReportsADefeatedWorkflow proves that mutationIssueDefects can fail.
func TestTheIssueReaderReportsADefeatedWorkflow(t *testing.T) {
	defeated := "name: x\non:\n  schedule:\n    - cron: '47 3 * * *'\njobs:\n  sweep:\n    runs-on: ubuntu-latest\n"

	defects := mutationIssueDefects(defeated)
	if len(defects) != 5 {
		t.Errorf("the issue reader found %d defect(s) of a workflow that opens no issue, and it reads five: %v", len(defects), defects)
	}

	// The tracked job holds every phrase, so the reader separates the two texts.
	if held := mutationIssueDefects(workflowJobCommands(t, mutationWorkflow, "sweep")); len(held) != 0 {
		t.Errorf("the issue reader found a defect of both texts, so it separates neither: %v", held)
	}
}

// TestTheMutationWorkflowOpensAnIssueForANewUnsettledMutation holds FR-mutation-18.
//
// It reads the job without its comment lines, for the reason that mutationIssueDefects
// states.
func TestTheMutationWorkflowOpensAnIssueForANewUnsettledMutation(t *testing.T) {
	for _, defect := range mutationIssueDefects(workflowJobCommands(t, mutationWorkflow, "sweep")) {
		t.Errorf("%s: %s", mutationWorkflow, defect)
	}
}

// TestTheMutationWorkflowDedupesTheIssueByTitle holds the bound on FR-mutation-18.
//
// **A mutation is identified by its file, its line, its column and its mutator type, and an
// inserted line above it moves the line number.** So one unrelated edit can make every
// mutation below it read as new. A title that carried the count or the date would then open
// one issue for each night. The title names the swept path alone, and the dedup holds the
// run to one open issue.
func TestTheMutationWorkflowDedupesTheIssueByTitle(t *testing.T) {
	commands := workflowJobCommands(t, mutationWorkflow, "sweep")

	if !strings.Contains(commands, `grep -c -F -x "$title"`) {
		t.Errorf("the sweep job does not dedupe the issue by title:\n%s", commands)
	}

	title := regexp.MustCompile(`(?m)^ *title="([^"]*)"`).FindStringSubmatch(commands)
	if title == nil {
		t.Fatalf("the sweep job builds no issue title:\n%s", commands)
	}

	// A count or a date in the title opens one issue for each run.
	if strings.Contains(title[1], "$COUNT") || strings.Contains(title[1], "$DATE") {
		t.Errorf("the issue title %q carries a value that moves on each run, so the dedup holds nothing", title[1])
	}
}

// TestEveryPipedStepOfTheMutationWorkflowSetsPipefail holds a silent failure of the
// scheduled run.
//
// **The default shell of a `run` step is `bash -e {0}`, and a pipeline then carries the
// status of its last command.** `tee` exits 0 whatever it reads, so a failed comparison
// would report success and the next step would read an empty output. The run would then
// state that the sweep found nothing.
//
// The case reads each script that holds a pipe into `tee`, and it needs the option in the
// same script.
func TestEveryPipedStepOfTheMutationWorkflowSetsPipefail(t *testing.T) {
	scripts := mutationRunScripts(workflowJobCommands(t, mutationWorkflow, "sweep"))
	if len(scripts) == 0 {
		t.Fatalf("%s holds no run script, so this case checked nothing", mutationWorkflow)
	}

	piped := 0
	for _, script := range scripts {
		if !strings.Contains(script, "| tee ") {
			continue
		}
		piped++

		if !strings.Contains(script, "set -o pipefail") {
			t.Errorf("a run script of %s pipes into tee and it sets no pipefail, so a failed command reports success:\n%s", mutationWorkflow, script)
		}
	}

	if piped == 0 {
		t.Errorf("%s holds no piped step, and the sweep reads its two answers through a pipe", mutationWorkflow)
	}
}

// mutationRunScripts returns each `run: |` script of one job.
//
// The reader takes the job without its comment lines, so a quotation in the prose reaches
// no case.
func mutationRunScripts(job string) []string {
	scripts := []string{}
	current := []string{}
	inRun := false

	for _, line := range strings.Split(job, "\n") {
		if strings.TrimSpace(line) == "run: |" {
			if inRun {
				scripts = append(scripts, strings.Join(current, "\n"))
			}
			inRun = true
			current = nil

			continue
		}

		// A key at the step level ends the script block.
		if inRun && !strings.HasPrefix(line, "          ") {
			scripts = append(scripts, strings.Join(current, "\n"))
			inRun = false
			current = nil

			continue
		}

		if inRun {
			current = append(current, line)
		}
	}

	if inRun {
		scripts = append(scripts, strings.Join(current, "\n"))
	}

	return scripts
}

// TestTheRunScriptReaderSeparatesTwoScripts proves that mutationRunScripts can fail.
//
// A reader that returned the whole job as one script would find `set -o pipefail` of the
// first step and report the second step clean.
func TestTheRunScriptReaderSeparatesTwoScripts(t *testing.T) {
	job := "    steps:\n" +
		"      - name: first\n" +
		"        run: |\n" +
		"          set -o pipefail\n" +
		"          a | tee x\n" +
		"      - name: second\n" +
		"        run: |\n" +
		"          b | tee y\n"

	scripts := mutationRunScripts(job)
	if len(scripts) != 2 {
		t.Fatalf("the reader found %d script(s) of a job that holds two: %q", len(scripts), scripts)
	}

	if strings.Contains(scripts[1], "pipefail") {
		t.Errorf("the reader carried the option of the first script into the second: %q", scripts[1])
	}
}

// mutationReportDirectoryDefect returns the defect of a workflow that writes its report
// beside the tracked baseline, or the empty string.
//
// **This is the silent defeat of the whole detector.** `internal/mutationdiff` takes the
// last name of `docs/mutation_reports/` as the baseline. A sweep that wrote its own report
// into that directory would make the next run compare the tree against itself, and the
// comparison would then report no new mutation whatever the tests do.
func mutationReportDirectoryDefect(text string) string {
	sweep := regexp.MustCompile(`(?m)^ *make mutate .*$`).FindString(text)
	if sweep == "" {
		return "the workflow runs no sweep"
	}

	if !strings.Contains(sweep, "MUTATION_REPORT_DIR=") {
		return "the sweep writes its report to the tracked directory, so the next run compares the tree against itself"
	}

	if strings.Contains(sweep, "MUTATION_REPORT_DIR=docs/mutation_reports") {
		return "the sweep names the tracked directory, so the next run compares the tree against itself"
	}

	return ""
}

// TestTheReportDirectoryReaderReportsADefeatedWorkflow proves that
// mutationReportDirectoryDefect can fail.
func TestTheReportDirectoryReaderReportsADefeatedWorkflow(t *testing.T) {
	cases := map[string]string{
		"          make mutate PKG=\"$SWEPT_PATH\"\n":                                           "the sweep writes its report to the tracked directory, so the next run compares the tree against itself",
		"          make mutate PKG=\"$SWEPT_PATH\" MUTATION_REPORT_DIR=docs/mutation_reports\n": "the sweep names the tracked directory, so the next run compares the tree against itself",
		"          echo nothing\n":                                                              "the workflow runs no sweep",
	}

	for text, want := range cases {
		if found := mutationReportDirectoryDefect(text); found != want {
			t.Errorf("the reader answered %q for %q, and it answers %q", found, strings.TrimSpace(text), want)
		}
	}
}

// TestTheMutationWorkflowWritesItsReportOutsideTheTrackedDirectory holds the trap that
// mutationReportDirectoryDefect names.
func TestTheMutationWorkflowWritesItsReportOutsideTheTrackedDirectory(t *testing.T) {
	if defect := mutationReportDirectoryDefect(workflowJobCommands(t, mutationWorkflow, "sweep")); defect != "" {
		t.Errorf("%s: %s", mutationWorkflow, defect)
	}
}

// TestTheMutationWorkflowSweepsThePathOfTheBaseline holds the like-for-like rule of
// FR-mutation-18.
//
// **A sweep of a wider path reports every mutation of every unmeasured package as new.** The
// baseline of 2026-08-14 reads `./internal/parser`, and the whole named set holds 1675
// mutations. So the workflow reads the path out of the tracked report, and it names no path
// of its own.
func TestTheMutationWorkflowSweepsThePathOfTheBaseline(t *testing.T) {
	commands := workflowJobCommands(t, mutationWorkflow, "sweep")

	if !strings.Contains(commands, "go run ./internal/mutationdiff -dir docs/mutation_reports") {
		t.Errorf("the sweep job does not read the baseline from the tracked directory:\n%s", commands)
	}

	if !strings.Contains(commands, `SWEPT_PATH: ${{ steps.baseline.outputs.swept-path }}`) {
		t.Errorf("the sweep job does not take the swept path from the baseline:\n%s", commands)
	}

	sweep := regexp.MustCompile(`(?m)^ *make mutate .*$`).FindString(commands)
	if !strings.Contains(sweep, `PKG="$SWEPT_PATH"`) {
		t.Errorf("the sweep names a package path of its own rather than the path of the baseline: %q", strings.TrimSpace(sweep))
	}
}

// TestTheMutationWorkflowRecordsTheDefaultBranchLimit holds the measured limit that the
// maintainer accepted on 2026-08-14.
//
// A scheduled workflow runs on the default branch alone. The default branch of this
// repository is `master`, and this project develops on `dev` under a held promotion. So the
// sweep starts no run until a promotion reaches `master`. A file that did not state the
// limit would read as a sweep that runs tonight.
func TestTheMutationWorkflowRecordsTheDefaultBranchLimit(t *testing.T) {
	workflow := readRepoFile(t, mutationWorkflow)

	quotation := "Scheduled workflows run on the latest commit on the default branch."
	if !strings.Contains(workflow, quotation) {
		t.Errorf("%s does not quote the default-branch rule of the documentation", mutationWorkflow)
	}

	if !strings.Contains(workflow, "docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows") {
		t.Errorf("%s cites no documentation for the default-branch rule", mutationWorkflow)
	}

	// `.claude/rules/rulings.md` states that a ruling record quotes no live measurement
	// without its date.
	if !strings.Contains(workflow, "2026-08-14") {
		t.Errorf("%s states no date beside its measurements", mutationWorkflow)
	}
}

// TestTheMutationWorkflowPassesNoTemplateToAShell holds the injection rule of this
// repository. A value that a template writes into a command reaches the shell as code, and
// a value that an `env:` key carries reaches it as data.
func TestTheMutationWorkflowPassesNoTemplateToAShell(t *testing.T) {
	inRun := false
	for _, line := range strings.Split(readRepoFile(t, mutationWorkflow), "\n") {
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

// TestTheMutationWorkflowPinsEveryAction holds FR-supply-12 for the file that #93 added. A
// tag moves and a commit hash does not.
func TestTheMutationWorkflowPinsEveryAction(t *testing.T) {
	workflow := readRepoFile(t, mutationWorkflow)

	uses := regexp.MustCompile(`(?m)^ *(?:- )?uses: (\S+)`).FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatalf("%s names no action", mutationWorkflow)
	}

	pinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, reference := range uses {
		if !pinned.MatchString(reference[1]) {
			t.Errorf("the action reference %q names no 40-character commit hash", reference[1])
		}
	}
}

// TestTheMutationWorkflowNamesTheGoToolchainRange holds FR-foundation-2 for the file that
// #93 added. `TestCIWorkflowNamesOneGoVersion` of `foundation_test.go` owns
// `.github/workflows/ci.yml`, and no case reads the file of another case.
func TestTheMutationWorkflowNamesTheGoToolchainRange(t *testing.T) {
	workflow := readRepoFile(t, mutationWorkflow)

	versions := regexp.MustCompile(`(?m)^ *go-version: '(.*)'$`).FindAllStringSubmatch(workflow, -1)
	if versions == nil {
		t.Fatalf("%s holds no literal go-version input", mutationWorkflow)
	}

	for _, version := range versions {
		if version[1] != goToolchainRange {
			t.Errorf("a job of %s names go-version %q, and FR-foundation-2 names one range", mutationWorkflow, version[1])
		}
	}
}

// TestThePreReleaseFeatureFileChecksTheMostRecentSweep holds FR-mutation-20.
//
// **FR-mutation-20 names another feature file, and Epic 16 (#94) owns the case it names.**
// #99 built `TestEveryLivedMutationOfTheMostRecentSweepIsSettled` in `prerelease_gate_test.go`
// on `epic/94-prerelease-validation`, which is a different integration branch. So #93 builds
// no second case, and this case reads the cross-reference that FR-mutation-20 states.
//
// **The case that #99 built was a tripwire, and #642 completed it on 2026-08-15 UTC.** It
// skipped while the `Makefile` held no `mutate` target, and it failed once #90 landed that
// target on `epic/89-mutation-sweep`. The case now reads the settlement record of the most
// recent sweep against the report of that sweep.
func TestThePreReleaseFeatureFileChecksTheMostRecentSweep(t *testing.T) {
	text := readRepoFile(t, preReleaseFeatureFile)

	if !strings.Contains(text, "FR-prerelease-28") {
		t.Fatalf("%s holds no FR-prerelease-28, and FR-mutation-20 names the check it carries", preReleaseFeatureFile)
	}

	requirement := regexp.MustCompile(`(?s)\*\*FR-prerelease-28\*\* — (.{0,200})`).FindStringSubmatch(text)
	if requirement == nil {
		t.Fatalf("%s states FR-prerelease-28 in no readable form", preReleaseFeatureFile)
	}

	for _, word := range []string{"LIVED", "mutation", "settled"} {
		if !strings.Contains(requirement[1], word) {
			t.Errorf("FR-prerelease-28 of %s names no %q, and FR-mutation-20 needs it: %q",
				preReleaseFeatureFile, word, strings.TrimSpace(requirement[1]))
		}
	}
}

// TestTheMutationSweepFeatureFileNamesTheScheduledWorkflow holds the `Data touched` row of
// `docs/specs/features/15-mutation-sweep.md`. The file that #93 adds is the file that row
// names, and a disagreement between the two would leave a reader looking for a second file.
func TestTheMutationSweepFeatureFileNamesTheScheduledWorkflow(t *testing.T) {
	text := readRepoFile(t, "docs/specs/features/15-mutation-sweep.md")

	if !strings.Contains(text, "`"+mutationWorkflow+"`") {
		t.Errorf("docs/specs/features/15-mutation-sweep.md names no %s, and #93 added that file", mutationWorkflow)
	}
}
