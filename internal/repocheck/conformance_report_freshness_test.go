package repocheck

import (
	"regexp"
	"strings"
	"testing"
)

// conformanceStaleReportStep names the CI step that fails on a stale conformance report.
//
// The suite rewrites `docs/audit/conformance.md` on every run, and it writes the file
// before it reports a deviation. The file on disk is therefore current whenever the suite
// runs, and a difference against the commit means the commit holds a stale report. #227.
const conformanceStaleReportStep = "- name: Fail when the tracked conformance report is stale"

// conformanceSkipStep names the CI step that fails when the conformance suite skips.
const conformanceSkipStep = "- name: Fail when the conformance suite skips"

// ciWorkflowStep returns the body of the named step of `.github/workflows/ci.yml`. It
// fails the test when the workflow holds no step of that name.
func ciWorkflowStep(t *testing.T, workflow, stepName string) string {
	t.Helper()

	start := strings.Index(workflow, stepName)
	if start < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no step named %q", stepName)
	}

	body := workflow[start+len(stepName):]
	if next := strings.Index(body, "- name:"); next >= 0 {
		body = body[:next]
	}

	return body
}

// conformanceReportPathFromSource returns the report path that the suite writes. The
// `conformance` build tag hides the constant from this package, so the test reads the
// source of the suite. `conformance_skip_marker_test.go` reads the same source for the
// same reason.
func conformanceReportPathFromSource(t *testing.T) string {
	t.Helper()

	source := readRepoFile(t, "conformance_report_test.go")

	match := regexp.MustCompile(`conformanceReportPath = "([^"]+)"`).FindStringSubmatch(source)
	if match == nil {
		t.Fatal("conformance_report_test.go declares no conformanceReportPath")
	}

	return match[1]
}

// #227 regenerated a report that three merged changes had left stale, and no check caught
// it. A reader who trusts a stale report reads counts that no tree produces.
func TestTheCIWorkflowFailsOnAStaleConformanceReport(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")
	step := ciWorkflowStep(t, workflow, conformanceStaleReportStep)

	if !strings.Contains(step, "git diff --exit-code") {
		t.Errorf("the stale-report step runs no `git diff --exit-code`:\n%s", step)
	}

	path := conformanceReportPathFromSource(t)
	if !strings.Contains(step, path) {
		t.Errorf("the stale-report step names no %s:\n%s", path, step)
	}
}

// An absent corpus makes the suite skip, and a skipped suite writes no report. The step
// order therefore decides which reason the job reports, and the skip reason is the true
// one. #142 found the job reporting the wrong reason once already.
func TestTheStaleReportStepRunsAfterTheSkipStep(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	skip := strings.Index(workflow, conformanceSkipStep)
	if skip < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no step named %q", conformanceSkipStep)
	}

	stale := strings.Index(workflow, conformanceStaleReportStep)
	if stale < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no step named %q", conformanceStaleReportStep)
	}

	if stale < skip {
		t.Error("the stale-report step runs before the skip step, so an absent corpus reports a stale report")
	}
}
