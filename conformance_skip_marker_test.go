package ja4plus

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// conformanceSkipMarker is the line that the conformance suite writes when the corpus
// directory is absent. `.github/workflows/ci.yml` reads it, and FR-conformance-36 fails
// the job on it.
//
// The skip message of FR-conformance-11 cannot carry the job. Three untagged tests write
// that same sentence when one capture is absent, and `make conformance` runs them, so
// their skip reaches the same log. A pin move that renames one capture would then fail
// the job with the wrong reason: the job would report an absent corpus that is present.
// This marker names the one condition the job means. #142.
//
// The constant sits in an untagged file, because the tests below read it and the
// `conformance` build tag hides the suite from them. The tagged build compiles this file
// too, so `conformanceSkipWithoutCorpus` reaches the constant.
const conformanceSkipMarker = "conformance-suite-skip: the corpus is absent"

// ciSkipDetectorPattern returns the pattern that the CI job reads the conformance log
// with to detect a skip. It fails the test when the workflow holds no such step.
func ciSkipDetectorPattern(t *testing.T) string {
	t.Helper()

	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	const stepName = "- name: Fail when the conformance suite skips"

	start := strings.Index(workflow, stepName)
	if start < 0 {
		t.Fatalf(".github/workflows/ci.yml holds no step named %q", stepName)
	}

	step := workflow[start+len(stepName):]
	if next := strings.Index(step, "- name:"); next >= 0 {
		step = step[:next]
	}

	match := regexp.MustCompile(`grep -q '([^']*)' conformance\.log`).FindStringSubmatch(step)
	if match == nil {
		t.Fatalf("the skip step reads the conformance log with no `grep -q` pattern:\n%s", step)
	}

	return match[1]
}

// hasConformanceBuildTag reports whether the source carries the `conformance` build
// constraint.
//
// It reads only the text above the package clause. A build constraint sits there, and
// this file names the same constraint text in a string below the clause. A whole-file
// search would therefore count this file as tagged.
func hasConformanceBuildTag(source string) bool {
	head, _, found := strings.Cut(source, "\npackage ")
	if !found {
		return false
	}

	return strings.Contains(head, "//go:build conformance")
}

// untaggedSkipMessage returns the format string of every `t.Skip` call and every
// `t.Skipf` call in a test file of the repository root that carries no `conformance`
// build tag. It maps the file name to the messages of that file.
//
// `make conformance` runs `go test -tags conformance -count=1 -v ./...`, so these files
// run inside the conformance job and every message reaches `conformance.log`.
func untaggedSkipMessage(t *testing.T) map[string][]string {
	t.Helper()

	names, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("list the test files of the repository root: %v", err)
	}

	skipCall := regexp.MustCompile(`t\.Skipf?\(\s*"((?:[^"\\]|\\.)*)"`)
	message := map[string][]string{}

	for _, name := range names {
		source := readRepoFile(t, name)
		if hasConformanceBuildTag(source) {
			continue
		}

		for _, call := range skipCall.FindAllStringSubmatch(source, -1) {
			message[name] = append(message[name], call[1])
		}
	}

	// A regular expression that matches nothing would pass every test below and never
	// read one message.
	if len(message) == 0 {
		t.Fatal("the repository root holds no untagged test file with a skip message")
	}

	return message
}

// FR-conformance-36 fails the job when the corpus is absent, and no other skip means
// that. This test holds the separation that #142 found missing.
func TestTheCISkipDetectorMatchesNoUntaggedSkipMessage(t *testing.T) {
	pattern := ciSkipDetectorPattern(t)

	for name, messages := range untaggedSkipMessage(t) {
		for _, message := range messages {
			if strings.Contains(message, pattern) {
				t.Errorf("the CI skip detector reads a skip of %s as an absent corpus:\n\tpattern: %s\n\tmessage: %s",
					name, pattern, message)
			}
		}
	}
}

// The job must still fail on an absent corpus, so the detector must match the marker.
func TestTheCISkipDetectorMatchesTheConformanceSkipMarker(t *testing.T) {
	pattern := ciSkipDetectorPattern(t)

	if !strings.Contains(conformanceSkipMarker, pattern) {
		t.Errorf("the CI skip detector matches no line of the conformance suite:\n\tpattern: %s\n\tmarker:  %s",
			pattern, conformanceSkipMarker)
	}
}

// The marker reaches the log only when the suite writes it. This package cannot call the
// tagged helper, so the test reads the source of the suite.
func TestTheConformanceSuiteWritesTheSkipMarkerBeforeItSkips(t *testing.T) {
	source := readRepoFile(t, "conformance_test.go")

	if !strings.Contains(source, "t.Log(conformanceSkipMarker)") {
		t.Error("conformance_test.go does not write conformanceSkipMarker before it skips")
	}
}

// The comment above the vet step counts the files that the build tag hides. #142 found
// the count stale at three, and a stale count teaches a reader the wrong scope.
func TestTheCIWorkflowCountsTheConformanceTaggedFiles(t *testing.T) {
	names, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("list the test files of the repository root: %v", err)
	}

	tagged := 0

	for _, name := range names {
		if hasConformanceBuildTag(readRepoFile(t, name)) {
			tagged++
		}
	}

	if tagged == 0 {
		t.Fatal("the repository root holds no test file with the conformance build tag")
	}

	workflow := readRepoFile(t, ".github/workflows/ci.yml")

	count := regexp.MustCompile(`The ` + "`conformance`" + ` build tag hides (\w+) test files`).FindStringSubmatch(workflow)
	if count == nil {
		t.Fatalf(".github/workflows/ci.yml states no count of the files that the build tag hides")
	}

	// The comment writes the count as a word, and the repository holds seven such files.
	word := map[int]string{3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}

	if count[1] != word[tagged] {
		t.Errorf("the workflow comment counts %s tagged test files, and the repository holds %d", count[1], tagged)
	}
}
