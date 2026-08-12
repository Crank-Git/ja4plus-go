package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
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

// skipCall returns every `t.Skip` call and every `t.Skipf` call of the file that carries
// an argument.
func skipCall(file *ast.File) []*ast.CallExpr {
	var calls []*ast.CallExpr

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if selector.Sel.Name != "Skip" && selector.Sel.Name != "Skipf" {
			return true
		}

		if len(call.Args) > 0 {
			calls = append(calls, call)
		}

		return true
	})

	return calls
}

// packageConstant maps the name of each constant of the parsed files to the expression
// that defines it.
func packageConstant(parsed map[string]*ast.File) map[string]ast.Expr {
	value := map[string]ast.Expr{}

	for _, file := range parsed {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}

			for _, specification := range general.Specs {
				spec, ok := specification.(*ast.ValueSpec)
				if !ok || len(spec.Names) != len(spec.Values) {
					continue
				}

				for index, name := range spec.Names {
					value[name.Name] = spec.Values[index]
				}
			}
		}
	}

	return value
}

// constantString returns the string that the expression holds, and it reports whether
// every part of the expression resolved. It reads a string literal, a constant of the
// package, and a concatenation of the two.
//
// The depth bounds the recursion. Go rejects a constant cycle at compile time, and this
// test reads a syntax tree that no compiler has accepted yet.
func constantString(expr ast.Expr, value map[string]ast.Expr, depth int) (string, bool) {
	const maxDepth = 32

	if depth > maxDepth {
		return "", false
	}

	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}

		text, err := strconv.Unquote(node.Value)
		if err != nil {
			return "", false
		}

		return text, true

	case *ast.Ident:
		next, ok := value[node.Name]
		if !ok {
			return "", false
		}

		return constantString(next, value, depth+1)

	case *ast.ParenExpr:
		return constantString(node.X, value, depth+1)

	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return "", false
		}

		left, leftOK := constantString(node.X, value, depth+1)
		right, rightOK := constantString(node.Y, value, depth+1)

		if !leftOK || !rightOK {
			return "", false
		}

		return left + right, true
	}

	return "", false
}

// untaggedSkipMessage returns the message of every `t.Skip` call and every `t.Skipf` call
// in a test file of the repository root that carries no `conformance` build tag. It maps
// the file name to the messages of that file.
//
// `make conformance` runs `go test -tags conformance -count=1 -v ./...`, so these files
// run inside the conformance job and every message reaches `conformance.log`.
//
// It reads each argument through the syntax tree, because a skip call passes a constant
// as often as a string literal. A text search for a string literal reads nothing from
// `t.Skip(foxioCorpusAbsentMessage)`, so the four skips of `foxio_citation_base_test.go`
// stood outside this guard from #335 until #342. A message that this function cannot read
// fails the caller, so the gap cannot return without a report.
func untaggedSkipMessage(t *testing.T) map[string][]string {
	t.Helper()

	names, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("list the test files of the repository root: %v", err)
	}

	fileSet := token.NewFileSet()
	parsed := map[string]*ast.File{}

	for _, name := range names {
		source := readRepoFile(t, name)
		if hasConformanceBuildTag(source) {
			continue
		}

		file, parseErr := parser.ParseFile(fileSet, name, source, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}

		parsed[name] = file
	}

	value := packageConstant(parsed)
	message := map[string][]string{}

	for name, file := range parsed {
		for _, call := range skipCall(file) {
			text, ok := constantString(call.Args[0], value, 0)
			if !ok {
				t.Errorf("this test reads no message from the skip call at %s, so the CI skip "+
					"detector runs against no text there. Write the message as a string literal, "+
					"or as a constant of this package. #342.", fileSet.Position(call.Pos()))

				continue
			}

			message[name] = append(message[name], text)
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

	// The comment writes the count as a word, and the glob above holds the count. This
	// sentence states no number, because a number here goes stale for the same reason the
	// workflow comment does.
	word := map[int]string{3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}

	if count[1] != word[tagged] {
		t.Errorf("the workflow comment counts %s tagged test files, and the repository holds %d", count[1], tagged)
	}
}
