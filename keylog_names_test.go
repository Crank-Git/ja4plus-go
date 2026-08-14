package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These two tests hold the FR-gaps-17 amendment of issue #171.
//
// The requirement held one sentence that states two facts. types.go holds eight exported
// names for a key log, and no exported function accepts a KeyLog. A reader who reads the
// first fact alone expects a fingerprint that a secret decrypts. The library produces none.
//
// Issue #492 needs a key log that a fingerprinter reads, and Epic 10 (#100) freezes the
// exported API. So the second fact is a boundary the maintainer moves, and never a defect.
// A reversal of the amendment removes the second test.

// conformanceGapsPath names the page that FR-gaps-17 lives on.
const conformanceGapsPath = "docs/specs/features/05-conformance-gaps.md"

// keyLogNameCount states the count of exported names that FR-gaps-17 through
// FR-gaps-17b name. The page states the same count in prose, so a change to one of them
// without the other fails this test.
const keyLogNameCount = 8

// keyLogCountSentence quotes the prose of the page that states the count above.
// A stale count is the defect this project measures most, so a test holds the sentence.
const keyLogCountSentence = "holds each of the eight exported names"

// TestFRGaps17NamesEveryExportedKeyLogName holds the first fact of the amendment.
// The requirement names an exported name of this package, and never a name the package
// does not hold.
func TestFRGaps17NamesEveryExportedKeyLogName(t *testing.T) {
	named := keyLogNamesOfTheRequirement(t)
	if len(named) != keyLogNameCount {
		t.Fatalf("FR-gaps-17 through FR-gaps-17b name %d exported names, want %d: %v",
			len(named), keyLogNameCount, named)
	}

	// The page wraps a sentence over more than one line, so the reader joins the lines
	// before it looks for the count.
	flat := strings.Join(strings.Fields(conformanceGapsPage(t)), " ")
	if !strings.Contains(flat, keyLogCountSentence) {
		t.Errorf("%s states no sentence that holds %q, so the prose count is stale",
			conformanceGapsPath, keyLogCountSentence)
	}

	held := exportedNamesOfThePackage(t)
	for _, name := range named {
		if !held[name] {
			t.Errorf("FR-gaps-17 names %s and the package exports no such name", name)
		}
	}
}

// TestNoExportedFunctionAcceptsAKeyLog holds FR-gaps-17c: a caller passes no secret to the
// Processor and to no fingerprinter.
// It reads every parameter of every exported function and method of the package, because
// the requirement binds the whole exported surface and not one file.
func TestNoExportedFunctionAcceptsAKeyLog(t *testing.T) {
	functions := 0

	for _, file := range packageSourceFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || !ast.IsExported(function.Name.Name) {
				continue
			}

			functions++

			for _, param := range function.Type.Params.List {
				if !strings.Contains(typeExpressionText(param.Type), "KeyLog") {
					continue
				}

				t.Errorf("%s of %s accepts a KeyLog, and FR-gaps-17c states that no exported function does",
					function.Name.Name, file)
			}
		}
	}

	if functions == 0 {
		t.Fatal("the package declares no exported function, so this test proves nothing")
	}
}

// keyLogNamesOfTheRequirement returns each name that a code span of FR-gaps-17
// through FR-gaps-17b holds, sorted and without a repeat.
func keyLogNamesOfTheRequirement(t *testing.T) []string {
	t.Helper()

	page := conformanceGapsPage(t)
	span := regexp.MustCompile("`([^`]+)`")
	seen := map[string]bool{}
	inside := false

	var names []string

	// The three requirements are consecutive, and FR-gaps-17c ends the block. A
	// requirement wraps over more than one line, so the reader holds the block state and
	// reads no line by its indent.
	for _, line := range strings.Split(page, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "- **FR-gaps-17**") {
			inside = true
		}

		if strings.HasPrefix(trimmed, "- **FR-gaps-17c**") {
			inside = false
		}

		if !inside {
			continue
		}

		for _, match := range span.FindAllStringSubmatch(line, -1) {
			name := match[1]
			if seen[name] {
				continue
			}

			seen[name] = true
			names = append(names, name)
		}
	}

	if !seen["KeyLog"] {
		t.Fatalf("%s holds no FR-gaps-17 block that names KeyLog", conformanceGapsPath)
	}

	sort.Strings(names)

	return names
}

// conformanceGapsPage returns the text of the page that FR-gaps-17 lives on.
func conformanceGapsPage(t *testing.T) string {
	t.Helper()

	page, err := os.ReadFile(conformanceGapsPath)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceGapsPath, err)
	}

	return string(page)
}

// exportedNamesOfThePackage returns every exported name the package declares, and it writes
// a method as `Type.Method`.
func exportedNamesOfThePackage(t *testing.T) map[string]bool {
	t.Helper()

	held := map[string]bool{}

	for _, file := range packageSourceFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range parsed.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(node.Name.Name) {
					continue
				}

				if node.Recv == nil {
					held[node.Name.Name] = true

					continue
				}

				held[receiverTypeName(node.Recv)+"."+node.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					addExportedSpecName(held, spec)
				}
			}
		}
	}

	return held
}

// addExportedSpecName adds the exported name of one type, variable or constant declaration.
func addExportedSpecName(held map[string]bool, spec ast.Spec) {
	switch node := spec.(type) {
	case *ast.TypeSpec:
		if ast.IsExported(node.Name.Name) {
			held[node.Name.Name] = true
		}
	case *ast.ValueSpec:
		for _, name := range node.Names {
			if ast.IsExported(name.Name) {
				held[name.Name] = true
			}
		}
	}
}

// packageSourceFiles returns every source file of the package, and no test file.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the source files: %v", err)
	}

	sources := make([]string, 0, len(files))

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		sources = append(sources, file)
	}

	if len(sources) == 0 {
		t.Fatal("the package holds no source file, so this test proves nothing")
	}

	return sources
}

// typeExpressionText returns the source text of a type expression.
// It calls types.ExprString, which reads every expression form the Go grammar states. A
// hand-written reader returns the empty string for the form it does not name, and a
// `func(*KeyLog)` parameter then passes the guard of FR-gaps-17c.
func typeExpressionText(expr ast.Expr) string {
	return types.ExprString(expr)
}
