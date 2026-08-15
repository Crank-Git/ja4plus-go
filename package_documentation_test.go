package ja4plus

// These tests hold FR-release-7 and FR-release-10 through FR-release-16 of
// `docs/specs/features/10-release.md`, which issue #102 carries.
//
// #101 measured the doc comment gap and built no guard for it, because FR-release-11 and
// FR-release-12 belong to #102. Comment 5301119159 of #100 holds that handoff. A gap that
// nothing measures returns at the next merge, so this file measures it.
//
// `api_test.go` walks the exported surface for the record, and this file walks it for the
// doc comment. Two walks of one surface can disagree, so
// `TestTheDocCommentWalkReadsTheSameSurfaceAsTheApiRecord` holds the two name sets equal.

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// documentedName is one exported name and the doc comment that precedes it.
type documentedName struct {
	// Key is the identity of the name, in the form that `apiEntry.key` produces.
	Key string
	// Name is the bare name, without its owner.
	Name string
	// Doc is the text of the doc comment, and it is empty when the name carries none.
	Doc string
}

// documentedNamesOf returns every exported name of one package directory, with its doc
// comment.
//
// It reads the same directory as `collectPackageAPI`, and it skips a test file, so the two
// walks read one surface.
func documentedNamesOf(t *testing.T, dir string) []documentedName {
	t.Helper()

	fset := token.NewFileSet()

	packages, err := parser.ParseDir(fset, dir, func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse the package of %s: %v", dir, err)
	}

	var names []documentedName

	for _, parsed := range packages {
		if strings.HasSuffix(parsed.Name, "_test") {
			continue
		}

		for _, file := range parsed.Files {
			names = append(names, documentedNamesOfFile(file)...)
		}
	}

	sort.Slice(names, func(i, j int) bool { return names[i].Key < names[j].Key })

	return names
}

// documentedNamesOfFile returns every exported name that one parsed file declares.
func documentedNamesOfFile(file *ast.File) []documentedName {
	var names []documentedName

	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			names = append(names, documentedFunc(declaration)...)
		case *ast.GenDecl:
			names = append(names, documentedGenDecl(declaration)...)
		}
	}

	return names
}

// documentedFunc returns the entry of one function or one method, or nothing.
//
// A method of an unexported type reaches no consumer, so `api_test.go` leaves it out of the
// record and this walk leaves it out too.
func documentedFunc(declaration *ast.FuncDecl) []documentedName {
	if !declaration.Name.IsExported() {
		return nil
	}

	text := docWalkCommentText(declaration.Doc)

	if declaration.Recv == nil {
		return []documentedName{{Key: "func|" + declaration.Name.Name, Name: declaration.Name.Name, Doc: text}}
	}

	owner := docWalkReceiverTypeName(declaration.Recv)
	if !ast.IsExported(owner) {
		return nil
	}

	return []documentedName{{
		Key:  "method|" + owner + "." + declaration.Name.Name,
		Name: declaration.Name.Name,
		Doc:  text,
	}}
}

// documentedGenDecl returns each exported name of one type, constant or variable block.
func documentedGenDecl(declaration *ast.GenDecl) []documentedName {
	var names []documentedName

	for _, spec := range declaration.Specs {
		switch spec := spec.(type) {
		case *ast.TypeSpec:
			if !spec.Name.IsExported() {
				continue
			}

			text := docWalkCommentText(spec.Doc)
			if text == "" {
				text = docWalkCommentText(declaration.Doc)
			}

			names = append(names, documentedName{Key: "type|" + spec.Name.Name, Name: spec.Name.Name, Doc: text})
			names = append(names, documentedMembers(spec)...)
		case *ast.ValueSpec:
			kind := "var"
			if declaration.Tok == token.CONST {
				kind = "const"
			}

			for _, ident := range spec.Names {
				if !ident.IsExported() {
					continue
				}

				text := docWalkCommentText(spec.Doc)
				if text == "" {
					text = docWalkCommentText(declaration.Doc)
				}

				names = append(names, documentedName{Key: kind + "|" + ident.Name, Name: ident.Name, Doc: text})
			}
		}
	}

	return names
}

// documentedMembers returns each exported field of a struct type, and each method of an
// interface type.
func documentedMembers(spec *ast.TypeSpec) []documentedName {
	var names []documentedName

	switch declared := spec.Type.(type) {
	case *ast.StructType:
		for _, field := range declared.Fields.List {
			for _, ident := range field.Names {
				if !ident.IsExported() {
					continue
				}

				names = append(names, documentedName{
					Key:  "field|" + spec.Name.Name + "." + ident.Name,
					Name: ident.Name,
					Doc:  docWalkCommentText(field.Doc),
				})
			}
		}
	case *ast.InterfaceType:
		for _, method := range declared.Methods.List {
			for _, ident := range method.Names {
				if !ident.IsExported() {
					continue
				}

				names = append(names, documentedName{
					Key:  "ifacemethod|" + spec.Name.Name + "." + ident.Name,
					Name: ident.Name,
					Doc:  docWalkCommentText(method.Doc),
				})
			}
		}
	}

	return names
}

// docWalkCommentText returns the text of one comment group, and it returns the empty string for a
// group that no declaration carries.
func docWalkCommentText(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}

	return strings.TrimSpace(group.Text())
}

// docWalkReceiverTypeName returns the type name of one receiver, without a pointer and without a
// type parameter.
func docWalkReceiverTypeName(receiver *ast.FieldList) string {
	if receiver == nil || len(receiver.List) != 1 {
		return ""
	}

	return docWalkBaseTypeName(receiver.List[0].Type)
}

// docWalkBaseTypeName returns the identifier at the base of one type expression.
func docWalkBaseTypeName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.StarExpr:
		return docWalkBaseTypeName(expression.X)
	case *ast.IndexExpr:
		return docWalkBaseTypeName(expression.X)
	case *ast.IndexListExpr:
		return docWalkBaseTypeName(expression.X)
	case *ast.Ident:
		return expression.Name
	}

	return ""
}

// FR-release-11 and FR-release-12. A doc comment that opens with another word breaks the
// convention of <https://go.dev/doc/comment>, and `go doc` then prints a sentence that
// names no subject.
func TestEveryExportedNameCarriesADocCommentThatOpensWithItsName(t *testing.T) {
	for _, pkg := range publishedPackages {
		for _, name := range documentedNamesOf(t, pkg.Dir) {
			if name.Doc == "" {
				t.Errorf("%s exports %s with no doc comment, and FR-release-11 requires one",
					pkg.ImportPath, name.Key)

				continue
			}

			if !strings.HasPrefix(name.Doc, name.Name) {
				t.Errorf("%s: the doc comment of %s opens with %q, and FR-release-12 requires the name %q",
					pkg.ImportPath, name.Key, docWalkFirstWord(name.Doc), name.Name)
			}
		}
	}
}

// docWalkFirstWord returns the first word of one doc comment, for the failure message.
func docWalkFirstWord(text string) string {
	if index := strings.IndexAny(text, " \t\n"); index >= 0 {
		return text[:index]
	}

	return text
}

// A second walk of one surface can drift from the first one, and it then reports a pass over
// a name it never read. This test holds the two name sets equal.
func TestTheDocCommentWalkReadsTheSameSurfaceAsTheApiRecord(t *testing.T) {
	for _, pkg := range publishedPackages {
		recorded, err := collectPackageAPI(pkg.Dir)
		if err != nil {
			t.Fatalf("measure the API of %s: %v", pkg.ImportPath, err)
		}

		measured := map[string]bool{}
		for _, name := range documentedNamesOf(t, pkg.Dir) {
			measured[name.Key] = true
		}

		for _, entry := range recorded {
			if !measured[entry.key()] {
				t.Errorf("%s: the doc comment walk reads no %s, and the API measurement records it",
					pkg.ImportPath, entry.key())
			}

			delete(measured, entry.key())
		}

		for key := range measured {
			t.Errorf("%s: the doc comment walk reads %s, and the API measurement records none",
				pkg.ImportPath, key)
		}
	}
}

// FR-release-7. `go doc` prints the package comment, so a reader of the terminal reads this
// section without a browser.
func TestThePackageDocumentationStatesTheMethodSection(t *testing.T) {
	source, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}

	text := string(source)

	// A godoc section heading starts with `#`, so a reader of `go doc` sees the heading.
	for _, want := range []string{
		"# Methods",
		"eleven methods",
		"ten fingerprinters",
		"JA4LFingerprinter",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("doc.go omits %q, and FR-release-7 requires it", want)
		}
	}

	// The section names each of the eleven methods: JA4, and the ten that `NOTICE` covers.
	for _, method := range []string{
		"JA4", "JA4S", "JA4H", "JA4X", "JA4SSH", "JA4T", "JA4TS", "JA4L", "JA4LS", "JA4D", "JA4D6",
	} {
		if !strings.Contains(text, method+" reads ") {
			t.Errorf("the # Methods section of doc.go states no input for %s", method)
		}
	}
}

// requiredExample names one example that a requirement of `10-release.md` asks for.
type requiredExample struct {
	// Name is the value that `go/doc` reports, which is the function name without the
	// `Example` prefix. A package-level example reports the empty string.
	Name string
	// Function is the name a reader greps for.
	Function string
	// Requirement is the requirement that asks for the example.
	Requirement string
}

// requiredExamples names each example that a requirement of `10-release.md` asks for.
//
// `Example` carries FR-release-10, because pkg.go.dev renders a package-level example under
// the package comment. The other three carry FR-release-13, FR-release-14 and
// FR-release-15.
var requiredExamples = []requiredExample{
	{Name: "", Function: "Example", Requirement: "FR-release-10"},
	{Name: "Processor", Function: "ExampleProcessor", Requirement: "FR-release-13"},
	{Name: "SyncProcessor", Function: "ExampleSyncProcessor", Requirement: "FR-release-14"},
	{Name: "LookupFingerprint", Function: "ExampleLookupFingerprint", Requirement: "FR-release-15"},
}

// FR-release-13 through FR-release-16. An example with no output comment compiles and never
// runs, so the output comment is what makes the example a check.
func TestEveryRequiredExampleRunsAndChecksItsOutput(t *testing.T) {
	examples := packageExamples(t)

	for _, required := range requiredExamples {
		example, found := examples[required.Name]
		if !found {
			t.Errorf("the package declares no %s function, and %s requires one",
				required.Function, required.Requirement)

			continue
		}

		if example.Output == "" && !example.EmptyOutput {
			t.Errorf("%s carries no output comment, so `go test` compiles it and never runs it; %s requires the check",
				required.Function, required.Requirement)
		}
	}
}

// packageExamples returns each example of the root package, by the name it exemplifies.
func packageExamples(t *testing.T) map[string]*doc.Example {
	t.Helper()

	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}

	var files []*ast.File

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fset, filepath.Join(".", entry.Name()), nil, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}

		files = append(files, file)
	}

	found := map[string]*doc.Example{}
	for _, example := range doc.Examples(files...) {
		found[example.Name] = example
	}

	return found
}
