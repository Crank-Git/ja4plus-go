package ja4plus

// The exported API record is the tracked file `docs/api/v1.md`. `v1.0.0` freezes it, and
// these tests hold FR-release-1 through FR-release-5 of
// `docs/specs/features/10-release.md`.
//
// A record that nothing compares goes stale at the first merge. So this file measures the
// exported surface from the source, and it fails when the measurement and the record
// differ.
//
// The measurement reads `go/build` and `go/parser` of the standard library. The feature
// file names `go/packages` and `golang.org/x/exp/apidiff` instead, and
// `docs/api/v1.md` `## The measurement reads the standard library` records the choice and
// the reversal path. Each named package adds a module requirement, and a `require` line
// reaches the module graph of every consumer of `v1.0.0`.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// apiRecordFile is the path of the record, relative to the package directory.
const apiRecordFile = "docs/api/v1.md"

// apiRecordDir is the directory of the record, relative to `docs/`. `mkdocs.yml` excludes
// it, and `excludedDocumentationDirs` in `mkdocs_config_test.go` holds the same name.
const apiRecordDir = "api"

// publishedPackage names one package that a consumer outside this module imports.
type publishedPackage struct {
	// Dir is the directory of the package, relative to the package directory of this test.
	Dir string
	// ImportPath is the path a consumer writes, and the record names one block for it.
	ImportPath string
}

// publishedPackages names every package the freeze binds.
//
// A package under `internal/` reaches no consumer, because the Go toolchain refuses the
// import from outside the subtree that the parent of `internal` roots. A `package main`
// exports no name a consumer calls. So neither kind is part of the exported API.
// `TestEveryImportablePackageIsRecordedOrDeclined` holds that boundary.
var publishedPackages = []publishedPackage{
	{Dir: ".", ImportPath: "github.com/Crank-Git/ja4plus-go"},
	{Dir: "ja4db", ImportPath: "github.com/Crank-Git/ja4plus-go/ja4db"},
}

// apiEntry is one row of the record, and one exported name of the measurement.
type apiEntry struct {
	// Kind is `type`, `func`, `method`, `const`, `var`, `field` or `ifacemethod`.
	Kind string
	// Name carries the owner of a method, of an interface method and of a field, as
	// `Processor.Reset` does. A top-level name carries no prefix.
	Name string
	// Signature is the declared form, and never the resolved type.
	Signature string
	// Sentence states what the name does. FR-release-2 requires it, and the measurement
	// leaves it empty.
	Sentence string
}

// key returns the identity of an entry. The sentence is prose, so it stays out.
func (e apiEntry) key() string { return e.Kind + "|" + e.Name }

// topLevelAPIKinds names every kind that FR-release-3 enumerates.
var topLevelAPIKinds = map[string]bool{
	"type": true, "func": true, "method": true, "const": true, "var": true,
}

// collectPackageAPI returns every exported name the package directory declares.
//
// It reads the directory with `go/build`, which applies the build constraints of the
// toolchain that runs the test. It then parses each file of `GoFiles`, so no test file
// reaches the result.
func collectPackageAPI(dir string) ([]apiEntry, error) {
	pkg, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return nil, fmt.Errorf("read the package of %s: %w", dir, err)
	}

	fset := token.NewFileSet()

	var entries []apiEntry

	for _, name := range pkg.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Join(dir, name), err)
		}

		entries = append(entries, exportedNamesOfFile(fset, file)...)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].key() < entries[j].key() })

	return entries, nil
}

// exportedNamesOfFile returns every exported name that one parsed file declares.
func exportedNamesOfFile(fset *token.FileSet, file *ast.File) []apiEntry {
	var entries []apiEntry

	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			entries = append(entries, exportedFunc(fset, decl)...)
		case *ast.GenDecl:
			entries = append(entries, exportedGenDecl(fset, decl)...)
		}
	}

	return entries
}

// exportedFunc returns the entry of one function or method declaration, or nothing.
//
// A method of an unexported type reaches no consumer, so it stays out of the record.
func exportedFunc(fset *token.FileSet, decl *ast.FuncDecl) []apiEntry {
	if !decl.Name.IsExported() {
		return nil
	}

	signature := renderAPINode(fset, decl.Type)

	if decl.Recv == nil {
		return []apiEntry{{Kind: "func", Name: decl.Name.Name, Signature: signature}}
	}

	owner := apiReceiverName(fset, decl.Recv)
	if !ast.IsExported(owner) {
		return nil
	}

	return []apiEntry{{Kind: "method", Name: owner + "." + decl.Name.Name, Signature: signature}}
}

// exportedGenDecl returns every exported name of one type, constant or variable block.
func exportedGenDecl(fset *token.FileSet, decl *ast.GenDecl) []apiEntry {
	var entries []apiEntry

	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.TypeSpec:
			if !spec.Name.IsExported() {
				continue
			}

			entries = append(entries, apiEntry{
				Kind:      "type",
				Name:      spec.Name.Name,
				Signature: apiTypeSignature(fset, spec),
			})
			entries = append(entries, exportedMembers(fset, spec)...)
		case *ast.ValueSpec:
			kind := "var"
			if decl.Tok == token.CONST {
				kind = "const"
			}

			for _, name := range spec.Names {
				if !name.IsExported() {
					continue
				}

				entries = append(entries, apiEntry{
					Kind:      kind,
					Name:      name.Name,
					Signature: apiValueSignature(fset, spec, name.Name),
				})
			}
		}
	}

	return entries
}

// exportedMembers returns every exported struct field and every method of an exported
// interface.
//
// FR-release-3 names neither one. The record holds both, because a removed field breaks a
// consumer's build exactly as a removed method does.
// `docs/api/v1.md` `## The record holds a field and an interface method` states the
// reading.
func exportedMembers(fset *token.FileSet, spec *ast.TypeSpec) []apiEntry {
	var entries []apiEntry

	switch declared := spec.Type.(type) {
	case *ast.StructType:
		if declared.Fields == nil {
			return nil
		}

		for _, field := range declared.Fields.List {
			for _, name := range field.Names {
				if !name.IsExported() {
					continue
				}

				entries = append(entries, apiEntry{
					Kind:      "field",
					Name:      spec.Name.Name + "." + name.Name,
					Signature: renderAPINode(fset, field.Type),
				})
			}
		}
	case *ast.InterfaceType:
		if declared.Methods == nil {
			return nil
		}

		for _, method := range declared.Methods.List {
			for _, name := range method.Names {
				if !name.IsExported() {
					continue
				}

				entries = append(entries, apiEntry{
					Kind:      "ifacemethod",
					Name:      spec.Name.Name + "." + name.Name,
					Signature: renderAPINode(fset, method.Type),
				})
			}
		}
	}

	return entries
}

// apiReceiverName returns the type name of a method receiver, without the pointer star
// and without a type parameter list.
func apiReceiverName(fset *token.FileSet, recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}

	name := strings.TrimPrefix(renderAPINode(fset, recv.List[0].Type), "*")
	if index := strings.IndexByte(name, '['); index >= 0 {
		name = name[:index]
	}

	return name
}

// apiTypeSignature returns the recorded form of one type declaration.
//
// A struct and an interface record as the bare word, because the record names each member
// on a row of its own. Every other type records its declared right side.
//
// The result opens with the type parameter list when the type declares one. A change from
// `[T any]` to `[T comparable]` breaks a caller that instantiates the type, so a signature
// that drops the list hides a breaking change.
func apiTypeSignature(fset *token.FileSet, spec *ast.TypeSpec) string {
	parameters := renderAPITypeParams(fset, spec.TypeParams)

	if spec.Assign.IsValid() {
		return parameters + "= " + renderAPINode(fset, spec.Type)
	}

	switch spec.Type.(type) {
	case *ast.StructType:
		return parameters + "struct"
	case *ast.InterfaceType:
		return parameters + "interface"
	}

	return parameters + renderAPINode(fset, spec.Type)
}

// renderAPITypeParams returns the type parameter list of a type declaration, and it
// returns the empty string when the declaration states none.
//
// `go/printer` prints no bare `*ast.FieldList`, so this function joins the fields itself.
// A result that holds a list ends with one space, so a caller writes it as a prefix.
func renderAPITypeParams(fset *token.FileSet, params *ast.FieldList) string {
	if params == nil || len(params.List) == 0 {
		return ""
	}

	fields := make([]string, 0, len(params.List))

	for _, field := range params.List {
		names := make([]string, 0, len(field.Names))
		for _, name := range field.Names {
			names = append(names, name.Name)
		}

		constraint := renderAPINode(fset, field.Type)
		if len(names) == 0 {
			fields = append(fields, constraint)

			continue
		}

		fields = append(fields, strings.Join(names, ", ")+" "+constraint)
	}

	return "[" + strings.Join(fields, ", ") + "] "
}

// apiValueSignature returns the declared type of one constant or variable, or its value
// when the declaration states no type.
func apiValueSignature(fset *token.FileSet, spec *ast.ValueSpec, name string) string {
	if spec.Type != nil {
		return renderAPINode(fset, spec.Type)
	}

	for index, declared := range spec.Names {
		if declared.Name == name && index < len(spec.Values) {
			return "= " + renderAPINode(fset, spec.Values[index])
		}
	}

	return ""
}

// renderAPINode returns the source form of one node on a single line.
//
// The printer writes a newline inside a struct, an interface and a long parameter list, so
// the result collapses every run of white space to one space. A record row holds one line.
func renderAPINode(fset *token.FileSet, node ast.Node) string {
	var out strings.Builder
	if err := printer.Fprint(&out, fset, node); err != nil {
		return "<unprintable>"
	}

	return strings.Join(strings.Fields(out.String()), " ")
}

// apiCellEscape returns the record-cell form of a signature.
//
// A markdown table splits a row on the pipe, so a signature that holds one would split its
// own row. A union type constraint holds one: `func[T int | string](v T) T` is a legal
// signature of this module. So the record writes `\|`, and `apiCellUnescape` reverses it.
func apiCellEscape(signature string) string {
	return strings.ReplaceAll(signature, "|", `\|`)
}

// apiCellUnescape returns the signature that a record cell holds.
func apiCellUnescape(cell string) string {
	return strings.ReplaceAll(cell, `\|`, "|")
}

// apiSplitRow returns the cells of one record row.
//
// It splits on an unescaped pipe alone, so a signature that holds `\|` stays in one cell.
func apiSplitRow(line string) []string {
	const placeholder = "\x00"

	guarded := strings.ReplaceAll(line, `\|`, placeholder)

	cells := strings.Split(strings.Trim(guarded, "|"), "|")
	for index, cell := range cells {
		cells[index] = strings.TrimSpace(strings.ReplaceAll(cell, placeholder, `\|`))
	}

	return cells
}

// apiIsAlignmentRow reports whether the cell is the alignment cell of a markdown table.
//
// A table writes the alignment with a dash, and it may write a colon on either side. Both
// forms are alignment, and neither one is a record.
func apiIsAlignmentRow(cell string) bool {
	if cell == "" {
		return false
	}

	return strings.Trim(cell, "-: ") == ""
}

// measureAPI returns the exported surface of one published package.
// It fails the test when the directory does not read.
func measureAPI(t *testing.T, pkg publishedPackage) []apiEntry {
	t.Helper()

	entries, err := collectPackageAPI(pkg.Dir)
	if err != nil {
		t.Fatalf("measure %s: %v", pkg.ImportPath, err)
	}

	return entries
}

// apiRecordBlock returns the text of the record between the two markers of the import
// path. It fails the test when the record holds no such pair.
func apiRecordBlock(t *testing.T, record string, importPath string) string {
	t.Helper()

	begin := "<!-- api-surface:begin " + importPath + " -->"
	end := "<!-- api-surface:end " + importPath + " -->"

	first := strings.Index(record, begin)
	last := strings.Index(record, end)

	if first < 0 || last < first {
		t.Fatalf("%s holds no block between %s and %s", apiRecordFile, begin, end)
	}

	return record[first+len(begin) : last]
}

// parseAPIRecordBlock returns every row of one marked block.
//
// It skips the header row and the alignment row, so a caller reads the records alone.
func parseAPIRecordBlock(t *testing.T, block string, importPath string) []apiEntry {
	t.Helper()

	var entries []apiEntry

	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}

		cells := apiSplitRow(line)
		if len(cells) != 4 {
			t.Errorf("%s block %s holds a row of %d cells, and a row holds 4. Escape a pipe of a signature as \\|: %s",
				apiRecordFile, importPath, len(cells), line)

			continue
		}

		if cells[0] == "Kind" || apiIsAlignmentRow(cells[0]) {
			continue
		}

		entries = append(entries, apiEntry{
			Kind:      strings.Trim(cells[0], "`"),
			Name:      strings.Trim(cells[1], "`"),
			Signature: apiCellUnescape(strings.Trim(cells[2], "`")),
			Sentence:  cells[3],
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].key() < entries[j].key() })

	return entries
}

// readAPIRecord returns the parsed record of every published package.
func readAPIRecord(t *testing.T) map[string][]apiEntry {
	t.Helper()

	record, err := os.ReadFile(apiRecordFile)
	if err != nil {
		t.Fatalf("read %s: %v", apiRecordFile, err)
	}

	recorded := make(map[string][]apiEntry, len(publishedPackages))
	for _, pkg := range publishedPackages {
		block := apiRecordBlock(t, string(record), pkg.ImportPath)
		recorded[pkg.ImportPath] = parseAPIRecordBlock(t, block, pkg.ImportPath)
	}

	return recorded
}

// TestARecordCellCarriesASignatureThatHoldsAPipe holds the escape of the record format.
//
// A union type constraint holds a pipe, and a markdown table splits a row on the pipe. The
// self-review of #101 measured the case: `func[T int | string](v T) T` split its own row
// into five cells and failed a test that no API change had touched.
func TestARecordCellCarriesASignatureThatHoldsAPipe(t *testing.T) {
	const signature = "func[T int | string](v T) T"

	row := "| `func` | `Union` | `" + apiCellEscape(signature) + "` | One sentence. |"

	cells := apiSplitRow(row)
	if len(cells) != 4 {
		t.Fatalf("apiSplitRow returned %d cells for %s, and a row holds 4", len(cells), row)
	}

	if got := apiCellUnescape(strings.Trim(cells[2], "`")); got != signature {
		t.Errorf("the record round trip returned %q, and the signature is %q", got, signature)
	}
}

// TestTheRecordReaderSkipsEveryAlignmentRow holds the second row of a markdown table.
//
// A table writes the alignment with a dash, and a formatter may add a colon on either
// side. An alignment row that reads as a record produces a row the package does not
// export.
func TestTheRecordReaderSkipsEveryAlignmentRow(t *testing.T) {
	alignment := []string{"---", ":---", "---:", ":---:", " --- "}
	for _, cell := range alignment {
		if !apiIsAlignmentRow(strings.TrimSpace(cell)) {
			t.Errorf("apiIsAlignmentRow(%q) reports false, and the cell is an alignment cell", cell)
		}
	}

	for _, cell := range []string{"`type`", "Kind", "", "-a-"} {
		if apiIsAlignmentRow(cell) {
			t.Errorf("apiIsAlignmentRow(%q) reports true, and the cell is not an alignment cell", cell)
		}
	}
}

// TestTheApiRecordExists holds FR-release-1.
func TestTheApiRecordExists(t *testing.T) {
	if _, err := os.Stat(apiRecordFile); err != nil {
		t.Fatalf("FR-release-1 states that the project records every exported name in %s: %v",
			apiRecordFile, err)
	}
}

// TestTheApiRecordHoldsEveryExportedName holds FR-release-3 and FR-release-4.
//
// It fails when the source declares a name the record does not hold, when the record holds
// a name the source does not declare, and when the two state different signatures. The
// edge case of `docs/specs/features/10-release.md` names the first of the three: the
// engineer adds the name to the record, or unexports it.
func TestTheApiRecordHoldsEveryExportedName(t *testing.T) {
	recorded := readAPIRecord(t)

	for _, pkg := range publishedPackages {
		measured := measureAPI(t, pkg)

		recordedByKey := make(map[string]apiEntry, len(recorded[pkg.ImportPath]))
		for _, entry := range recorded[pkg.ImportPath] {
			if _, seen := recordedByKey[entry.key()]; seen {
				t.Errorf("%s records %s of %s twice", apiRecordFile, entry.key(), pkg.ImportPath)
			}

			recordedByKey[entry.key()] = entry
		}

		measuredByKey := make(map[string]apiEntry, len(measured))
		for _, entry := range measured {
			measuredByKey[entry.key()] = entry
		}

		for _, entry := range measured {
			found, held := recordedByKey[entry.key()]
			if !held {
				t.Errorf("%s exports %s %s, and %s records no row for it. Add this row, or unexport the name:\n| `%s` | `%s` | `%s` | <one sentence> |",
					pkg.ImportPath, entry.Kind, entry.Name, apiRecordFile,
					entry.Kind, entry.Name, apiCellEscape(entry.Signature))

				continue
			}

			if found.Signature != entry.Signature {
				t.Errorf("%s %s of %s: the source states %q and %s states %q",
					entry.Kind, entry.Name, pkg.ImportPath, entry.Signature, apiRecordFile, found.Signature)
			}
		}

		for _, entry := range recorded[pkg.ImportPath] {
			if _, held := measuredByKey[entry.key()]; !held {
				t.Errorf("%s records %s %s of %s, and the package exports no such name",
					apiRecordFile, entry.Kind, entry.Name, pkg.ImportPath)
			}
		}
	}
}

// TestEveryApiRecordRowStatesWhatTheNameDoes holds FR-release-2.
func TestEveryApiRecordRowStatesWhatTheNameDoes(t *testing.T) {
	for importPath, entries := range readAPIRecord(t) {
		for _, entry := range entries {
			if strings.TrimSpace(entry.Sentence) == "" {
				t.Errorf("FR-release-2: %s records %s %s of %s with no sentence",
					apiRecordFile, entry.Kind, entry.Name, importPath)
			}
		}
	}
}

// TestTheApiRecordStatesTheV1Promise holds FR-release-5.
//
// The promise is the whole point of the record, so a rewrite that drops it leaves a list
// of names that promises nothing.
func TestTheApiRecordStatesTheV1Promise(t *testing.T) {
	record, err := os.ReadFile(apiRecordFile)
	if err != nil {
		t.Fatalf("read %s: %v", apiRecordFile, err)
	}

	const promise = "**`v1` removes no name of this page, and it changes the signature of no name of this\npage.**"

	if !strings.Contains(string(record), promise) {
		t.Errorf("FR-release-5: %s states no promise. It must hold this sentence:\n%s",
			apiRecordFile, promise)
	}
}

// TestTheApiRecordStatesTheMeasuredCounts fails when a count of the prose goes stale.
//
// The tables of the record state a count, and a reader trusts that count without a
// re-measurement. A row comparison alone leaves those numbers unchecked, so a member that
// adds one name and one row passes every other test of this file and leaves a false total.
func TestTheApiRecordStatesTheMeasuredCounts(t *testing.T) {
	record, err := os.ReadFile(apiRecordFile)
	if err != nil {
		t.Fatalf("read %s: %v", apiRecordFile, err)
	}

	var (
		totalKinds = map[string]int{}
		totalRows  int
	)

	for _, pkg := range publishedPackages {
		measured := measureAPI(t, pkg)

		kinds := map[string]int{}
		for _, entry := range measured {
			kinds[entry.Kind]++
			totalKinds[entry.Kind]++
		}

		totalRows += len(measured)

		for _, row := range apiCountRows(pkg.ImportPath, kinds, len(measured)) {
			if !strings.Contains(string(record), row) {
				t.Errorf("%s states no row that matches the measurement. It must hold:\n%s",
					apiRecordFile, row)
			}
		}
	}

	for _, row := range apiCountRows("", totalKinds, totalRows) {
		if !strings.Contains(string(record), row) {
			t.Errorf("%s states no total row that matches the measurement. It must hold:\n%s",
				apiRecordFile, row)
		}
	}

	topLevel := 0
	for kind, count := range totalKinds {
		if topLevelAPIKinds[kind] {
			topLevel += count
		}
	}

	sentence := fmt.Sprintf("**The module publishes %d top-level exported names**", topLevel)
	if !strings.Contains(string(record), sentence) {
		t.Errorf("%s states no measured total. It must hold:\n%s", apiRecordFile, sentence)
	}
}

// apiCountRows returns the two table rows that state the counts of one package.
// An empty import path returns the two total rows.
func apiCountRows(importPath string, kinds map[string]int, rows int) []string {
	topLevel := 0
	for kind, count := range kinds {
		if topLevelAPIKinds[kind] {
			topLevel += count
		}
	}

	label := "| `" + importPath + "` |"
	bold := ""

	if importPath == "" {
		label = "| **Both** |"
		bold = "**"
	}

	wrap := func(value int) string { return fmt.Sprintf("%s%d%s", bold, value, bold) }

	return []string{
		fmt.Sprintf("%s %s | %s | %s | %s | %s | %s |",
			label, wrap(kinds["type"]), wrap(kinds["func"]), wrap(kinds["method"]),
			wrap(kinds["const"]), wrap(kinds["var"]), wrap(topLevel)),
		fmt.Sprintf("%s %s | %s | %s | %s |",
			label, wrap(topLevel), wrap(kinds["field"]), wrap(kinds["ifacemethod"]), wrap(rows)),
	}
}

// TestTheApiRecordNamesTheKeyMaterialRoute holds the ruling of 2026-08-15 UTC.
//
// Comment 5300957840 of #441 holds the ruling, and #661 built the route. `WithKeyLog` on
// `NewProcessor` and on `NewSyncProcessor` is the one route by which key material reaches
// a fingerprinter, so the freeze binds all four names. #100 and #661 are the reversal path.
func TestTheApiRecordNamesTheKeyMaterialRoute(t *testing.T) {
	recorded := readAPIRecord(t)["github.com/Crank-Git/ja4plus-go"]

	held := make(map[string]string, len(recorded))
	for _, entry := range recorded {
		held[entry.key()] = entry.Signature
	}

	route := map[string]string{
		"type|ProcessorOption":  "func(*Processor)",
		"type|KeyLog":           "struct",
		"func|WithKeyLog":       "func(keyLog *KeyLog) ProcessorOption",
		"func|NewProcessor":     "func(options ...ProcessorOption) *Processor",
		"func|NewSyncProcessor": "func(options ...ProcessorOption) *SyncProcessor",
	}

	for key, signature := range route {
		found, records := held[key]
		if !records {
			t.Errorf("%s records no %s, and it is part of the one route for key material",
				apiRecordFile, key)

			continue
		}

		if found != signature {
			t.Errorf("%s records %s as %q, and the ruled route states %q",
				apiRecordFile, key, found, signature)
		}
	}

	// No Fingerprinter method takes a key log. A route that reaches a fingerprinter
	// directly reverses the ruling, so it lands before the freeze or it lands in `v2`.
	for _, entry := range recorded {
		if entry.Kind != "ifacemethod" && entry.Kind != "method" {
			continue
		}

		if strings.Contains(entry.Signature, "KeyLog") {
			t.Errorf("%s records %s as %q, and the ruling states that WithKeyLog is the one route for key material",
				apiRecordFile, entry.Name, entry.Signature)
		}
	}
}

// TestNoExportedTypeEmbedsAnotherType holds one limit of the measurement.
//
// The measurement records an explicitly declared method, and never a method that an
// embedded type promotes. No exported type of either published package embeds another type
// today, so the recorded set and the callable set are equal. This test fails when that
// stops holding, and the record then needs a type-checked comparison.
// `docs/api/v1.md` `## The measurement reads the standard library` names the reversal path.
func TestNoExportedTypeEmbedsAnotherType(t *testing.T) {
	for _, pkg := range publishedPackages {
		built, err := build.Default.ImportDir(pkg.Dir, 0)
		if err != nil {
			t.Fatalf("read the package of %s: %v", pkg.ImportPath, err)
		}

		fset := token.NewFileSet()

		for _, name := range built.GoFiles {
			path := filepath.Join(pkg.Dir, name)

			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			ast.Inspect(file, func(node ast.Node) bool {
				spec, isType := node.(*ast.TypeSpec)
				if !isType || !spec.Name.IsExported() {
					return true
				}

				declared, isStruct := spec.Type.(*ast.StructType)
				if !isStruct || declared.Fields == nil {
					return true
				}

				for _, field := range declared.Fields.List {
					if len(field.Names) == 0 {
						t.Errorf("%s embeds a type in %s, and the measurement records no promoted method. Read %s.",
							spec.Name.Name, path, apiRecordFile)
					}
				}

				return true
			})
		}
	}
}

// TestEveryImportablePackageIsRecordedOrDeclined holds the completeness of the record.
//
// A row comparison proves that the record describes the packages it names. It proves
// nothing about a package the record forgot. So this test walks the module, and it fails on
// a package that is neither published, nor `internal`, nor `package main`.
func TestEveryImportablePackageIsRecordedOrDeclined(t *testing.T) {
	published := make(map[string]bool, len(publishedPackages))
	for _, pkg := range publishedPackages {
		published[filepath.Clean(pkg.Dir)] = true
	}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if path != "." && (strings.HasPrefix(base, ".") || base == "testdata" || base == "bin") {
			return filepath.SkipDir
		}

		built, buildErr := build.Default.ImportDir(path, 0)
		if buildErr != nil {
			var noGo *build.NoGoError
			if !errors.As(buildErr, &noGo) {
				// A conflicting package clause reaches this branch, and it is a defect
				// rather than a platform mismatch. An earlier version swallowed it.
				t.Errorf("read the package of %s: %v", path, buildErr)

				return nil
			}

			// The directory builds no package on this platform. It still publishes a name
			// on the platform its build constraints name, so a gated-out directory needs a
			// decision rather than silence.
			if !pathHoldsInternalElement(path) && dirHoldsGoFile(t, path) {
				t.Errorf("%s holds a Go file that no build constraint of this platform selects, so this test cannot classify it. Add it to publishedPackages and to %s, or decline it.",
					path, apiRecordFile)
			}

			return nil
		}

		if len(built.GoFiles) == 0 {
			// The directory holds test files alone. A test file exports no name a consumer
			// reaches.
			return nil
		}

		switch {
		case published[filepath.Clean(path)]:
		case built.Name == "main":
		case pathHoldsInternalElement(path):
		default:
			t.Errorf("%s holds package %q, and it is neither published, nor internal, nor main. Add it to publishedPackages and to %s, or decline it.",
				path, built.Name, apiRecordFile)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the module: %v", err)
	}
}

// dirHoldsGoFile reports whether the directory holds a file that ends `.go`.
//
// `build.Default.ImportDir` returns a `*build.NoGoError` for a directory with no Go file
// and for a directory whose every Go file the build constraints exclude. This function
// separates the two.
func dirHoldsGoFile(t *testing.T, dir string) bool {
	t.Helper()

	listed, err := os.ReadDir(dir)
	if err != nil {
		t.Errorf("read the directory %s: %v", dir, err)

		return false
	}

	for _, entry := range listed {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			return true
		}
	}

	return false
}

// pathHoldsInternalElement reports whether the `go` command bars an import of the path
// from outside this module.
//
// The rule belongs to the `go` command, and the Go language specification does not state
// it. Verified against <https://go.dev/doc/go1.4#internalpackages>, retrieved 2026-08-15.
func pathHoldsInternalElement(path string) bool {
	for _, element := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if element == "internal" {
			return true
		}
	}

	return false
}

// TestTheSiteExcludesTheApiRecord holds the exclusion of `docs/api/` by name.
//
// `TestEveryExcludedDirectoryReachesTheSiteConfig` in `mkdocs_config_test.go` reads
// `excludedDocumentationDirs`, so it holds no name of its own and an edit that drops the
// entry leaves it green. This test names the directory as a literal.
//
// `docs/api/v1.md` `## This page is not published by the documentation site` states the two
// reasons and the reversal path.
func TestTheSiteExcludesTheApiRecord(t *testing.T) {
	if !isExcludedDocumentationDir(apiRecordDir) {
		t.Errorf("excludedDocumentationDirs holds no %q entry, and %s must not publish",
			apiRecordDir, apiRecordFile)
	}

	config, err := os.ReadFile("mkdocs.yml")
	if err != nil {
		t.Fatalf("read mkdocs.yml: %v", err)
	}

	if !strings.Contains(string(config), "\n  /"+apiRecordDir+"/\n") {
		t.Errorf("exclude_docs of mkdocs.yml holds no /%s/ pattern, so %s would publish and the strict build would fail on the missing nav entry",
			apiRecordDir, apiRecordFile)
	}
}
