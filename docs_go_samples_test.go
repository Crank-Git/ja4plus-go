package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The tests below hold FR-documentation-28 and FR-documentation-29 of #87.
//
// A code sample on a published page is code that nothing compiles. It rots at the first
// rename, and a reader who copies it reaches an error that the repository never saw. So
// every fenced Go block of `docs/` is mirrored twice, and each mirror is compiled.
//
//   - `examples/<name>/main.go` holds the whole block. `go build ./examples/...` compiles
//     it, and `.github/workflows/ci.yml` runs that build on every pull request under
//     FR-documentation-27.
//   - `example_test.go` holds the body of `main` as a testable example. `go test` compiles
//     it under FR-documentation-28.
//
// **So a sample that does not compile reddens the build, and the tests below hold the two
// mirrors equal to the page.** That chain is the edge case of #87: a code sample in
// `docs/` that does not compile fails FR-documentation-29.
//
// # The matching rule, and why it is the token sequence
//
// FR-documentation-29 states that a block "matches" a block of `example_test.go`, and it
// names no rule. **This project reads "matches" as equality of the Go token sequence,
// after the comments and the semicolons are removed.** The three candidate rules and the
// reason for the choice:
//
//   - **Byte equality is impossible here, and it is not a preference.** The fenced blocks
//     of `docs/` indent with four spaces, measured at `docs/usage.md:132` and at
//     `docs/concurrency.md:46`. `gofmt` indents with a tab, and the `gofmt` formatter of
//     `.golangci.yml` binds every Go file of this repository. So no Go file can be
//     byte-equal to a fenced block of a page.
//   - **A semantic rule matches too much.** A rule that compares behavior passes a mirror
//     that renames a variable, drops a field of the printed line, or calls a different
//     constructor. That guard guards nothing, and `CLAUDE.md` names a guard that guards
//     nothing as one of the five cases that earns an issue.
//   - **The token sequence is exact about the code and blind to the layout.** It fails on
//     a renamed identifier, a changed literal and a dropped call. It passes a reindent, a
//     rewrap and an added or edited comment, so a documentation edit that changes no code
//     never reddens the build.
//
// The semicolons are removed because the Go scanner inserts one at a line ending. Keeping
// them would make a rewrapped line a failure, which is the reformatting case the rule
// exists to permit.
//
// Three measurements of the rule, taken on 2026-08-14 against `docs/usage.md`.
//
//   - A renamed variable fails, and the message names the page and the line.
//   - A reindent, an added blank line and an added comment each pass.
//   - **A call rewrapped across lines fails**, because Go requires a trailing comma there
//     and that comma is a token. `gofmt` never rewraps a call, so no formatter produces
//     this case. A person who rewraps a call edits the mirror in the same commit.
//
// # The mapping is one to one
//
// Each fenced block matches exactly one example program and exactly one example function.
// Each example program and each example function matches exactly one fenced block.
// **A one-way rule lets a deleted page leave an orphan mirror behind.** The next reader
// then cannot tell an orphan from a sample whose page moved.

const (
	// exampleTestFile holds one testable example for each fenced Go block of `docs/`.
	exampleTestFile = "example_test.go"
	// examplesRoot holds one runnable program for each fenced Go block of `docs/`.
	// FR-documentation-25 requires the directory.
	examplesRoot = "examples"
)

// goSample is one fenced Go block of one published page.
type goSample struct {
	// page is the path of the page that holds the block.
	page string
	// line is the line number of the opening fence.
	line int
	// source is the text between the two fences.
	source string
}

// name returns the citation this project writes for the block, as `path:line`.
func (s goSample) name() string {
	return s.page + ":" + strconv.Itoa(s.line)
}

// collectGoSamples returns every fenced Go block of every published page.
//
// It skips `docs/specs/` and `docs/audit/`, because `exclude_docs` of `mkdocs.yml` drops
// both directories from the site. A sample in the spec package documents a design and
// never an interface a reader calls.
func collectGoSamples(t *testing.T) []goSample {
	t.Helper()

	var samples []goSample
	err := filepath.WalkDir(documentationRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != documentationRoot && (entry.Name() == "specs" || entry.Name() == "audit") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}

		lines := strings.Split(readTextFile(t, path), "\n")
		for index := 0; index < len(lines); index++ {
			opening := strings.TrimSpace(lines[index])
			if opening != "```go" && !strings.HasPrefix(opening, "```go ") {
				continue
			}
			closing := index + 1
			for closing < len(lines) && strings.TrimSpace(lines[closing]) != "```" {
				closing++
			}
			if closing == len(lines) {
				t.Errorf("%s:%d opens a Go block that no fence closes", path, index+1)
				break
			}
			samples = append(samples, goSample{
				page:   path,
				line:   index + 1,
				source: strings.Join(lines[index+1:closing], "\n"),
			})
			index = closing
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", documentationRoot, err)
	}
	return samples
}

// normalizedTokens returns the Go token sequence of one fragment, without the comments and
// without the semicolons.
//
// The fragment is a whole file or a statement list. The scanner reads either one, because
// it reads tokens and never a grammar.
func normalizedTokens(source string) []string {
	var tokens []string

	set := token.NewFileSet()
	file := set.AddFile("fragment", set.Base(), len(source))

	var reader scanner.Scanner
	// The error handler is nil and the mode holds no `ScanComments`, so the scanner drops
	// every comment and it reports no error. A fragment that does not scan produces a
	// short sequence, and the comparison then fails with the sequences beside each other.
	reader.Init(file, []byte(source), nil, 0)
	for {
		_, kind, literal := reader.Scan()
		if kind == token.EOF {
			return tokens
		}
		if kind == token.SEMICOLON {
			continue
		}
		if literal != "" {
			tokens = append(tokens, kind.String()+" "+literal)
			continue
		}
		tokens = append(tokens, kind.String())
	}
}

// tokenKey joins a token sequence into one comparable string.
func tokenKey(tokens []string) string {
	return strings.Join(tokens, "\n")
}

// functionBodyTokens returns the normalized token sequence of the body of one function,
// and it excludes the two braces.
func functionBodyTokens(t *testing.T, path, source string, body *ast.BlockStmt, set *token.FileSet) []string {
	t.Helper()

	first := set.Position(body.Lbrace).Offset + 1
	last := set.Position(body.Rbrace).Offset
	if first > last || last > len(source) {
		t.Fatalf("%s: the body offsets fall outside the source", path)
	}
	return normalizedTokens(source[first:last])
}

// TestEveryGoSampleOfTheSiteIsARunnableProgram holds FR-documentation-26 and the first
// half of FR-documentation-29.
//
// It proves each of these.
//
//   - Each fenced Go block parses as a whole Go file.
//   - That file declares `package main` and `func main`.
//   - `examples/` holds exactly one program whose token sequence equals the block.
func TestEveryGoSampleOfTheSiteIsARunnableProgram(t *testing.T) {
	samples := collectGoSamples(t)
	if len(samples) == 0 {
		t.Fatalf("%s holds no fenced Go block, so this guard reads nothing", documentationRoot)
	}

	programs := map[string]string{}
	err := filepath.WalkDir(examplesRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Base(path) != "main.go" {
			return nil
		}
		programs[tokenKey(normalizedTokens(readTextFile(t, path)))] = path
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", examplesRoot, err)
	}
	if len(programs) == 0 {
		t.Fatalf("%s holds no program, and FR-documentation-25 requires one for each sample", examplesRoot)
	}

	matched := map[string]string{}
	for _, sample := range samples {
		set := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(set, sample.name(), sample.source, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Errorf("%s does not parse as a Go file: %v", sample.name(), parseErr)
			continue
		}
		if parsed.Name.Name != "main" {
			t.Errorf("%s declares package %q, and a runnable program declares package main",
				sample.name(), parsed.Name.Name)
			continue
		}
		if findFunction(parsed, "main") == nil {
			t.Errorf("%s declares no func main, and a runnable program declares one", sample.name())
			continue
		}

		key := tokenKey(normalizedTokens(sample.source))
		program, ok := programs[key]
		if !ok {
			t.Errorf("%s matches no program of %s; add one whose token sequence equals the block",
				sample.name(), examplesRoot)
			continue
		}
		if earlier, taken := matched[program]; taken {
			t.Errorf("%s and %s both match %s, and the mapping is one to one",
				earlier, sample.name(), program)
			continue
		}
		matched[program] = sample.name()
	}

	for _, program := range programs {
		if _, ok := matched[program]; ok {
			continue
		}
		t.Errorf("%s matches no fenced Go block of %s; delete it or add the page that carries it",
			program, documentationRoot)
	}
}

// TestEveryGoSampleOfTheSiteIsATestableExample holds FR-documentation-28 and the second
// half of FR-documentation-29.
//
// It proves that `example_test.go` holds exactly one testable example for each fenced Go
// block. The body of that example equals the body of `main` in the block.
func TestEveryGoSampleOfTheSiteIsATestableExample(t *testing.T) {
	samples := collectGoSamples(t)
	if len(samples) == 0 {
		t.Fatalf("%s holds no fenced Go block, so this guard reads nothing", documentationRoot)
	}

	source := readTextFile(t, exampleTestFile)
	set := token.NewFileSet()
	parsed, err := parser.ParseFile(set, exampleTestFile, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", exampleTestFile, err)
	}

	examples := map[string]string{}
	names := map[string]string{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || function.Body == nil {
			continue
		}
		if !strings.HasPrefix(function.Name.Name, "Example") {
			continue
		}
		key := tokenKey(functionBodyTokens(t, exampleTestFile, source, function.Body, set))
		examples[key] = function.Name.Name
		names[function.Name.Name] = ""
	}
	if len(examples) == 0 {
		t.Fatalf("%s holds no testable example, and FR-documentation-28 requires one for each sample",
			exampleTestFile)
	}

	for _, sample := range samples {
		sampleSet := token.NewFileSet()
		parsedSample, parseErr := parser.ParseFile(sampleSet, sample.name(), sample.source, parser.SkipObjectResolution)
		if parseErr != nil {
			// TestEveryGoSampleOfTheSiteIsARunnableProgram reports the parse failure, and
			// one message for one defect is enough.
			continue
		}
		main := findFunction(parsedSample, "main")
		if main == nil {
			continue
		}

		key := tokenKey(functionBodyTokens(t, sample.name(), sample.source, main.Body, sampleSet))
		name, ok := examples[key]
		if !ok {
			t.Errorf("%s matches no testable example of %s; add one whose body equals the body of main",
				sample.name(), exampleTestFile)
			continue
		}
		if earlier := names[name]; earlier != "" {
			t.Errorf("%s and %s both match %s, and the mapping is one to one", earlier, sample.name(), name)
			continue
		}
		names[name] = sample.name()
	}

	for name, sample := range names {
		if sample != "" {
			continue
		}
		t.Errorf("%s of %s matches no fenced Go block of %s; delete it or add the page that carries it",
			name, exampleTestFile, documentationRoot)
	}
}

// findFunction returns the named top-level function of one file, and nil when the file
// declares none.
func findFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name {
			return function
		}
	}
	return nil
}
