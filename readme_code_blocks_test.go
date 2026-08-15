package ja4plus

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests below hold FR-release-28 of #103: every code block of `README.md` is checked
// by a test.
//
// A code block that nothing runs is a claim that nothing measures. It rots at the first
// rename, and a reader who copies it reaches an error that the repository never saw. The
// README is the first page a reader meets, so a stale block there costs the most.
//
// `docs_go_samples_test.go` holds the same rule for `docs/`, and it does not reach this
// file. It walks `documentationRoot`, which is `docs`, so `README.md` stood outside every
// code check until #103. The two guards differ in what they can demand, and the reason is
// the mirror.
//
//   - A block of `docs/` is mirrored by `examples/<name>/main.go` and by a testable
//     example, so the compiler reads it.
//   - A block of `README.md` has no mirror. The four tests below read the block itself.
//
// **This file adds no mirror, and that is deliberate.** A mirror for each README block
// would duplicate the concurrency functions that `concurrency_doc_test.go` already holds
// byte for byte, and #103 owns `README.md` alone. So the checks below read the block
// where it lives.
//
// # What each test proves
//
//   - Every fence names a language, and the language is one this file checks. A block
//     with no language reaches no check, so an unchecked block cannot enter the page.
//   - Every Go block parses, and every block that declares `package main` compiles.
//   - Every exported name that a Go block reads through `ja4plus.` or through `ja4db.`
//     is a name that the package declares. **This is the API freeze guard for the
//     README.** A rename that `api_test.go` catches in the record, this test catches in
//     the prose.
//   - Every command of a shell block that runs the program names a subcommand that the
//     program defines.
//   - The output that the README shows for one run equals the output that the program
//     writes for that run.

const (
	// readmeOutputSection heads the one section whose output block is compared against a
	// real run. FR-release-21 requires that output to be real.
	readmeOutputSection = "### One run, and the output it writes"

	// readmeProgramPackage is the package that `go run` builds for the output check.
	readmeProgramPackage = "./cmd/ja4plus"

	// readmeCommandName is the first word of every shell line that runs the program.
	readmeCommandName = "ja4plus"

	// readmeCaptureAbsentMessage states that the guard read no capture.
	//
	// It carries no word of `conformanceSkipMarker`, because
	// `.github/workflows/ci.yml` fails the conformance job on that marker and this skip
	// means something else. TestTheCISkipDetectorMatchesNoUntaggedSkipMessage holds that
	// separation.
	readmeCaptureAbsentMessage = "the README command-line guard read no capture; " +
		"run `make corpus` to fetch it. Every other block check ran."
)

// readmeBlock is one fenced block of `README.md`.
type readmeBlock struct {
	// language is the word that follows the opening fence, and it is empty when the fence
	// names none.
	language string
	// line is the line number of the opening fence.
	line int
	// source is the text between the two fences.
	source string
}

// name returns the citation this project writes for the block, as `path:line`.
func (b readmeBlock) name() string {
	return readmeFile + ":" + strconv.Itoa(b.line)
}

// readmeBlocks returns every fenced block of `README.md`, in the order the page holds
// them.
func readmeBlocks(t *testing.T) []readmeBlock {
	t.Helper()

	lines := strings.Split(readTextFile(t, readmeFile), "\n")

	var blocks []readmeBlock
	for index := 0; index < len(lines); index++ {
		opening := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(opening, "```") {
			continue
		}

		closing := index + 1
		for closing < len(lines) && strings.TrimSpace(lines[closing]) != "```" {
			closing++
		}
		if closing == len(lines) {
			t.Fatalf("%s:%d opens a block that no fence closes", readmeFile, index+1)
		}

		blocks = append(blocks, readmeBlock{
			language: strings.TrimSpace(strings.TrimPrefix(opening, "```")),
			line:     index + 1,
			source:   strings.Join(lines[index+1:closing], "\n"),
		})
		index = closing
	}

	if len(blocks) == 0 {
		t.Fatalf("%s holds no fenced block, so these guards read nothing", readmeFile)
	}

	return blocks
}

// TestEveryFencedBlockOfTheReadmeNamesACheckedLanguage holds the first half of
// FR-release-28.
//
// A block with no language reaches no check below, so this test is the gate. A later
// language joins the set here, and it joins a check at the same time.
func TestEveryFencedBlockOfTheReadmeNamesACheckedLanguage(t *testing.T) {
	checked := map[string]string{
		"go":   "TestEveryGoBlockOfTheReadmeParses reads it.",
		"bash": "TestEveryProgramCommandOfTheReadmeNamesASubcommand reads it.",
		"text": "TestTheReadmeCommandLineOutputMatchesTheProgram reads it.",
	}

	for _, block := range readmeBlocks(t) {
		if block.language == "" {
			t.Errorf("%s opens a block that names no language, and no check reads it. "+
				"Name one of %s.", block.name(), readmeSortedLanguages(checked))

			continue
		}

		if _, ok := checked[block.language]; !ok {
			t.Errorf("%s names the language %q, and no check reads it. Name one of %s, "+
				"or add a check for %q.", block.name(), block.language,
				readmeSortedLanguages(checked), block.language)
		}
	}
}

// readmeSortedLanguages returns the checked languages as one quoted list, for a failure
// message.
func readmeSortedLanguages(checked map[string]string) string {
	names := make([]string, 0, len(checked))
	for name := range checked {
		names = append(names, strconv.Quote(name))
	}
	// A map iterates in no order, so the sort keeps one failure message stable.
	slices.Sort(names)

	return strings.Join(names, ", ")
}

// parseReadmeGoBlock returns the syntax tree of one Go block.
//
// A block of the README is one of three shapes, and the parser reads a whole file alone.
// So this function tries each shape and it returns the first tree that parses.
//
//  1. A whole program, which declares `package main`.
//  2. A declaration list, which declares a function or an import and no package clause.
//  3. A statement list, which a reader pastes into a function body.
//
// It returns the offset that the successful shape added before the block, so a caller
// reports a position of the page.
func parseReadmeGoBlock(block readmeBlock) (*ast.File, *token.FileSet, error) {
	shapes := []string{
		block.source,
		"package p\n" + block.source,
		"package p\nfunc _() {\n" + block.source + "\n}\n",
	}

	var lastErr error
	for _, shape := range shapes {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, block.name(), shape, parser.SkipObjectResolution)
		if err == nil {
			return file, set, nil
		}
		lastErr = err
	}

	return nil, nil, lastErr
}

// TestEveryGoBlockOfTheReadmeParses holds the second half of FR-release-28 for Go.
//
// A block that does not parse cannot compile, so a reader who copies it reaches an error.
func TestEveryGoBlockOfTheReadmeParses(t *testing.T) {
	var seen int
	for _, block := range readmeBlocks(t) {
		if block.language != "go" {
			continue
		}
		seen++

		if _, _, err := parseReadmeGoBlock(block); err != nil {
			t.Errorf("%s does not parse as Go: %v", block.name(), err)
		}
	}

	if seen == 0 {
		t.Fatalf("%s holds no Go block, and this guard then reads nothing", readmeFile)
	}
}

// TestEveryProgramBlockOfTheReadmeCompiles holds FR-release-20.
//
// FR-release-20 states that the README holds a library example that compiles, and a parse
// is weaker than a compile. A parse reads the grammar alone, so it passes a block that
// names a function this library dropped, or that leaves an import unused.
//
// The build directory sits under the repository root, because the block imports this
// module and a directory outside the module resolves no import. `go build` writes the
// binary to the null device, so the run leaves no artifact.
func TestEveryProgramBlockOfTheReadmeCompiles(t *testing.T) {
	var seen int
	for _, block := range readmeBlocks(t) {
		if block.language != "go" {
			continue
		}

		file, _, err := parseReadmeGoBlock(block)
		if err != nil {
			// TestEveryGoBlockOfTheReadmeParses reports the parse failure.
			continue
		}
		// A shape that this function added declares `package p`, so a block that declares
		// `package main` is the whole program the reader copies.
		if file.Name.Name != "main" || findFunction(file, "main") == nil {
			continue
		}
		seen++

		readmeCompileProgram(t, block)
	}

	if seen == 0 {
		t.Fatalf("%s holds no Go block that declares package main, and FR-release-20 "+
			"requires a library example", readmeFile)
	}
}

// readmeCompileProgram builds one program block, and it reports the compiler output on a
// failure.
func readmeCompileProgram(t *testing.T, block readmeBlock) {
	t.Helper()

	//nolint:usetesting // t.TempDir returns a path outside the module, and the block imports this module.
	dir, err := os.MkdirTemp(".", "readmebuild")
	if err != nil {
		t.Fatalf("create the build directory for %s: %v", block.name(), err)
	}
	t.Cleanup(func() {
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			t.Errorf("remove the build directory %s: %v", dir, removeErr)
		}
	})

	if writeErr := os.WriteFile(filepath.Join(dir, "main.go"), []byte(block.source), 0o600); writeErr != nil {
		t.Fatalf("write the program of %s: %v", block.name(), writeErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	build := exec.CommandContext(ctx, "go", "build", "-o", os.DevNull, "./"+dir)

	if report, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Errorf("%s does not compile: %v\n%s", block.name(), buildErr, report)
	}
}

// readmeExportedNames returns every exported top-level name that the package in one
// directory declares, from the files that are not tests.
func readmeExportedNames(t *testing.T, dir string) map[string]bool {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("list the Go files of %s: %v", dir, err)
	}

	exported := map[string]bool{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		set := token.NewFileSet()
		file, parseErr := parser.ParseFile(set, name, readTextFile(t, name), parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}

		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				// A method belongs to its receiver, and a package qualifier never reaches
				// one.
				if typed.Recv == nil && typed.Name.IsExported() {
					exported[typed.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch declared := spec.(type) {
					case *ast.TypeSpec:
						if declared.Name.IsExported() {
							exported[declared.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, ident := range declared.Names {
							if ident.IsExported() {
								exported[ident.Name] = true
							}
						}
					}
				}
			}
		}
	}

	if len(exported) == 0 {
		t.Fatalf("%s declares no exported name, and this guard then reads nothing", dir)
	}

	return exported
}

// TestEveryLibraryNameOfTheReadmeIsExported holds FR-release-28 against the API freeze.
//
// Every name that a Go block of the README reads through a package qualifier is a name
// that the package declares. `api_test.go` holds the record of the surface, and this test
// holds the prose against the same surface.
//
// It reads the syntax tree and never the text, so a name inside a comment or inside a
// string reaches no assertion.
func TestEveryLibraryNameOfTheReadmeIsExported(t *testing.T) {
	declared := map[string]map[string]bool{
		"ja4plus": readmeExportedNames(t, "."),
		"ja4db":   readmeExportedNames(t, "ja4db"),
	}

	var seen int
	for _, block := range readmeBlocks(t) {
		if block.language != "go" {
			continue
		}

		file, _, err := parseReadmeGoBlock(block)
		if err != nil {
			// TestEveryGoBlockOfTheReadmeParses reports the parse failure, and one
			// message for one defect is enough.
			continue
		}

		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			qualifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}

			names, ok := declared[qualifier.Name]
			if !ok {
				return true
			}
			seen++

			if !names[selector.Sel.Name] {
				t.Errorf("%s reads %s.%s, and the package declares no such exported name",
					block.name(), qualifier.Name, selector.Sel.Name)
			}

			return true
		})
	}

	if seen == 0 {
		t.Fatalf("no Go block of %s reads a name of this library, and this guard then "+
			"reads nothing", readmeFile)
	}
}

// readmeSubcommands returns every word that the program accepts as its first argument.
//
// It reads the case labels of `cmd/ja4plus/main.go`. The set is a superset of the
// subcommands, because the file switches on a subcommand of `db` in the same shape. A
// superset still fails on a subcommand that the program drops or renames, which is the
// defect this guard exists to catch.
func readmeSubcommands(t *testing.T) map[string]bool {
	t.Helper()

	const mainFile = "cmd/ja4plus/main.go"

	labels := regexp.MustCompile(`case ("[^"]*"(?:, "[^"]*")*):`).
		FindAllStringSubmatch(readTextFile(t, mainFile), -1)
	if len(labels) == 0 {
		t.Fatalf("%s holds no case label, and this guard then reads nothing", mainFile)
	}

	accepted := map[string]bool{}
	for _, label := range labels {
		for _, quoted := range strings.Split(label[1], ", ") {
			word, err := strconv.Unquote(quoted)
			if err != nil {
				t.Fatalf("read the case label %s of %s: %v", quoted, mainFile, err)
			}
			accepted[word] = true
		}
	}

	return accepted
}

// TestEveryProgramCommandOfTheReadmeNamesASubcommand holds FR-release-28 for a shell
// block.
//
// A README that names a subcommand the program dropped sends the reader to an error.
func TestEveryProgramCommandOfTheReadmeNamesASubcommand(t *testing.T) {
	accepted := readmeSubcommands(t)

	var seen int
	for _, block := range readmeBlocks(t) {
		if block.language != "bash" {
			continue
		}

		for offset, line := range strings.Split(block.source, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != readmeCommandName {
				continue
			}
			seen++

			if !accepted[fields[1]] {
				t.Errorf("%s:%d runs `%s %s`, and %s accepts no such subcommand",
					readmeFile, block.line+1+offset, readmeCommandName, fields[1],
					readmeCommandName)
			}
		}
	}

	if seen == 0 {
		t.Fatalf("no shell block of %s runs %s, and this guard then reads nothing",
			readmeFile, readmeCommandName)
	}
}

// readmeOutputCase returns the command and the output that the output section holds.
//
// The command comes from the one shell block of the section, and the output comes from
// the one text block that follows it.
func readmeOutputCase(t *testing.T) (command []string, output string) {
	t.Helper()

	page := readTextFile(t, readmeFile)
	if !strings.Contains(page, readmeOutputSection) {
		t.Fatalf("%s holds no section headed %q, and FR-release-21 requires the output "+
			"of one real run", readmeFile, readmeOutputSection)
	}

	start := strings.Index(page, readmeOutputSection)
	section := page[start:]
	if next := strings.Index(section[len(readmeOutputSection):], "\n### "); next >= 0 {
		section = section[:len(readmeOutputSection)+next]
	}

	for _, block := range readmeBlocks(t) {
		if !strings.Contains(section, block.source) {
			continue
		}

		switch block.language {
		case "bash":
			if command != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(block.source), "\n")
			if len(lines) != 1 {
				t.Fatalf("%s holds %d command lines, and the output check runs exactly one",
					block.name(), len(lines))
			}
			command = strings.Fields(lines[0])
		case "text":
			if output == "" {
				output = block.source
			}
		}
	}

	if len(command) == 0 {
		t.Fatalf("the section %q holds no shell block, and the output check needs the "+
			"command", readmeOutputSection)
	}
	if output == "" {
		t.Fatalf("the section %q holds no text block, and the output check needs the "+
			"output", readmeOutputSection)
	}
	if command[0] != readmeCommandName {
		t.Fatalf("the command of %q is %q, and the output check runs %s",
			readmeOutputSection, command[0], readmeCommandName)
	}

	return command, output
}

// TestTheReadmeCommandLineOutputMatchesTheProgram holds FR-release-21 and the last part
// of FR-release-28.
//
// It runs the command that the README shows, and it compares the output to the block that
// the README shows. A README that states output nobody re-ran is the defect this test
// exists to catch.
//
// The capture comes from the FoxIO corpus, which this repository never tracks. So the
// test skips when the worktree holds no corpus, and it names the repair.
func TestTheReadmeCommandLineOutputMatchesTheProgram(t *testing.T) {
	command, want := readmeOutputCase(t)

	// The command names the capture, so the guard reads the path the page states.
	capture := command[len(command)-1]
	if _, err := os.Stat(capture); err != nil {
		t.Skip(readmeCaptureAbsentMessage)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	arguments := append([]string{"run", readmeProgramPackage}, command[1:]...)
	run := exec.CommandContext(ctx, "go", arguments...)

	produced, err := run.Output()
	if err != nil {
		t.Fatalf("run `go %s`: %v", strings.Join(arguments, " "), err)
	}

	got := strings.TrimRight(string(produced), "\n")
	if got != strings.TrimRight(want, "\n") {
		t.Errorf("the output block of %q does not match the program.\nthe README states:\n%s\n\nthe program writes:\n%s",
			readmeOutputSection, want, got)
	}
}
