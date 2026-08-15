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
//   - A block of `README.md` has no mirror. The six tests below read the block itself.
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
//
// One test of this file reads no block, and #702 built it.
// TestTheReadmeNameWalkReadsTheSameSurfaceAsTheApiRecord holds the name set of
// `readmeExportedNames` equal to the top-level surface of the API record, so the guard
// above cannot pass over a name it never read.

const (
	// readmeOutputSection heads the one section whose output block is compared against a
	// real run. FR-release-21 requires that output to be real.
	readmeOutputSection = "### One run, and the output it writes"

	// readmeProgramPackage is the package that `go run` builds for the output check.
	readmeProgramPackage = "./cmd/ja4plus"

	// readmeCommandName is the first word of every shell line that runs the program.
	readmeCommandName = "ja4plus"

	// readmeRunCapture is the capture that a program block reads. It is a pcap file,
	// because the Quick Start block reads one through `pcapgo.NewReader`.
	readmeRunCapture = "testdata/foxio/pcap/tls12.pcap"

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
// **Two limits, and a reader must know both.**
//
// Shape 2 and shape 3 each add a line above the block, so the position that the parser
// reports for a failure of one of them is one line low or two lines low. The citation
// still names the page and the fence, which is what a reader needs to find the block.
//
// A block that drops its `package main` line parses under shape 2, so this function
// reports nothing for it. TestEveryProgramBlockOfTheReadmeCompiles reads a whole program
// alone, and a reader who copies a program block reaches the compiler.
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

	binary := filepath.Join(dir, "program")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./"+dir)

	if report, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Errorf("%s does not compile: %v\n%s", block.name(), buildErr, report)

		return
	}

	readmeRunProgram(t, ctx, block, dir)
}

// readmeRunProgram runs one built program block against a real capture.
//
// FR-release-20 states that the example compiles, and the acceptance criterion of #100
// states that it runs. A program that compiles still fails at the first packet, so the
// run is the stronger evidence.
//
// The block opens a capture under a fixed name, so this function copies one there. It
// returns without a run when the block reads no capture, and it returns without a run
// when the worktree holds no corpus.
func readmeRunProgram(t *testing.T, ctx context.Context, block readmeBlock, dir string) {
	t.Helper()

	const captureName = "capture.pcap"

	if !strings.Contains(block.source, captureName) {
		return
	}

	capture, err := os.ReadFile(readmeRunCapture)
	if err != nil {
		t.Log(readmeCaptureAbsentMessage)

		return
	}

	if writeErr := os.WriteFile(filepath.Join(dir, captureName), capture, 0o600); writeErr != nil {
		t.Fatalf("write the capture for %s: %v", block.name(), writeErr)
	}

	run := exec.CommandContext(ctx, "./program")
	run.Dir = dir

	report, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Errorf("%s compiles and it does not run: %v\n%s", block.name(), runErr, report)

		return
	}

	if len(report) == 0 {
		t.Errorf("%s runs against %s and it writes nothing, so the run proves no read",
			block.name(), readmeRunCapture)
	}
}

// readmeTopLevelKinds names each kind of the API record that a package qualifier reaches.
//
// A method, a field and an interface method each belong to a value, so `ja4plus.Name`
// never reads one. `api_test.go` states the kind set of `apiEntry.Kind`.
//
// **`topLevelAPIKinds` in `api_test.go` names one more kind, and that difference is
// deliberate.** It holds `method`, because FR-release-3 enumerates every kind the API record
// carries. This map holds no `method`, because a README block writes `ja4plus.Name` and
// never `ja4plus.Processor.Reset`. **The two sets answer two questions, so neither one may
// adopt the members of the other.**
var readmeTopLevelKinds = map[string]bool{
	"func":  true,
	"type":  true,
	"const": true,
	"var":   true,
}

// readmeExportedNames returns every exported top-level name that the package in one
// directory declares.
//
// It reads the surface through `collectPackageAPI`, so one walk feeds this guard and the
// API record together. #702 replaced a second walk here. That walk globbed `*.go`, so it
// applied no build constraint and it read a file that the API record never reads.
//
// **The two walks read one file set at the merge of #702, and the defect was latent.**
// Measured on 2026-08-15 UTC: `go list` reports 16 files for the root package and 2 for
// `ja4db`, and a glob of each directory that drops a test file reports the same two counts.
// Each `IgnoredGoFiles` entry of the two packages is a test file. The `libpcap` build tag
// selects a file of `internal/capture/`, which no published package holds, so no constraint
// separated the two walks. The separation lands the first time a published package carries
// a constrained file or a file with a platform name suffix.
func readmeExportedNames(t *testing.T, dir string) map[string]bool {
	t.Helper()

	recorded, err := collectPackageAPI(dir)
	if err != nil {
		t.Fatalf("measure the API of %s: %v", dir, err)
	}

	exported := map[string]bool{}

	for _, entry := range recorded {
		if readmeTopLevelKinds[entry.Kind] {
			exported[entry.Name] = true
		}
	}

	if len(exported) == 0 {
		t.Fatalf("%s declares no exported name, and this guard then reads nothing", dir)
	}

	return exported
}

// A name that the README walk never reads makes TestEveryLibraryNameOfTheReadmeIsExported
// pass over that name, so this test holds the walked name set equal to the top-level
// surface of the API record. #702 built it.
//
// **This test selects a top-level entry by its name, and `readmeExportedNames` selects one
// by its kind.** The two criteria are independent, so a kind that leaves
// `readmeTopLevelKinds` fails this test. A test that read the same constant would move
// both sides together and it would report a pass over the dropped kind. `apiEntry` states
// the naming rule: an owner and a period precede the name of a method, of a field and of an
// interface method, and a top-level name carries no prefix.
func TestTheReadmeNameWalkReadsTheSameSurfaceAsTheApiRecord(t *testing.T) {
	for _, pkg := range publishedPackages {
		recorded, err := collectPackageAPI(pkg.Dir)
		if err != nil {
			t.Fatalf("measure the API of %s: %v", pkg.ImportPath, err)
		}

		walked := readmeExportedNames(t, pkg.Dir)

		for _, entry := range recorded {
			if strings.Contains(entry.Name, ".") {
				continue
			}

			if !walked[entry.Name] {
				t.Errorf("%s: the README name walk reads no %s, and the API measurement records it",
					pkg.ImportPath, entry.key())
			}

			delete(walked, entry.Name)
		}

		for name := range walked {
			t.Errorf("%s: the README name walk reads %s, and the API measurement records no top-level name of it",
				pkg.ImportPath, name)
		}
	}
}

// TestEveryLibraryNameOfTheReadmeIsExported holds FR-release-28 against the API freeze.
//
// Every name that a Go block of the README reads through a package qualifier is a name
// that the package declares. `api_test.go` holds the record of the surface, and this test
// holds the prose against the same surface.
//
// It reads the syntax tree and never the text, so a name inside a comment or inside a
// string reaches no assertion.
//
// **What this test does not reach.** It reads a selector whose base is the identifier
// `ja4plus` or the identifier `ja4db`, so three kinds of name stand outside it.
//
//   - A method of a value, such as `proc.ProcessPacket`.
//   - A field of a struct, such as `r.Fingerprint`.
//   - A name that a block reads through another import alias.
//
// `api_test.go` holds each of those against `docs/api/v1.md`, and
// TestEveryProgramBlockOfTheReadmeCompiles reaches every one of them in a program block.
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
// It reads the case labels of `cmd/ja4plus/main.go`, and it drops every label that opens
// with `-`.
//
// **The file holds three switches of this shape, and the drop is what separates them.**
// One switch dispatches the subcommand, one dispatches a subcommand of `db`, and one
// reads the flags of `analyze`. Without the drop the set holds `--json` and `--csv`, and
// the guard would then read `ja4plus --json` as a valid command. The program accepts no
// such first argument.
//
// The set is still a superset, because `update` and `info` reach `db` alone. A superset
// fails on a subcommand that the program drops or renames, which is the defect this guard
// exists to catch.
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
			if strings.HasPrefix(word, "-") {
				continue
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

	// A section ends at the next heading of any level. A search for `\n### ` alone runs
	// past a `## ` heading, and the section then holds a block of another section.
	rest := section[len(readmeOutputSection):]
	end := len(rest)
	for _, heading := range []string{"\n## ", "\n### "} {
		if next := strings.Index(rest, heading); next >= 0 && next < end {
			end = next
		}
	}
	section = section[:len(readmeOutputSection)+end]

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

	// The command names the capture last, and readmeOutputCase holds the command to one
	// line. A trailing flag would put the flag here instead, and the test would then skip
	// rather than report. So the guard fails on a command that ends in a flag.
	capture := command[len(command)-1]
	if strings.HasPrefix(capture, "-") {
		t.Fatalf("the command of %q ends with %q, and the guard reads the last field as "+
			"the capture", readmeOutputSection, capture)
	}
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
