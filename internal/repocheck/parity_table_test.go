package repocheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These tests hold FR-parity-1 through FR-parity-7 of
// `docs/specs/features/08-python-parity.md`.
//
// The port is the Python implementation at `Crank-Git/ja4plus`. The port's issue #533
// settled the words "reading" and "ruling" that this file uses. The port's own parity rule 3
// bars a test that builds, runs or imports the port. `.claude/rules/parity.md` holds the
// same rule for this repository.
//
// No test here reaches the network, and no test here reads the port. Each recorded fact
// names the port commit that a reader re-reads it at.

// parityTableFile names the page that records one row for each exported port name.
const parityTableFile = "docs/parity.md"

// The three constants record where the promised names were read. `portReadCommit` is the
// commit that the tag `v1.1.0` points at in `Crank-Git/ja4plus`.
const (
	portReadVersion = "v1.1.0"
	portReadCommit  = "21299645366591331eb93155355b65a76a3729f3"
	portReadDate    = "2026-08-12"
)

// portInitBlobHash is the blob hash of `ja4plus/__init__.py` at the port tag. The page
// states the command that reproduces it, so a reader re-reads the list at one object.
const portInitBlobHash = "d901aa690c6d6f36b542d0317372ec053760a55b"

// portExportedNames holds the `__all__` list of `ja4plus/__init__.py` at the port tag,
// in the order the port writes it.
//
// The port's own comment on that list states that a name absent from it is not promised,
// so this list is what FR-parity-6 counts. A public name of a submodule reaches no row,
// because the port promises no submodule name.
var portExportedNames = []string{
	"FingerprintResult",
	"Processor",
	"JA4Fingerprinter",
	"JA4SFingerprinter",
	"JA4HFingerprinter",
	"JA4LFingerprinter",
	"JA4XFingerprinter",
	"JA4SSHFingerprinter",
	"JA4TFingerprinter",
	"JA4TSFingerprinter",
	"JA4DFingerprinter",
	"JA4D6Fingerprinter",
	"generate_ja4",
	"generate_ja4s",
	"generate_ja4h",
	"generate_ja4l",
	"generate_ja4x",
	"generate_ja4ssh",
	"generate_ja4t",
	"generate_ja4ts",
	"generate_ja4d",
	"generate_ja4d6",
	"compute_ja4x_from_der",
	"compute_ja4x_from_pem",
	"__version__",
}

// The markers bound the table. The page carries a record table above them, and a bare row
// pattern would read a row of that table as a promised name.
const (
	parityTableBeginMarker = "<!-- parity-table:begin -->"
	parityTableEndMarker   = "<!-- parity-table:end -->"
)

// parityRow holds the five cells of one row of the table.
type parityRow struct {
	PortName     string
	Kind         string
	PortLocation string
	Equivalent   string
	Reason       string
}

// parityDeclinePattern matches the decline form of the Go equivalent cell. FR-parity-7
// names the two applicability words, and the pattern accepts one of them alone.
var parityDeclinePattern = regexp.MustCompile("^`none`, (applicable|not applicable)$")

// parityGoNamePattern matches the equivalent form of the Go equivalent cell. The cell
// holds one identifier, so `TestEveryGoNameTheParityTableNamesIsExportedByThePackage`
// compares it against the exported names of the package without a parse of prose.
var parityGoNamePattern = regexp.MustCompile("^`([A-Za-z0-9]+)`$")

// parityPortLocationPattern matches the port location cell. `.claude/rules/rulings.md`
// states that a reading cites a file and a line, so a row that names a module alone fails.
var parityPortLocationPattern = regexp.MustCompile(`^ja4plus/[A-Za-z0-9_/]+\.py:[0-9]+$`)

// parityStatedCountPattern matches the `Promised names` row of the record table. The page
// states its own count, and a reader must not trust a stale number.
var parityStatedCountPattern = regexp.MustCompile(`\|\s*Promised names\s*\|\s*(\d+)\s*\|`)

// readParityTableRows returns the rows between the two markers.
func readParityTableRows(t *testing.T) []parityRow {
	t.Helper()

	page := readRepoFile(t, parityTableFile)

	begin := strings.Index(page, parityTableBeginMarker)
	end := strings.Index(page, parityTableEndMarker)
	if begin < 0 || end < begin {
		t.Fatalf("%s holds no table between %s and %s", parityTableFile, parityTableBeginMarker, parityTableEndMarker)
	}

	var rows []parityRow

	// SplitSeq allocates no slice of lines. The page grows with the count of promised
	// names, and the loop reads each line once.
	for line := range strings.SplitSeq(page[begin+len(parityTableBeginMarker):end], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}

		// The header row and the alignment row carry no backtick in the first cell, so
		// this prefix test drops both without a line number.
		if !strings.HasPrefix(line, "| `") {
			continue
		}

		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 5 {
			t.Errorf("the row %q holds %d cells, and the table holds 5 columns", line, len(cells))
			continue
		}

		rows = append(rows, parityRow{
			PortName:     strings.Trim(strings.TrimSpace(cells[0]), "`"),
			Kind:         strings.TrimSpace(cells[1]),
			PortLocation: strings.Trim(strings.TrimSpace(cells[2]), "`"),
			Equivalent:   strings.TrimSpace(cells[3]),
			Reason:       strings.TrimSpace(cells[4]),
		})
	}

	return rows
}

// FR-parity-5 — a reader who cannot reach the page cannot check a parity row.
func TestTheParityTableExists(t *testing.T) {
	if _, err := os.Stat(parityTableFile); err != nil {
		t.Fatalf("FR-parity-5 requires %s: %v", parityTableFile, err)
	}
}

// FR-parity-5 — an untracked page reaches no other reader.
func TestGitTracksTheParityTable(t *testing.T) {
	// A build environment that holds no git cannot answer the question, and a failure
	// there would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "--error-unmatch", parityTableFile)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FR-parity-5 requires git to track %s: %v\n%s", parityTableFile, err, output)
	}
}

// FR-parity-5 — the page names the port version that a reader reads each row at. It names
// the commit and the blob as well. A tag moves, and a version string locates no file.
func TestTheParityTableNamesThePortVersionAndTheReadCommit(t *testing.T) {
	page := readRepoFile(t, parityTableFile)

	for _, wanted := range []string{portReadVersion, portReadCommit, portReadDate, portInitBlobHash} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not name %q, and FR-parity-5 names the port version each row was read from", parityTableFile, wanted)
		}
	}
}

// FR-parity-6 — the count turns on which list the page counted, so the page names it.
// The port root re-exports 25 names, and the public submodule names are a larger set.
func TestTheParityTableNamesTheListItCounted(t *testing.T) {
	page := readRepoFile(t, parityTableFile)

	for _, wanted := range []string{
		"`ja4plus/__init__.py`",
		"`__all__`",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not name %q, and FR-parity-6 counts one list", parityTableFile, wanted)
		}
	}
}

// FR-parity-6 — the drift check. A row that disappears, a row that duplicates and a row
// for a name the port does not promise each fail here.
func TestTheParityTableHoldsOneRowForEachExportedPortName(t *testing.T) {
	rows := readParityTableRows(t)

	// #307 states the count on every run, and this check follows that habit. A reader of
	// the log reads the recorded count without a re-read of the page.
	t.Logf("the table holds %d rows, and the port promises %d names at %s", len(rows), len(portExportedNames), portReadCommit)

	if len(rows) != len(portExportedNames) {
		t.Fatalf("%s holds %d rows, and the port promises %d names at the port tag %s. Re-read `ja4plus/__init__.py` at that tag, and update the table and parity_table_test.go together",
			parityTableFile, len(rows), len(portExportedNames), portReadVersion)
	}

	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.PortName] {
			t.Errorf("%s holds two rows for the port name %q", parityTableFile, row.PortName)
		}
		seen[row.PortName] = true
	}

	for _, name := range portExportedNames {
		if !seen[name] {
			t.Errorf("%s holds no row for the port name %q. Re-read `ja4plus/__init__.py` at the port commit %s", parityTableFile, name, portReadCommit)
		}
	}

	for _, row := range rows {
		if !slices.Contains(portExportedNames, row.PortName) {
			t.Errorf("%s holds a row for %q, and `__all__` at the port commit %s does not promise that name. Re-read the promised names", parityTableFile, row.PortName, portReadCommit)
		}
	}
}

// FR-parity-6 — the page states its own row count, and a reader must not trust a stale
// number. A page edited without this test fails here.
func TestTheParityTableStatesTheRowCountThatItHolds(t *testing.T) {
	page := readRepoFile(t, parityTableFile)
	rows := readParityTableRows(t)

	match := parityStatedCountPattern.FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("%s records no `Promised names` row, and FR-parity-6 needs the recorded count", parityTableFile)
	}

	stated, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("the `Promised names` row holds %q, and FR-parity-6 needs a number", match[1])
	}

	if stated != len(rows) {
		t.Errorf("%s states %d promised names and holds %d rows. Re-read the promised names at the port commit %s", parityTableFile, stated, len(rows), portReadCommit)
	}
}

// FR-parity-7 — each row records the Go equivalent, or records `none` with an
// applicability word and one sentence of reason.
func TestEveryRowOfTheParityTableRecordsAGoEquivalentOrADecline(t *testing.T) {
	for _, row := range readParityTableRows(t) {
		if row.Kind == "" {
			t.Errorf("the row for %q records no kind", row.PortName)
		}

		if !parityPortLocationPattern.MatchString(row.PortLocation) {
			t.Errorf("the row for %q records the port location %q, and a reading cites a file and a line", row.PortName, row.PortLocation)
		}

		switch {
		case parityGoNamePattern.MatchString(row.Equivalent):
			// A row that names a Go equivalent needs no applicability word.
		case parityDeclinePattern.MatchString(row.Equivalent):
			if row.Reason == "" || !strings.HasSuffix(row.Reason, ".") {
				t.Errorf("the row for %q records %q and records no sentence of reason, and FR-parity-7 names one", row.PortName, row.Equivalent)
			}
		default:
			t.Errorf("the row for %q records the Go equivalent %q, and FR-parity-7 names one Go name or `none` with `applicable` or `not applicable`", row.PortName, row.Equivalent)
		}
	}
}

// FR-parity-6 — a Go name that moves leaves the table naming a name the package does not
// export. This test reads the exported names from the source, so a rename fails it.
func TestEveryGoNameTheParityTableNamesIsExportedByThePackage(t *testing.T) {
	exported := readExportedPackageNames(t)

	for _, row := range readParityTableRows(t) {
		match := parityGoNamePattern.FindStringSubmatch(row.Equivalent)
		if match == nil {
			continue
		}

		if !exported[match[1]] {
			t.Errorf("the row for %q names the Go equivalent %q, and package ja4plus exports no such name. Update the row, or restore the name", row.PortName, match[1])
		}
	}
}

// readExportedPackageNames returns every exported top-level name of package ja4plus.
func readExportedPackageNames(t *testing.T) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}

	exported := map[string]bool{}
	fileSet := token.NewFileSet()

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				// A method reaches no row, because the table cell holds one identifier.
				if declaration.Recv == nil && declaration.Name.IsExported() {
					exported[declaration.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							exported[spec.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, valueName := range spec.Names {
							if valueName.IsExported() {
								exported[valueName.Name] = true
							}
						}
					}
				}
			}
		}
	}

	return exported
}

// portRunPatterns match a test that runs the port. A Go test reaches the port through an
// interpreter or through a Python tool. Each pattern therefore reads the call, and not the
// word "python" alone. Many tests name a vector path under `testdata/foxio/python/`, so the
// bare word reports no defect.
//
// The check reads literal text, and indirection defeats it. A call that holds the
// interpreter name in a variable passes. FR-parity-4 bars a rig that an author writes
// deliberately, and a call-graph analysis would still read no intent.
var portRunPatterns = []*regexp.Regexp{
	regexp.MustCompile(`exec\.Command(Context)?\([^)]*(python|pytest|pip|poetry|uv)`),
	regexp.MustCompile(`(?m)^\s*(from|import)\s+ja4plus`),
}

// FR-parity-4 — the port and this repository move at different speeds. A cross-language rig
// therefore fails for a reason that the change under test did not cause. The port's parity
// rule 3 states the rule, and `.claude/rules/parity.md` adopts it.
func TestNoTestBuildsRunsOrImportsThePort(t *testing.T) {
	scanned := 0

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			// The corpus and the build output hold no test of this repository.
			if entry.Name() == "testdata" || entry.Name() == "bin" || entry.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++

		for _, pattern := range portRunPatterns {
			if found := pattern.FindString(string(content)); found != "" {
				t.Errorf("%s holds %q, and FR-parity-4 bars a test that builds, runs or imports the port", path, found)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository: %v", err)
	}

	if scanned == 0 {
		t.Fatalf("the walk read no test file, so this check proves nothing")
	}

	t.Logf("the check read %d test files", scanned)
}
