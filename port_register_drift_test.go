package ja4plus

import (
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These tests hold FR-parity-58, FR-parity-59 and FR-parity-60 of
// `docs/specs/features/08-python-parity.md`.
//
// `docs/specs/foxio/port-register.md` copies one section of the port's specification. The
// port adds a row to that section when it records a new divergence, and this repository
// reads a stale copy until a reader replaces it. The row count is the cheapest signal of
// that drift, so the record table of the page states the count and this file compares it.
//
// FR-parity-57 already holds, and `deviations_test.go:484` and `deviations_test.go:500`
// hold it. Those two tests read the port commit, the retrieval date and the SHA-256 digest
// of the copy.
//
// The drift check of `parity_table_test.go:208` counts a different page. It reads
// `docs/parity.md` against the promised names of the port, which is FR-parity-6.

// The two markers bound the copy. The record table sits above the begin marker, and it is
// this project's own text.
const (
	portRegisterBeginMarker = "<!-- port-register:begin -->"
	portRegisterEndMarker   = "<!-- port-register:end -->"
)

// portRegisterDriftSourceFile names the source of this file. FR-parity-59 asks that the
// drift check perform no network call, and the check below reads these bytes.
const portRegisterDriftSourceFile = "port_register_drift_test.go"

// portRegisterTableHeading names the heading that opens the table this file counts. The
// copy holds prose and a numbered list above it, and neither one holds a table.
const portRegisterTableHeading = "### Divergence register"

// portRegisterStatedRowsPattern matches the `Rows` record of the record table. The record
// sits beside the `Bytes` record and the `SHA-256` record, which record the same copy.
var portRegisterStatedRowsPattern = regexp.MustCompile(`\|\s*Rows\s*\|\s*(\d+)\s*\|`)

// portRegisterDriftAllowedImports holds every package this file may import. A network call
// needs a package that reaches the network, so a whitelist bars one call and every
// indirect one. FR-parity-59 states the requirement.
var portRegisterDriftAllowedImports = []string{
	"go/parser",
	"go/token",
	"regexp",
	"strconv",
	"strings",
	"testing",
}

// readPortRegisterCopy returns the text between the two markers of
// `docs/specs/foxio/port-register.md`.
//
// It fails the test when the page holds no marked copy. It performs no network input and
// no network output.
func readPortRegisterCopy(t *testing.T) string {
	t.Helper()

	page := readRepoFile(t, portRegisterFile)

	begin := strings.Index(page, portRegisterBeginMarker)
	end := strings.Index(page, portRegisterEndMarker)

	if begin < 0 || end < begin {
		t.Fatalf("%s holds no marked copy between %s and %s", portRegisterFile, portRegisterBeginMarker, portRegisterEndMarker)
	}

	return page[begin+len(portRegisterBeginMarker) : end]
}

// readPortRegisterRows returns the body rows of the divergence register table of the copy.
//
// The counting rule is this, and a reader who counts differently reports a drift that the
// copy does not hold.
//
//   - The count starts at the heading `### Divergence register`, and it ends at the end
//     marker of the copy.
//   - A row is one line that starts with `|` after that heading.
//   - The header row `| Item | This project today | The port today | Rule | Action |` is
//     not a body row.
//   - A separator row, which starts with `|---`, is not a body row.
//   - The port writes a blank line inside the table, and a row after a blank line is still
//     a body row. The copy holds five such breaks, and each one carries no second header.
//
// It performs no network input and no network output.
func readPortRegisterRows(t *testing.T) []string {
	t.Helper()

	copied := readPortRegisterCopy(t)

	heading := strings.Index(copied, portRegisterTableHeading)
	if heading < 0 {
		t.Fatalf("the copy in %s holds no %q heading, and FR-parity-58 counts the rows under it", portRegisterFile, portRegisterTableHeading)
	}

	var rows []string

	for line := range strings.SplitSeq(copied[heading+len(portRegisterTableHeading):], "\n") {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "|") {
			continue
		}

		if strings.HasPrefix(line, "| Item |") || strings.HasPrefix(line, "|---") {
			continue
		}

		rows = append(rows, line)
	}

	return rows
}

// FR-parity-58 and FR-parity-60 — the port adds a row when it records a new divergence,
// and the copy then goes stale. This test reads the count the record table states, and it
// names the re-read when the two counts differ.
func TestThePortRegisterCopyHoldsTheRowCountTheRecordTableStates(t *testing.T) {
	page := readRepoFile(t, portRegisterFile)
	rows := readPortRegisterRows(t)

	// The record table sits above the begin marker, so this read cannot reach a row of the
	// copy. `.claude/rules/rulings.md` bars an edit of the copy.
	begin := strings.Index(page, portRegisterBeginMarker)
	if begin < 0 {
		t.Fatalf("%s holds no %s marker", portRegisterFile, portRegisterBeginMarker)
	}

	// #307 states the count on every run, and this check follows that habit. A reader of
	// the log reads the recorded count without a re-read of the page.
	t.Logf("the copy holds %d divergence register rows at the port commit %s", len(rows), portReadCommit)

	match := portRegisterStatedRowsPattern.FindStringSubmatch(page[:begin])
	if match == nil {
		t.Fatalf("%s records no `Rows` row above %s, and FR-parity-58 needs the recorded count", portRegisterFile, portRegisterBeginMarker)
	}

	stated, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("the `Rows` record of %s holds %q, and FR-parity-58 needs a number", portRegisterFile, match[1])
	}

	if stated != len(rows) {
		t.Errorf("%s states %d rows and the copy holds %d rows. Re-read the `## Parity with ja4plus-go` section of `docs/specs/spec.md` in `Crank-Git/ja4plus` at the port commit %s, replace the copy, and write the `Rows` record, the `Bytes` record and the `SHA-256` record together",
			portRegisterFile, stated, len(rows), portReadCommit)
	}
}

// FR-parity-59 — the drift check reads a committed copy, and never the port. A network
// read would fail for a reason the change under test did not cause, and it would couple
// this repository to the availability of another one.
//
// The check reads the imports of this file, because a Go test reaches the network through
// a package. `TestNoTestBuildsRunsOrImportsThePort` holds FR-parity-4, which is a separate
// rule: it bars a test that builds, runs or imports the port in any language.
func TestThePortRegisterDriftCheckImportsNoPackageThatReachesTheNetwork(t *testing.T) {
	fileSet := token.NewFileSet()

	file, err := parser.ParseFile(fileSet, portRegisterDriftSourceFile, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", portRegisterDriftSourceFile, err)
	}

	if len(file.Imports) == 0 {
		t.Fatalf("the parse of %s read no import, so this check proves nothing", portRegisterDriftSourceFile)
	}

	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("%s holds the import path %s, which is not a quoted string", portRegisterDriftSourceFile, imported.Path.Value)
		}

		found := false
		for _, allowed := range portRegisterDriftAllowedImports {
			if path == allowed {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("%s imports %q, and FR-parity-59 allows %v alone. A package outside that list can reach the network",
				portRegisterDriftSourceFile, path, portRegisterDriftAllowedImports)
		}
	}
}
