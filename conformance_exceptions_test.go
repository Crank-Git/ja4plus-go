package ja4plus

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The exceptions page is the tracked file `docs/audit/conformance-exceptions.md`. It
// records a deviation that no closure removes. These tests hold FR-gaps-5 and FR-gaps-6
// of `docs/specs/features/05-conformance-gaps.md`.
//
// The page holds no entry today, because the maintainer has accepted none. An empty
// record passes every content test without exercising the reader, so the reader tests
// below run over fixture rows that this file holds. `deviations_test.go` reads the
// register the same way, and this file follows it.
//
// The reader stays in the test build. `v1.0.0` freezes the exported API, and the page
// serves the release gate and the test suite alone.

// exceptionsPageFile is the path of the exceptions page, relative to the package
// directory.
const exceptionsPageFile = "docs/audit/conformance-exceptions.md"

// exceptionRecordBlock names the marked block that holds the record table.
const exceptionRecordBlock = "conformance-exceptions"

// exceptionColumns names every column of the record, in order. FR-gaps-5 names the
// reason, the evidence and the acceptance. FR-gaps-6 splits the acceptance into a name
// and a date, so that a test can read each one.
var exceptionColumns = []string{"Key", "Reason", "Evidence", "Accepted by", "Date"}

// exceptionCaptureSuffixes names every suffix a corpus capture carries. FoxIO names one
// capture `dtls-udp.notest.cap`, so the list holds `.cap` as well as the two suffixes the
// Terms table defines.
var exceptionCaptureSuffixes = []string{".pcap", ".pcapng", ".cap"}

// exceptionDatePattern is the form of a `Date` value. The project writes a date as
// `YYYY-MM-DD`, and `docs/audit/findings.md` writes the same form.
var exceptionDatePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// exceptionPlaceholders names every value that states nothing. FR-gaps-6 requires the
// maintainer's own name, and the word `maintainer` names no person. A later maintainer
// cannot reverse a ruling that names no person.
var exceptionPlaceholders = []string{
	"the maintainer",
	"maintainer",
	"tbd",
	"todo",
	"pending",
	"unknown",
	"none",
	"n/a",
	"-",
}

// exceptionEntry is one deviation that no closure removes.
type exceptionEntry struct {
	// Key names the capture, and it names the stream and the method when a comparison
	// reaches them.
	Key string
	// Reason states why the closure is not possible.
	Reason string
	// Evidence cites the source that supports the reason.
	Evidence string
	// AcceptedBy holds the maintainer's name.
	AcceptedBy string
	// Date holds the acceptance date, as `YYYY-MM-DD`.
	Date string
}

// parseExceptionRecord returns one entry for each body row of the record table.
// It returns an error in three cases.
//
//   - The block holds no table, or the header does not name the columns in order.
//   - A row holds a cell count the header does not match.
//   - A cell value has the wrong form.
func parseExceptionRecord(block string) ([]exceptionEntry, error) {
	rows, err := auditTableRows(block, exceptionColumns)
	if err != nil {
		return nil, err
	}

	entries := make([]exceptionEntry, 0, len(rows))

	for index, cells := range rows {
		entry, err := readExceptionRow(cells)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// readExceptionRow returns the entry that the cells describe.
// It returns an error in four cases.
//
//   - A cell is empty.
//   - A cell holds a value that states nothing.
//   - The key names no capture file.
//   - The date is no calendar date.
func readExceptionRow(cells []string) (exceptionEntry, error) {
	entry := exceptionEntry{
		Key:        exceptionCellValue(cells[0]),
		Reason:     exceptionCellValue(cells[1]),
		Evidence:   exceptionCellValue(cells[2]),
		AcceptedBy: exceptionCellValue(cells[3]),
		Date:       exceptionCellValue(cells[4]),
	}

	// The list keeps the order fixed. A range over a map reports a different column first
	// on each run, and a row with two defects would then produce two error messages.
	for _, column := range []struct {
		name  string
		value string
	}{
		{"Key", entry.Key},
		{"Reason", entry.Reason},
		{"Evidence", entry.Evidence},
		{"Accepted by", entry.AcceptedBy},
		{"Date", entry.Date},
	} {
		if column.value == "" {
			return entry, fmt.Errorf("the column %q is empty, and every column of an entry holds a value", column.name)
		}

		if slices.Contains(exceptionPlaceholders, strings.ToLower(column.value)) {
			return entry, fmt.Errorf("the column %q holds %q, and that value names nothing", column.name, column.value)
		}
	}

	if err := checkExceptionKey(entry.Key); err != nil {
		return entry, err
	}

	return entry, checkExceptionDate(entry.Date)
}

// exceptionCellValue returns the cell text without the code span markers the page writes
// around a path and around a key.
func exceptionCellValue(cell string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(cell), "`"))
}

// checkExceptionKey returns an error when the key does not name a capture file. The key
// names the capture first, as `testdata/README.md` writes a register key.
func checkExceptionKey(key string) error {
	first := strings.Split(key, "/")[0]

	for _, suffix := range exceptionCaptureSuffixes {
		if strings.HasSuffix(first, suffix) {
			return nil
		}
	}

	return fmt.Errorf("the column %q holds %q, and its first part must name a capture file", "Key", key)
}

// checkExceptionDate returns an error when the date is not a calendar date in the
// `YYYY-MM-DD` form. FR-gaps-6 requires a date, and `2026-13-40` is not one.
func checkExceptionDate(date string) error {
	if !exceptionDatePattern.MatchString(date) {
		return fmt.Errorf("the column %q holds %q, and FR-gaps-6 requires a date as YYYY-MM-DD", "Date", date)
	}

	if _, err := time.Parse(time.DateOnly, date); err != nil {
		return fmt.Errorf("the column %q holds %q, and that is no calendar date: %w", "Date", date, err)
	}

	return nil
}

// exceptionMarkedBlock returns the text of the page between the two markers of the name.
// It fails the test when the page holds no such pair.
func exceptionMarkedBlock(t *testing.T, page string, name string) string {
	t.Helper()

	begin := "<!-- " + name + ":begin -->"
	end := "<!-- " + name + ":end -->"

	first := strings.Index(page, begin)
	last := strings.Index(page, end)

	if first < 0 || last < first {
		t.Fatalf("%s holds no block between %s and %s", exceptionsPageFile, begin, end)
	}

	return page[first+len(begin) : last]
}

// readExceptionRecord returns the parsed record of the tracked page.
// It fails the test when the page is absent or when the record does not parse.
func readExceptionRecord(t *testing.T) []exceptionEntry {
	t.Helper()

	page := readRepoFile(t, exceptionsPageFile)

	entries, err := parseExceptionRecord(exceptionMarkedBlock(t, page, exceptionRecordBlock))
	if err != nil {
		t.Fatalf("parse the record of %s: %v", exceptionsPageFile, err)
	}

	return entries
}

// oneValidExceptionRow returns the cells of one well-formed entry.
// A test changes one cell of the result to build a malformed case.
func oneValidExceptionRow() []string {
	return []string{
		"`dtls-udp.notest.cap`",
		"This row is a fixture of the test, and the maintainer accepted no entry.",
		"`docs/specs/features/05-conformance-gaps.md:82`",
		"Crank-Git",
		"2026-08-11",
	}
}

// oneExceptionRecord returns the marked block form of a record that holds the rows.
func oneExceptionRecord(rows ...[]string) string {
	lines := []string{
		"| " + strings.Join(exceptionColumns, " | ") + " |",
		"|" + strings.Repeat("---|", len(exceptionColumns)),
	}

	for _, row := range rows {
		lines = append(lines, "| "+strings.Join(row, " | ")+" |")
	}

	return "\n" + strings.Join(lines, "\n") + "\n"
}

func TestTheExceptionsPageExists(t *testing.T) {
	if _, err := os.Stat(exceptionsPageFile); err != nil {
		t.Fatalf("FR-gaps-5 requires %s: %v", exceptionsPageFile, err)
	}
}

func TestGitTracksTheExceptionsPage(t *testing.T) {
	// A build environment that holds no git cannot answer the question, and a failure
	// there would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "--error-unmatch", exceptionsPageFile)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FR-gaps-5 requires git to track %s: %v\n%s", exceptionsPageFile, err, output)
	}
}

func TestTheExceptionsRecordParsesAndEveryEntryHoldsEveryColumn(t *testing.T) {
	entries := readExceptionRecord(t)

	t.Logf("the exceptions page holds %d entries", len(entries))
}

func TestEveryExceptionNamesTheMaintainerAndADate(t *testing.T) {
	// The reader already declines an entry that names no maintainer. It already declines
	// an entry that carries no date. This loop repeats both checks over the tracked page.
	//
	// The repeat is deliberate. FR-gaps-6 names a test of its own, so an engineer who
	// moves the form check out of the reader still holds one.
	// `TestTheExceptionsReaderRejectsAMalformedEntry` holds the cases that prove the check.
	for _, entry := range readExceptionRecord(t) {
		if entry.AcceptedBy == "" || slices.Contains(exceptionPlaceholders, strings.ToLower(entry.AcceptedBy)) {
			t.Errorf("entry %q holds %q under `Accepted by`, and FR-gaps-6 requires the maintainer's name",
				entry.Key, entry.AcceptedBy)
		}

		if err := checkExceptionDate(entry.Date); err != nil {
			t.Errorf("entry %q fails FR-gaps-6: %v", entry.Key, err)
		}
	}
}

func TestTheExceptionsPageStatesThatOnlyTheMaintainerAcceptsAnEntry(t *testing.T) {
	page := readRepoFile(t, exceptionsPageFile)

	// A page that states the format and not the authority invites an engineer to write an
	// entry. `.claude/rules/rulings.md` gives the ruling to the maintainer alone.
	for _, wanted := range []string{
		".claude/rules/rulings.md",
		"FR-gaps-5",
		"FR-gaps-6",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not name %q", exceptionsPageFile, wanted)
		}
	}
}

func TestTheExceptionsReaderAcceptsAWellFormedEntry(t *testing.T) {
	entries, err := parseExceptionRecord(oneExceptionRecord(oneValidExceptionRow()))
	if err != nil {
		t.Fatalf("the reader rejects a well-formed record: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("the reader returns %d entries, and the record holds 1", len(entries))
	}

	if entries[0].Key != "dtls-udp.notest.cap" {
		t.Errorf("entry 0 holds the key %q, and the fixture holds `dtls-udp.notest.cap`", entries[0].Key)
	}

	if entries[0].AcceptedBy != "Crank-Git" {
		t.Errorf("entry 0 holds %q under `Accepted by`, and the fixture holds `Crank-Git`", entries[0].AcceptedBy)
	}
}

func TestTheExceptionsReaderAcceptsAnEmptyRecord(t *testing.T) {
	entries, err := parseExceptionRecord(oneExceptionRecord())
	if err != nil {
		t.Fatalf("the reader rejects an empty record: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("the reader returns %d entries for an empty record", len(entries))
	}
}

func TestTheExceptionsReaderRejectsAMalformedEntry(t *testing.T) {
	withColumn := func(name string, value string) string {
		row := oneValidExceptionRow()
		row[slices.Index(exceptionColumns, name)] = value

		return oneExceptionRecord(row)
	}

	cases := []struct {
		name  string
		block string
	}{
		{"the block holds no table", "no table here\n"},
		{"the header names another column", "\n| Key | Reason |\n|---|---|\n"},
		{"the row holds too few cells", "| " + strings.Join(exceptionColumns, " | ") +
			" |\n|---|---|---|---|---|\n| `a.pcap` | a reason |\n"},
		{"the entry names no maintainer", withColumn("Accepted by", "")},
		{"the entry names the maintainer by role", withColumn("Accepted by", "the maintainer")},
		{"the entry names the maintainer as pending", withColumn("Accepted by", "TBD")},
		{"the entry carries no date", withColumn("Date", "")},
		{"the entry carries a date in another form", withColumn("Date", "11 August 2026")},
		{"the entry carries no calendar date", withColumn("Date", "2026-13-40")},
		{"the entry carries a date as a placeholder", withColumn("Date", "TODO")},
		{"the entry holds no key", withColumn("Key", "")},
		{"the entry names no capture file", withColumn("Key", "`dtls-udp`")},
		{"the entry holds no reason", withColumn("Reason", "")},
		{"the entry holds a reason that states nothing", withColumn("Reason", "TBD")},
		{"the entry holds no evidence", withColumn("Evidence", "")},
		{"the entry holds evidence that states nothing", withColumn("Evidence", "none")},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseExceptionRecord(testCase.block); err == nil {
				t.Errorf("the reader accepts a record where %s", testCase.name)
			}
		})
	}
}
