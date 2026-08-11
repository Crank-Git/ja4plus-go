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

// The exclusions page is the tracked file `docs/audit/conformance-exclusions.md`. It
// records a deviation that no closure removes. These tests hold FR-gaps-5 and FR-gaps-6
// of `docs/specs/features/05-conformance-gaps.md`.
//
// The page holds one entry today, and FR-gaps-20 requires it. One entry exercises no
// malformed case, so the reader tests below run over fixture rows that this file holds.
// `deviations_test.go` reads the register the same way, and this file follows it.
//
// The reader stays in the test build. `v1.0.0` freezes the exported API, and the page
// serves the release gate and the test suite alone.

// exclusionsPageFile is the path of the exclusions page, relative to the package
// directory.
const exclusionsPageFile = "docs/audit/conformance-exclusions.md"

// exclusionRecordBlock names the marked block that holds the record table.
const exclusionRecordBlock = "conformance-exclusions"

// exclusionColumns names every column of the record, in order. FR-gaps-5 names the
// reason, the evidence and the acceptance. FR-gaps-6 splits the acceptance into a name
// and a date, so that a test can read each one.
var exclusionColumns = []string{"Key", "Reason", "Evidence", "Accepted by", "Date"}

// exclusionCaptureSuffixes names every suffix a corpus capture carries. FoxIO names one
// capture `dtls-udp.notest.cap`, so the list holds `.cap` as well as the two suffixes the
// Terms table defines.
var exclusionCaptureSuffixes = []string{".pcap", ".pcapng", ".cap"}

// exclusionDatePattern is the form of a `Date` value. The project writes a date as
// `YYYY-MM-DD`, and `docs/audit/findings.md` writes the same form.
var exclusionDatePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// exclusionPlaceholders names every value that states nothing. FR-gaps-6 requires the
// maintainer's own name, and the word `maintainer` names no person. A later maintainer
// cannot reverse a ruling that names no person.
var exclusionPlaceholders = []string{
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

// exclusionEntry is one deviation that no closure removes.
type exclusionEntry struct {
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

// parseExclusionRecord returns one entry for each body row of the record table.
// It returns an error in three cases.
//
//   - The block holds no table, or the header does not name the columns in order.
//   - A row holds a cell count the header does not match.
//   - A cell value has the wrong form.
func parseExclusionRecord(block string) ([]exclusionEntry, error) {
	rows, err := auditTableRows(block, exclusionColumns)
	if err != nil {
		return nil, err
	}

	entries := make([]exclusionEntry, 0, len(rows))

	for index, cells := range rows {
		entry, err := readExclusionRow(cells)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// readExclusionRow returns the entry that the cells describe.
// It returns an error in four cases.
//
//   - A cell is empty.
//   - A cell holds a value that states nothing.
//   - The key names no capture file.
//   - The date is no calendar date.
func readExclusionRow(cells []string) (exclusionEntry, error) {
	entry := exclusionEntry{
		Key:        exclusionCellValue(cells[0]),
		Reason:     exclusionCellValue(cells[1]),
		Evidence:   exclusionCellValue(cells[2]),
		AcceptedBy: exclusionCellValue(cells[3]),
		Date:       exclusionCellValue(cells[4]),
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

		if slices.Contains(exclusionPlaceholders, strings.ToLower(column.value)) {
			return entry, fmt.Errorf("the column %q holds %q, and that value names nothing", column.name, column.value)
		}
	}

	if err := checkExclusionKey(entry.Key); err != nil {
		return entry, err
	}

	return entry, checkExclusionDate(entry.Date)
}

// exclusionCellValue returns the cell text without the code span markers the page writes
// around a path and around a key.
func exclusionCellValue(cell string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(cell), "`"))
}

// checkExclusionKey returns an error when the key does not name a capture file. The key
// names the capture first, as `testdata/README.md` writes a register key.
func checkExclusionKey(key string) error {
	first := strings.Split(key, "/")[0]

	for _, suffix := range exclusionCaptureSuffixes {
		if strings.HasSuffix(first, suffix) {
			return nil
		}
	}

	return fmt.Errorf("the column %q holds %q, and its first part must name a capture file", "Key", key)
}

// checkExclusionDate returns an error when the date is not a calendar date in the
// `YYYY-MM-DD` form. FR-gaps-6 requires a date, and `2026-13-40` is not one.
func checkExclusionDate(date string) error {
	if !exclusionDatePattern.MatchString(date) {
		return fmt.Errorf("the column %q holds %q, and FR-gaps-6 requires a date as YYYY-MM-DD", "Date", date)
	}

	if _, err := time.Parse(time.DateOnly, date); err != nil {
		return fmt.Errorf("the column %q holds %q, and that is no calendar date: %w", "Date", date, err)
	}

	return nil
}

// exclusionMarkedBlock returns the text of the page between the two markers of the name.
// It fails the test when the page holds no such pair.
func exclusionMarkedBlock(t *testing.T, page string, name string) string {
	t.Helper()

	begin := "<!-- " + name + ":begin -->"
	end := "<!-- " + name + ":end -->"

	first := strings.Index(page, begin)
	last := strings.Index(page, end)

	if first < 0 || last < first {
		t.Fatalf("%s holds no block between %s and %s", exclusionsPageFile, begin, end)
	}

	return page[first+len(begin) : last]
}

// readExclusionRecord returns the parsed record of the tracked page.
// It fails the test when the page is absent or when the record does not parse.
func readExclusionRecord(t *testing.T) []exclusionEntry {
	t.Helper()

	page := readRepoFile(t, exclusionsPageFile)

	entries, err := parseExclusionRecord(exclusionMarkedBlock(t, page, exclusionRecordBlock))
	if err != nil {
		t.Fatalf("parse the record of %s: %v", exclusionsPageFile, err)
	}

	return entries
}

// oneValidExclusionRow returns the cells of one well-formed entry.
// A test changes one cell of the result to build a malformed case.
func oneValidExclusionRow() []string {
	return []string{
		"`dtls-udp.notest.cap`",
		"This row is a fixture of the test, and the maintainer accepted no entry.",
		"`docs/specs/features/05-conformance-gaps.md:82`",
		"Crank-Git",
		"2026-08-11",
	}
}

// oneExclusionRecord returns the marked block form of a record that holds the rows.
func oneExclusionRecord(rows ...[]string) string {
	lines := []string{
		"| " + strings.Join(exclusionColumns, " | ") + " |",
		"|" + strings.Repeat("---|", len(exclusionColumns)),
	}

	for _, row := range rows {
		lines = append(lines, "| "+strings.Join(row, " | ")+" |")
	}

	return "\n" + strings.Join(lines, "\n") + "\n"
}

func TestTheExclusionsPageExists(t *testing.T) {
	if _, err := os.Stat(exclusionsPageFile); err != nil {
		t.Fatalf("FR-gaps-5 requires %s: %v", exclusionsPageFile, err)
	}
}

func TestGitTracksTheExclusionsPage(t *testing.T) {
	// A build environment that holds no git cannot answer the question, and a failure
	// there would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "--error-unmatch", exclusionsPageFile)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FR-gaps-5 requires git to track %s: %v\n%s", exclusionsPageFile, err, output)
	}
}

func TestTheExclusionsRecordParsesAndEveryEntryHoldsEveryColumn(t *testing.T) {
	entries := readExclusionRecord(t)

	t.Logf("the exclusions page holds %d entries", len(entries))
}

func TestEveryExclusionNamesTheMaintainerAndADate(t *testing.T) {
	// The reader already declines an entry that names no maintainer. It already declines
	// an entry that carries no date. This loop repeats both checks over the tracked page.
	//
	// The repeat is deliberate. FR-gaps-6 names a test of its own, so an engineer who
	// moves the form check out of the reader still holds one.
	// `TestTheExclusionsReaderRejectsAMalformedEntry` holds the cases that prove the check.
	for _, entry := range readExclusionRecord(t) {
		if entry.AcceptedBy == "" || slices.Contains(exclusionPlaceholders, strings.ToLower(entry.AcceptedBy)) {
			t.Errorf("entry %q holds %q under `Accepted by`, and FR-gaps-6 requires the maintainer's name",
				entry.Key, entry.AcceptedBy)
		}

		if err := checkExclusionDate(entry.Date); err != nil {
			t.Errorf("entry %q fails FR-gaps-6: %v", entry.Key, err)
		}
	}
}

func TestTheExclusionsPageStatesThatOnlyTheMaintainerAcceptsAnEntry(t *testing.T) {
	page := readRepoFile(t, exclusionsPageFile)

	// A page that states the format and not the authority invites an engineer to write an
	// entry. `.claude/rules/rulings.md` gives the ruling to the maintainer alone.
	for _, wanted := range []string{
		".claude/rules/rulings.md",
		"FR-gaps-5",
		"FR-gaps-6",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not name %q", exclusionsPageFile, wanted)
		}
	}
}

// exclusionEvidencePattern is the form of an `Evidence` value that cites a source line.
// `.claude/rules/rulings.md` requires a file and a line, because a claim about a source
// without the location is one the next reader cannot check.
var exclusionEvidencePattern = regexp.MustCompile(`[^ ` + "`" + `]+:[0-9]+`)

// TestTheExclusionsRecordHoldsTheNotestCapture holds FR-gaps-20 of
// `docs/specs/features/05-conformance-gaps.md`.
//
// FoxIO reaches no method on `dtls-udp.notest.cap`, so the entry keys the capture alone.
// The suite records `not applicable` for every method of the capture, and
// `TestTheReportNamesTheNotestMarkerAsTheReasonOfADeclinedCapture` of
// `conformance_report_check_test.go` holds that behavior for JA4.
func TestTheExclusionsRecordHoldsTheNotestCapture(t *testing.T) {
	const capture = "dtls-udp.notest.cap"

	entries := readExclusionRecord(t)

	index := slices.IndexFunc(entries, func(entry exclusionEntry) bool {
		return entry.Key == capture
	})

	if index < 0 {
		t.Fatalf("FR-gaps-20 requires an entry keyed %q in %s, and the record holds %d entries",
			capture, exclusionsPageFile, len(entries))
	}

	entry := entries[index]

	// The reason names the party that excludes the capture. A reason that names no party
	// leaves the next reader to guess whether this project or FoxIO made the choice.
	if !strings.Contains(entry.Reason, "FoxIO") {
		t.Errorf("entry %q holds the reason %q, and FR-gaps-20 requires the reason to name FoxIO",
			capture, entry.Reason)
	}

	if !exclusionEvidencePattern.MatchString(entry.Evidence) {
		t.Errorf("entry %q cites %q, and `.claude/rules/rulings.md` requires a file and a line",
			capture, entry.Evidence)
	}
}

func TestTheExclusionsReaderAcceptsAWellFormedEntry(t *testing.T) {
	entries, err := parseExclusionRecord(oneExclusionRecord(oneValidExclusionRow()))
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

func TestTheExclusionsReaderAcceptsAnEmptyRecord(t *testing.T) {
	entries, err := parseExclusionRecord(oneExclusionRecord())
	if err != nil {
		t.Fatalf("the reader rejects an empty record: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("the reader returns %d entries for an empty record", len(entries))
	}
}

func TestTheExclusionsReaderRejectsAMalformedEntry(t *testing.T) {
	withColumn := func(name string, value string) string {
		row := oneValidExclusionRow()
		row[slices.Index(exclusionColumns, name)] = value

		return oneExclusionRecord(row)
	}

	cases := []struct {
		name  string
		block string
	}{
		{"the block holds no table", "no table here\n"},
		{"the header names another column", "\n| Key | Reason |\n|---|---|\n"},
		{"the row holds too few cells", "| " + strings.Join(exclusionColumns, " | ") +
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
			if _, err := parseExclusionRecord(testCase.block); err == nil {
				t.Errorf("the reader accepts a record where %s", testCase.name)
			}
		})
	}
}
