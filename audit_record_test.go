package ja4plus

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These tests hold the shape of the audit record. `docs/specs/features/02-correctness-audit.md`
// states the requirements, and issue #21 defines the record that the later slices fill.
//
// The report is a document, so nothing but a test stops a later slice from adding a row
// that omits a field. The reader below parses every table of the report and reports each
// row that breaks a rule. Issues #22, #23, #24 and #25 each own one section, so the reader
// runs once for each section.
//
// The report holds no finding today. An empty table passes every content rule without
// exercising the reader, so the rejection tests below run over fixture rows that this file
// holds. `deviations_test.go` uses the same pattern for the same reason.

// auditReportFile is the path of the findings report. FR-audit-9 names it.
const auditReportFile = "docs/audit/findings.md"

// auditRoots names each directory that holds a file under audit. FR-audit-1 names these
// three, and the walk reads no subdirectory of them.
var auditRoots = []string{".", "internal/parser", "cmd/ja4plus"}

// auditIssues names each issue that owns one section of the report. A section per issue
// keeps two slices that run at the same time off one another's rows.
var auditIssues = []string{"22", "23", "24", "25"}

// auditSeverities holds the three values FR-audit-5 allows.
var auditSeverities = []string{"critical", "major", "minor"}

// auditStatuses holds every status a finding row carries.
//
//   - `open` — the audit reproduced the failure scenario, and no commit closes it yet.
//   - `confirmed` — a commit closed it. FR-audit-27 requires the commit.
//   - `no change needed` — the code is a deliberate design choice. The row states why.
//   - `unconfirmed` — the audit could not confirm it. FR-audit-10 requires the reason.
//   - `declined` — the maintainer decided not to close it. FR-audit-28 requires the reason.
var auditStatuses = []string{"open", "confirmed", "no change needed", "unconfirmed", "declined"}

// auditSuspectedStatuses holds every status that a suspected finding carries. The feature
// file's acceptance criteria name the last three, and `open` holds the state before the
// audit reaches S1, S2 or S3.
//
// The `## Terms` table of `docs/specs/spec.md` bars the word `verdict`, which it reserves
// as a barred synonym of `ruling`. The report writes `Status` for that reason.
var auditSuspectedStatuses = []string{"open", "confirmed", "no change needed", "unconfirmed"}

// auditReasonStatuses names each status whose row states a reason.
var auditReasonStatuses = []string{"no change needed", "unconfirmed", "declined"}

// auditFindingColumns names every column of a findings table, in order.
var auditFindingColumns = []string{
	"ID", "File", "Line", "Severity", "Status", "Failure scenario", "Closing commit", "Reason",
}

// auditFileColumns names every column of a table of audited files. FR-audit-2 requires
// both of them.
var auditFileColumns = []string{"File", "Audit date"}

// auditSetColumns names every column of the audit set table.
var auditSetColumns = []string{"File", "Read by"}

// auditAddedColumns names every column of the table of added files.
var auditAddedColumns = []string{"File", "Added by"}

// auditSuspectedColumns names every column of the suspected findings table.
var auditSuspectedColumns = []string{"ID", "Files", "Owner", "Status", "Findings", "Reason"}

// auditSignatureColumns names every column of the exported signature table. The last
// acceptance criterion of the feature file requires the table.
var auditSignatureColumns = []string{"Finding", "Symbol", "Before", "After", "Commit"}

// auditSuspectedIDs names the three suspected findings that the feature file states.
var auditSuspectedIDs = []string{"S1", "S2", "S3"}

// auditMinimumScenario is the shortest failure scenario the reader accepts. FR-audit-4
// requires an input and a wrong result, and neither fits in fewer characters.
const auditMinimumScenario = 40

// auditHedgeWords names each word that turns a failure scenario into a code smell.
// FR-audit-4 bars a code smell, and a hedge word is the form one takes.
var auditHedgeWords = []string{
	"could", "might", "possibly", "perhaps", "code smell", "unclear", "confusing",
	"hard to read", "ugly", "cleaner", "refactor",
}

// auditDatePattern is the form of an audit date. FR-audit-2 requires the date, and this
// project writes a date as `YYYY-MM-DD`.
var auditDatePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// auditCommitPattern is the form of a closing commit. FR-audit-27 requires the commit,
// and git abbreviates a commit to seven hexadecimal characters or more.
var auditCommitPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// auditIssuePattern is the form of an issue reference in the `Read by` column.
var auditIssuePattern = regexp.MustCompile(`^#([1-9][0-9]*)$`)

// auditSeparatorPattern matches one cell of a table separator line.
var auditSeparatorPattern = regexp.MustCompile(`^:?-{3,}:?$`)

// auditStatusPattern reads the report status. The line states whether the epic finished,
// and the strict rules below apply once it reads `complete`.
var auditStatusPattern = regexp.MustCompile(`(?m)^\*\*Report status:\*\* (in progress|complete)$`)

// auditFinding is one row of a findings table.
type auditFinding struct {
	// ID names the finding. Its second part names the issue that owns the row.
	ID string
	// File is the path of the file that holds the defect.
	File string
	// Line is the line number of the defect.
	Line int
	// Severity is one of `critical`, `major` and `minor`.
	Severity string
	// Status is one value of auditStatuses.
	Status string
	// Scenario names the input and the wrong result.
	Scenario string
	// Commit names the commit that closed the finding.
	Commit string
	// Reason states why the finding stays open, or why the audit could not confirm it.
	Reason string
}

// auditGoFiles returns the path of every file the audit reads.
//
// It reads each directory of auditRoots and no subdirectory of them.
//
// It drops a file whose name ends in `_test.go`, because a test file ships nothing. The
// `Purpose` section of the feature file counts nine parser files, and that count holds
// only without the test files.
func auditGoFiles(t *testing.T) []string {
	t.Helper()

	var files []string

	for _, root := range auditRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}

		for _, entry := range entries {
			name := entry.Name()

			if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
				continue
			}

			files = append(files, filepath.ToSlash(filepath.Join(root, name)))
		}
	}

	slices.Sort(files)

	return files
}

// auditMarkedBlock returns the text of the report between the two markers of the name.
// It fails the test when the report holds no such pair.
func auditMarkedBlock(t *testing.T, page string, name string) string {
	t.Helper()

	begin := "<!-- " + name + ":begin -->"
	end := "<!-- " + name + ":end -->"

	first := strings.Index(page, begin)
	last := strings.Index(page, end)

	if first < 0 || last < first {
		t.Fatalf("%s holds no block between %s and %s", auditReportFile, begin, end)
	}

	return page[first+len(begin) : last]
}

// auditTableRows returns one string slice for each body row of the table in the block.
// It returns an error in four cases.
//
//   - The block holds no table.
//   - The header does not name the columns, in order.
//   - The separator line is absent.
//   - A row holds a cell count that the header does not match.
func auditTableRows(block string, columns []string) ([][]string, error) {
	var lines []string

	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "|") {
			lines = append(lines, line)
		}
	}

	if len(lines) < 2 {
		return nil, fmt.Errorf("the block holds no table header and no separator line")
	}

	header := auditTableCells(lines[0])
	if !slices.Equal(header, columns) {
		return nil, fmt.Errorf("the header names %v, and the record names %v", header, columns)
	}

	separator := auditTableCells(lines[1])
	if len(separator) != len(columns) {
		return nil, fmt.Errorf("the separator line holds %d cells, and the header holds %d",
			len(separator), len(columns))
	}

	for _, cell := range separator {
		if !auditSeparatorPattern.MatchString(cell) {
			return nil, fmt.Errorf("the second line is no separator line: %q", lines[1])
		}
	}

	rows := make([][]string, 0, len(lines)-2)

	for index, line := range lines[2:] {
		cells := auditTableCells(line)
		if len(cells) != len(columns) {
			return nil, fmt.Errorf("row %d holds %d cells, and the record holds %d",
				index+1, len(cells), len(columns))
		}

		rows = append(rows, cells)
	}

	return rows, nil
}

// auditTableCells returns the trimmed cells of one table line. A cell holds no `|`, so
// the report writes a value that needs one in a different column.
func auditTableCells(line string) []string {
	line = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(line), "|"), "|")

	cells := strings.Split(line, "|")
	for index, cell := range cells {
		cells[index] = strings.TrimSpace(cell)
	}

	return cells
}

// readAuditFinding returns the finding that the cells describe.
//
// The issue names the section that holds the row, and every identifier of that section
// names it. The files hold every path of the audit set.
//
// It returns an error when a row breaks any rule of FR-audit-3 through FR-audit-10.
func readAuditFinding(issue string, files []string, cells []string) (auditFinding, error) {
	finding := auditFinding{
		ID:       cells[0],
		File:     strings.Trim(cells[1], "`"),
		Severity: cells[3],
		Status:   cells[4],
		Scenario: cells[5],
		Commit:   strings.Trim(cells[6], "`"),
		Reason:   cells[7],
	}

	identifier := regexp.MustCompile(`^F-` + issue + `-[1-9][0-9]*$`)
	if !identifier.MatchString(finding.ID) {
		return finding, fmt.Errorf("the identifier %q does not name issue #%s", finding.ID, issue)
	}

	if !slices.Contains(files, finding.File) {
		return finding, fmt.Errorf("the file %q is no file of the audit set", finding.File)
	}

	line, err := strconv.Atoi(cells[2])
	if err != nil || line < 1 {
		return finding, fmt.Errorf("the line %q is no line number", cells[2])
	}

	finding.Line = line

	if !slices.Contains(auditSeverities, finding.Severity) {
		return finding, fmt.Errorf("the severity %q is none of %v", finding.Severity, auditSeverities)
	}

	if !slices.Contains(auditStatuses, finding.Status) {
		return finding, fmt.Errorf("the status %q is none of %v", finding.Status, auditStatuses)
	}

	if err := readAuditScenario(finding.Scenario); err != nil {
		return finding, err
	}

	if err := readAuditClosure(finding); err != nil {
		return finding, err
	}

	return finding, nil
}

// readAuditScenario returns an error when the scenario breaks FR-audit-4.
//
// A failure scenario names the input and the wrong result. A hedge word names neither, so
// the reader declines one. The reader cannot prove that a sentence names an input, so the
// length rule holds the floor.
func readAuditScenario(scenario string) error {
	if len(scenario) < auditMinimumScenario {
		return fmt.Errorf("the failure scenario %q is shorter than %d characters, so it names no input and no wrong result",
			scenario, auditMinimumScenario)
	}

	if !strings.HasSuffix(scenario, ".") {
		return fmt.Errorf("the failure scenario %q ends with no full stop", scenario)
	}

	lowered := strings.ToLower(scenario)

	for _, word := range auditHedgeWords {
		if strings.Contains(lowered, word) {
			return fmt.Errorf("the failure scenario %q holds the word %q, which names a code smell and no wrong result",
				scenario, word)
		}
	}

	return nil
}

// readAuditClosure returns an error when the commit and the reason do not match the
// status. FR-audit-27 requires the commit, and FR-audit-10 and FR-audit-28 require the
// reason.
func readAuditClosure(finding auditFinding) error {
	if finding.Status == "confirmed" {
		if !auditCommitPattern.MatchString(finding.Commit) {
			return fmt.Errorf("the finding %s is confirmed and names the closing commit %q",
				finding.ID, finding.Commit)
		}
	} else if finding.Commit != "" {
		return fmt.Errorf("the finding %s is %s and names a closing commit", finding.ID, finding.Status)
	}

	if slices.Contains(auditReasonStatuses, finding.Status) && !strings.HasSuffix(finding.Reason, ".") {
		return fmt.Errorf("the finding %s is %s and states the reason %q", finding.ID, finding.Status, finding.Reason)
	}

	// An open finding reached no outcome, so a reason for it states nothing a reader can
	// act on. A confirmed finding may state why the closure took the shape it took.
	if finding.Status == "open" && finding.Reason != "" {
		return fmt.Errorf("the finding %s is open and states the reason %q", finding.ID, finding.Reason)
	}

	return nil
}

// auditGitReadsTheHistory reports whether a git command reads the history of this
// checkout. It returns false on three conditions.
//
//  1. The machine holds no `git` program.
//  2. The directory is no git working tree. A consumer that builds this module from a
//     module cache reads one of these, and the closing commit rule cannot apply there.
//  3. The clone is shallow. `actions/checkout` fetches one commit by default, and a clone
//     that holds one commit answers no question about an earlier one.
//
// A shallow clone must skip and never fail. It holds too little history to tell an
// unreachable commit from a commit it did not fetch.
func auditGitReadsTheHistory() bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}

	if exec.Command("git", "rev-parse", "--git-dir").Run() != nil {
		return false
	}

	shallow, err := exec.Command("git", "rev-parse", "--is-shallow-repository").Output()

	return err == nil && strings.TrimSpace(string(shallow)) == "false"
}

// readAuditCommitReachable returns an error when HEAD does not reach the commit the hash
// names. FR-audit-27 asks a closed finding to name the commit that closed it, and a
// reader finds that commit only when the branch reaches it.
//
// The batch process squash-merges a sub-branch, so a hash recorded on that branch names a
// commit the integration branch never carries. That commit stays in the clone that wrote
// it, and it is absent from every fresh clone. Existence therefore proves nothing, and
// reachability is the property the record needs.
func readAuditCommitReachable(hash string) error {
	if err := exec.Command("git", "cat-file", "-e", hash+"^{commit}").Run(); err != nil {
		return fmt.Errorf("the closing commit %q names no commit of this repository", hash)
	}

	if err := exec.Command("git", "merge-base", "--is-ancestor", hash, "HEAD").Run(); err != nil {
		return fmt.Errorf("the closing commit %q names a commit that HEAD does not reach", hash)
	}

	return nil
}

// auditReportStatus returns the status the report states.
func auditReportStatus(t *testing.T, page string) string {
	t.Helper()

	match := auditStatusPattern.FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("%s states no report status", auditReportFile)
	}

	return match[1]
}

// auditSetRows returns the file of each audit set row, and the issue set that reads it.
func auditSetRows(t *testing.T, page string) map[string][]string {
	t.Helper()

	rows, err := auditTableRows(auditMarkedBlock(t, page, "audit-set"), auditSetColumns)
	if err != nil {
		t.Fatalf("the audit set table: %v", err)
	}

	readers := make(map[string][]string, len(rows))

	for _, cells := range rows {
		file := strings.Trim(cells[0], "`")

		if _, held := readers[file]; held {
			t.Errorf("the audit set names %s twice, and FR-audit-2 holds one row for each file", file)
		}

		var issues []string

		for _, reference := range strings.Split(cells[1], ",") {
			match := auditIssuePattern.FindStringSubmatch(strings.TrimSpace(reference))
			if match == nil {
				t.Errorf("the audit set row for %s names the reader %q, which is no issue", file, reference)
				continue
			}

			if !slices.Contains(auditIssues, match[1]) {
				t.Errorf("the audit set row for %s names issue #%s, which owns no section", file, match[1])
			}

			issues = append(issues, match[1])
		}

		readers[file] = issues
	}

	return readers
}

// readAuditAddedRow returns the file of one added file row, and the issue that added it.
//
// It returns an error in three cases.
//
//   - The row names no file.
//   - The second cell names no issue.
//   - The second cell names an issue of the audit. Such an issue reads its files, so the
//     audit set records them and this table does not.
func readAuditAddedRow(cells []string) (string, string, error) {
	file := strings.Trim(cells[0], "`")

	if file == "" {
		return "", "", fmt.Errorf("the row names no file")
	}

	match := auditIssuePattern.FindStringSubmatch(strings.TrimSpace(cells[1]))
	if match == nil {
		return file, "", fmt.Errorf("the row for %s names the issue %q, which is no issue", file, cells[1])
	}

	if slices.Contains(auditIssues, match[1]) {
		return file, match[1], fmt.Errorf("the row for %s names issue #%s, which owns a section of the audit and reads its own files",
			file, match[1])
	}

	return file, match[1], nil
}

// auditAddedRows returns the file of each added file row, and the issue that added it.
//
// An audit of Epic 2 read no file that a later epic adds, so a reader row for such a file
// records an audit that nobody performed. The report classifies the file as added instead,
// and names the issue that added it. Issue #162 states the classification.
func auditAddedRows(t *testing.T, page string) map[string]string {
	t.Helper()

	rows, err := auditTableRows(auditMarkedBlock(t, page, "added-files"), auditAddedColumns)
	if err != nil {
		t.Fatalf("the added files table: %v", err)
	}

	added := make(map[string]string, len(rows))

	for _, cells := range rows {
		file, issue, err := readAuditAddedRow(cells)
		if err != nil {
			t.Errorf("the added files table: %v", err)
			continue
		}

		if _, held := added[file]; held {
			t.Errorf("the added files table names %s twice, and one file carries one row", file)
		}

		added[file] = issue
	}

	return added
}

// unclassifiedAuditFiles returns each file the report classifies neither way.
//
// A file of the three directories carries one of two classifications: an audit issue reads
// it, or a later issue added it. A file that carries neither is a file the record does not
// account for.
func unclassifiedAuditFiles(files []string, readers map[string][]string, added map[string]string) []string {
	var unclassified []string

	for _, file := range files {
		_, read := readers[file]
		_, later := added[file]

		if !read && !later {
			unclassified = append(unclassified, file)
		}
	}

	return unclassified
}

// unknownAuditFiles returns each file the report classifies that the three directories do
// not hold. A row for an absent file records a classification of nothing.
func unknownAuditFiles(files []string, recorded ...map[string][]string) []string {
	var unknown []string

	for _, table := range recorded {
		for file := range table {
			if !slices.Contains(files, file) {
				unknown = append(unknown, file)
			}
		}
	}

	slices.Sort(unknown)

	return unknown
}

// auditAddedFileKeys returns the added file table in the shape unknownAuditFiles reads.
func auditAddedFileKeys(added map[string]string) map[string][]string {
	keys := make(map[string][]string, len(added))
	for file, issue := range added {
		keys[file] = []string{issue}
	}

	return keys
}

// twiceClassifiedAuditFiles returns each file that both tables name.
//
// One file carries one classification. A file that carries both claims an audit and denies
// it, so the reader reports it. The result is sorted, because a test that reports a map in
// its iteration order prints a different line order on each run.
func twiceClassifiedAuditFiles(readers map[string][]string, added map[string]string) []string {
	var twice []string

	for file := range added {
		if _, read := readers[file]; read {
			twice = append(twice, file)
		}
	}

	slices.Sort(twice)

	return twice
}

func TestTheReportClassifiesEveryGoFileOfTheThreeDirectories(t *testing.T) {
	page := readRepoFile(t, auditReportFile)
	readers := auditSetRows(t, page)
	added := auditAddedRows(t, page)

	for _, file := range twiceClassifiedAuditFiles(readers, added) {
		t.Errorf("the report records %s as read and as added, and one file carries one classification", file)
	}

	files := auditGoFiles(t)

	for _, file := range unclassifiedAuditFiles(files, readers, added) {
		t.Errorf("the report classifies %s neither as read by an audit issue nor as added by a later issue, and FR-audit-1 reads every file of the three directories", file)
	}

	for _, file := range unknownAuditFiles(files, readers, auditAddedFileKeys(added)) {
		t.Errorf("the report classifies %s, and the three directories hold no such file", file)
	}
}

func TestTheClassificationReaderRejectsAFileThatNeitherTableNames(t *testing.T) {
	files := []string{"ja4.go", "internal/parser/tls.go", "cmd/ja4plus/main.go"}
	readers := map[string][]string{"ja4.go": {"22"}}
	added := map[string]string{"internal/parser/tls.go": "39"}

	unclassified := unclassifiedAuditFiles(files, readers, added)
	if !slices.Equal(unclassified, []string{"cmd/ja4plus/main.go"}) {
		t.Errorf("the reader reports %v, and one file carries no classification", unclassified)
	}
}

func TestTheClassificationReaderRejectsAFileThatBothTablesName(t *testing.T) {
	readers := map[string][]string{"ja4.go": {"22"}, "lookup.go": {"22", "23"}}
	added := map[string]string{"lookup.go": "39", "internal/parser/tls.go": "39"}

	twice := twiceClassifiedAuditFiles(readers, added)
	if !slices.Equal(twice, []string{"lookup.go"}) {
		t.Errorf("the reader reports %v, and one file carries both classifications", twice)
	}
}

func TestTheClassificationReaderRejectsARowForAnAbsentFile(t *testing.T) {
	files := []string{"ja4.go"}

	unknown := unknownAuditFiles(files,
		map[string][]string{"ja4.go": {"22"}, "gone.go": {"22"}},
		map[string][]string{"later.go": {"39"}})

	if !slices.Equal(unknown, []string{"gone.go", "later.go"}) {
		t.Errorf("the reader reports %v, and two rows name a file the three directories do not hold", unknown)
	}
}

func TestTheAddedFileReaderRejectsADefectiveRow(t *testing.T) {
	if _, _, err := readAuditAddedRow([]string{"`internal/parser/tls.go`", "#39"}); err != nil {
		t.Fatalf("the reader declines a sound row: %v", err)
	}

	cases := []struct {
		name string
		row  []string
	}{
		{"the row names no file", []string{"", "#39"}},
		{"the issue holds no number sign", []string{"`internal/parser/tls.go`", "39"}},
		{"the issue is empty", []string{"`internal/parser/tls.go`", ""}},
		{"the issue is a word", []string{"`internal/parser/tls.go`", "a later epic"}},
		{"the issue owns a section of the audit", []string{"`internal/parser/tls.go`", "#22"}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, err := readAuditAddedRow(testCase.row); err == nil {
				t.Errorf("the reader accepts a row where %s", testCase.name)
			}
		})
	}
}

func TestEveryIssueOfTheAuditReadsAtLeastOneFile(t *testing.T) {
	readers := auditSetRows(t, readRepoFile(t, auditReportFile))

	for _, issue := range auditIssues {
		read := false

		for _, issues := range readers {
			if slices.Contains(issues, issue) {
				read = true
				break
			}
		}

		if !read {
			t.Errorf("the audit set gives issue #%s no file to read", issue)
		}
	}
}

func TestEveryRecordedFindingHoldsEveryFieldOfTheRecord(t *testing.T) {
	page := readRepoFile(t, auditReportFile)
	files := auditGoFiles(t)

	identifiers := map[string]string{}

	for _, issue := range auditIssues {
		rows, err := auditTableRows(auditMarkedBlock(t, page, "findings:"+issue), auditFindingColumns)
		if err != nil {
			t.Fatalf("the findings table of issue #%s: %v", issue, err)
		}

		for _, cells := range rows {
			finding, err := readAuditFinding(issue, files, cells)
			if err != nil {
				t.Errorf("the findings table of issue #%s: %v", issue, err)
				continue
			}

			if owner, held := identifiers[finding.ID]; held {
				t.Errorf("issue #%s and issue #%s both record the finding %s", owner, issue, finding.ID)
			}

			identifiers[finding.ID] = issue
		}
	}
}

func TestEveryConfirmedFindingNamesAClosingCommitThatHeadReaches(t *testing.T) {
	if !auditGitReadsTheHistory() {
		t.Skip("git reads no history here: the machine holds no git program, or the directory is no git working tree, or the clone is shallow")
	}

	page := readRepoFile(t, auditReportFile)
	files := auditGoFiles(t)

	for _, issue := range auditIssues {
		rows, err := auditTableRows(auditMarkedBlock(t, page, "findings:"+issue), auditFindingColumns)
		if err != nil {
			t.Fatalf("the findings table of issue #%s: %v", issue, err)
		}

		for _, cells := range rows {
			// TestEveryRecordedFindingHoldsEveryFieldOfTheRecord reports a defective row,
			// so this test reads the reachability of a sound row alone.
			finding, err := readAuditFinding(issue, files, cells)
			if err != nil || finding.Status != "confirmed" {
				continue
			}

			if err := readAuditCommitReachable(finding.Commit); err != nil {
				t.Errorf("the finding %s: %v", finding.ID, err)
			}
		}
	}
}

func TestTheCommitReaderRejectsAHashThatHeadDoesNotReach(t *testing.T) {
	if !auditGitReadsTheHistory() {
		t.Skip("git reads no history here: the machine holds no git program, or the directory is no git working tree, or the clone is shallow")
	}

	if err := readAuditCommitReachable("HEAD"); err != nil {
		t.Errorf("HEAD reaches itself: %v", err)
	}

	// A hash of the right shape that names no object must fail. auditCommitPattern accepts
	// this value, which is why the shape check alone let the unreachable hashes through.
	absent := "0123456789abcdef0123456789abcdef01234567"
	if err := readAuditCommitReachable(absent); err == nil {
		t.Errorf("the reader accepts the hash %q, which names no commit", absent)
	}

	// A dangling commit is the defect this reader exists to catch: it exists in this clone
	// and no branch reaches it, which is the state a squash merge leaves behind.
	build := exec.Command("git", "commit-tree", "HEAD^{tree}", "-m", "a commit that no branch reaches")
	build.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=audit", "GIT_AUTHOR_EMAIL=audit@example.com",
		"GIT_COMMITTER_NAME=audit", "GIT_COMMITTER_EMAIL=audit@example.com")

	written, err := build.Output()
	if err != nil {
		t.Skipf("git wrote no dangling commit, so this checkout cannot hold the case: %v", err)
	}

	dangling := strings.TrimSpace(string(written))
	if err := readAuditCommitReachable(dangling); err == nil {
		t.Errorf("the reader accepts the dangling commit %q, which no branch reaches", dangling)
	}
}

func TestEveryAuditedFileRowNamesAFileThatTheIssueReads(t *testing.T) {
	page := readRepoFile(t, auditReportFile)
	readers := auditSetRows(t, page)

	for _, issue := range auditIssues {
		rows, err := auditTableRows(auditMarkedBlock(t, page, "files:"+issue), auditFileColumns)
		if err != nil {
			t.Fatalf("the audited files table of issue #%s: %v", issue, err)
		}

		recorded := map[string]bool{}

		for _, cells := range rows {
			file := strings.Trim(cells[0], "`")

			if !slices.Contains(readers[file], issue) {
				t.Errorf("issue #%s records %s as audited, and the audit set gives it no such file", issue, file)
			}

			if recorded[file] {
				t.Errorf("issue #%s records %s twice, and FR-audit-2 holds one row for each file", issue, file)
			}

			recorded[file] = true

			if !auditDatePattern.MatchString(cells[1]) {
				t.Errorf("issue #%s records %s with the audit date %q, which is no date", issue, file, cells[1])
			}
		}
	}
}

func TestTheSuspectedFindingsTableHoldsAStatusForS1AndS2AndS3(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	rows, err := auditTableRows(auditMarkedBlock(t, page, "suspected"), auditSuspectedColumns)
	if err != nil {
		t.Fatalf("the suspected findings table: %v", err)
	}

	var recorded []string

	for _, cells := range rows {
		recorded = append(recorded, cells[0])

		match := auditIssuePattern.FindStringSubmatch(cells[2])
		if match == nil || !slices.Contains(auditIssues, match[1]) {
			t.Errorf("the suspected finding %s names the owner %q, which owns no section", cells[0], cells[2])
		}

		if !slices.Contains(auditSuspectedStatuses, cells[3]) {
			t.Errorf("the suspected finding %s holds the status %q, which is none of %v",
				cells[0], cells[3], auditSuspectedStatuses)
		}

		if cells[3] != "open" && !strings.HasSuffix(cells[5], ".") {
			t.Errorf("the suspected finding %s holds the status %q and states the reason %q",
				cells[0], cells[3], cells[5])
		}
	}

	if !slices.Equal(recorded, auditSuspectedIDs) {
		t.Errorf("the suspected findings table names %v, and the feature file names %v",
			recorded, auditSuspectedIDs)
	}
}

func TestTheExportedSignatureTableCarriesTheColumnsOfTheApiFreeze(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	rows, err := auditTableRows(auditMarkedBlock(t, page, "signatures"), auditSignatureColumns)
	if err != nil {
		t.Fatalf("the exported signature table: %v", err)
	}

	for _, cells := range rows {
		for index, cell := range cells {
			if cell == "" {
				t.Errorf("the exported signature row for %q omits the column %q",
					cells[0], auditSignatureColumns[index])
			}
		}
	}
}

func TestACompleteReportLeavesNoOpenFindingAndNoUnauditedFile(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	if auditReportStatus(t, page) != "complete" {
		t.Skip("the report states that the audit runs, so the closing rules do not apply yet")
	}

	readers := auditSetRows(t, page)
	files := auditGoFiles(t)

	for _, issue := range auditIssues {
		rows, err := auditTableRows(auditMarkedBlock(t, page, "files:"+issue), auditFileColumns)
		if err != nil {
			t.Fatalf("the audited files table of issue #%s: %v", issue, err)
		}

		audited := make([]string, 0, len(rows))
		for _, cells := range rows {
			audited = append(audited, strings.Trim(cells[0], "`"))
		}

		for _, file := range files {
			if slices.Contains(readers[file], issue) && !slices.Contains(audited, file) {
				t.Errorf("the report is complete, and issue #%s records no audit date for %s", issue, file)
			}
		}

		findings, err := auditTableRows(auditMarkedBlock(t, page, "findings:"+issue), auditFindingColumns)
		if err != nil {
			t.Fatalf("the findings table of issue #%s: %v", issue, err)
		}

		for _, cells := range findings {
			if cells[4] == "open" {
				t.Errorf("the report is complete, and the finding %s stays open", cells[0])
			}
		}
	}

	suspected, err := auditTableRows(auditMarkedBlock(t, page, "suspected"), auditSuspectedColumns)
	if err != nil {
		t.Fatalf("the suspected findings table: %v", err)
	}

	for _, cells := range suspected {
		if cells[3] == "open" {
			t.Errorf("the report is complete, and the suspected finding %s stays open", cells[0])
		}
	}
}

func TestTheReportStatesTheRuleThatAFailureScenarioNamesAnInput(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	// FR-audit-4 is the rule a later slice breaks first, so the report states it above the
	// tables. The quoted requirement text is verbatim.
	for _, wanted := range []string{
		"A failure scenario names the input and the wrong result. It does not\n  name a code smell.",
		"FR-audit-4",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not state %q", auditReportFile, wanted)
		}
	}
}

func TestTheReportStatesEachSeverityRule(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	// FR-audit-6, FR-audit-7 and FR-audit-8 define the three severities. A slice that
	// assigns a severity reads the definition from the report.
	for _, wanted := range []string{
		"a wrong fingerprint, a panic, a data race, or\n  an unbounded growth of state",
		"a wrong result for an uncommon input, or a\n  contract that the code states and does not keep",
		"a defect that produces no wrong result",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not state %q", auditReportFile, wanted)
		}
	}
}

func TestTheReportNamesTheIssueThatOwnsEachSection(t *testing.T) {
	page := readRepoFile(t, auditReportFile)

	for _, issue := range auditIssues {
		for _, marker := range []string{"files:" + issue, "findings:" + issue} {
			if !strings.Contains(page, "<!-- "+marker+":begin -->") {
				t.Errorf("%s holds no section marked %s", auditReportFile, marker)
			}
		}

		if !strings.Contains(page, "issue #"+issue) {
			t.Errorf("%s does not name issue #%s as the owner of a section", auditReportFile, issue)
		}
	}
}

func TestTheFindingReaderRejectsADefectiveRow(t *testing.T) {
	files := auditGoFiles(t)

	// The row is well formed. Each case below changes one cell of it.
	sound := []string{
		"F-22-1",
		"`ja4.go`",
		"49",
		"critical",
		"open",
		"A TLS record whose length field exceeds the remaining buffer makes the parser panic.",
		"",
		"",
	}

	withCell := func(index int, value string) []string {
		row := slices.Clone(sound)
		row[index] = value

		return row
	}

	if _, err := readAuditFinding("22", files, sound); err != nil {
		t.Fatalf("the reader declines a sound row: %v", err)
	}

	cases := []struct {
		name string
		row  []string
	}{
		{"the identifier names another issue", withCell(0, "F-23-1")},
		{"the identifier holds no number", withCell(0, "F-22-")},
		{"the identifier is empty", withCell(0, "")},
		{"the file is no file of the audit set", withCell(1, "`nowhere.go`")},
		{"the file is a test file", withCell(1, "`ja4_test.go`")},
		{"the file is empty", withCell(1, "")},
		{"the line is no number", withCell(2, "near the top")},
		{"the line is zero", withCell(2, "0")},
		{"the line is empty", withCell(2, "")},
		{"the severity is none of the three", withCell(3, "blocker")},
		{"the severity is empty", withCell(3, "")},
		{"the status is none of the five", withCell(4, "wontfix")},
		{"the status is empty", withCell(4, "")},
		{"the failure scenario is empty", withCell(5, "")},
		{"the failure scenario is one phrase", withCell(5, "A bad length.")},
		{"the failure scenario ends with no full stop", withCell(5, "A TLS record whose length field exceeds the buffer")},
		{"the failure scenario names a code smell", withCell(5, "This parser could panic on a crafted TLS record length.")},
		{"the failure scenario asks for a refactor", withCell(5, "The record parser needs a refactor of its length handling.")},
		{"an open finding names a closing commit", withCell(6, "`abc1234`")},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := readAuditFinding("22", files, testCase.row); err == nil {
				t.Errorf("the reader accepts a row where %s", testCase.name)
			}
		})
	}
}

func TestTheFindingReaderHoldsTheClosureRulesOfEachStatus(t *testing.T) {
	files := auditGoFiles(t)

	const scenario = "A TLS record whose length field exceeds the remaining buffer makes the parser panic."
	const reason = "The maintainer declined the change, because the caller bounds the buffer."

	row := func(status string, commit string, reason string) []string {
		return []string{"F-24-7", "`ja4.go`", "49", "major", status, scenario, commit, reason}
	}

	cases := []struct {
		name     string
		row      []string
		accepted bool
	}{
		{"a confirmed finding names the closing commit", row("confirmed", "`a1b2c3d`", ""), true},
		{"a confirmed finding names no closing commit", row("confirmed", "", ""), false},
		{"a confirmed finding names no commit hash", row("confirmed", "`the merge commit`", ""), false},
		{"a declined finding states the reason", row("declined", "", reason), true},
		{"a declined finding states no reason", row("declined", "", ""), false},
		{"an unconfirmed finding states the reason", row("unconfirmed", "", reason), true},
		{"an unconfirmed finding states no reason", row("unconfirmed", "", ""), false},
		{"a finding that needs no change states the reason", row("no change needed", "", reason), true},
		{"a finding that needs no change states no reason", row("no change needed", "", ""), false},
		{"an open finding states a reason", row("open", "", reason), false},
		{"a confirmed finding states why the closure took its shape", row("confirmed", "`a1b2c3d`", reason), true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := readAuditFinding("24", files, testCase.row)

			if testCase.accepted && err != nil {
				t.Errorf("the reader declines a row where %s: %v", testCase.name, err)
			}

			if !testCase.accepted && err == nil {
				t.Errorf("the reader accepts a row where %s", testCase.name)
			}
		})
	}
}

func TestTheTableReaderRejectsADefectiveTable(t *testing.T) {
	cases := []struct {
		name  string
		block string
	}{
		{"the block holds no table", "The audit found nothing."},
		{"the header names another column", "| File | Date |\n|---|---|\n"},
		{"the header omits a column", "| File |\n|---|\n"},
		{"the separator line is absent", "| File | Audit date |\n| `ja4.go` | 2026-08-11 |\n"},
		{"the separator line omits a cell", "| File | Audit date |\n|---|\n| `ja4.go` | 2026-08-11 |\n"},
		{"a row omits a cell", "| File | Audit date |\n|---|---|\n| `ja4.go` |\n"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := auditTableRows(testCase.block, auditFileColumns); err == nil {
				t.Errorf("the reader accepts a table where %s", testCase.name)
			}
		})
	}
}
