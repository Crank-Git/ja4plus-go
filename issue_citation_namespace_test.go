package ja4plus

// This file holds the issue-namespace rule of `.claude/rules/rulings.md`
// `## A citation names its repository`. That section states that a bare `#N` names an issue
// of this repository, and that a citation of an issue of the port names the port. #255 wrote
// the rule, and no guard held it anywhere.
//
// The failure the rule prevents is a reader who follows a number into the wrong repository.
// #127 names the JA4L part count here, and it names the JA4 ALPN value in the port, so one
// bare number reaches two rulings. The cross-member review of batch #342 found the breach
// inside the batch that wrote the rule, and `c5e2aad` repaired it.
//
// `foxio_citation_base_test.go` holds the other citation rule, the file namespace, and
// FR-reference-18a scopes that guard to `docs/specs/foxio/*.md`. This guard reads the whole
// tree, because the issue-namespace rule binds every file. `docs/specs/features/
// 11-foxio-reference.md` numbers this file as FR-reference-32 through FR-reference-52.
//
// This guard proves one half of the rule and it declines the other half. It proves that a
// number names no issue of this repository, where the number is above the recorded high-water
// number. It proves nothing about the subject of a number at or below that mark, because the
// tracker holds the subject and this guard reads no tracker.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// issueCitationHighWaterMark is the highest number this repository had allocated on
// 2026-08-14. GitHub allocates one number sequence to issues and to pull requests, so every
// number at or below it names something of this repository and no number above it does.
//
// The command that produced it:
//
//	gh api '/repos/Crank-Git/ja4plus-go/issues?state=all&per_page=1' --jq '.[0].number'
//
// The mark is a lower bound, and this repository only allocates upward. So a stale mark
// loosens this guard and it never reddens it. A batch that cites a number above the mark
// re-measures the mark with the command above, and the failure below states that repair.
//
// The value reads 520 rather than 516, because the pull request of #351 allocated 517 through
// 520. The batch documentation round cites a pull-request number, as round 36 of the
// `## Changelog` of `docs/specs/spec.md` cites `#349`, so a mark measured before that pull
// request reports the round's own citation.
const issueCitationHighWaterMark = 520

// issueCitationExtension names the file extension of a file this guard reads. Round 36 of
// the `## Changelog` of `docs/specs/spec.md` measured the citation forms over this same set,
// so the guard and that measurement read one tree.
var issueCitationExtension = map[string]bool{
	".go":   true,
	".md":   true,
	".html": true,
	".json": true,
	".yml":  true,
}

// issueCitationSkipDirectory names a directory this guard never enters, as a path from the
// repository root.
//
// The entries name a path and never a directory name, because two directories of this
// repository are named `foxio`. `testdata/foxio` holds the fetched corpus, and
// `docs/specs/foxio` holds the transcriptions that this guard must read.
//
// `.claude/worktrees` holds the worktree of every live issue worker, so a walk that enters it
// reads the tree of another issue and reports a defect that this branch does not hold.
// `testdata/foxio` holds the fetched FoxIO corpus, which is untracked and FoxIO-licensed, so
// no rule of this project binds it.
var issueCitationSkipDirectory = map[string]bool{
	".git":              true,
	"bin":               true,
	"vendor":            true,
	"node_modules":      true,
	".claude/worktrees": true,
	"testdata/foxio":    true,
}

// issueCitationExcludedFile names a whole file that carries a local rule, with the reason.
//
// `.claude/rules/rulings.md` `## A citation names its repository` states the local rule of
// each entry. The section bars an edit of the copy, so the guard reads it and reports nothing.
var issueCitationExcludedFile = map[string]string{
	"docs/specs/foxio/port-register.md": "The page is a verbatim copy of a section of the " +
		"port's specification, so a bare number in it names the port. " +
		"`docs/specs/foxio/README.md` holds that reading, and `.claude/rules/rulings.md` " +
		"bars an edit of the copy.",
}

// issueCitationRulingColumn names the header cell that marks a register table. The preamble
// of the register in `docs/specs/spec.md` states that this column names the port issue, so
// the guard blanks the final cell of every row of a table this cell heads.
const issueCitationRulingColumn = "Ruling"

// issueCitationException records one bare citation that names the port and that this member
// repairs not, with the count and the reason.
//
// Each entry names one file, one number and the count of occurrences on that file. A count
// keeps the entry narrow, exactly as `foxioCitationException` does: a second breach of the
// same number on the same file fails the test rather than hiding under the entry.
var issueCitationException = []struct {
	file   string
	number int
	count  int
	reason string
}{
	{
		file:   "docs/specs/spec.md",
		number: 594,
		count:  1,
		reason: "Round 19 of the `## Changelog` writes `when it closes " +
			issueCitationHash(594) + "`, and `Crank-Git/ja4plus#594` is the issue that " +
			"sentence names. #512 owns this file on the `epic/441-deviation-fixes` branch, " +
			"so #351 repairs no line of it. The batch documentation round writes the " +
			"explicit form, and it then removes this entry.",
	},
}

// issueCitationPortForm matches a citation that names the port.
//
// The tree uses five shapes, and round 36 of the `## Changelog` of `docs/specs/spec.md`
// measured four of them. The fifth is a list: a marker that names the port carries a
// following list of numbers, and each number of that list names the port too.
var issueCitationPortForm = regexp.MustCompile(
	"(?i)(?:Crank-Git/ja4plus(?:/(?:issues|pull)/|#|`?\\s+(?:issues?\\s+)?#)" +
		"|\\bja4plus#" +
		"|\\b(?:the\\s+)?port(?:'s)?\\s+issues?\\s+#" +
		")([0-9]+)((?:\\s*(?:,|and)\\s*#[0-9]+)*)")

// issueCitationListItem matches one number of the list that follows a port marker.
var issueCitationListItem = regexp.MustCompile(`#[0-9]+`)

// issueCitationMalformedPortForm matches a shape that names the port beside a number, and
// that no recorded form holds. A reader of one of these cannot tell which repository the
// number names, because the shape names the port and the number stands bare.
var issueCitationMalformedPortForm = regexp.MustCompile(
	`(?i)(?:\bja4plus\s+#|\bja4plus/#|\bthe\s+port's\s+#|\bport\s+#)([0-9]+)`)

// issueCitationDigits matches the shape of a citation. A citation of this repository carries
// three digits today, and the guard reads at most four.
var issueCitationDigits = regexp.MustCompile(`#[0-9]{1,4}`)

// issueCitationHash returns the citation token for the number.
//
// This file is in scope of its own guard, so a literal token above the mark would report
// itself. Every fixture and every quotation below composes the token instead, and each one
// renders the same bytes the tree holds.
func issueCitationHash(number int) string {
	return "#" + strconv.Itoa(number)
}

// issueCitation is one bare number of one file.
type issueCitation struct {
	file   string
	line   int
	number int
	text   string
}

// issueCitationFile returns every file this guard reads, as a slash-separated path from the
// repository root.
func issueCitationFile(t *testing.T) []string {
	t.Helper()

	var found []string

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		slashed := filepath.ToSlash(path)

		if entry.IsDir() {
			if issueCitationSkipDirectory[slashed] {
				return fs.SkipDir
			}

			return nil
		}

		if !issueCitationExtension[strings.ToLower(filepath.Ext(slashed))] {
			return nil
		}

		found = append(found, slashed)

		return nil
	})
	if err != nil {
		t.Fatalf("the walk of the repository root failed: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("the walk of the repository root found no file, and the tree holds many")
	}

	return found
}

// issueCitationBlankRulingColumn returns the lines of the file with the final cell of every
// register row replaced by an empty cell.
//
// The preamble of the register in `docs/specs/spec.md` states that the `Ruling` column names
// the port issue. `docs/specs/spec.html` renders the same table, so one rule reads both
// formats: the guard finds the header cell, and it blanks the final cell of each row until
// the table ends.
//
// The function blanks a cell rather than a line, so a reported line number names the line of
// the file and a citation in another cell of the same row still reaches the guard.
func issueCitationBlankRulingColumn(lines []string) []string {
	blanked := make([]string, len(lines))
	copy(blanked, lines)

	markdownTable := false
	htmlTable := false

	for index, line := range lines {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "|"):
			if issueCitationFinalMarkdownCell(trimmed) == issueCitationRulingColumn {
				markdownTable = true

				continue
			}

			if markdownTable {
				blanked[index] = issueCitationCutFinalMarkdownCell(line)
			}
		case strings.Contains(trimmed, "<th>"+issueCitationRulingColumn+"</th></tr>"):
			htmlTable = true
		case strings.Contains(trimmed, "</table>"):
			htmlTable = false
		case htmlTable && strings.Contains(trimmed, "<tr>"):
			blanked[index] = issueCitationCutFinalHTMLCell(line)
		default:
			markdownTable = false
		}
	}

	return blanked
}

// issueCitationFinalMarkdownCell returns the final cell of a markdown table row, trimmed.
func issueCitationFinalMarkdownCell(row string) string {
	cell := strings.Split(strings.Trim(row, "|"), "|")

	return strings.TrimSpace(cell[len(cell)-1])
}

// issueCitationCutFinalMarkdownCell returns the row with the final cell emptied.
func issueCitationCutFinalMarkdownCell(row string) string {
	last := strings.LastIndex(row, "|")
	if last <= 0 {
		return row
	}

	head := row[:last]

	previous := strings.LastIndex(head, "|")
	if previous < 0 {
		return row
	}

	return head[:previous+1] + row[last:]
}

// issueCitationCutFinalHTMLCell returns the row with the final `<td>` element emptied.
func issueCitationCutFinalHTMLCell(row string) string {
	open := strings.LastIndex(row, "<td>")
	if open < 0 {
		return row
	}

	end := strings.LastIndex(row, "</td>")
	if end < open {
		return row
	}

	return row[:open+len("<td>")] + row[end:]
}

// issueCitationBare returns every bare number of one line.
//
// A bare number is a `#` that carries digits, and that no recorded port form covers. Three
// shapes carry the `#` character and cite nothing, and the function declines each one.
//
//   - A token of five or more digits. A CSS color literal such as `#101216` is one, and no
//     number of this repository reaches five digits.
//   - A token that a word character or a `/` precedes. A URL fragment such as
//     `spec.html#127` is one.
//   - A token that a letter follows. A CSS color literal such as `#0b0d11` is one.
func issueCitationBare(line string) []int {
	stripped := issueCitationPortForm.ReplaceAllStringFunc(line, func(match string) string {
		return issueCitationListItem.ReplaceAllString(match, "PORTREF")
	})

	var found []int

	for _, span := range issueCitationDigits.FindAllStringIndex(stripped, -1) {
		start, end := span[0], span[1]

		if start > 0 && issueCitationWordByte(stripped[start-1]) {
			continue
		}

		if start > 0 && stripped[start-1] == '/' {
			continue
		}

		if end < len(stripped) && issueCitationWordByte(stripped[end]) {
			continue
		}

		number, err := strconv.Atoi(stripped[start+1 : end])
		if err != nil {
			continue
		}

		found = append(found, number)
	}

	return found
}

// issueCitationWordByte reports whether the byte is a letter, a digit or an underscore.
func issueCitationWordByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b == '_':
		return true
	default:
		return false
	}
}

// issueCitationRead returns every bare citation of every file this guard reads.
func issueCitationRead(t *testing.T) []issueCitation {
	t.Helper()

	var found []issueCitation

	for _, file := range issueCitationFile(t) {
		if _, excluded := issueCitationExcludedFile[file]; excluded {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s does not open: %v", file, err)
		}

		lines := issueCitationBlankRulingColumn(strings.Split(string(content), "\n"))

		for index, line := range lines {
			for _, number := range issueCitationBare(line) {
				found = append(found, issueCitation{
					file:   file,
					line:   index + 1,
					number: number,
					text:   strings.TrimSpace(line),
				})
			}
		}
	}

	return found
}

// issueCitationExceptionKey names one entry of the exception table.
type issueCitationExceptionKey struct {
	file   string
	number int
}

// issueCitationExcepted returns the count the exception table records for the citation.
func issueCitationExcepted(citation issueCitation) (int, bool) {
	for _, entry := range issueCitationException {
		if entry.file == citation.file && entry.number == citation.number {
			return entry.count, true
		}
	}

	return 0, false
}

// FR-reference-32, FR-reference-35 and FR-reference-39 — a bare `#N` names an issue of this
// repository, and a bare number above the recorded high-water number names none.
//
// The check is one-directional, and that is the whole reason it holds. This repository
// allocates a number to an issue and to a pull request from one sequence, so every number at
// or below the mark resolves to something here and the guard proves nothing about it. A
// number above the mark resolves to nothing here, so the citation names another repository.
func TestNoBareIssueCitationNamesANumberAboveTheHighWaterMark(t *testing.T) {
	seen := map[issueCitationExceptionKey]int{}

	for _, citation := range issueCitationRead(t) {
		if citation.number <= issueCitationHighWaterMark {
			continue
		}

		if _, excepted := issueCitationExcepted(citation); excepted {
			seen[issueCitationExceptionKey{file: citation.file, number: citation.number}]++

			continue
		}

		t.Errorf("%s:%d writes a bare #%d, and this repository had allocated %d numbers on "+
			"2026-08-14.\n\tThe line reads: %s\n\tEither the citation names the port, and "+
			"the repair writes `Crank-Git/ja4plus#%d`, or this repository has allocated "+
			"more numbers since, and the repair re-measures %s.",
			citation.file, citation.line, citation.number, issueCitationHighWaterMark,
			citation.text, citation.number, "issueCitationHighWaterMark")
	}

	for _, entry := range issueCitationException {
		key := issueCitationExceptionKey{file: entry.file, number: entry.number}

		if seen[key] != entry.count {
			t.Errorf("the exception table records %d bare #%d of %s, and the file holds "+
				"%d.\n\tThe recorded reason is: %s",
				entry.count, entry.number, entry.file, seen[key], entry.reason)
		}
	}
}

// FR-reference-33 and FR-reference-34 — a citation of an issue of the port carries a
// recorded form.
//
// A shape that names the port beside a bare number tells a reader two things at once. The
// recorded forms carry the repository into the citation itself, so a reader who reads the
// number alone still reaches the right repository.
func TestEveryPortIssueCitationCarriesARecordedForm(t *testing.T) {
	for _, file := range issueCitationFile(t) {
		if _, excluded := issueCitationExcludedFile[file]; excluded {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s does not open: %v", file, err)
		}

		for index, line := range strings.Split(string(content), "\n") {
			match := issueCitationMalformedPortForm.FindString(line)
			if match == "" {
				continue
			}

			t.Errorf("%s:%d writes %q, and no recorded form holds that shape.\n\t"+
				"The line reads: %s\n\tWrite `Crank-Git/ja4plus#N`, `the port's issue #N` "+
				"or `port issue #N`.",
				file, index+1, match, strings.TrimSpace(line))
		}
	}
}

// FR-reference-50, FR-reference-51 and FR-reference-52 — an exception names one file, one
// number, one count and one reason, and an exception that no longer reproduces fails.
//
// A stale exception hides the next breach of the same file, exactly as a file-wide exclusion
// does.
func TestTheIssueCitationExceptionTableHoldsNoBreachThatNoLongerReproduces(t *testing.T) {
	reproduced := map[issueCitationExceptionKey]int{}

	for _, citation := range issueCitationRead(t) {
		if citation.number <= issueCitationHighWaterMark {
			continue
		}

		reproduced[issueCitationExceptionKey{
			file:   citation.file,
			number: citation.number,
		}]++
	}

	for _, entry := range issueCitationException {
		if entry.reason == "" {
			t.Errorf("the exception for #%d of %s states no reason", entry.number, entry.file)
		}

		if entry.count < 1 {
			t.Errorf("the exception for #%d of %s records a count of %d, and an entry that "+
				"records no occurrence covers a whole file", entry.number, entry.file, entry.count)
		}

		key := issueCitationExceptionKey{file: entry.file, number: entry.number}

		if reproduced[key] != entry.count {
			t.Errorf("the exception table records %d bare #%d of %s, and the file holds "+
				"%d.\n\tThe recorded reason is: %s",
				entry.count, entry.number, entry.file, reproduced[key], entry.reason)
		}
	}
}

// FR-reference-40, FR-reference-41 and FR-reference-42 — the guard reads the tree, it opens
// no file of the corpus, and no test of it skips.
//
// #335 records that a silent skip is not a guard. This guard needs no corpus, so it states
// the property rather than a skip message: the walk enters no directory the corpus holds, and
// every test above runs on every checkout.
func TestTheIssueCitationGuardReadsNoCorpusAndSkipsForNoReason(t *testing.T) {
	if !issueCitationSkipDirectory["testdata/foxio"] {
		t.Error("the walk enters `testdata/foxio`, which holds the untracked FoxIO corpus")
	}

	if !issueCitationSkipDirectory[".claude/worktrees"] {
		t.Error("the walk enters `.claude/worktrees`, which holds the tree of another issue")
	}

	transcription := false

	for _, file := range issueCitationFile(t) {
		if strings.HasPrefix(file, "testdata/foxio/") {
			t.Errorf("the walk reached %s, which the corpus holds", file)
		}

		if strings.Contains(file, "/worktrees/") {
			t.Errorf("the walk reached %s, which another worktree holds", file)
		}

		if strings.HasPrefix(file, "docs/specs/foxio/") {
			transcription = true
		}
	}

	// Two directories of this repository are named `foxio`, and the guard must read one of
	// them. A skip rule that reads a directory name rather than a path drops all 20 pages of
	// the transcription directory, and it reports nothing.
	if !transcription {
		t.Error("the walk reached no page of `docs/specs/foxio`, which holds the transcriptions")
	}

	if len(issueCitationRead(t)) == 0 {
		t.Error("the guard read no citation, and the tree holds many")
	}
}

// FR-reference-46 through FR-reference-49 — one test case holds each exclusion the guard
// makes.
//
// A false positive costs more than a gap here. A `#N` of a URL, of a CSS color literal or of
// a register cell cites no issue, and a guard that reports one of them earns a deletion.
func TestTheIssueCitationGuardExcludesEachRecordedShape(t *testing.T) {
	line := []struct {
		name string
		text string
		want []int
	}{
		{
			name: "a bare number is a citation of this repository",
			text: "Issue #127 holds the question.",
			want: []int{127},
		},
		{
			name: "the table-cell port form names the port",
			text: "The port half is `Crank-Git/ja4plus#215`, and it is closed.",
			want: nil,
		},
		{
			name: "the sentence port form names the port",
			text: "The port's issue #533 settled the vocabulary.",
			want: nil,
		},
		{
			name: "the short sentence port form names the port",
			text: "Port issue #594 records that.",
			want: nil,
		},
		{
			name: "the backticked repository name form names the port",
			text: "The change opens the port half, and `Crank-Git/ja4plus` #597 holds it.",
			want: nil,
		},
		{
			name: "a list after a port marker names the port",
			text: "The port's issues #127, #141, #162 and #522 hold these rulings.",
			want: nil,
		},
		{
			name: "a port issue URL names the port",
			text: "See <https://github.com/Crank-Git/ja4plus/issues/598> for the port half.",
			want: nil,
		},
		{
			name: "a CSS color literal of six digits cites no issue",
			text: "--bg: #101216; --panel: #171a20;",
			want: nil,
		},
		{
			name: "a CSS color literal that carries a letter cites no issue",
			text: ":root { --term-bg: #0b0d11; }",
			want: nil,
		},
		{
			name: "a URL fragment cites no issue",
			text: "Open <spec.html#127> for the readable overview.",
			want: nil,
		},
		{
			name: "an anaphoric port form leaves the number bare",
			text: "The port decided it as D4 of its issue #231 on 2026-08-08.",
			want: []int{231},
		},
	}

	for _, one := range line {
		t.Run(one.name, func(t *testing.T) {
			got := issueCitationBare(one.text)

			if fmt.Sprint(got) != fmt.Sprint(one.want) {
				t.Errorf("the guard reads %v of %q, and it must read %v",
					got, one.text, one.want)
			}
		})
	}
}

// FR-reference-43, FR-reference-44 and FR-reference-45 — the guard honors the two local
// rules, and each exclusion states its reason.
func TestTheIssueCitationGuardHonorsTheTwoLocalRules(t *testing.T) {
	for file, reason := range issueCitationExcludedFile {
		if reason == "" {
			t.Errorf("the exclusion of %s states no reason", file)
		}

		if _, err := os.Stat(file); err != nil {
			t.Errorf("the exclusion names %s, and this checkout holds no such file: %v",
				file, err)
		}
	}

	row := []struct {
		name string
		text []string
		want []int
	}{
		{
			name: "the Ruling column of the register names the port",
			text: []string{
				"| Item | This project today | What must change | Rule | Ruling |",
				"|---|---|---|---|---|",
				"| The ALPN value | Writes `99`. | Done. | 1 | #141, #162, " +
					issueCitationHash(522) + " |",
			},
			want: nil,
		},
		{
			name: "another cell of a register row reaches the guard",
			text: []string{
				"| Item | This project today | What must change | Rule | Ruling |",
				"|---|---|---|---|---|",
				"| The ALPN value | " + issueCitationHash(517) + " built it. | Done. | 1 | " +
					issueCitationHash(522) + " |",
			},
			want: []int{517},
		},
		{
			name: "the rendered Ruling column names the port",
			text: []string{
				"<tr><th>Method</th><th>What must change</th><th>Ruling</th></tr>",
				"<tr><td>JA4, JA4S</td><td>Write `99`.</td><td>#127 " +
					issueCitationHash(522) + "</td></tr>",
				"</table>",
			},
			want: nil,
		},
		{
			name: "a table that no Ruling cell heads reaches the guard",
			text: []string{
				"| Round | Date | What changed |",
				"|---|---|---|",
				"| 19 | 2026-08-12 | The port reaches it when it closes " +
					issueCitationHash(594) + ". |",
			},
			want: []int{594},
		},
	}

	for _, one := range row {
		t.Run(one.name, func(t *testing.T) {
			var got []int

			for _, line := range issueCitationBlankRulingColumn(one.text) {
				got = append(got, issueCitationBare(line)...)
			}

			if fmt.Sprint(got) != fmt.Sprint(one.want) {
				t.Errorf("the guard reads %v of the row, and it must read %v", got, one.want)
			}
		})
	}
}
