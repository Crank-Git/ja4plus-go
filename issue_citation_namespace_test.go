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
// 11-foxio-reference.md` numbers this file as FR-reference-32 through FR-reference-53.
//
// This file uses two words for two things, and it never rotates them. An **exclusion** names
// text that cites no issue, so the guard reads it and reports nothing. An **exception** names
// one live breach that this member repairs not, with the count and the reason.
//
// This guard proves one half of the rule and it declines the other half. It proves that a
// number names no issue of this repository, where the number is above the recorded high-water
// number. It proves nothing about the subject of a number at or below that mark. The tracker
// holds that subject, and this guard reads no tracker.

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
// 2026-08-14. GitHub allocates one number sequence to issues and to pull requests. So every
// number at or below the mark names something of this repository, and no number above it does.
//
// The command that produced it:
//
//	gh api '/repos/Crank-Git/ja4plus-go/issues?state=all&per_page=1' --jq '.[0].number'
//
// The mark is a lower bound, and this repository only allocates upward. So a stale mark
// loosens this guard and it never reddens it. A batch that cites a number above the mark
// re-measures the mark with the command above, and the failure below states that repair.
//
// The value read 520 when #351 first measured it, and the batch documentation round
// re-measured it with the same command on the same day. #351 named this maintenance cost, and
// the round pays it: the round cites its own issue number, and that number sits above the mark
// the round inherits. Round 36 of the `## Changelog` of `docs/specs/spec.md` cites `#349`, so a
// round that cites a pull request pays the cost too.
// The batch #516 gate re-measured the mark on 2026-08-14 and it read 530. The gate note of
// round 49 cites `#525`, which is the issue that carries the anaphoric citation ruling, and
// that number sits above the inherited mark of 522. **The guard reported it and CI failed on
// it**, which is the guard doing its work rather than a defect of the round.
// The batch #530 round re-measured the mark on 2026-08-14 and it read 543. **That batch
// merged `dev` into its integration branch after six members had landed**, so this guard
// reached their commits only at the merge. It reported 8 bare citations above 530: 6 name
// #532 and 2 name #533, and every one names an issue of this repository.
// The batch #536 round re-measured the mark on 2026-08-14 and it read 552. The round cites
// #544, #547, #548, #549, #550, #551 and #552, and each number sits above the inherited
// mark of 543. Every one names an issue or a pull request of this repository.
// Issue #565 re-measured the mark on 2026-08-14 and it read 578. That issue bounds the eight
// fingerprinter state maps, and its code comments cite #565, #577 and #193. Each of the three
// names an issue of this repository, and #565 and #577 sit above the inherited mark of 552.
// **The self-review of #565 filed #577, and the guard then reported the new citation.** So one
// issue re-measured the mark twice, and 578 is the second reading.
//
// The #556 hotfix re-measured the mark on 2026-08-14 and it read 568. That hotfix cites
// `#556` in a code comment and in a test, and 556 sits above the inherited mark of 552. **A
// hotfix pays this maintenance cost exactly as a batch round does**, because the guard reads
// the number and never the shape of the change that carries it.
//
// The hotfix read 560 before it filed #568, and it read 568 after. **A mark that a later
// allocation passes stays safe**, because the mark is a lower bound and this repository only
// allocates upward.
//
// #87 re-measured the mark on 2026-08-14 and it read 595. `docs/reference/index.md` cites
// #593, which records the `pkg.go.dev` license reading, and 593 sits above the inherited
// mark of 568. **A member of a batch pays this maintenance cost exactly as a round does**,
// because the guard reads the number and never the shape of the change that carries it.
//
// The Epic 9 round re-measured the mark on 2026-08-14 and it read 581. That round cites
// #573, #577 and #581, and each number sits above the inherited mark of 543.
//
// The merge of `dev` into `epic/71-database-lookup` met two marks, 568 and 581, and it kept
// 581. The mark is a lower bound, so the higher reading covers every citation the lower one
// covers.
//
// The batch #555 round re-measured the mark on 2026-08-14 and it read 583. The round cites
// #555, #557, #559, #560, #561, #563 and #575, and each number sits above the inherited
// mark of 552. Every one names an issue or a pull request of this repository.
//
// **The merge of `dev` into batch #555 met two marks, and it keeps the higher one.** The
// hotfix read 568 and the round read 583. **A mark is a lower bound, so the higher reading
// covers the lower one** and no citation of either change falls outside it.
//
// **The second merge of `dev` into `epic/71-database-lookup` met the marks 581 and 583, and
// it keeps 583.** Batch #555 landed on `dev` after the first merge, and it carried the
// higher reading. The mark stays a lower bound, so 583 covers every citation that 581
// covers.
//
// **The merge of `dev` into batch #432 met a third reading, and it keeps the highest.** #565
// read 578, the hotfix read 568 and the round read 583. **Three readings of one lower bound
// reconcile to the largest**, because this repository allocates upward and never reuses a
// number.
//
// **Five changes of one day each re-measured this mark, and every reading reconciles to
// 583.** A reader who counts the paragraphs above reads the maintenance cost that #351
// named, and never a disagreement.
//
// The Epic 6 round re-measured the mark on 2026-08-14 and it read 602. The round cites #591,
// #596, #600 and #602, and each number sits above the inherited mark of 568. Every one names
// an issue or a pull request of this repository. **#602 is the round's own issue**, which is
// the maintenance cost that #351 named and that every round pays.
//
// **The merge of `dev` into epic #43 met the marks 583 and 602, and it keeps 602.** The
// Epic 6 round allocated #602 for itself, so its reading is the later one. **The mark is a
// lower bound, so 602 covers every citation that 583 covers.**
//
// **The Epic 14 round merged `dev` into `epic/83-documentation-site` and it met two marks,
// 595 and 583.** The round re-measured the mark on 2026-08-14 and it read 604. The round
// cites #603, which is the issue that carries the merge and the refresh, and 603 sits above
// both inherited marks. **A mark is a lower bound, so 604 covers every citation that 595
// covers and every citation that 583 covers.**
//
// **The second merge of `dev` into `epic/83-documentation-site` met the marks 604 and 602,
// and it keeps 604.** Epic 6 landed on `dev` after the first merge, and it carried the
// reading of 602. **A mark is a lower bound, so 604 covers every citation that 602 covers.**
//
// #77 re-measured the mark on 2026-08-14 and it read 564. `internal/capture/pcapgo_linux.go`
// cites #564 at three places. #564 names the issue that carries the capture filter question,
// and that number sits above the inherited mark of 552. **A member pays this cost too**, and
// no round of the batch precedes a member that files an issue.
//
// **The sentence above named a TODO comment until the Epic 13 round repaired it.**
// `grep -n "TODO" internal/capture/pcapgo_linux.go` reports nothing on 2026-08-14. The
// three #564 citations sit at `:42`, `:112` and `:120`: one ordinary comment inside `open`,
// and two lines of the doc comment of `compileFilter`. `.claude/rules/ste.md`
// `### A code comment` gives `TODO(#N)` a defined form, so a reader who grepped that marker
// found no target.
//
// #80 re-measured the mark on 2026-08-14 and it read 591. The doc comment of `newMonitor`
// in `cmd/ja4plus/watch.go` cites #577, which names the issue that carries the age-pass
// clock question, and that number sits above the inherited mark of 564. **Two members of
// one batch each pay this cost**, because #77 landed before #577 existed.
//
// **The merge of `dev` into `epic/76-live-capture` met the marks 604 and 591, and it keeps
// 604.** Epic 14 allocated #603 for its own round, and that reading is the later one. **A
// mark is a lower bound, so 604 covers every citation that 591 covers**, and it covers the
// #564 citation of #77 and the #577 citation of #80.
//
// The Epic 13 round re-measured the mark on 2026-08-14 and it read 614. The round cites
// #609, #610, #611, #612, #613 and #614, and each number sits above the inherited mark of
// 604. Every one names an issue of this repository. **#614 is the round's own issue**, and
// #609 through #613 are the five findings of the Epic 13 cross-member review that earned a
// tracker issue. **A round that runs after its review allocates six numbers rather than
// one**, which is the maintenance cost that #351 named.
//
// The batch #617 round re-measured the mark on 2026-08-14 and it read 622. That round cites
// #594, #596, #617 and #619 through #622, and each number sits above the inherited mark of
// 614. Every one names an issue or a pull request of this repository.
//
// **This round names four numbers that both repositories allocated, and the two sets differ.**
// This repository holds #619 through #622, and the port holds `Crank-Git/ja4plus#619` through
// `Crank-Git/ja4plus#622`. `Crank-Git/ja4plus#619` and this repository's #619 each concern the
// JA4X empty list, and `Crank-Git/ja4plus#620` and this repository's #620 concern two
// different questions. **So a bare number in that range is ambiguous**, and
// `.claude/rules/rulings.md` `## A citation names its repository` already bars it. This guard
// enforces the bare form for this repository, and
// `TestEveryPortIssueCitationCarriesARecordedForm` reads the qualified form.
// #96 re-measured the mark on 2026-08-14 and it read 628.
// `prerelease_install_test.go` cites #628, which names the issue that carries the version
// of a program that `go install` builds. That number sits above the inherited mark of 622.
// **A member pays this cost**, and no round of Epic 16 precedes a member that files an
// issue. **Three members of Epic 16 run beside #96**, so a later member re-measures the
// mark again and the union of the four is one number.
//
// **The project manager re-measured the mark on 2026-08-14 and it read 635.** It resolved
// the three registry conflicts of Epic 16 by hand, and its own resolution wrote a bare
// `#633` into `prerelease_registry_test.go`. **#633 names the issue that carries the
// FR-prerelease-26 question**, and the project manager filed it after #96 measured 628.
//
// **The guard reported that citation and the ordinary gate turned red**, which is the guard
// doing its work rather than a defect of any member. **#96 predicted this exact breach**,
// three paragraphs above, and no member closed it because the number arrived after every
// member had measured.
//
// **A project manager pays this cost too, and not a member alone.** A conflict resolution
// writes prose, and prose cites an issue. **So the resolver re-measures the mark**, and the
// Epic 16 cross-member review is what found that it had not.
//
// **The Epic 16 round re-measured the mark on 2026-08-14 and it read 637.** The round cites
// #637, which is its own issue, and 637 sits above the inherited mark of 635. **A round pays
// this cost after the project manager pays it.** The round allocates its own number after the
// resolution that raised the mark.
//
// **The round read 637 before it opened its pull request, and it read 639 after.** The pull
// request is #639, and the constant holds the second reading. **A mark that a later
// allocation passes stays safe**, because the mark is a lower bound and this repository only
// allocates upward. The #556 hotfix recorded the same pair of readings on the same day.
//
// **No tracked file cites a number above 637**, so either reading leaves this guard green.
//
// #92 re-measured the mark on 2026-08-14 and it read 635. The highest number this repository
// had allocated is #635, which is the pull request of #93. #92 cites #634, which is the
// issue that carries the FR-mutation-11 amendment of the maintainer's ruling, and that
// number sits above the inherited mark of 622. **#634 names an issue of this repository**,
// and its title is `Amend FR-mutation-11 to settle by fingerprint risk and count the
// remainder`.
// #638 re-measured the mark on 2026-08-14 and it read 639. #638 is the Epic 15 documentation
// round, and it cites its own number in round 59 of the `## Changelog` of
// `docs/specs/spec.md`. That number sits above the inherited mark of 635, which is the case
// the paragraph above names. The highest number this repository had allocated is #639, which
// is the pull request of the Epic 16 documentation round.
//
// **The merge of `dev` into `epic/94-prerelease-validation` met two readings, and both read
// 639.** Epic 15 and Epic 16 each ran a round on 2026-08-14, and each round re-measured the
// mark. **Two rounds that measure one tracker on one day reach one number**, so the merge
// takes the union of the two histories and one constant.
//
// **#652 re-measured the mark on 2026-08-15 and it read 661.** #652 cites its own number in
// `ja4ls_seconds_truncation_test.go`, in `testdata/deviations.json` and in
// `docs/audit/ja4l-deviation-cluster.md`. That number sits above the inherited mark of 639.
// **A member pays this cost exactly as a round does**, because the guard reads the number
// and never the shape of the change that carries it.
const issueCitationHighWaterMark = 661

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
// `.claude/worktrees` holds the worktree of every live issue worker. A walk that enters it
// reads the tree of another issue, and it then reports a defect that this branch does not
// hold. `testdata/foxio` holds the fetched FoxIO corpus. That corpus is untracked and
// FoxIO-licensed, so no rule of this project binds it.
//
// `site` and `.venv` each hold an artifact that `make docs` produces, and `.gitignore:47`
// and `.gitignore:48` name them. **`make docs` became a real target on 2026-08-14**, so a
// developer who builds the site and then runs `go test` gave this guard a second copy of
// every page. It then reported one defect twice, and it named a generated HTML file that no
// repair can reach. #87 measured it: a run after `make docs` reported
// `site/reference/index.html:1511` and `site/search/search_index.json:1` beside the page
// that holds the citation.
var issueCitationSkipDirectory = map[string]bool{
	".git":              true,
	"bin":               true,
	"vendor":            true,
	"node_modules":      true,
	"site":              true,
	".venv":             true,
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
// The table is empty on 2026-08-14. #351 recorded one entry, for the one bare number of round
// 19 of the `## Changelog` of `docs/specs/spec.md`. Round 49 of that changelog writes
// `Crank-Git/ja4plus#594` in place of that number, so the breach no longer reproduces and the
// batch documentation round removed the entry.
var issueCitationException = []struct {
	file   string
	number int
	count  int
	reason string
}{}

// issueCitationPortForm matches a citation that names the port.
//
// The tree uses five shapes, and round 36 of the `## Changelog` of `docs/specs/spec.md`
// measured four of them. The fifth one is a list. A marker that names the port carries a
// following list of numbers, and each number of that list names the port too.
//
// The list reads three separators. A comma joins the items, and `and` or `or` joins the last
// two. A separator this pattern does not name leaves the number bare, and the guard then
// reports a citation that the sentence resolves.
var issueCitationPortForm = regexp.MustCompile(
	"(?i)(?:Crank-Git/ja4plus(?:/(?:issues|pull)/|#|`?\\s+(?:issues?\\s+)?#)" +
		"|\\bja4plus#" +
		"|\\b(?:the\\s+)?port(?:'s)?\\s+issues?\\s+#" +
		")([0-9]+)((?:\\s*(?:,|and|or)\\s*#[0-9]+)*)")

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
// formats. The guard finds the header cell, and it blanks the final cell of each row until the
// table ends.
//
// The function blanks a cell rather than a line, for two reasons. A reported line number then
// names the line of the file. A citation in another cell of the same row then still reaches the
// guard.
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

// issueCitationWrappedRulingRow returns the line number of every row of a rendered register
// table that carries a cell on a line of its own.
//
// The rule above reads one row on one line. A row that wraps puts its `Ruling` cell on a line
// that carries no `<tr>`, and the rule then blanks nothing there. That failure is silent, so
// FR-reference-53 bars a wrapped row rather than a permissive rule that blanks every cell of
// such a line.
func issueCitationWrappedRulingRow(lines []string) []int {
	var wrapped []int

	table := false

	for index, line := range lines {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.Contains(trimmed, "<th>"+issueCitationRulingColumn+"</th></tr>"):
			table = true
		case strings.Contains(trimmed, "</table>"):
			table = false
		case table && strings.Contains(trimmed, "<td>") && !strings.Contains(trimmed, "<tr>"):
			wrapped = append(wrapped, index+1)
		}
	}

	return wrapped
}

// issueCitationFinalCell returns the cells of a markdown table row and the index of the final
// cell.
//
// Both helpers below read this one split, so a row that carries no trailing separator reaches
// the same cell as a row that carries one. Two helpers that split a row two ways disagree on a
// malformed row, and the disagreement blanks the wrong cell.
func issueCitationFinalCell(row string) ([]string, int) {
	cell := strings.Split(row, "|")

	final := len(cell) - 1
	if final > 0 && strings.TrimSpace(cell[final]) == "" {
		final--
	}

	return cell, final
}

// issueCitationFinalMarkdownCell returns the final cell of a markdown table row, trimmed.
func issueCitationFinalMarkdownCell(row string) string {
	cell, final := issueCitationFinalCell(row)
	if final < 0 {
		return ""
	}

	return strings.TrimSpace(cell[final])
}

// issueCitationCutFinalMarkdownCell returns the row with the final cell emptied.
func issueCitationCutFinalMarkdownCell(row string) string {
	cell, final := issueCitationFinalCell(row)
	if final < 1 {
		return row
	}

	cell[final] = ""

	return strings.Join(cell, "|")
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
			name: "a list that `or` joins names the port",
			text: "The port's issues #127 or #141 hold these rulings.",
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

// FR-reference-53 — a row of a rendered register table stays on one line.
//
// The rule that blanks the `Ruling` column reads one row on one line. A row that wraps hides
// its `Ruling` cell from that rule, and the guard then reports a citation the register
// resolves. This test names the wrapped row rather than let the rule guess.
func TestEveryRenderedRulingRowStaysOnOneLine(t *testing.T) {
	// The detector is worth nothing until a wrapped row proves it, so these two fixtures run
	// before the tree does.
	oneLine := []string{
		"<tr><th>Method</th><th>What must change</th><th>Ruling</th></tr>",
		"<tr><td>JA4</td><td>Write `99`.</td><td>#127</td></tr>",
		"</table>",
	}

	if got := issueCitationWrappedRulingRow(oneLine); got != nil {
		t.Errorf("the detector names line %v of a table that wraps no row", got)
	}

	wrapped := []string{
		"<tr><th>Method</th><th>What must change</th><th>Ruling</th></tr>",
		"<tr>",
		"<td>JA4</td><td>Write `99`.</td><td>#127</td>",
		"</tr>",
		"</table>",
	}

	if got := issueCitationWrappedRulingRow(wrapped); len(got) != 1 || got[0] != 3 {
		t.Errorf("the detector names %v of a table whose row wraps onto line 3", got)
	}

	for _, file := range issueCitationFile(t) {
		if !strings.HasSuffix(file, ".html") {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s does not open: %v", file, err)
		}

		for _, line := range issueCitationWrappedRulingRow(strings.Split(string(content), "\n")) {
			t.Errorf("%s:%d carries a cell of a register row on a line of its own.\n\t"+
				"Write the whole row on one line, so the guard reads its `%s` cell.",
				file, line, issueCitationRulingColumn)
		}
	}
}

// FR-reference-36, FR-reference-37 and FR-reference-38 — the record of the high-water number
// names its date and its command, the number is a lower bound, and the guard reads no tracker.
//
// A guard that reads a tracker fails when the network fails, and it then reports a defect that
// the tree does not hold. So this test reads the source of the guard and it bars the three
// shapes that reach a tracker.
func TestTheIssueCitationGuardRecordsItsSourceAndReadsNoTracker(t *testing.T) {
	const source = "issue_citation_namespace_test.go"

	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("%s does not open: %v", source, err)
	}

	text := string(content)

	// FR-reference-36 — the record names the date and the command.
	for _, want := range []string{
		"2026-08-14",
		"gh api '/repos/Crank-Git/ja4plus-go/issues?state=all&per_page=1'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the record of the high-water number names no %q", want)
		}
	}

	// FR-reference-38 — the guard reaches no tracker. `gh` in a code span of the record above
	// is the command a person runs, and never a call this file makes.
	//
	// Each name below is composed, because this test reads its own source. A literal here
	// would match itself and report the guard it holds.
	for _, barred := range []string{"net/" + "http", "os/" + "exec", "exec." + "Command"} {
		if strings.Contains(text, barred) {
			t.Errorf("the guard names %q, and a guard that reads a tracker fails with the "+
				"network", barred)
		}
	}

	// FR-reference-37 — the mark bounds the report from one side. A number at or below it
	// reaches no report, so a stale mark loosens the guard.
	reported := 0

	for _, citation := range issueCitationRead(t) {
		if citation.number <= issueCitationHighWaterMark {
			continue
		}

		reported++
	}

	if reported != len(issueCitationException) {
		t.Errorf("the guard reports %d citation above the mark, and the exception table "+
			"holds %d", reported, len(issueCitationException))
	}

	if len(issueCitationRead(t)) <= reported {
		t.Error("every citation of the tree sits above the mark, so the mark bounds nothing")
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
			name: "a row without a trailing separator blanks the same cell",
			text: []string{
				"| Item | This project today | What must change | Rule | Ruling |",
				"|---|---|---|---|---|",
				"| The ALPN value | Writes `99`. | Done. | 1 | " + issueCitationHash(522),
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
