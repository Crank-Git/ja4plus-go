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
// tree, because the issue-namespace rule binds every file.
// `docs/specs/features/11-foxio-reference.md` numbers this file as FR-reference-32 through
// FR-reference-34, FR-reference-38, FR-reference-38a, and FR-reference-40 through
// FR-reference-44. It names FR-reference-39 in no row, because #759 withdrew it.
//
// # This guard bounds no number, and #759 removed the bound
//
// The guard held a hand-maintained constant until 2026-08-16 UTC. That constant recorded the
// highest number the tracker had allocated, and it failed a bare citation above that number.
// **#759 deleted it, because a person raised it by hand and it went stale within the hour.**
//
// Three measurements decided the question, each taken on 2026-08-16 UTC.
//
//   - **The constant made this file the second most-edited file of the repository.** It sits
//     in 43 of the last 300 commits of `dev`, ahead of `CHANGELOG.md`.
//   - **The tracker allocates numbers without a gap.** It reported 760 issues and pull
//     requests together, and 760 as the highest number. So every number at or below the
//     highest one already resolves to something here, and a bound reports a number above it
//     alone. **The gapless property is the measurement that matters, and the count is dated
//     evidence for it.** The same two commands reported 763 and 763 later in the same
//     session, after this member and two siblings each opened a pull request. **A number
//     that moves while one member works is the cost this change removes**, and the gapless
//     property holds at each reading.
//   - **The bound reported no typo in its whole life.** The deleted comment recorded 39
//     re-measurements of the mark, measured with `grep -c "re-measured the mark"`. Every
//     citation that reddened the guard named an issue or a pull request that the tracker
//     allocated minutes later, so each report named the author's own fresh number. **The
//     measured precision of the bound is zero.**
//
// **A typo now reaches the tree, and this file accepts that cost.** A number that names the
// wrong issue of this repository sits inside the allocated range, so no bound ever reported
// it and no bound ever could. A reader who follows the number reaches the wrong issue, and
// the tracker corrects the reader in one lookup. **A citation that names the wrong repository
// is the expensive failure**, and `TestEveryPortIssueCitationCarriesARecordedForm` still
// reports it.
//
// **A person sweeps the tree on demand**, and no gate runs the sweep:
//
//	git grep -o -E '(^|[^0-9A-Za-z_/])#[0-9]{1,4}' | grep -o '#[0-9]*' | sort -u
//
// #759 is the reversal path. A change that restores a bound states which typo it caught.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// issueCitationHash returns the citation token for the number.
//
// This file is in scope of its own guard, so a literal malformed fixture below would report
// itself. Each malformed fixture composes the token instead, and it renders the bytes the
// fixture describes.
func issueCitationHash(number int) string {
	return "#" + strconv.Itoa(number)
}

// issueCitationExtension names the file extension of a file this guard reads.
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
// repair can reach. #87 measured it.
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

// This guard excluded one file until 2026-08-16 UTC, and #758 removed that file.
//
// `docs/specs/foxio/port-register.md` was a verbatim copy of a section of the port's
// specification, so a bare number in it named the port and no change of this repository
// could repair a hit. #758 removed the copy, so the guard now reads every file it walks and
// it excludes none.
//
// **The `Ruling` column of the register in `docs/specs/spec.md` still carries a local
// rule**, and this guard needs no exclusion for it. The guard matches
// `issueCitationMalformedPortForm` alone, which names the port beside a number. A bare
// number of that column matches no such shape.

// issueCitationMalformedPortForm matches a shape that names the port beside a number, and
// that no recorded form holds. A reader of one of these cannot tell which repository the
// number names, because the shape names the port and the number stands bare.
var issueCitationMalformedPortForm = regexp.MustCompile(
	`(?i)(?:\bja4plus\s+#|\bja4plus/#|\bthe\s+port's\s+#|\bport\s+#)([0-9]+)`)

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

// FR-reference-33 and FR-reference-34 — a citation of an issue of the port carries a
// recorded form.
//
// A shape that names the port beside a bare number tells a reader two things at once. The
// recorded forms carry the repository into the citation itself, so a reader who reads the
// number alone still reaches the right repository.
//
// **This test is the whole guard now**, because #759 removed the bound that the deleted
// constant held. It reports the failure that costs a reader the most: a number that names
// the wrong repository.
func TestEveryPortIssueCitationCarriesARecordedForm(t *testing.T) {
	for _, file := range issueCitationFile(t) {
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

// FR-reference-34 — the detector reads each recorded shape, and it reports each malformed
// shape.
//
// The tree-wide test above reports nothing on a clean tree, so it proves nothing about the
// detector on its own. These fixtures separate the two sets, and they redden when a later
// edit widens or narrows the pattern.
func TestTheMalformedPortFormDetectorReadsEachRecordedShape(t *testing.T) {
	line := []struct {
		name   string
		text   string
		report bool
	}{
		{
			name:   "the table-cell port form carries the repository",
			text:   "The port half is `Crank-Git/ja4plus#215`, and it is closed.",
			report: false,
		},
		{
			name:   "the sentence port form carries the repository",
			text:   "The port's issue #533 settled the vocabulary.",
			report: false,
		},
		{
			name:   "the short sentence port form carries the repository",
			text:   "Port issue #594 records that.",
			report: false,
		},
		{
			name:   "a port issue URL carries the repository",
			text:   "See <https://github.com/Crank-Git/ja4plus/issues/598> for the port half.",
			report: false,
		},
		{
			// The maintainer ruled this form on 2026-08-14, and #525 carries the ruling into
			// `.claude/rules/rulings.md`. The possessive takes the port as its antecedent in
			// the same sentence, so the reader reaches the right repository.
			name:   "the anaphoric possessive form carries the repository",
			text:   "The port decided it as D4 of its issue #231 on 2026-08-08.",
			report: false,
		},
		{
			name:   "a bare number of this repository reports nothing",
			text:   "Issue #127 holds the question.",
			report: false,
		},
		{
			name:   "a bare number above the tracker reports nothing now",
			text:   "Issue #9999 holds the question.",
			report: false,
		},
		{
			name:   "the bare port shape reports",
			text:   "The port half is port " + issueCitationHash(215) + ", and it is closed.",
			report: true,
		},
		{
			name:   "the bare repository-name shape reports",
			text:   "The port half is ja4plus " + issueCitationHash(215) + ", and it is closed.",
			report: true,
		},
		{
			name:   "the slashed repository-name shape reports",
			text:   "The port half is ja4plus/" + issueCitationHash(215) + ", and it is closed.",
			report: true,
		},
		{
			name: "the bare possessive shape reports",
			text: "The port half is the port's " + issueCitationHash(215) +
				", and it is closed.",
			report: true,
		},
	}

	for _, one := range line {
		t.Run(one.name, func(t *testing.T) {
			got := issueCitationMalformedPortForm.FindString(one.text) != ""

			if got != one.report {
				t.Errorf("the detector reports %v of %q, and it must report %v",
					got, one.text, one.report)
			}
		})
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
}

// FR-reference-43 and FR-reference-44 named the copied page, and #758 removed that page on
// 2026-08-16 UTC. The test that read the exclusion went out with it.
//
// **An empty exclusion map makes that test pass over zero entries**, so it would report a
// rule it no longer reads. `TestTheTreeHoldsNoMirroredCopyOfThePortRegister` in
// `deviations_test.go` holds the removal instead, and it fails when the copy returns.

// FR-reference-38 — the guard reads no tracker, and it bounds no number.
// FR-reference-38a — the guard holds no high-water mark, and this test reads its own source.
//
// A guard that reads a tracker fails when the network fails, and it then reports a defect
// that the tree does not hold. #759 read that cost against the bound it removed, and it
// declined the tracker.
//
// The second half of this test holds the decision of #759. A batch gate raised the deleted
// constant by reflex for 43 commits, so a later gate can restore it without reading why it
// went. **A restored bound reddens this test**, and the author then states which typo the
// bound caught.
func TestTheIssueCitationGuardReadsNoTrackerAndBoundsNoNumber(t *testing.T) {
	const source = "issue_citation_namespace_test.go"

	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("%s does not open: %v", source, err)
	}

	text := string(content)

	// Each name below is composed, because this test reads its own source. A literal here
	// would match itself and report the guard it holds.
	for _, barred := range []string{"net/" + "http", "os/" + "exec", "exec." + "Command"} {
		if strings.Contains(text, barred) {
			t.Errorf("the guard names %q, and a guard that reads a tracker fails with the "+
				"network", barred)
		}
	}

	if strings.Contains(text, "issueCitation"+"HighWaterMark") {
		t.Error("the guard holds a high-water mark again, and #759 removed it because a " +
			"person raised it by hand in 43 of 300 commits.\n\tA change that restores a " +
			"bound states which typo the bound caught.")
	}
}
