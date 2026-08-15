package ja4plus

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"
)

// `.claude/rules/ste.md` `## This project writes US English` states the rule, and no check
// of this repository enforced it for this word until #697. `.golangci.yml` sets
// `locale: US`, and `misspell` at that locale reads a Go file alone and flags neither
// spelling of this word. So round 48 of the `## Changelog` of `docs/specs/spec.md`
// converted it once, and the tree grew the British form again.
//
// This guard names one word. A guard over every British spelling would fail on the shared
// section heading that 17 feature files carry, and `.claude/rules/ste.md`
// `## This project writes US English` holds that heading until one change converts every
// file. `misspell` at `locale: US` bars this comment from naming the heading.
//
// Issue #697 is the reversal path.

// theBritishAcknowledgmentWord is the spelling this project declines.
//
// The two parts join at run time, so this file holds no literal occurrence of the word and
// the guard does not fail on itself. `theBehaviorWord` of `rule_file_policies_test.go`
// records the same trap.
const theBritishAcknowledgmentWord = "acknowledg" + "ement"

// theVerbatimCopyPage is the one tracked page that no change of this repository may edit.
//
// `docs/specs/foxio/README.md` states that the page is a verbatim copy of a section of the
// port's specification, and `.claude/rules/rulings.md` `## A citation names its repository`
// states `Never edit the copy.` The page carries British prose outside a code span today,
// so a hit there would report a defect that no repair reaches.
const theVerbatimCopyPage = "docs/specs/foxio/port-register.md"

// TestNoTrackedFileWritesTheBritishAcknowledgmentSpelling fails when a tracked file writes
// the British spelling as prose.
//
// It reads the whole index rather than the files one batch opens, because the rule binds
// every file and a reader enforces it nowhere else.
func TestNoTrackedFileWritesTheBritishAcknowledgmentSpelling(t *testing.T) {
	// A build environment that holds no git cannot read the index, and a failure there
	// would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "-z")

	output, err := command.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	for _, path := range strings.Split(strings.TrimRight(string(output), "\x00"), "\x00") {
		if path == "" || path == theVerbatimCopyPage {
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			// The index names a path that the worktree does not hold, so this run reads
			// no content and it reports no defect.
			continue
		}

		// A file that holds no text carries no prose, and a byte of it can match the word
		// by accident.
		if !utf8.Valid(content) {
			continue
		}

		for number, line := range strings.Split(string(content), "\n") {
			if !holdsTheBritishAcknowledgmentSpelling(line) {
				continue
			}

			t.Errorf(
				"%s:%d writes %q as prose, and `.claude/rules/ste.md` `## This project writes US English` states the US form `acknowledgment`.\n"+
					"A verbatim quotation keeps the spelling of its source, and this guard accepts one inside a code span or a block quote.\n"+
					"Issue #697 is the reversal path.\n%s",
				path, number+1, theBritishAcknowledgmentWord, line,
			)
		}
	}
}

// holdsTheBritishAcknowledgmentSpelling reports whether one line writes the British
// spelling as prose.
//
// It returns false for an occurrence inside a code span and for a block-quote line,
// because `.claude/rules/ste.md` `## What is verbatim, and never rewritten` holds a
// quotation and an identifier unchanged. Round 48 measured that every British spelling it
// declined to convert sits inside a code span.
func holdsTheBritishAcknowledgmentSpelling(line string) bool {
	if strings.HasPrefix(strings.TrimSpace(line), ">") {
		return false
	}

	// A backtick opens and closes a code span in turn, so an odd segment sits inside one.
	for index, segment := range strings.Split(line, "`") {
		if index%2 == 1 {
			continue
		}

		if strings.Contains(strings.ToLower(segment), theBritishAcknowledgmentWord) {
			return true
		}
	}

	return false
}
