package repocheck

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/deviations"
)

// The register is the tracked file `testdata/deviations.json`. It holds one entry for
// each accepted difference from a FoxIO value. These tests hold FR-reference-19 through
// FR-reference-24, FR-reference-27 and FR-reference-28.
//
// The register is empty today, because no conformance run has measured a deviation. An
// empty register passes every content test without exercising the reader, so the reader
// tests below run over fixture entries that this file holds. #33 builds the conformance
// suite, and FR-reference-25 and FR-reference-26 move there with it.
//
// The reader stays in the test build. `v1.0.0` freezes the exported API, and the register
// serves the test suite alone.

func TestTheRegisterFileExists(t *testing.T) {
	if _, err := os.Stat(deviations.RegisterFile); err != nil {
		t.Fatalf("FR-reference-19 requires %s: %v", deviations.RegisterFile, err)
	}
}

func TestGitTracksTheRegisterFile(t *testing.T) {
	// A build environment that holds no git cannot answer the question, and a failure
	// there would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "--error-unmatch", deviations.RegisterFile)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FR-reference-19 requires git to track %s: %v\n%s", deviations.RegisterFile, err, output)
	}
}

func TestTheRegisterParsesAndEveryEntryHoldsEveryField(t *testing.T) {
	entries := readDeviationRegister(t)

	t.Logf("the register holds %d entries", len(entries))
}

func TestEveryRulingOfTheRegisterNamesAnIssue(t *testing.T) {
	// The check reads the form of the value and reaches no network. A call to the
	// GitHub API fails offline and fails in CI without a token, so a unit test that
	// made one would report a defect that the register does not hold.
	//
	// The reader already declines a malformed ruling, so this loop repeats that check
	// over the tracked file. The repeat is deliberate: FR-reference-27 names a test of
	// its own, and a reader who moves the form check out of the reader still has one.
	// `TestTheReaderRejectsAMalformedRegister` holds the cases that prove the check.
	for _, entry := range readDeviationRegister(t) {
		if !deviations.RulingPattern.MatchString(entry.Ruling) {
			t.Errorf("entry %q names the ruling %q, and FR-reference-23 requires an issue", entry.Key, entry.Ruling)
		}
	}
}

func TestTheRegisterHoldsEachKeyOnce(t *testing.T) {
	// This test reads the keys of the tracked file and never `readDeviationRegister`. The
	// reader declines a second entry for one key, so a test that read the register through
	// it could never reach this loop and could never fail. FR-reference-31 names a test of
	// its own, and a reader who moves the check out of the reader still has one.
	content, err := os.ReadFile(deviations.RegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", deviations.RegisterFile, err)
	}

	var raw []struct {
		Key string `json:"key"`
	}

	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatalf("decode %s: %v", deviations.RegisterFile, err)
	}

	first := make(map[string]int, len(raw))

	for index, entry := range raw {
		if held, twice := first[entry.Key]; twice {
			t.Errorf("entry %d and entry %d hold the key %q, and FR-reference-31 gives one entry to one comparison",
				held, index, entry.Key)

			continue
		}

		first[entry.Key] = index
	}

	t.Logf("the register holds %d entries and %d keys", len(raw), len(first))
}

func TestTheSchemaDocumentStatesTheMeaningOfTheMiddleKeyPart(t *testing.T) {
	document := readRepoFile(t, "testdata/README.md")

	// FR-reference-29 gives the middle part two meanings, one for each vector set. A reader
	// cannot tell a frame number from a stream number, because both are small integers, so
	// the schema document must name both.
	for _, wanted := range []string{"stream number", "frame number"} {
		if !strings.Contains(document, wanted) {
			t.Errorf("testdata/README.md does not name the %s, and FR-reference-29 states both meanings of the middle key part", wanted)
		}
	}
}

func TestTheSchemaDocumentNamesEveryRegisterField(t *testing.T) {
	// A JSON file carries no comment, so the schema lives beside the register.
	document := readRepoFile(t, "testdata/README.md")

	for _, field := range deviations.FieldNames {
		if !strings.Contains(document, "`"+field+"`") {
			t.Errorf("testdata/README.md does not name the field %q", field)
		}
	}
}

// #758 removed the mirrored copy of the port's register on 2026-08-16 UTC, and this test
// holds the removal.
//
// A whole-page copy of the port's material restates every value that page holds.
// `.claude/rules/ste.md` `### A value of another repository is cited, and never mirrored`
// states the rule that bars it. A later change that restores the copy restores the drift
// check, the local bare-number namespace and the maintenance cost with it, so the guard
// reports the return of the path rather than the return of the text.
//
// Issue #758 is the reversal path. A reversal removes this test and it states the reason.
func TestTheTreeHoldsNoMirroredCopyOfThePortRegister(t *testing.T) {
	const removedPage = "docs/specs/foxio/port-register.md"

	if _, err := os.Stat(removedPage); err == nil {
		t.Errorf("%s exists, and #758 removed it on 2026-08-16 UTC. Cite the port at the tag %s instead, under `.claude/rules/rulings.md` `## A citation names its repository`",
			removedPage, portReadVersion)
	}
}
