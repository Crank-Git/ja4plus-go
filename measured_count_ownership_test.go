package ja4plus

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// `.claude/rules/ste.md` `## One document owns each measured count` states the rule these
// tests hold. #757 earned it from a measurement of the closed backlog on 2026-08-16 UTC:
// of 365 closed issues, 67 repaired a sentence, a citation, a count or a term, and 46 of
// the 67 name an earlier issue as their cause.
//
// The mechanism is restatement. A count that three documents state costs three repairs
// when the measurement moves, and the third repair becomes a separate issue when a later
// reader finds it. So the rule gives each measured count one owner, and every other
// document cites that owner.
//
// These tests hold the rule for the counts that `ownedCounts` names, and for no other
// count. A guard over every number of the tree would fail on a dated record, because a
// record states what one run measured on one date and no change edits it. The registry
// therefore names each record surface, and a later batch adds an entry for the class it
// converts.
//
// #752 built two `CHANGELOG.md` guards on this principle in batch #760, and each one
// derives its expected value from `go.mod` rather than from a literal. These tests derive
// the fuzz target count from the tree for the same reason.

// ownedCountRestatement names one document that states an owned count, and the test that
// derives the expected value from the owner.
//
// `.claude/rules/ste.md` `## Two permitted restatements, and one date rule` permits a
// restatement under a guard, and it permits no other one.
type ownedCountRestatement struct {
	// file is the tracked path that states the value.
	file string
	// guard is the test function that fails when the statement and the owner disagree.
	guard string
}

// ownedCountRecord names one surface whose statements are dated records.
//
// A record states what one run measured on one date, so a later measurement never
// falsifies it and no change edits it. `.claude/rules/ste.md`
// `## Two permitted restatements, and one date rule` states that reading.
type ownedCountRecord struct {
	// file is the tracked path that holds the records.
	file string
	// fromHeading names the section where the records start. An empty value makes the
	// whole file a record surface.
	fromHeading string
}

// ownedCount names one measured count, the file that owns its value, and every surface
// that the rule permits to state it.
type ownedCount struct {
	// name reads as the count a failure message names.
	name string
	// owner is the tracked path that holds the value. It is empty when the command owns
	// the count, which is rank 3 of the rule.
	owner string
	// command reproduces the value.
	command string
	// derive returns the value that the tree holds now.
	derive func(t *testing.T) int
	// records names each surface whose statements are dated records.
	records []ownedCountRecord
	// restatements names each live statement that a guard holds fresh.
	restatements []ownedCountRestatement
	// patterns match one statement of the value. A hit outside a record and outside a
	// restatement is the defect.
	patterns []*regexp.Regexp
}

// ownedCounts is the registry. It names the fuzz target count today, and a batch that
// converts a class adds the entry for that class.
var ownedCounts = []ownedCount{
	{
		name:    "the fuzz target count",
		owner:   "",
		command: `grep -rn --include='*_test.go' '^func Fuzz' .`,
		derive:  deriveFuzzTargetCount,
		records: []ownedCountRecord{
			// Every entry of the changelog records one release or one batch.
			{file: "CHANGELOG.md"},
			// The `## Changelog` section records one round of the specification. Every
			// section above it is live, and the `## Terms` table sits above it.
			{file: "docs/specs/spec.md", fromHeading: "## Changelog"},
			// Each statement of this page records one dated run of Epic 6 or one
			// accepted criterion of it. So this guard does not reach a new live
			// statement in this file, and a reader of that file reaches the rule
			// through `docs/specs/spec.md` `## Terms`.
			{file: "docs/specs/features/06-fuzz-testing.md"},
		},
		restatements: nil,
		patterns: []*regexp.Regexp{
			// `holds 15 targets`, `fuzzes 15 targets in turn`, `runs 15 targets`.
			regexp.MustCompile(`(?i)\b(?:holds|fuzzes|runs|covers|names)\s+(?:about\s+)?[0-9]+\s+(?:fuzz\s+)?targets?\b`),
			// The `## Terms` row of `docs/specs/spec.md` read `**The tree holds 15**`,
			// and the word `targets` sits in the row heading rather than in the sentence.
			regexp.MustCompile(`(?i)fuzz target.*\bthe tree holds\s+\*{0,2}[0-9]+`),
		},
	},
}

// theOwnedCountRegistryFile holds the registry, so it holds each pattern as a literal.
// A scan of it would report the pattern source as a defect.
const theOwnedCountRegistryFile = "measured_count_ownership_test.go"

// deriveFuzzTargetCount returns the count of fuzz targets that the tree holds.
//
// It reads every tracked test file, because `make fuzz` reads the target list from the
// tree with `go test -list '^Fuzz'`. So a new target moves the value without an edit to
// any document.
func deriveFuzzTargetCount(t *testing.T) int {
	t.Helper()

	count := 0

	for _, path := range trackedFilesForOwnedCounts(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}

		for _, line := range strings.Split(readTrackedFile(path), "\n") {
			if strings.HasPrefix(line, "func Fuzz") {
				count++
			}
		}
	}

	return count
}

// trackedFilesForOwnedCounts returns every path of the git index. It skips the test when
// the environment holds no git, because a build environment without git reads no index
// and a failure there would report a defect the repository does not hold.
func trackedFilesForOwnedCounts(t *testing.T) []string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	output, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	var paths []string

	for _, path := range strings.Split(strings.TrimRight(string(output), "\x00"), "\x00") {
		if path != "" {
			paths = append(paths, path)
		}
	}

	return paths
}

// readTrackedFile returns the text of a tracked path. It returns an empty string for a
// path the worktree does not hold, and for a file that holds no text.
func readTrackedFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	if !utf8.Valid(content) {
		return ""
	}

	return string(content)
}

// liveTextOfOwnedCount returns the part of a file that the entry treats as a live
// statement. It returns an empty string when the whole file is a record surface.
func liveTextOfOwnedCount(count ownedCount, path, content string) string {
	for _, record := range count.records {
		if record.file != path {
			continue
		}

		if record.fromHeading == "" {
			return ""
		}

		if start := strings.Index(content, record.fromHeading); start >= 0 {
			content = content[:start]
		}
	}

	return content
}

func TestNoDocumentStatesAMeasuredCountThatTheRegistryOwns(t *testing.T) {
	paths := trackedFilesForOwnedCounts(t)

	for _, count := range ownedCounts {
		held := count.derive(t)

		for _, path := range paths {
			if path == theOwnedCountRegistryFile {
				continue
			}

			if !strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, ".go") {
				continue
			}

			if statesTheOwnedCount(count, path) {
				continue
			}

			live := liveTextOfOwnedCount(count, path, readTrackedFile(path))

			for number, line := range strings.Split(live, "\n") {
				for _, pattern := range count.patterns {
					if !pattern.MatchString(line) {
						continue
					}

					t.Errorf(
						"%s:%d states %s, and `.claude/rules/ste.md` `## One document owns each measured count` gives that count %s.\n"+
							"Cite the owner and state no number. Reproduce the value with: %s\n"+
							"The tree holds %d today.\n%s",
						path, number+1, count.name, ownerSentenceOfOwnedCount(count),
						count.command, held, strings.TrimSpace(line),
					)
				}
			}
		}
	}
}

// statesTheOwnedCount reports whether the registry permits this path to state the value.
func statesTheOwnedCount(count ownedCount, path string) bool {
	if path == count.owner {
		return true
	}

	for _, restatement := range count.restatements {
		if restatement.file == path {
			return true
		}
	}

	return false
}

// ownerSentenceOfOwnedCount names the owner of a count for a failure message.
func ownerSentenceOfOwnedCount(count ownedCount) string {
	if count.owner == "" {
		return "the command as its owner, and no document at all"
	}

	return "the owner " + count.owner
}

func TestEachEntryOfTheOwnedCountRegistryDerivesAPositiveCount(t *testing.T) {
	// A derivation that stops matching the tree returns zero, and the ownership test above
	// then reports a true count of zero in every message. This case fails instead.
	for _, count := range ownedCounts {
		if held := count.derive(t); held <= 0 {
			t.Errorf("the derivation of %s reports %d, and the command %s reports the value",
				count.name, held, count.command)
		}
	}
}

func TestEachEntryOfTheOwnedCountRegistryNamesALiveTarget(t *testing.T) {
	// A record file that a later change renames leaves an exclusion that covers nothing,
	// and the ownership test above then reports a defect at a path it no longer reads.
	// The same reading covers an owner and a named guard.
	tracked := make(map[string]bool)
	for _, path := range trackedFilesForOwnedCounts(t) {
		tracked[path] = true
	}

	for _, count := range ownedCounts {
		if count.command == "" {
			t.Errorf("the entry for %s names no command, and a reader reproduces the value with one", count.name)
		}

		if count.owner != "" && !tracked[count.owner] {
			t.Errorf("the entry for %s names the owner %s, and the index holds no such path", count.name, count.owner)
		}

		for _, record := range count.records {
			if !tracked[record.file] {
				t.Errorf("the entry for %s names the record surface %s, and the index holds no such path",
					count.name, record.file)
			}

			if record.fromHeading == "" {
				continue
			}

			if !strings.Contains(readTrackedFile(record.file), record.fromHeading) {
				t.Errorf("the entry for %s names the record heading %q of %s, and that file holds no such heading",
					count.name, record.fromHeading, record.file)
			}
		}

		for _, restatement := range count.restatements {
			if !tracked[restatement.file] {
				t.Errorf("the entry for %s names the restatement %s, and the index holds no such path",
					count.name, restatement.file)
			}

			if !holdsTheOwnedCountGuard(t, restatement.guard) {
				t.Errorf("the entry for %s names the guard %s, and no tracked test file declares it",
					count.name, restatement.guard)
			}
		}
	}
}

// holdsTheOwnedCountGuard reports whether a tracked test file declares the named test.
func holdsTheOwnedCountGuard(t *testing.T, guard string) bool {
	t.Helper()

	declaration := "func " + guard + "("

	for _, path := range trackedFilesForOwnedCounts(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}

		if strings.Contains(readTrackedFile(path), declaration) {
			return true
		}
	}

	return false
}

func TestTheWritingStandardStatesTheMeasuredCountRule(t *testing.T) {
	// The registry holds the rule for the counts it names, and the rule file holds the
	// rule for every other count. A later edit that removes the section leaves the tests
	// above with nothing to cite.
	standard := readRepoFile(t, ".claude/rules/ste.md")

	for _, heading := range []string{
		"## One document owns each measured count",
		"### One owner, and every other document cites it",
		"### Two permitted restatements, and one date rule",
		"### A value of another repository is cited, and never mirrored",
	} {
		if !strings.Contains(standard, heading) {
			t.Errorf(".claude/rules/ste.md holds no %q, and %s cites that heading",
				heading, theOwnedCountRegistryFile)
		}
	}
}
