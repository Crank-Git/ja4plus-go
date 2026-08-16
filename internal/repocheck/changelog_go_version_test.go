package repocheck

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// This test holds the Go language floor that `## [Unreleased]` of `CHANGELOG.md` states.
//
// #725 moved the language version to Go 1.25 on 2026-08-15 UTC, and the section still read
// `Go 1.24`. **No guard read that sentence**, so the defect passed every check and reached
// the batch #742 documentation round. #752 records it.
//
// `changelog_counts_freshness_test.go` reads the preamble of the same section. It reads the
// first paragraph alone, and the floor sentence sits in `### Changed` at the end of the
// section. So that guard could never reach this sentence.
//
// **This test reads `## [Unreleased]` alone, and it never reads `## [v1.0.0]`.** The
// `v1.0.0` section is a release record, and it states `Go 1.24 or later` because that floor
// was true at `v1.0.0`. `.claude/rules/rulings.md` states that a dated record names its own
// base, so a guard that read the whole file would demand a false repair of that record.
//
// **The expected version reads `go.mod`, and no constant of this file states it.** A guard
// that hard-coded the number would need the same hand edit that it exists to catch.
//
// **A release of this project keeps `## [Unreleased]`, and it adds a section beside it.**
// `## [v1.0.0]` states that reading: it holds the release position, and `## [Unreleased]`
// holds the per-issue log of the same work. So a release moves no sentence out of the
// section that these tests read.

// changelogGoDirective reads the language version that `go.mod` declares.
var changelogGoDirective = regexp.MustCompile(`(?m)^go (1\.\d+)(\.\d+)?$`)

// changelogUnreleasedSection returns the `## [Unreleased]` section of the changelog, with
// each run of whitespace collapsed to one space.
//
// The section ends at the next version heading. A sentence of the section wraps across
// lines, so the caller collapses the whitespace before it matches. The epic #441
// cross-member review read the same file by line and undercounted a wrapped paragraph.
func changelogUnreleasedSection(t *testing.T) string {
	t.Helper()

	changelog := readRepoFile(t, changelogFile)

	start := strings.Index(changelog, changelogUnreleasedHeading)
	if start < 0 {
		t.Fatalf("%s holds no %q section", changelogFile, changelogUnreleasedHeading)
	}

	body := changelog[start+len(changelogUnreleasedHeading):]

	if end := strings.Index(body, "\n## ["); end >= 0 {
		body = body[:end]
	}

	return strings.Join(strings.Fields(body), " ")
}

// TestTheUnreleasedSectionStatesTheGoFloorThatGoModDeclares reads the floor sentence of
// `## [Unreleased]` against the `go` directive.
//
// **The test reads the floor sentence, and it reads no history clause.** The section also
// records the floor that an earlier release needed, and that clause names an older version
// on purpose. A guard that refused every older number would fail on the true history.
func TestTheUnreleasedSectionStatesTheGoFloorThatGoModDeclares(t *testing.T) {
	directive := changelogGoDirective.FindStringSubmatch(readRepoFile(t, "go.mod"))
	if directive == nil {
		t.Fatalf("go.mod declares no language version")
	}

	sentence := fmt.Sprintf("The module needs Go %s or later", directive[1])

	if !strings.Contains(changelogUnreleasedSection(t), sentence) {
		t.Errorf("the %s section of %s states no %q sentence, and go.mod declares the %s language version",
			changelogUnreleasedHeading, changelogFile, sentence, directive[1])
	}
}

// TestTheUnreleasedSectionRecordsEveryDependencyOfGoMod reads each module requirement of
// `go.mod` against `## [Unreleased]`.
//
// **A dependency move that the section never records leaves a consumer to find it at the
// upgrade.** #752 measured that gap: four moves landed in one cycle, and the section
// recorded none of them. The `gopacket` move repairs a decoder panic under
// `GHSA-6h9g-cjv3-pg2c`, so a consumer who reads no entry misses a security repair.
//
// **The test reads the direct requirements alone.** An indirect requirement carries no
// entry, because a consumer of this module never names it.
func TestTheUnreleasedSectionRecordsEveryDependencyOfGoMod(t *testing.T) {
	requirement := regexp.MustCompile(`(?m)^\t(\S+) (v\S+)$`)

	// The section writes each module path in a code span. This guard reads the content and
	// never the formatting, so it removes the code-span marker before it matches.
	section := strings.ReplaceAll(changelogUnreleasedSection(t), "`", "")

	for _, module := range requirement.FindAllStringSubmatch(readRepoFile(t, "go.mod"), -1) {
		entry := module[1] + " to " + module[2]

		if !strings.Contains(section, entry) {
			t.Errorf("the %s section of %s records no %q, and go.mod requires that version",
				changelogUnreleasedHeading, changelogFile, entry)
		}
	}
}
