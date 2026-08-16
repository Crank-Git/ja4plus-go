package ja4plus

import (
	"strings"
	"testing"
)

// The release workflow reads the release notes from `CHANGELOG.md`, and a tag whose section
// the file does not hold stops the release.
//
// **The `v1.1.0` release job failed at the step `Read the release notes from the CHANGELOG`
// on 2026-08-16 UTC.** Run `31930896325` reported
// `CHANGELOG.md holds no section for v1.1.0, and FR-release-39 reads one`, and the job
// stopped before GoReleaser ran. So no artifact reached the release, and the tag stayed
// valid on the module proxy. Issue #779 holds the recovery.
//
// **The pre-release constants name the tag the maintainer pushes next**, and #767 moved them
// to `v1.1.0` in batch #768. This guard would have failed in that batch, before any tag
// existed, because the file held no `## [v1.1.0]` section on that day.
//
// **The expected heading reads the constant, and no constant of this file states a tag.**
// `.claude/rules/ste.md` `### Two permitted restatements, and one date rule` permits a
// restatement that a test derives from the owner, and #752 built two `CHANGELOG.md` guards
// that way. A guard that held the tag as a literal would need the hand edit that it exists
// to catch.

// changelogReleaseSectionBody returns the body of the `## [<tag>]` section of the changelog.
//
// It returns an empty string when the file holds no such heading. The section ends at the
// next line that opens a heading of the same level, which is the rule that the `awk` program
// of `.github/workflows/release.yml` reads.
func changelogReleaseSectionBody(changelog, tag string) string {
	heading := "## [" + tag + "]"

	var body []string

	inside := false

	for _, line := range strings.Split(changelog, "\n") {
		if strings.HasPrefix(line, heading) {
			inside = true
			continue
		}

		if inside && strings.HasPrefix(line, "## ") {
			break
		}

		if inside {
			body = append(body, line)
		}
	}

	return strings.Join(body, "\n")
}

// TestTheChangelogHoldsAReleaseSectionForEveryReleaseTagConstant reads each tag constant
// against the changelog.
//
// The case fails when the file holds no section for the tag, and it fails when that section
// holds no text. The release step writes the notes to a file and it stops on an empty file,
// so an empty section reaches the same failure that this guard exists to catch.
func TestTheChangelogHoldsAReleaseSectionForEveryReleaseTagConstant(t *testing.T) {
	changelog := readRepoFile(t, changelogFile)

	for _, declaration := range releaseTagConstants {
		tag := releaseConstantValue(t, declaration)

		body := changelogReleaseSectionBody(changelog, tag)
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s holds no %q section with text, and %s in %s names the tag %s. "+
				"The release workflow reads the notes of that section, and it stops without them.",
				changelogFile, "## ["+tag+"]", declaration.name, declaration.file, tag)
		}
	}
}
