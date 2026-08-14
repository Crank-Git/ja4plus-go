package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// These tests hold FR-foundation-23. The maintainer ruled the question on 2026-08-14, and
// issue #472 holds the ruling and the reversal path. The ruling picked candidate answer 1
// of #472: `README.md` and `doc.go` state a minimum build toolchain, and `go.mod` does not
// move.
//
// A reader conflates a language version with a toolchain, and the two answer different
// questions. #438 established that `go.mod` states a language version and never a
// toolchain. So each page states which reading it carries, and these tests hold that
// separation.
//
// `TestGoModDeclaresGo124` in `foundation_test.go` holds the other half: the language
// version stays at 1.24, because the ruling declined candidate answer 2.

// minimumBuildToolchain is the toolchain that `README.md` and `doc.go` each name.
//
// It is the oldest toolchain that #472 measured at zero called vulnerabilities of the
// standard library. On 2026-08-14, `govulncheck` v1.6.0 reported 13 for go1.24.13, 0 for
// go1.25.13, 4 for go1.26.5 and 0 for go1.26.6.
//
// **A later toolchain is not a clean toolchain by itself.** go1.26.5 is later than this
// value and it carries four, so the Go 1.26 line takes go1.26.6 or later. That is why this
// constant states a toolchain rather than a major line.
const minimumBuildToolchain = "go1.25.13"

// toolchainStatementPages names each page that FR-foundation-23 binds.
var toolchainStatementPages = []string{"README.md", "doc.go"}

// FR-foundation-23. A page that names no toolchain leaves a user on go1.24.13, and that
// toolchain linked 13 called standard library vulnerabilities on 2026-08-14.
func TestTheToolchainPagesNameTheMinimumBuildToolchain(t *testing.T) {
	for _, page := range toolchainStatementPages {
		content := readRepoFile(t, page)

		if !strings.Contains(content, minimumBuildToolchain) {
			t.Errorf("%s names no %s, and FR-foundation-23 requires the minimum build toolchain", page, minimumBuildToolchain)
		}
	}
}

// FR-foundation-23. A page that names one Go version and no reading reads two ways, and a
// reader then takes the language version for a toolchain floor.
func TestTheToolchainPagesSeparateTheLanguageVersionFromTheToolchain(t *testing.T) {
	for _, page := range toolchainStatementPages {
		content := readRepoFile(t, page)

		if !strings.Contains(content, "language version") {
			t.Errorf("%s states no language version reading, and FR-foundation-23 requires the separation", page)
		}

		if !strings.Contains(content, "toolchain") {
			t.Errorf("%s states no toolchain reading, and FR-foundation-23 requires the separation", page)
		}
	}
}

// FR-foundation-23. The vulnerability database is live, so a count without a date reads as
// a property of the toolchain. The `vuln` job of `.github/workflows/ci.yml` went red at
// `~1.26.5` about one hour after it passed, with no change to the tree.
func TestTheToolchainPagesDateTheVulnerabilityMeasurement(t *testing.T) {
	date := regexp.MustCompile(`\b2026-08-14\b`)

	for _, page := range toolchainStatementPages {
		content := readRepoFile(t, page)

		if !date.MatchString(content) {
			t.Errorf("%s states no date for the govulncheck measurement, and a live database makes an undated count a false claim", page)
		}
	}
}

// FR-foundation-23. The ruling declined candidate answer 2 of #472, which moved the `go`
// directive. So each page states the language version that `go.mod` declares, and a reader
// who consumes the module reads that number rather than the toolchain above.
func TestTheToolchainPagesNameTheGo124LanguageVersion(t *testing.T) {
	// The pattern accepts `Go 1.24` and `go 1.24.0`, because one page names the version in
	// prose and the other names the directive.
	version := regexp.MustCompile(`(?i)go 1\.24(\.\d+)?\b`)

	for _, page := range toolchainStatementPages {
		if !version.MatchString(readRepoFile(t, page)) {
			t.Errorf("%s names no Go 1.24 language version, and the #472 ruling leaves the `go` directive at `go 1.24.0`", page)
		}
	}
}

// FR-foundation-23. `CLAUDE.md` states `Go 1.24 or later`, and that sentence states a
// language version. A reader who takes it for a toolchain floor builds with go1.24.13.
func TestClaudeMdSeparatesTheLanguageVersionFromTheToolchain(t *testing.T) {
	content := readRepoFile(t, "CLAUDE.md")

	if !strings.Contains(content, "Go 1.24 or later") {
		t.Fatal("CLAUDE.md states no Go 1.24 language version, and FR-foundation-1 names it")
	}

	if !strings.Contains(content, minimumBuildToolchain) {
		t.Errorf("CLAUDE.md names no %s, and every page that names a Go version agrees with the #472 ruling", minimumBuildToolchain)
	}

	if !strings.Contains(content, goToolchainRange) {
		t.Errorf("CLAUDE.md names no %s, and that range is the toolchain every CI job builds on", goToolchainRange)
	}
}
