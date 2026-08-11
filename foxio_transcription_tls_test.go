package ja4plus

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The transcription pages record what a FoxIO image states, as numbered rules. These tests
// hold the structural properties of the four pages that issue #16 writes: FR-reference-6,
// FR-reference-7 and FR-reference-10.
//
// A test reads structure, and never a fingerprint value. The value belongs to the image,
// and `.claude/rules/rulings.md` reserves a ruling on a value to the maintainer.

// tlsTranscriptionPagePaths names the four pages that issue #16 writes. Issue #17 writes
// the other five, so this list stays at four until that issue lands.
var tlsTranscriptionPagePaths = []string{
	"docs/specs/foxio/JA4.md",
	"docs/specs/foxio/JA4S.md",
	"docs/specs/foxio/JA4H.md",
	"docs/specs/foxio/JA4X.md",
}

// tlsTranscriptionRulePattern matches the opening of one numbered rule. A rule opens a
// list item, so the page cannot hide a rule inside a paragraph.
var tlsTranscriptionRulePattern = regexp.MustCompile(`(?m)^- \*\*R([0-9]+)\*\* — `)

// tlsTranscriptionImplementationRoots names the directory that each FoxIO reference
// implementation lives in. A rule that names one of these makes a claim about a source.
var tlsTranscriptionImplementationRoots = []string{
	"python/",
	"rust/",
	"wireshark/",
	"zeek/",
}

// tlsTranscriptionCitationPattern matches one `file:line` citation. FR-reference-10 names
// the implementation, the file and the line, in the form `python/ja4/ja4.py:120`. The
// first group holds the path, so a caller reads which implementation the citation reaches.
var tlsTranscriptionCitationPattern = regexp.MustCompile(`([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+\.[A-Za-z]+):[0-9]+`)

// readTLSTranscriptionPage returns the content of one transcription page.
func readTLSTranscriptionPage(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// splitTLSTranscriptionRules returns the text of each numbered rule, in page order. A rule
// runs from its own marker to the marker of the next rule, so the text holds every
// citation line that the rule carries.
func splitTLSTranscriptionRules(page string) []string {
	starts := tlsTranscriptionRulePattern.FindAllStringIndex(page, -1)

	rules := make([]string, 0, len(starts))
	for i, start := range starts {
		end := len(page)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		rules = append(rules, page[start[0]:end])
	}

	return rules
}

// FR-reference-6 — a reader checks a citation in this repository, with no clone of the
// FoxIO repository. A missing page sends that reader back to an image.
func TestTLSTranscriptionPagesExistForEveryImageThisIssueTranscribes(t *testing.T) {
	for _, path := range tlsTranscriptionPagePaths {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", path, err)
			continue
		}

		if info.Size() == 0 {
			t.Errorf("%s holds no content, and FR-reference-6 names one page per image method", path)
		}
	}
}

// FR-reference-7 — each page numbers its rules `R1`, `R2` and onward. A gap or a duplicate
// breaks every citation that names a rule by number.
func TestTLSTranscriptionPagesNumberTheRulesFromR1WithNoGap(t *testing.T) {
	for _, path := range tlsTranscriptionPagePaths {
		page := readTLSTranscriptionPage(t, path)

		matches := tlsTranscriptionRulePattern.FindAllStringSubmatch(page, -1)
		if len(matches) == 0 {
			t.Errorf("%s holds no numbered rule, and FR-reference-7 names R1 and onward", path)
			continue
		}

		for i, match := range matches {
			number, err := strconv.Atoi(match[1])
			if err != nil {
				t.Errorf("%s holds the rule number %q, and FR-reference-7 names a decimal number", path, match[1])
				continue
			}

			if number != i+1 {
				t.Errorf("%s holds R%d at position %d, and FR-reference-7 expects R%d", path, number, i+1, i+1)
			}
		}
	}
}

// FR-reference-10 — a claim about a source without a location is worthless. A rule that
// names a reference implementation carries the file and the line of that same
// implementation.
//
// The test matches each named implementation against its own citation. A rule that named
// the Zeek package and cited only a Python line would otherwise pass, and its Zeek claim
// would still carry no location.
func TestTLSTranscriptionRulesThatNameAnImplementationCarryAFileAndALine(t *testing.T) {
	for _, path := range tlsTranscriptionPagePaths {
		page := readTLSTranscriptionPage(t, path)

		for i, rule := range splitTLSTranscriptionRules(page) {
			cited := map[string]bool{}
			for _, match := range tlsTranscriptionCitationPattern.FindAllStringSubmatch(rule, -1) {
				for _, root := range tlsTranscriptionImplementationRoots {
					if strings.HasPrefix(match[1], root) {
						cited[root] = true
					}
				}
			}

			for _, root := range tlsTranscriptionImplementationRoots {
				if strings.Contains(rule, root) && !cited[root] {
					t.Errorf("%s R%d names %s and carries no %s file:line citation, and FR-reference-10 names one", path, i+1, root, root)
				}
			}
		}
	}
}
