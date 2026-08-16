package repocheck

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The transcription pages turn a FoxIO image into numbered prose, so that a ruling cites a
// line rather than a picture. These tests hold the structural requirements of
// `docs/specs/features/11-foxio-reference.md` for the five pages that issue #17 writes.
//
// A test here checks structure and never a fingerprint value. The page records what each
// source states, and `.claude/rules/rulings.md` reserves every ruling to the maintainer.

// foxioTCPTranscriptionPages names the page that issue #17 writes for each image.
var foxioTCPTranscriptionPages = map[string]string{
	"JA4L.png":   "docs/specs/foxio/JA4L.md",
	"JA4T.png":   "docs/specs/foxio/JA4T.md",
	"JA4SSH.png": "docs/specs/foxio/JA4SSH.md",
	"JA4D.png":   "docs/specs/foxio/JA4D.md",
	"JA4D6.png":  "docs/specs/foxio/JA4D6.md",
}

// foxioTCPTranscriptionRuleStart matches the opening of one numbered rule.
var foxioTCPTranscriptionRuleStart = regexp.MustCompile(`(?m)^- \*\*R([0-9]+)\*\* — `)

// foxioTCPTranscriptionCitation matches one `file:line` citation of a reference
// implementation. The four path prefixes are the four implementation directories of the
// FoxIO repository.
var foxioTCPTranscriptionCitation = regexp.MustCompile(
	"`(?:zeek|wireshark|rust|python)/[^`]+:[0-9]+(?:[-,][0-9]+)*`",
)

// foxioTCPTranscriptionImplementation matches the name of one reference implementation.
var foxioTCPTranscriptionImplementation = regexp.MustCompile(`\b(?:Zeek|Wireshark|Rust|Python)\b`)

// foxioTCPTranscriptionImageOnlyMarker is the sentence that FR-reference-9 requires of a
// rule that the image alone states.
const foxioTCPTranscriptionImageOnlyMarker = "The image alone states this rule."

// foxioTCPTranscriptionWhitespace matches one run of whitespace. A rule wraps over several
// lines, so a check that matched raw text would miss a sentence that a line break splits.
var foxioTCPTranscriptionWhitespace = regexp.MustCompile(`\s+`)

// foxioTCPTranscriptionRule holds one parsed rule of one page.
type foxioTCPTranscriptionRule struct {
	number int
	body   string
}

// readFoxioTCPTranscriptionPage returns the content of one transcription page.
func readFoxioTCPTranscriptionPage(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// parseFoxioTCPTranscriptionRules returns every numbered rule of one page, in page order.
// The body of a rule runs to the start of the next rule, so a rule that wraps over several
// lines stays whole.
func parseFoxioTCPTranscriptionRules(page string) []foxioTCPTranscriptionRule {
	starts := foxioTCPTranscriptionRuleStart.FindAllStringSubmatchIndex(page, -1)
	rules := make([]foxioTCPTranscriptionRule, 0, len(starts))

	for i, start := range starts {
		end := len(page)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}

		number, err := strconv.Atoi(page[start[2]:start[3]])
		if err != nil {
			continue
		}

		rules = append(rules, foxioTCPTranscriptionRule{
			number: number,
			body:   foxioTCPTranscriptionWhitespace.ReplaceAllString(page[start[1]:end], " "),
		})
	}

	return rules
}

// FR-reference-6 — one page per method that an image specifies. A missing page leaves a
// citation that a reader cannot check without the FoxIO repository.
func TestFoxioTCPTranscriptionHoldsOnePagePerImage(t *testing.T) {
	for image, path := range foxioTCPTranscriptionPages {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s transcribes %s, and the file is absent: %v", path, image, err)
		}
	}
}

// FR-reference-7 — each page numbers its rules `R1`, `R2` and onward. A gap or a duplicate
// breaks every citation that names a number after it.
func TestFoxioTCPTranscriptionNumbersItsRulesFromR1WithNoGap(t *testing.T) {
	for _, path := range foxioTCPTranscriptionPages {
		page := readFoxioTCPTranscriptionPage(t, path)

		rules := parseFoxioTCPTranscriptionRules(page)
		if len(rules) == 0 {
			t.Errorf("%s holds no numbered rule, and FR-reference-7 names R1 and onward", path)
			continue
		}

		seen := map[int]bool{}
		for i, rule := range rules {
			if want := i + 1; rule.number != want {
				t.Errorf("%s holds R%d at position %d, and FR-reference-7 names R%d", path, rule.number, i+1, want)
			}
			if seen[rule.number] {
				t.Errorf("%s holds two rules numbered R%d", path, rule.number)
			}
			seen[rule.number] = true
		}
	}
}

// FR-reference-10 — a rule that a reference implementation corroborates names the
// implementation, the file and the line. A claim with no location is not evidence.
func TestFoxioTCPTranscriptionCitesAFileAndALineForEveryImplementation(t *testing.T) {
	for _, path := range foxioTCPTranscriptionPages {
		page := readFoxioTCPTranscriptionPage(t, path)

		for _, rule := range parseFoxioTCPTranscriptionRules(page) {
			if !foxioTCPTranscriptionImplementation.MatchString(rule.body) {
				continue
			}
			if foxioTCPTranscriptionCitation.MatchString(rule.body) {
				continue
			}
			t.Errorf("%s R%d names a reference implementation and carries no file:line citation", path, rule.number)
		}
	}
}

// FR-reference-9 — a rule that the image alone states says so. A reader must be able to
// tell a schema fact from a behavior that one implementation chose.
func TestFoxioTCPTranscriptionMarksEveryRuleThatTheImageAloneStates(t *testing.T) {
	for _, path := range foxioTCPTranscriptionPages {
		page := readFoxioTCPTranscriptionPage(t, path)

		for _, rule := range parseFoxioTCPTranscriptionRules(page) {
			if foxioTCPTranscriptionImplementation.MatchString(rule.body) {
				continue
			}
			if strings.Contains(rule.body, foxioTCPTranscriptionImageOnlyMarker) {
				continue
			}
			t.Errorf("%s R%d names no reference implementation and carries no %q", path, rule.number, foxioTCPTranscriptionImageOnlyMarker)
		}
	}
}

// FR-reference-16 — no page reproduces a FoxIO image, and each page links to its own image.
// The images are FoxIO-licensed material, and this repository commits no part of it.
func TestFoxioTCPTranscriptionLinksToItsImageAndReproducesNone(t *testing.T) {
	pin := readFoxioTranscriptionTCPPin(t)

	for image, path := range foxioTCPTranscriptionPages {
		page := readFoxioTCPTranscriptionPage(t, path)

		if strings.Contains(page, "![") {
			t.Errorf("%s embeds an image, and FR-reference-16 declines to reproduce one", path)
		}

		link := fmt.Sprintf(
			"https://github.com/FoxIO-LLC/ja4/blob/%s/technical_details/%s",
			pin, image,
		)
		if !strings.Contains(page, link) {
			t.Errorf("%s links to no image at the pin, and FR-reference-16 names the link %q", path, link)
		}
	}
}

// readFoxioTranscriptionTCPPin returns the commit that `testdata/foxio.pin` holds.
func readFoxioTranscriptionTCPPin(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile("testdata/foxio.pin")
	if err != nil {
		t.Fatalf("read testdata/foxio.pin: %v", err)
	}

	return strings.TrimSpace(string(content))
}

// The port measured two facts that a reader of these pages needs, and a page that loses
// one of them sends the next engineer back to the image.
//
// `JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so it specifies JA4TS. `JA4L.png`
// states no server rule, so no image specifies JA4LS, and `features/12-ja4ls.md` builds
// JA4LS from the reference implementations for that reason.
func TestFoxioTCPTranscriptionRecordsTheTwoMeasuredFacts(t *testing.T) {
	tcp := readFoxioTCPTranscriptionPage(t, foxioTCPTranscriptionPages["JA4T.png"])
	if !strings.Contains(tcp, "JA4T/S: TCP Fingerprint") {
		t.Errorf("docs/specs/foxio/JA4T.md quotes no image title, and the title is what makes the page cover JA4TS")
	}
	if !strings.Contains(tcp, "JA4TS") {
		t.Errorf("docs/specs/foxio/JA4T.md names no JA4TS rule, and `JA4T.png` specifies JA4TS")
	}

	latency := readFoxioTCPTranscriptionPage(t, foxioTCPTranscriptionPages["JA4L.png"])
	if !strings.Contains(latency, "No image specifies JA4LS.") {
		t.Errorf("docs/specs/foxio/JA4L.md does not state that no image specifies JA4LS")
	}
}

// FR-reference-11 — R10 records the Zeek stop at option kind 0, and the references
// contradict it. Zeek writes no entry, and Wireshark and Rust write one entry for each
// kind 0 byte. The maintainer ruled the question on 2026-08-12, and #297 holds the ruling.
//
// A reader who matches the Zeek rule breaks every other reference, so the page must name
// each value.
func TestFoxioTCPTranscriptionMarksTheEndOfOptionListSplit(t *testing.T) {
	page := readFoxioTCPTranscriptionPage(t, foxioTCPTranscriptionPages["JA4T.png"])

	for _, part := range []string{
		"`zeek/ja4t/main.zeek:96`",
		"`wireshark/source/packet-ja4.c:1456`",
		"`rust/ja4/src/tcp.rs:70`",
		"2-1-3-1-1-8-4-0-0",
		"#297",
	} {
		if !strings.Contains(page, part) {
			t.Errorf("docs/specs/foxio/JA4T.md holds no %q, and R10 records a reference split", part)
		}
	}
}

// FR-reference-11 — a rule that the reference implementations contradict is marked as a
// reference split, and the page states each value. Issue #18 found the JA4TS delay split,
// and the page must carry both values so that a reader does not match one reference and
// break the other.
func TestFoxioTCPTranscriptionMarksTheJA4TSDelaySplit(t *testing.T) {
	page := readFoxioTCPTranscriptionPage(t, foxioTCPTranscriptionPages["JA4T.png"])

	for _, part := range []string{
		"Reference split",
		"`zeek/ja4t/main.zeek:180`",
		"`wireshark/source/packet-ja4.c:277`",
		"#18",
	} {
		if !strings.Contains(page, part) {
			t.Errorf("docs/specs/foxio/JA4T.md holds no %q, and FR-reference-11 records the JA4TS delay split", part)
		}
	}
}
