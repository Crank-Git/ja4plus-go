package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests hold FR-ja4ls-15 through FR-ja4ls-20, which issue #62 carries.
//
// `CLAUDE.md` states the doctrine. FoxIO names twelve methods, and this project implements
// eleven of them. `JA4LFingerprinter` writes both JA4L and JA4LS, so ten fingerprinters
// carry eleven methods. A reader who applies the count of ten to methods, or the count of
// eleven to fingerprinters, reads the wrong number.
//
// `concurrency_doc_test.go:136` reads fourteen files and reports no line number. This scan
// reads every document of the repository and reports the file and the line of each
// violation, which FR-ja4ls-19 requires.

// methodCountForm names one count form that the doctrine above declares wrong.
type methodCountForm struct {
	pattern *regexp.Regexp
	reason  string
}

// methodCountForbiddenForms holds the two forms the scan reports.
//
// Each pattern joins the count word to the noun it counts, so a sentence that counts a
// subset passes. `NOTICE` covers ten of the eleven methods, and that sentence states the
// subset rather than the total.
//
// The scan reports these two forms alone. The tree holds true sentences that count
// something else with the same words: `internal/parser/http.go:29` counts HTTP request
// methods, and `NOTICE:37` counts the methods that one FoxIO record names. A wider pattern
// would report each one, and a reader who silences a true report stops reading the
// reports.
//
// **A word between the count and the noun escapes the scan.** The self-review of #62
// measured it, and a sentence such as `ten total methods` reports nothing. **A pattern that
// admits one word between them reports the doctrine itself**, because
// `ten fingerprinters, eleven methods` then matches. So the scan holds the adjacent form,
// and a reader reads a green run as a report about the adjacent form alone.
//
// Each pattern is built from parts, so this file does not report itself.
var methodCountForbiddenForms = []methodCountForm{
	{
		pattern: regexp.MustCompile(`(?i)\b(` + "ten" + `|10)\s+(JA4\+\s+)?` + "methods" + `\b`),
		reason:  "the count of ten covers fingerprinters, and eleven covers methods",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(` + "eleven" + `|11)\s+` + "fingerprinters" + `\b`),
		reason:  "the count of eleven covers methods, and ten covers fingerprinters",
	},
}

// methodCountSkipDirs holds the directories the scan does not read.
//
// `testdata/foxio` holds the fetched FoxIO corpus, which is evidence rather than a
// document of this project. **The scan reads the rest of `testdata`**, because
// `testdata/README.md` states the conventions of the register and this project wrote it.
//
// `.golangci-cache` holds the linter cache that #257 moved inside the checkout, and `bin`
// holds a built artifact.
//
// `.claude/worktrees` holds one checkout for each issue worker of a batch, and `.gitignore`
// holds it. A run from the main checkout would otherwise read the documents of every
// worker at once, and report a violation that belongs to another issue.
//
// The scan reads the rest of `.claude`, because `.claude/skills/release/SKILL.md` states
// the count as a release gate.
var methodCountSkipDirs = map[string]bool{
	".git":              true,
	".golangci-cache":   true,
	".claude/worktrees": true,
	"bin":               true,
	"node_modules":      true,
	"testdata/foxio":    true,
	"assets":            true,
}

// methodCountExtensions holds the file kinds the scan reads.
// The empty extension covers `NOTICE` and `LICENSE`.
var methodCountExtensions = map[string]bool{
	"":      true,
	".md":   true,
	".html": true,
	".go":   true,
}

// methodCountExemptDelimiters holds the marks that quote a count form.
// A code span takes the first one, and a quotation takes the second one.
const methodCountExemptDelimiters = "`\""

// methodCountHistoryFile names the one document whose history section the scan skips.
const methodCountHistoryFile = "docs/specs/spec.md"

// methodCountHistoryHeading opens that history section.
const methodCountHistoryHeading = "\n## Changelog\n"

// methodCountViolation names one count form that one line of one file holds.
type methodCountViolation struct {
	path   string
	line   int
	phrase string
	reason string
}

// methodCountIsQuoted reports whether one delimiter sits against each end of the phrase
// that the text holds between start and end.
//
// The scan exempts a quoted phrase, because a writer who quotes a wrong form states a rule
// about that form and never states the count. `CLAUDE.md:10` and FR-ja4ls-17 each quote
// the form the doctrine declares wrong.
//
// **The exemption reads the two bytes that touch the phrase, and no other byte.** An
// earlier form paired each delimiter with the next one and blanked the text between them.
// A stray delimiter then paired with an unrelated one, and the pair hid a real violation
// that sat between the two. `TestMethodCountScanReportsAFormThatAStrayDelimiterPrecedes`
// holds the repair.
func methodCountIsQuoted(text string, start, end int) bool {
	if start == 0 || end >= len(text) {
		return false
	}

	opener := text[start-1]
	if !strings.ContainsRune(methodCountExemptDelimiters, rune(opener)) {
		return false
	}

	return text[end] == opener
}

// methodCountMaskHistory returns the text with the history section replaced by a space for
// each byte. It preserves the length of the text, so every offset survives.
//
// The `## Changelog` table of `docs/specs/spec.md` records what each round of the spec
// changed, and a round that repairs a count quotes the form it deleted. The project
// manager owns that section, and no member of a batch rewrites it.
func methodCountMaskHistory(path, text string) string {
	if filepath.ToSlash(path) != methodCountHistoryFile {
		return text
	}

	start := strings.Index(text, methodCountHistoryHeading)
	if start < 0 {
		return text
	}

	masked := []byte(text)
	for i := start; i < len(masked); i++ {
		if masked[i] != '\n' {
			masked[i] = ' '
		}
	}

	return string(masked)
}

// methodCountNormalize returns the text with each run of white space replaced by one
// space, and the offset in the text of each byte of that result.
//
// A count sentence wraps across two lines in several documents, so a scan of one line at a
// time reads no phrase that a line break splits.
func methodCountNormalize(text string) (string, []int) {
	var normal strings.Builder
	offsets := make([]int, 0, len(text))

	for i := 0; i < len(text); {
		if isMethodCountSpace(text[i]) {
			normal.WriteByte(' ')
			offsets = append(offsets, i)

			for i < len(text) && isMethodCountSpace(text[i]) {
				i++
			}

			continue
		}

		normal.WriteByte(text[i])
		offsets = append(offsets, i)
		i++
	}

	return normal.String(), offsets
}

// isMethodCountSpace reports whether the byte is white space that a document holds.
func isMethodCountSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// methodCountScan returns one violation for each forbidden count form in the text.
// It reports the line of the text that holds the first byte of the phrase.
func methodCountScan(path, text string) []methodCountViolation {
	normal, offsets := methodCountNormalize(methodCountMaskHistory(path, text))

	var violations []methodCountViolation
	for _, form := range methodCountForbiddenForms {
		for _, match := range form.pattern.FindAllStringIndex(normal, -1) {
			if methodCountIsQuoted(normal, match[0], match[1]) {
				continue
			}

			offset := offsets[match[0]]

			violations = append(violations, methodCountViolation{
				path:   filepath.ToSlash(path),
				line:   strings.Count(text[:offset], "\n") + 1,
				phrase: strings.TrimSpace(normal[match[0]:match[1]]),
				reason: form.reason,
			})
		}
	}

	return violations
}

// methodCountGoComments returns the Go source with every byte outside a comment replaced
// by a space. It preserves the length of the source, so every offset survives.
//
// FR-ja4ls-18 names the Go doc comment, and a Go string literal states no count to a
// reader. `licensing_test.go:94` holds a count inside the message of a failure, and that
// message reports the history of issue #121.
func methodCountGoComments(source string, file *ast.File, fset *token.FileSet) string {
	masked := []byte(source)
	for i := range masked {
		if masked[i] != '\n' {
			masked[i] = ' '
		}
	}

	for _, group := range file.Comments {
		start := fset.Position(group.Pos()).Offset
		end := fset.Position(group.End()).Offset

		if start < 0 || end > len(source) || start > end {
			continue
		}

		copy(masked[start:end], source[start:end])
	}

	return string(masked)
}

// methodCountDocuments returns the scannable text of each document of the repository, by
// path. A Go file reaches the map as its comments alone.
func methodCountDocuments(t *testing.T) map[string]string {
	t.Helper()

	documents := map[string]string{}

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		path = filepath.ToSlash(path)

		if entry.IsDir() {
			if methodCountSkipDirs[path] || methodCountSkipDirs[entry.Name()] {
				return fs.SkipDir
			}

			return nil
		}

		if !methodCountExtensions[filepath.Ext(path)] {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		source := string(content)

		if filepath.Ext(path) == ".go" {
			fset := token.NewFileSet()

			file, parseErr := parser.ParseFile(fset, path, source, parser.ParseComments|parser.SkipObjectResolution)
			if parseErr != nil {
				t.Errorf("parse %s: %v", path, parseErr)

				return nil
			}

			source = methodCountGoComments(source, file, fset)
		}

		documents[path] = source

		return nil
	})
	if err != nil {
		t.Fatalf("read the repository: %v", err)
	}

	return documents
}

// FR-ja4ls-15, FR-ja4ls-16, FR-ja4ls-17 and FR-ja4ls-18.
func TestMethodCountAppliesElevenToMethodsAndTenToFingerprinters(t *testing.T) {
	for path, text := range methodCountDocuments(t) {
		for _, violation := range methodCountScan(path, text) {
			// FR-ja4ls-19 requires the file and the line.
			t.Errorf("%s:%d states %q, and %s", violation.path, violation.line, violation.phrase, violation.reason)
		}
	}
}

// A scan that reads no file reports no violation, and a reader takes that silence for a
// pass. This test names the documents that carry the doctrine, so a later change to the
// walk cannot empty the scan without a failure.
func TestMethodCountScanReadsEveryDocumentThatCarriesTheDoctrine(t *testing.T) {
	documents := methodCountDocuments(t)

	for _, path := range []string{
		"CLAUDE.md",
		"README.md",
		"NOTICE",
		"doc.go",
		"CHANGELOG.md",
		"docs/specs/spec.md",
		"docs/specs/spec.html",
		"docs/specs/features/12-ja4ls.md",
		".claude/skills/release/SKILL.md",
		"testdata/README.md",
	} {
		if _, found := documents[path]; !found {
			t.Errorf("the scan reads no %s, and that document states a count", path)
		}
	}

	// A run from the main checkout reaches the worktree of every issue worker of the
	// batch. Those documents belong to another issue, and this scan reports none of them.
	for path := range documents {
		if strings.HasPrefix(path, ".claude/worktrees/") {
			t.Errorf("the scan reads %s, and that document belongs to the worktree of another issue", path)
		}
	}
}

// FR-ja4ls-19. The scan reads a phrase that a line break splits, and it reports the line
// that holds the first word of that phrase.
func TestMethodCountScanNamesTheFileAndTheLineOfAViolation(t *testing.T) {
	// The document is built from parts, so this file holds no forbidden form.
	document := "One line.\nThe library implements " + "ten\n" + "methods" + " today.\n"

	violations := methodCountScan("example.md", document)
	if len(violations) != 1 {
		t.Fatalf("the scan reports %d violations, and the document holds one: %v", len(violations), violations)
	}

	if violations[0].path != "example.md" {
		t.Errorf("the scan names the file %q, and the document is example.md", violations[0].path)
	}

	if violations[0].line != 2 {
		t.Errorf("the scan names line %d, and the phrase starts on line 2", violations[0].line)
	}
}

// The scan reports the second forbidden form, which applies the count of eleven to
// fingerprinters.
func TestMethodCountScanReportsAFingerprinterCountOfEleven(t *testing.T) {
	document := "The " + "eleven " + "fingerprinters" + " run.\n"

	violations := methodCountScan("example.md", document)
	if len(violations) != 1 {
		t.Fatalf("the scan reports %d violations, and the document holds one: %v", len(violations), violations)
	}
}

// The scan exempts a quotation of a forbidden form, and it reports the same form outside a
// quotation. A rule that names the wrong form must be writable.
func TestMethodCountScanExemptsAQuotationOfAForbiddenForm(t *testing.T) {
	quoted := "A document that writes \"" + "ten " + "methods" + "\" is wrong.\n"
	if violations := methodCountScan("example.md", quoted); len(violations) != 0 {
		t.Errorf("the scan reports %v for a quotation, and a quotation states no count", violations)
	}

	spanned := "A document that writes `" + "ten " + "methods" + "` is wrong.\n"
	if violations := methodCountScan("example.md", spanned); len(violations) != 0 {
		t.Errorf("the scan reports %v for a code span, and a code span states no count", violations)
	}

	// A delimiter that touches one end of the phrase alone exempts nothing.
	unmatched := "A document \" that states " + "ten " + "methods" + " is wrong.\n"
	if violations := methodCountScan("example.md", unmatched); len(violations) != 1 {
		t.Errorf("the scan reports %d violations after an unmatched quotation mark, and the line holds one", len(violations))
	}
}

// A stray delimiter earlier in the line exempts nothing.
//
// An earlier form of the exemption paired each delimiter with the next one, and it blanked
// the text between them. The pair then hid a real violation that sat between the two, and
// the scan reported nothing. The self-review of #62 measured this input.
func TestMethodCountScanReportsAFormThatAStrayDelimiterPrecedes(t *testing.T) {
	document := "Stray ` states " + "ten " + "methods" + " here ` and `z` follows.\n"

	if violations := methodCountScan("example.md", document); len(violations) != 1 {
		t.Errorf("the scan reports %d violations, and the line states the count outside a quotation", len(violations))
	}

	attribute := "<img alt=\"the library implements " + "ten " + "methods" + " here\">\n"
	if violations := methodCountScan("example.html", attribute); len(violations) != 1 {
		t.Errorf("the scan reports %d violations, and the attribute states the count", len(violations))
	}
}

// A sentence that counts a subset of the methods states the subset and never the total.
// `NOTICE` covers ten of the eleven methods, and that sentence passes.
func TestMethodCountScanReportsNoSubsetSentence(t *testing.T) {
	document := "FoxIO License 1.1 covers " + "ten" + " of the eleven " + "methods" + ".\n"

	if violations := methodCountScan("example.md", document); len(violations) != 0 {
		t.Errorf("the scan reports %v, and the sentence counts a subset", violations)
	}
}

// FR-ja4ls-20.
func TestMethodCountCLAUDEmdStatesTheDoctrine(t *testing.T) {
	claude := readRepoFile(t, "CLAUDE.md")

	for _, want := range []string{
		"implements eleven",
		"ten fingerprinters carry eleven",
	} {
		if !strings.Contains(claude, want) {
			t.Errorf("CLAUDE.md does not hold %q, and FR-ja4ls-20 needs the doctrine", want)
		}
	}
}
