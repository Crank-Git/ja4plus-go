package ja4plus

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests hold the correction that issue #135 records.
//
// `technical_details/` holds no `JA4TS.png`, so JA4TS reaches no image of its own name.
// `JA4T.png` nonetheless titles itself `JA4T/S: TCP Fingerprint`, so it specifies the
// schema of JA4TS. A document that drops the `of their own name` qualifier turns a true
// statement about file names into a false statement about evidence.
//
// The false statement inverts the source ranking for one method, because
// `.claude/rules/rulings.md` ranks a FoxIO image above a reference implementation. The
// port guards the same claim across its own documentation tree.

const (
	// imageClaimQualifier makes the claim about the three methods true.
	imageClaimQualifier = "of their own name"

	// imageClaimWindow is the character count each side of a `no image` phrase that the
	// scan reads for the method name. One sentence of this project fits in it.
	imageClaimWindow = 160
)

// imageClaimRoots names each directory the scan walks.
var imageClaimRoots = []string{"docs", ".claude/rules"}

// imageClaimFiles names each single file the scan reads.
var imageClaimFiles = []string{"CLAUDE.md", "README.md"}

// imageClaimExtensions names each page format the scan reads.
var imageClaimExtensions = []string{".md", ".html"}

// imageClaimPhrase matches a statement that a method reaches no image.
var imageClaimPhrase = regexp.MustCompile(`(?i)(?:have|has|hold|holds|reach|reaches)\s+no\s+image`)

// imageClaimWhitespace matches one run of whitespace, which the scan collapses to one
// space. A claim that wraps over two lines must read as one sentence.
var imageClaimWhitespace = regexp.MustCompile(`\s+`)

func TestDocumentationQualifiesTheClaimThatJA4TSReachesNoImage(t *testing.T) {
	for _, path := range imageClaimPages(t) {
		text := imageClaimWhitespace.ReplaceAllString(readRepoFile(t, path), " ")

		for _, match := range imageClaimPhrase.FindAllStringIndex(text, -1) {
			window := text[max(0, match[0]-imageClaimWindow):min(len(text), match[1]+imageClaimWindow)]

			if !strings.Contains(window, "JA4TS") {
				continue
			}

			if !strings.Contains(window, imageClaimQualifier) {
				t.Errorf("%s states that JA4TS reaches no image, without the %q qualifier:\n%s",
					path, imageClaimQualifier, window)
			}
		}
	}
}

func TestSourceRankingStatesThatTheJA4TImageSpecifiesJA4TS(t *testing.T) {
	pages := []string{
		".claude/rules/rulings.md",
		"docs/specs/features/11-foxio-reference.md",
	}

	// The title is FoxIO material, so `.claude/rules/ste.md` holds it verbatim.
	phrases := []string{
		"`JA4T/S: TCP Fingerprint`",
		"the schema of JA4TS",
	}

	for _, page := range pages {
		text := imageClaimWhitespace.ReplaceAllString(readRepoFile(t, page), " ")

		for _, phrase := range phrases {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s does not state %q", page, phrase)
			}
		}
	}
}

// imageClaimPages returns the path of every page the scan reads.
func imageClaimPages(t *testing.T) []string {
	t.Helper()

	pages := append([]string{}, imageClaimFiles...)

	for _, root := range imageClaimRoots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.IsDir() {
				return nil
			}

			for _, extension := range imageClaimExtensions {
				if strings.EqualFold(filepath.Ext(path), extension) {
					pages = append(pages, path)

					return nil
				}
			}

			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	for _, page := range pages {
		if _, err := os.Stat(page); err != nil {
			t.Fatalf("stat %s: %v", page, err)
		}
	}

	return pages
}
