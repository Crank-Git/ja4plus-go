package repocheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The README and `doc.go` are short restatements of `NOTICE`. These tests hold
// FR-licensing-10 through FR-licensing-13, so that a later edit cannot restore the
// unqualified BSD 3-Clause claim that issue #12 deletes.
//
// `NOTICE` is the authority for the split. `notice_test.go` holds it, and these tests
// read the same method list from `noticeMethods`.

const (
	// readmeLicenseHeading opens the License section of the README.
	readmeLicenseHeading = "\n## License\n"

	// readmeBadgeTarget is the file the license badge links to. FR-licensing-11 requires
	// that the target exists.
	readmeBadgeTarget = "LICENSE"
)

// readmeLicenseBadge matches the Markdown badge whose label is `License`.
// Group 1 holds the badge image URL, and group 2 holds the link target.
var readmeLicenseBadge = regexp.MustCompile(`\[!\[License\]\(([^)]*)\)\]\(([^)]*)\)`)

// sentenceEnd matches the end of one sentence. A period inside a version number, a URL or
// a file name is followed by a character that is not a space, so it does not match.
var sentenceEnd = regexp.MustCompile(`[.!?](\s|$)`)

// unimplementedMethods holds the JA4+ methods this library does not implement today.
// Epic 12 moved JA4LS into `noticeMethods`, so this list no longer names it.
var unimplementedMethods = []string{"JA4TScan", "JA4SScan", "JA4E"}

// readmeLicenseSection returns the body of the README License section.
// It fails the test when the README holds no License heading.
func readmeLicenseSection(t *testing.T) string {
	t.Helper()

	_, rest, found := strings.Cut(readRepoFile(t, "README.md"), readmeLicenseHeading)
	if !found {
		t.Fatalf("README.md holds no %q heading", strings.TrimSpace(readmeLicenseHeading))
	}

	section, _, _ := strings.Cut(rest, "\n## ")

	return section
}

// namesMethod reports whether the text names the method as a whole word.
// `JA4S` is a prefix of `JA4SSH`, so a substring test reports a false match.
func namesMethod(text, method string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(method) + `\b`).MatchString(text)
}

// FR-licensing-11. The badge linked to a file that did not exist before Epic 1.
func TestReadmeLicenseBadgeLinksToAFileThatExists(t *testing.T) {
	match := readmeLicenseBadge.FindStringSubmatch(readRepoFile(t, "README.md"))
	if match == nil {
		t.Fatal("README.md holds no License badge, and FR-licensing-11 requires one")
	}

	if match[2] != readmeBadgeTarget {
		t.Errorf("the License badge links to %q, and FR-licensing-11 requires %q", match[2], readmeBadgeTarget)
	}

	if _, err := os.Stat(match[2]); err != nil {
		t.Errorf("the License badge target %q does not exist: %v", match[2], err)
	}
}

// FR-licensing-11. The § License section of `CLAUDE.md` bars an unqualified BSD 3-Clause
// claim, and the badge text is a claim.
func TestReadmeLicenseBadgeClaimsNoBSD3ClauseForTheWholeProject(t *testing.T) {
	match := readmeLicenseBadge.FindStringSubmatch(readRepoFile(t, "README.md"))
	if match == nil {
		t.Fatal("README.md holds no License badge, and FR-licensing-11 requires one")
	}

	if !strings.Contains(match[1], "FoxIO") {
		t.Errorf("the License badge reads %q, and it names no FoxIO license", match[1])
	}
}

// FR-licensing-10.
func TestReadmeLicenseSectionStatesTheSplitInThreeSentencesOrFewer(t *testing.T) {
	section := readmeLicenseSection(t)

	sentences := len(sentenceEnd.FindAllString(section, -1))
	if sentences > 3 {
		t.Errorf("the README License section holds %d sentences, and FR-licensing-10 allows 3", sentences)
	}

	if sentences == 0 {
		t.Error("the README License section holds no sentence")
	}
}

// FR-licensing-10. The section names the methods that FoxIO License 1.1 covers, and
// `NOTICE` is the authority for that list.
func TestReadmeLicenseSectionNamesEveryMethodThatNoticeNames(t *testing.T) {
	section := readmeLicenseSection(t)

	for _, method := range noticeMethods {
		if !namesMethod(section, method) {
			t.Errorf("the README License section names no %s, and NOTICE covers it", method)
		}
	}
}

// FR-licensing-10. The README states this library's own list, and it names no method the
// library does not implement. `NOTICE` states that the FoxIO list is a different list.
func TestReadmeLicenseSectionNamesNoUnimplementedMethod(t *testing.T) {
	section := readmeLicenseSection(t)

	for _, method := range unimplementedMethods {
		if namesMethod(section, method) {
			t.Errorf("the README License section names %s, and this library does not implement it", method)
		}
	}
}

// FR-licensing-10. `NOTICE` states this term, and the README must not drift from it.
func TestReadmeLicenseSectionStatesNonCommercialUseOnly(t *testing.T) {
	section := readmeLicenseSection(t)

	if !strings.Contains(section, "non-commercial use only") {
		t.Error("the README License section states no non-commercial term for FoxIO License 1.1")
	}
}

// FR-licensing-12. The project answers a commercial question with a pointer to FoxIO, and
// with no legal advice of its own.
func TestReadmeLicenseSectionSendsACommercialUserToFoxIO(t *testing.T) {
	section := readmeLicenseSection(t)

	if !strings.Contains(section, "commercial user contacts") {
		t.Error("the README License section does not send a commercial user to FoxIO, and FR-licensing-12 requires it")
	}

	if !strings.Contains(section, "foxio.io") {
		t.Error("the README License section holds no FoxIO address for a commercial user")
	}
}

// FR-licensing-10. `NOTICE` holds the full terms, and the section links to it.
func TestReadmeLicenseSectionLinksToNoticeAndToLicense(t *testing.T) {
	section := readmeLicenseSection(t)

	for _, target := range []string{"(NOTICE)", "(LICENSE)"} {
		if !strings.Contains(section, target) {
			t.Errorf("the README License section holds no %s link", target)
		}
	}
}

// FR-licensing-13. `doc.go` holds the package documentation, and `go doc` prints it.
func TestDocGoStatesTheLicenseSplit(t *testing.T) {
	docGo := readRepoFile(t, "doc.go")

	if !strings.HasPrefix(docGo, "// Package ja4plus ") {
		t.Error("doc.go does not open with the name it documents, and `.claude/rules/ste.md` requires it")
	}

	for _, statement := range []string{
		"BSD 3-Clause",
		"FoxIO License 1.1",
		"non-commercial use only",
		"NOTICE",
	} {
		if !strings.Contains(docGo, statement) {
			t.Errorf("doc.go states no %q, and FR-licensing-13 requires the split", statement)
		}
	}

	for _, method := range noticeMethods {
		if !namesMethod(docGo, method) {
			t.Errorf("doc.go names no %s, and NOTICE covers it", method)
		}
	}
}

// The library writes nothing to standard output or standard error, and `doc.go` carries
// documentation alone. A declaration in this file is a declaration no reader expects here.
func TestDocGoHoldsThePackageClauseAlone(t *testing.T) {
	docGo := readRepoFile(t, "doc.go")

	_, code, found := strings.Cut(docGo, "\npackage ja4plus\n")
	if !found {
		t.Fatal("doc.go holds no `package ja4plus` clause")
	}

	if strings.TrimSpace(code) != "" {
		t.Errorf("doc.go holds code after the package clause: %q", strings.TrimSpace(code))
	}
}

// licenseClaimSkipDirs holds the directories the repository-wide scan does not read.
//
// `docs/specs` records the defect that issue #12 repairs, and it quotes the FoxIO list
// verbatim. `.claude` and `.git` hold no license statement about this library.
//
// `.golangci-cache` holds the linter cache that #257 moved inside the checkout. The
// extension filter below admits the empty extension and `.txt`, which that cache holds in
// thousands of files, so the scan reads the whole cache after a `make lint` run.
var licenseClaimSkipDirs = map[string]bool{
	".git":            true,
	".claude":         true,
	".golangci-cache": true,
	"bin":             true,
	"docs/specs":      true,
	"testdata":        true,
	"assets":          true,
	"node_modules":    true,
}

// licenseClaimExtensions holds the file kinds the repository-wide scan reads.
// The empty extension covers `LICENSE` and `NOTICE`.
var licenseClaimExtensions = map[string]bool{
	"":      true,
	".md":   true,
	".go":   true,
	".txt":  true,
	".html": true,
	".yml":  true,
	".yaml": true,
}

// The acceptance criterion of `docs/specs/features/01-licensing.md`: no file in the
// repository states that the JA4+ methods are BSD 3-Clause. FoxIO License 1.1 covers
// them, and a reader who acts on the wrong claim takes a permission FoxIO does not grant.
//
// The scan reads one line at a time. A line that names a FoxIO-licensed method and the
// BSD 3-Clause license together is the shape of the claim this issue deletes from
// `README.md:204`.
func TestNoFileStatesThatTheFoxIOMethodsAreBSD3Clause(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// The skip set holds one slash-separated path, so the walk path takes the same
		// form on every platform.
		path = filepath.ToSlash(path)

		if entry.IsDir() {
			if licenseClaimSkipDirs[path] || licenseClaimSkipDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}

		// A test file states no license. It names a method and the license together to
		// hold this rule, so the scan would report itself.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		if !licenseClaimExtensions[filepath.Ext(path)] {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		for number, line := range strings.Split(string(content), "\n") {
			if !strings.Contains(line, "BSD") {
				continue
			}

			for _, method := range noticeMethods {
				if namesMethod(line, method) {
					t.Errorf("%s:%d names %s and the BSD 3-Clause license together, and FoxIO License 1.1 covers %s", path, number+1, method, method)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("read the repository: %v", err)
	}
}
