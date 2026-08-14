package ja4plus

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The documentation site of Epic 14 lives in two files that no Go code reads: `mkdocs.yml`
// and `docs/requirements.txt`. So no compiler and no linter of this repository sees a
// change to either one, and a silent edit removes a requirement without a message.
//
// The tests below read the two files as text and hold each requirement of #84. Each one
// names the requirement it holds.
//
// The tests read the files as text rather than as YAML, because this module declares no
// YAML dependency and #84 adds no Go dependency.

const (
	mkdocsConfigPath  = "mkdocs.yml"
	docsRequirements  = "docs/requirements.txt"
	documentationRoot = "docs"
)

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

// TestMkdocsConfigSitsAtTheRepositoryRoot holds FR-documentation-2.
func TestMkdocsConfigSitsAtTheRepositoryRoot(t *testing.T) {
	if _, err := os.Stat(mkdocsConfigPath); err != nil {
		t.Fatalf("FR-documentation-2 states that mkdocs.yml sits at the repository root: %v", err)
	}
}

// TestMkdocsConfigNamesTheMaterialTheme holds FR-documentation-1.
func TestMkdocsConfigNamesTheMaterialTheme(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	if !regexp.MustCompile(`(?m)^theme:\s*$`).MatchString(config) {
		t.Fatal("mkdocs.yml holds no theme block")
	}
	if !regexp.MustCompile(`(?m)^\s+name:\s+material\s*$`).MatchString(config) {
		t.Error("FR-documentation-1 states that the site uses the Material theme")
	}
}

// TestMkdocsConfigReadsTheDocsDirectory holds FR-documentation-3.
func TestMkdocsConfigReadsTheDocsDirectory(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	if !regexp.MustCompile(`(?m)^docs_dir:\s+docs\s*$`).MatchString(config) {
		t.Error("FR-documentation-3 states that docs_dir is docs/")
	}
}

// TestMkdocsConfigFailsTheBuildOnAWarning holds FR-documentation-4.
func TestMkdocsConfigFailsTheBuildOnAWarning(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	if !regexp.MustCompile(`(?m)^strict:\s+true\s*$`).MatchString(config) {
		t.Error("FR-documentation-4 states that strict is true, so a warning fails the build")
	}
}

// TestMkdocsConfigRaisesABrokenLinkAndABrokenAnchor holds FR-documentation-5.
//
// `links.anchors` defaults to `info`, so the anchor half of the requirement exists only
// because the configuration raises it.
func TestMkdocsConfigRaisesABrokenLinkAndABrokenAnchor(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	if !regexp.MustCompile(`(?m)^\s+not_found:\s+warn\s*$`).MatchString(config) {
		t.Error("FR-documentation-5 states that a broken link reaches warn")
	}
	if !regexp.MustCompile(`(?m)^\s+anchors:\s+warn\s*$`).MatchString(config) {
		t.Error("FR-documentation-5 states that a broken anchor reaches warn")
	}
}

// TestMkdocsConfigExcludesTheSpecPackageAndTheAudit holds FR-documentation-6 and
// FR-documentation-7.
func TestMkdocsConfigExcludesTheSpecPackageAndTheAudit(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	for requirement, pattern := range map[string]string{
		"FR-documentation-6": "/specs/",
		"FR-documentation-7": "/audit/",
	} {
		if !regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(pattern) + `\s*$`).MatchString(config) {
			t.Errorf("%s states that %s is excluded from the site, and exclude_docs names no %s pattern",
				requirement, strings.Trim(pattern, "/"), pattern)
		}
	}
}

// TestTheGeneratorPinsAreExact holds FR-documentation-8.
//
// A range lets a generator release change the rendered site without a commit of this
// repository. The issue states the rule: a bump is a commit that does nothing else.
func TestTheGeneratorPinsAreExact(t *testing.T) {
	pins := 0
	for number, line := range strings.Split(readTextFile(t, docsRequirements), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pins++
		if !strings.Contains(line, "==") {
			t.Errorf("%s:%d states no exact pin: %q", docsRequirements, number+1, line)
		}
	}
	if pins == 0 {
		t.Errorf("FR-documentation-8 states that one file pins every generator, and %s pins none", docsRequirements)
	}
}

// TestTheThemeOffersALightPaletteAndADarkPalette holds FR-documentation-9.
//
// Material names the light palette `default` and the dark palette `slate`.
func TestTheThemeOffersALightPaletteAndADarkPalette(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	for _, scheme := range []string{"default", "slate"} {
		if !regexp.MustCompile(`(?m)^\s+scheme:\s+` + scheme + `\s*$`).MatchString(config) {
			t.Errorf("FR-documentation-9 states two palettes, and the theme names no %q scheme", scheme)
		}
	}
}

// TestTheTableOfContentsSlugMatchesTheGitHubSlug holds FR-documentation-10.
//
// Two values of this setting are silently wrong, and each one builds without a message.
//
//  1. The key is `kwds`. PyYAML reads `args`, `kwds`, `state`, `listitems` and
//     `dictitems`, and it drops every other key. A file that writes `kwargs` therefore
//     builds, and it writes `Parity-with-the-port` where GitHub writes
//     `parity-with-the-port`.
//  2. The case is `lower`. `lower-ascii` lowers `A` to `Z` alone, so it writes
//     `École-normale` where GitHub writes `école-normale`. The deprecated
//     `pymdownx.slugs.gfm` alias calls `lower-ascii`, so its name misreports what it does.
//
// Measured on 2026-08-14 against `Flet/github-slugger`, which states that it generates
// "a slug just like GitHub does for markdown headings".
func TestTheTableOfContentsSlugMatchesTheGitHubSlug(t *testing.T) {
	config := readTextFile(t, mkdocsConfigPath)
	if !strings.Contains(config, "slugify: !!python/object/apply:pymdownx.slugs.slugify") {
		t.Fatal("FR-documentation-10 states that the slug matches GitHub, and the toc extension names no slugify function")
	}
	if !regexp.MustCompile(`(?m)^\s+kwds:\s*$`).MatchString(config) {
		t.Error("the key is kwds, and PyYAML drops kwargs without a message")
	}
	if !regexp.MustCompile(`(?m)^\s+case:\s+lower\s*$`).MatchString(config) {
		t.Error("the case is lower, and lower-ascii leaves a non-ASCII capital letter")
	}
}

// TestTheMakefileBuildsTheSite holds step 6 of `## A change is done when` in `CLAUDE.md`.
//
// `docs/` is a directory of this repository, so make reads the bare target name as that
// directory and finds it already up to date. It then prints
// `make: Nothing to be done for 'docs'.` and it exits 0 without a build. The `.PHONY`
// entry is what makes the recipe run.
func TestTheMakefileBuildsTheSite(t *testing.T) {
	makefile := readTextFile(t, "Makefile")
	phony := regexp.MustCompile(`(?m)^\.PHONY:(.*)$`).FindStringSubmatch(makefile)
	if phony == nil {
		t.Fatal("the Makefile states no .PHONY line")
	}
	if !strings.Contains(" "+strings.TrimSpace(phony[1])+" ", " docs ") {
		t.Error("the .PHONY line names no docs target, so make docs exits 0 without a build")
	}
	if !regexp.MustCompile(`(?m)^docs:\s*$`).MatchString(makefile) {
		t.Error("the Makefile holds no docs recipe")
	}
	if !strings.Contains(makefile, "build --strict") {
		t.Error("the docs recipe runs no strict build, so a warning would not fail it")
	}
}

// excludedDocumentationDirs names every directory of `docs/` that `exclude_docs` of
// `mkdocs.yml` drops from the built site.
//
// One list serves every walker of `docs/`, so a fifth exclusion reaches each guard at once.
// #91 added `mutation_reports` under FR-mutation-6.
var excludedDocumentationDirs = []string{"specs", "audit", "mutation_reports"}

// isExcludedDocumentationDir reports whether the site publishes no page of the directory.
func isExcludedDocumentationDir(name string) bool {
	for _, excluded := range excludedDocumentationDirs {
		if name == excluded {
			return true
		}
	}

	return false
}

// TestNoPublishedPageLinksIntoAnExcludedDirectory holds the edge case of #84: a page that
// links to `docs/specs/` fails.
//
// MkDocs alone does not hold it. `_RelativePathTreeprocessor.path_to_url` in
// `mkdocs/structure/pages.py` computes
// `warning_level = min(logging.INFO, self.config.validation.links.not_found)`, so a link
// into an excluded file is capped at `INFO` and no value of `validation` raises it.
// Measured on 2026-08-14 at `mkdocs==1.6.1`: a page that links to `specs/spec.md` builds
// and exits 0.
//
// So this test is the guard, and `strict` is not.
func TestNoPublishedPageLinksIntoAnExcludedDirectory(t *testing.T) {
	// A markdown link or a markdown image whose target opens with an excluded directory.
	// The pattern reads a relative target alone, because an absolute URL to the GitHub
	// blob view is a link to another site and never a link into the built site.
	intoExcluded := regexp.MustCompile(`]\(\.?/?(?:` + strings.Join(excludedDocumentationDirs, "|") + `)/`)

	pages := 0
	err := filepath.WalkDir(documentationRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// An excluded directory publishes no page, so the rule binds none of them.
			if path != documentationRoot && isExcludedDocumentationDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		pages++
		for number, line := range strings.Split(readTextFile(t, path), "\n") {
			if intoExcluded.MatchString(line) {
				t.Errorf("%s:%d links into an excluded directory, and the built site holds no target for it: %q",
					path, number+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", documentationRoot, err)
	}
	if pages == 0 {
		t.Fatalf("%s holds no published page, so this guard reads nothing", documentationRoot)
	}
}
