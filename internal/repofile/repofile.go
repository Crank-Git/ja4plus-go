// Package repofile names the tracked files of this repository and reads them for a test.
//
// Two test packages read the same tracked files: `ja4plus` holds the tests that also reach
// the library, and `internal/repocheck` holds the tests that read this repository alone. A
// test helper lives in a `_test.go` file, and no package imports another package's test
// files. A name that both packages need therefore lives here rather than in either one.
//
// A caller runs from the repository root. `TestMain` of `internal/repocheck` enters it, and
// the tests of `ja4plus` already run there.
package repofile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DocsBuildWorkflow builds the documentation site on a pull request.
const DocsBuildWorkflow = ".github/workflows/docs-build.yml"

// DocsPublishWorkflow publishes the documentation site from the default branch.
const DocsPublishWorkflow = ".github/workflows/docs.yml"

// DocumentationSiteURL is the address the published documentation site answers on.
const DocumentationSiteURL = "https://crank-git.github.io/ja4plus-go/"

// ProductionGoFiles returns every Go file of one directory that the build compiles into
// the package. It skips a subdirectory and it skips a test file, so the result names the
// surface a consumer of the package reaches.
func ProductionGoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read the directory %s: %w", dir, err)
	}

	var paths []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		paths = append(paths, filepath.Join(dir, name))
	}

	sort.Strings(paths)

	return paths, nil
}

// MkdocsConfigPath is the site configuration, at the repository root. FR-documentation-2
// puts it there.
const MkdocsConfigPath = "mkdocs.yml"

// DocsRequirements pins the generator that builds the site.
const DocsRequirements = "docs/requirements.txt"

// DocumentationRoot holds every page the site publishes.
const DocumentationRoot = "docs"

// ExampleTestFile holds one testable example for each fenced Go block of `docs/`.
const ExampleTestFile = "example_test.go"

// ExamplesRoot holds one runnable program for each fenced Go block of `docs/`.
// FR-documentation-25 requires the directory.
const ExamplesRoot = "examples"

// ExcludedDocumentationDirs names every directory of `docs/` that `exclude_docs` of
// `mkdocs.yml` drops from the built site.
//
// One list serves every walker of `docs/`, so a sixth exclusion reaches each guard at once.
// #91 added `mutation_reports` under FR-mutation-6, #92 added `mutation_settlements`
// under FR-mutation-13, and #101 added `api` under FR-release-1.
var ExcludedDocumentationDirs = []string{"specs", "audit", "mutation_reports", "mutation_settlements", "api"}

// IsExcludedDocumentationDir reports whether the site publishes no page of the directory.
func IsExcludedDocumentationDir(name string) bool {
	for _, excluded := range ExcludedDocumentationDirs {
		if name == excluded {
			return true
		}
	}

	return false
}

// Read returns the text of a tracked file. It returns an error when the file is absent.
func Read(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	return string(content), nil
}
