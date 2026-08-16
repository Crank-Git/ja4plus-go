package ja4plus

import (
	"os"
	"strings"
	"testing"
)

// readRepoFile returns the content of a file in the repository root.
// It fails the test when the file is absent.
//
// `internal/repocheck` holds the same helper, and the two cannot be shared. A test helper
// lives in a `_test.go` file, and no package imports another package's test files. The
// tests of this package that read a tracked file are the few that also reach a symbol of
// the library, so they stay here while the rest moved.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// makefileRecipe returns the recipe of a target in the `Makefile`.
// It fails the test when the `Makefile` holds no such target.
//
// A recipe line starts with a tab, so the first line without one ends the recipe.
// `internal/repocheck` holds the same helper, for the reason `readRepoFile` states above.
func makefileRecipe(t *testing.T, target string) string {
	t.Helper()

	recipe := []string{}
	found := false

	for _, line := range strings.Split(readRepoFile(t, "Makefile"), "\n") {
		if !found {
			found = strings.HasPrefix(line, target+":")

			continue
		}

		if !strings.HasPrefix(line, "\t") {
			break
		}

		recipe = append(recipe, line)
	}

	if !found {
		t.Fatalf("the Makefile holds no %s target", target)
	}

	return strings.Join(recipe, "\n")
}
