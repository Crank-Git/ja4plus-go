package repocheck

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// environmentConfigSpec holds the `## Environments & config` table.
const environmentConfigSpec = "docs/specs/spec.md"

// environmentConfigHeading opens the section that holds the table.
const environmentConfigHeading = "## Environments & config"

// environmentVariableRow matches one row of the table, and it captures the variable name of
// the first column.
var environmentVariableRow = regexp.MustCompile("(?m)^\\| `([A-Z][A-Z0-9_]*)` \\|")

// environmentConfigVariables returns each variable name that the table names.
func environmentConfigVariables(t *testing.T) []string {
	t.Helper()

	spec := readRepoFile(t, environmentConfigSpec)

	start := strings.Index(spec, "\n"+environmentConfigHeading+"\n")
	if start < 0 {
		t.Fatalf("%s holds no %q section", environmentConfigSpec, environmentConfigHeading)
	}

	section := spec[start+1:]
	if end := strings.Index(section[len(environmentConfigHeading):], "\n## "); end >= 0 {
		section = section[:len(environmentConfigHeading)+end]
	}

	var names []string
	for _, match := range environmentVariableRow.FindAllStringSubmatch(section, -1) {
		names = append(names, match[1])
	}

	if len(names) == 0 {
		t.Fatalf("the %q section of %s names no variable", environmentConfigHeading, environmentConfigSpec)
	}

	return names
}

// environmentReaderText returns the text of every file that can read a variable: each
// production Go file of the tree, each file under `scripts/`, and each workflow file.
//
// A Go file reads a variable through a string literal, so the Go text keeps only the quoted
// form of a name. A comment line of a shell script or a workflow reads nothing, so the text
// drops each line that opens with `#`.
func environmentReaderText(t *testing.T) (goText, otherText string) {
	t.Helper()

	var goParts, otherParts []string

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			switch path {
			case ".git", ".claude", "docs", "testdata", "bin":
				return filepath.SkipDir
			}

			return nil
		}

		switch {
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
			goParts = append(goParts, readRepoFile(t, path))
		case strings.HasPrefix(path, "scripts"+string(filepath.Separator)),
			strings.HasPrefix(path, filepath.Join(".github", "workflows")+string(filepath.Separator)):
			for _, line := range strings.Split(readRepoFile(t, path), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") {
					otherParts = append(otherParts, line)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}

	return strings.Join(goParts, "\n"), strings.Join(otherParts, "\n")
}

// TestEveryEnvironmentConfigRowNamesAVariableThatAFileReads holds #804. The table named three
// variables that no file read, and the table was the only file that held each name. So a user
// who set one of them got nothing, and no check reported it.
//
// The test passes when a production Go file holds the name as a string literal, or when a
// script or a workflow holds the name outside a comment line. The test reads no `.github/`
// directory other than `workflows`, because a workflow is the one file there that a runner
// executes.
func TestEveryEnvironmentConfigRowNamesAVariableThatAFileReads(t *testing.T) {
	goText, otherText := environmentReaderText(t)

	for _, name := range environmentConfigVariables(t) {
		if strings.Contains(goText, `"`+name+`"`) {
			continue
		}

		if regexp.MustCompile(`\b` + name + `\b`).MatchString(otherText) {
			continue
		}

		t.Errorf("the %q table of %s names %s, and no production Go file, script or workflow reads it",
			environmentConfigHeading, environmentConfigSpec, name)
	}
}
