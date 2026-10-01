package repocheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
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

// environmentReaderText returns the variable names that a production Go file reads, and the
// text of each file under `scripts/` and each workflow file.
//
// A comment line of a shell script or a workflow reads nothing, so the text drops each line
// that opens with `#`.
func environmentReaderText(t *testing.T) (goReads map[string]bool, otherText string) {
	t.Helper()

	goSources := map[string]string{}

	var otherParts []string

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
			goSources[path] = readRepoFile(t, path)
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

	return goEnvironmentReads(t, goSources), strings.Join(otherParts, "\n")
}

// goEnvironmentReads returns each variable name that a Go source passes to a call named
// `Getenv` or `LookupEnv`. The sources map a file path to its text.
//
// The name is a string literal of the call, or a string constant of the same directory that
// the call names. A string literal elsewhere reads no variable, so this function ignores
// it. The match on the call name ignores case, because `cmd/ja4plus` passes `os.Getenv` as a
// parameter named `getenv`, so that a test reads a map and never the process environment.
func goEnvironmentReads(t *testing.T, sources map[string]string) map[string]bool {
	t.Helper()

	files := token.NewFileSet()
	parsed := map[string]*ast.File{}
	constants := map[string]string{}

	for path, source := range sources {
		file, err := parser.ParseFile(files, path, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		parsed[path] = file

		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}

			for _, spec := range general.Specs {
				value := spec.(*ast.ValueSpec)
				for index, name := range value.Names {
					if index < len(value.Values) {
						if text, ok := stringLiteral(value.Values[index]); ok {
							constants[filepath.Dir(path)+"/"+name.Name] = text
						}
					}
				}
			}
		}
	}

	reads := map[string]bool{}

	for path, file := range parsed {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || !isEnvironmentCall(call.Fun) {
				return true
			}

			if text, ok := stringLiteral(call.Args[0]); ok {
				reads[text] = true
			} else if ident, ok := call.Args[0].(*ast.Ident); ok {
				if text, held := constants[filepath.Dir(path)+"/"+ident.Name]; held {
					reads[text] = true
				}
			}

			return true
		})
	}

	return reads
}

// isEnvironmentCall reports whether the called function carries the name `Getenv` or
// `LookupEnv`, in any case.
func isEnvironmentCall(function ast.Expr) bool {
	var name string

	switch typed := function.(type) {
	case *ast.Ident:
		name = typed.Name
	case *ast.SelectorExpr:
		name = typed.Sel.Name
	default:
		return false
	}

	return strings.EqualFold(name, "Getenv") || strings.EqualFold(name, "LookupEnv")
}

// stringLiteral returns the value of a string literal expression.
func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}

	text, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}

	return text, true
}

// TestEveryEnvironmentConfigRowNamesAVariableThatAFileReads holds #804. The table named three
// variables that no file read, and the table was the only file that held each name. So a user
// who set one of them got nothing, and no check reported it.
//
// The test passes when a production Go file passes the name to a `Getenv` or `LookupEnv`
// call, or when a script or a workflow holds the name outside a comment line. The test read
// any quoted literal of a Go file until the batch #807 gate, so a name that no call read
// passed it. The test reads no `.github/` directory other than `workflows`, because a
// workflow is the one file there that a runner executes.
func TestEveryEnvironmentConfigRowNamesAVariableThatAFileReads(t *testing.T) {
	goReads, otherText := environmentReaderText(t)

	for _, name := range environmentConfigVariables(t) {
		if goReads[name] {
			continue
		}

		if regexp.MustCompile(`\b` + name + `\b`).MatchString(otherText) {
			continue
		}

		t.Errorf("the %q table of %s names %s, and no production Go file, script or workflow reads it",
			environmentConfigHeading, environmentConfigSpec, name)
	}
}

func TestTheGoReaderCountsAGetenvCallAndNeverABareLiteral(t *testing.T) {
	sources := map[string]string{
		"a/literal.go":  "package a\n\nvar name = \"BARE_LITERAL\"\n",
		"a/direct.go":   "package a\n\nimport \"os\"\n\nvar v = os.Getenv(\"DIRECT_CALL\")\n",
		"b/constant.go": "package b\n\nconst variable = \"CONSTANT_CALL\"\n",
		"b/reader.go": "package b\n\nimport \"os\"\n\n" +
			"func read() bool { _, ok := os.LookupEnv(variable); return ok }\n",
		"c/param.go": "package c\n\nconst variable = \"PARAMETER_CALL\"\n\n" +
			"func read(getenv func(string) string) string { return getenv(variable) }\n",
	}

	reads := goEnvironmentReads(t, sources)

	for _, name := range []string{"DIRECT_CALL", "CONSTANT_CALL", "PARAMETER_CALL"} {
		if !reads[name] {
			t.Errorf("the reader misses %s", name)
		}
	}

	if reads["BARE_LITERAL"] {
		t.Error("the reader counts a bare string literal that no call reads")
	}
}
