package ja4plus

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #72 holds this guard, and `docs/audit/network-boundary.md` holds the record.
//
// The maintainer ruled the boundary question on 2026-08-14, and the ruling chose the third
// option of FR-lookup-2: the remote lookup moves to a separate package. FR-lookup-4 states
// that the default build of the library performs no network input and no network output
// unless the caller calls a function whose name states that it does.
//
// A naming convention holds that requirement only while every later contributor reads the
// convention. A package boundary holds it structurally, because the core package imports no
// HTTP client and a reader of the import list sees that.
//
// This guard holds a property of this repository, and it makes no network call.

// httpClientImportPath names the import path of the HTTP client of the standard library.
// The guard also reads a subpackage of it, such as `net/http/httptest`, because a
// subpackage carries the same reach.
const httpClientImportPath = "net/http"

// networkBoundarySkipDir names each directory that the core walk declines, as a path from
// the repository root.
//
// Two of the entries carry the boundary, and the rest hold no Go file of the library.
//
//   - `cmd` holds the command-line program. `CLAUDE.md` states that all output belongs to
//     it, and `ja4plus db update` downloads the mapping file.
//   - `ja4db` holds the remote lookup. That package is the network side of the boundary.
//
// The rule reads the whole path, and it reads no base name. A base-name rule would skip a
// later `internal/cmd/` and report a property it never checked.
var networkBoundarySkipDir = map[string]bool{
	".git":     true,
	".claude":  true,
	".github":  true,
	"bin":      true,
	"cmd":      true,
	"docs":     true,
	"ja4db":    true,
	"testdata": true,
}

// remoteLookupPackageDir names the directory of the package that holds the remote lookup.
const remoteLookupPackageDir = "ja4db"

// remoteLookupImportPath names the import path of that package. The core package imports it
// nowhere, so the import graph holds no cycle.
const remoteLookupImportPath = "github.com/Crank-Git/ja4plus-go/ja4db"

// remoteLookupFunction names the one exported function that reaches the network.
const remoteLookupFunction = "LookupFingerprintRemote"

// networkBoundaryRecordPage records the decision, the three options and the reason.
const networkBoundaryRecordPage = "docs/audit/network-boundary.md"

// httpClientImportSite returns each line of each production file below the root that imports
// the HTTP client, keyed by the path.
//
// It reads no test file. A test file reaches no released binary, and `go list -deps` reads
// no test import either, so the two parts of this guard measure one set of files.
func httpClientImportSite(t *testing.T, root string, skipDir map[string]bool) map[string][]int {
	t.Helper()

	site := map[string][]int{}
	parsed := 0

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		path = filepath.ToSlash(path)

		if entry.IsDir() {
			if skipDir[path] {
				return fs.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		fset := token.NewFileSet()

		file, parseErr := parser.ParseFile(fset, path, content, parser.ImportsOnly|parser.SkipObjectResolution)
		if parseErr != nil {
			t.Errorf("parse %s: %v", path, parseErr)

			return nil
		}

		parsed++

		for _, spec := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("read the import path %s of %s: %v", spec.Path.Value, path, unquoteErr)

				continue
			}

			if !isHTTPClientImport(importPath) {
				continue
			}

			site[path] = append(site[path], fset.Position(spec.Pos()).Line)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the production files of %s: %v", root, err)
	}

	// A walk that parsed nothing would pass every test below and read no file.
	if parsed == 0 {
		t.Fatalf("the walk of %s parsed no production Go file, and the guard reads every one of them", root)
	}

	return site
}

// isHTTPClientImport reports whether the import path names the HTTP client or a subpackage
// of it.
func isHTTPClientImport(importPath string) bool {
	return importPath == httpClientImportPath ||
		strings.HasPrefix(importPath, httpClientImportPath+"/")
}

// TestNoProductionFileOfTheCorePackageImportsAnHTTPClient holds the property that the ruling
// of #72 states. The core package and every package below `internal/` reach no HTTP client.
func TestNoProductionFileOfTheCorePackageImportsAnHTTPClient(t *testing.T) {
	for path, lines := range httpClientImportSite(t, ".", networkBoundarySkipDir) {
		sort.Ints(lines)

		t.Errorf("%s imports %s at line %v, and it is no test file.\n"+
			"\tThe maintainer ruled on 2026-08-14 that the remote lookup lives in the %s package.\n"+
			"\tMove the network code to %s, or record a reversal of that ruling. %s holds the record.",
			path, httpClientImportPath, lines, remoteLookupPackageDir, remoteLookupPackageDir,
			networkBoundaryRecordPage)
	}
}

// TestTheRemoteLookupPackageImportsAnHTTPClient proves that the reader above finds the import
// it looks for. A clean result from a broken reader guards nothing.
func TestTheRemoteLookupPackageImportsAnHTTPClient(t *testing.T) {
	site := httpClientImportSite(t, remoteLookupPackageDir, map[string]bool{})

	if len(site) == 0 {
		t.Errorf("no production file of %s imports %s.\n"+
			"\tThat package holds the remote lookup, so the reader of this guard reads nothing\n"+
			"\tand the clean result of the core package proves nothing.",
			remoteLookupPackageDir, httpClientImportPath)
	}
}

// TestTheDependencyGraphOfTheCorePackageHoldsNoHTTPClient reads the whole import graph, and
// the guard above reads one import list. A dependency of this module that adds the import
// reaches the released binary, and no walk of this repository sees it.
func TestTheDependencyGraphOfTheCorePackageHoldsNoHTTPClient(t *testing.T) {
	goCommand, lookErr := exec.LookPath("go")
	if lookErr != nil {
		t.Skipf("the go command is absent, so this run checks no transitive import: %v", lookErr)
	}

	out, err := exec.Command(goCommand, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps .: %v\n%s", err, out)
	}

	var found []string

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if isHTTPClientImport(strings.TrimSpace(line)) {
			found = append(found, line)
		}
	}

	if len(found) > 0 {
		t.Errorf("the dependency graph of the core package holds %v.\n"+
			"\tFR-lookup-4 states that the default build performs no network input and no network output\n"+
			"\tunless the caller calls a function whose name states that it does.\n"+
			"\t%s holds the record of the ruling.", found, networkBoundaryRecordPage)
	}
}

// TestTheNetworkBoundaryRecordNamesTheDecisionAndTheReason holds FR-lookup-1, FR-lookup-2 and
// FR-lookup-3. A record that names one option states no decision, because a decision is a
// choice between the three.
func TestTheNetworkBoundaryRecordNamesTheDecisionAndTheReason(t *testing.T) {
	record := readRepoFile(t, networkBoundaryRecordPage)

	// FR-lookup-2 names three options, and the record names every one of them.
	for _, option := range []string{
		"keep the remote lookup in the package",
		"move it behind a build tag",
		"move it to a separate package",
	} {
		if !strings.Contains(record, option) {
			t.Errorf("%s names no option %q, and FR-lookup-2 names three options",
				networkBoundaryRecordPage, option)
		}
	}

	// The record names the package that the decision creates, and the function that reaches
	// the network. A record that names neither leaves the reader with no way to check it.
	for _, named := range []string{remoteLookupImportPath, remoteLookupFunction} {
		if !strings.Contains(record, named) {
			t.Errorf("%s names no %s, and the decision moves it", networkBoundaryRecordPage, named)
		}
	}

	// The page reports a property of this repository, so it names the guard that holds it.
	if !strings.Contains(record, "TestNoProductionFileOfTheCorePackageImportsAnHTTPClient") {
		t.Errorf("%s names no guard, and a record without a guard states an unheld property",
			networkBoundaryRecordPage)
	}
}

// TestThePackageDocumentationAndTheReadmeNameTheNetworkFunction holds FR-lookup-5 and
// FR-lookup-6. Each page states which function reaches the network.
func TestThePackageDocumentationAndTheReadmeNameTheNetworkFunction(t *testing.T) {
	for _, page := range []string{"doc.go", "README.md"} {
		content := readRepoFile(t, page)

		for _, named := range []string{remoteLookupImportPath, remoteLookupFunction} {
			if !strings.Contains(content, named) {
				t.Errorf("%s names no %s, and it states which function reaches the network", page, named)
			}
		}
	}
}
