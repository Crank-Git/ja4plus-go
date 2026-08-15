package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
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

// coreWalkMustReach names each path prefix that the walk of the core package parses a file
// under.
//
// A count of parsed files reports a walk that read nothing, and it reports no walk that read
// the repository root and skipped a subtree. The root holds about fifteen production files,
// so a skip of `internal/` leaves that count high and the guard then reports a property it
// never checked.
var coreWalkMustReach = []string{"internal/"}

// httpClientImportSite returns each line of each production file below the root that imports
// the HTTP client, keyed by the path.
//
// It reads no test file. A test file reaches no released binary, and `go list -deps` reads
// no test import either, so the two parts of this guard measure one set of files.
//
// mustReach names each path prefix that the walk parses a file under. An empty list states
// that the caller reads one directory, and it makes no claim about a subtree.
func httpClientImportSite(t *testing.T, root string, skipDir map[string]bool, mustReach []string) map[string][]int {
	t.Helper()

	site := map[string][]int{}
	reached := map[string]bool{}
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

		for _, prefix := range mustReach {
			if strings.HasPrefix(path, prefix) {
				reached[prefix] = true
			}
		}

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

	// A walk that skipped one subtree still parses the files of the root, so the count above
	// stays high and reports nothing.
	for _, prefix := range mustReach {
		if !reached[prefix] {
			t.Fatalf("the walk of %s parsed no production Go file under %s, and the guard reads every one of them",
				root, prefix)
		}
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
	for path, lines := range httpClientImportSite(t, ".", networkBoundarySkipDir, coreWalkMustReach) {
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
	site := httpClientImportSite(t, remoteLookupPackageDir, map[string]bool{}, nil)

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

	// The page writes an option at the head of a sentence and inside a table cell, so the
	// first letter carries no meaning here. The reader lowers the case for the option alone.
	lowered := strings.ToLower(record)

	// FR-lookup-2 names three options, and the record names every one of them.
	for _, option := range []string{
		"keep the remote lookup in the package",
		"move it behind a build tag",
		"move it to a separate package",
	} {
		if !strings.Contains(lowered, option) {
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

// The maintainer narrowed the boundary on 2026-08-15 UTC, and comment 5299776533 of issue
// #613 holds that ruling. The boundary names an HTTP call and a remote lookup, and it names
// no raw socket. `internal/capture` reads a local interface through a raw socket, and that
// reach is outside the boundary.
//
// The guard below holds the narrowed rule. It permits `internal/capture/` alone, so a second
// package that calls one of the functions of `socketOpenFunction` fails the test. Issue #613
// is the reversal path.
//
// The guard reads one call site, and it resolves no type. So it reaches a direct call, and it
// reaches no call that a helper of a permitted package wraps. A package that calls an
// exported helper of `internal/capture` opens a socket, and this guard reports nothing about
// it. `docs/audit/network-boundary.md` states that limit, and no sentence of this file claims
// a reach the guard does not hold.

// socketOpenFunction names each function that opens a socket, keyed by the import path of
// the package that declares it.
//
// The guard reads a call site, and it reads no import. One import carries both meanings:
// `pcapgo.NewReader` reads a capture file, and `pcapgo.NewEthernetHandle` opens a packet
// socket. `examples/readcapture/main.go` imports that package for the reader alone.
var socketOpenFunction = map[string][]string{
	"syscall":                             {"Socket"},
	"net":                                 {"Dial", "DialTimeout", "Listen", "ListenPacket"},
	"github.com/gopacket/gopacket/pcap":   {"OpenLive"},
	"github.com/gopacket/gopacket/pcapgo": {"NewEthernetHandle"},
}

// socketPermittedDir names the one directory that the ruling of #613 permits a socket open
// in. The value ends with a separator, so it names no sibling directory of a longer name.
const socketPermittedDir = "internal/capture/"

// isPermittedSocketPath reports whether the ruling of #613 permits a socket open in the file.
func isPermittedSocketPath(path string) bool {
	return strings.HasPrefix(path, socketPermittedDir)
}

// importedPackageName returns the local name of one import of a parsed file.
//
// A named import states the local name. An unnamed import takes the last element of the
// import path, which holds for every package that `socketOpenFunction` names.
func importedPackageName(spec *ast.ImportSpec, importPath string) string {
	if spec.Name != nil {
		return spec.Name.Name
	}

	return path.Base(importPath)
}

// socketOpenSite returns each line of each production file below the root that calls a
// function of socketOpenFunction, keyed by the path.
//
// It reads no test file, because a test file reaches no released binary.
//
// It resolves the local name of each import before it reads a call, so an aliased import
// reports and an unrelated identifier of the same spelling does not.
func socketOpenSite(t *testing.T, root string, skipDir map[string]bool) map[string][]int {
	t.Helper()

	site := map[string][]int{}
	parsed := 0

	err := filepath.WalkDir(root, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		walkPath = filepath.ToSlash(walkPath)

		if entry.IsDir() {
			if skipDir[walkPath] {
				return fs.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(walkPath, ".go") || strings.HasSuffix(walkPath, "_test.go") {
			return nil
		}

		content, readErr := os.ReadFile(walkPath)
		if readErr != nil {
			return readErr
		}

		fset := token.NewFileSet()

		file, parseErr := parser.ParseFile(fset, walkPath, content, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Errorf("parse %s: %v", walkPath, parseErr)

			return nil
		}

		parsed++

		// The map keys the local name of an import to the function list of the package it
		// names, so the reader below reads one identifier and not an import path.
		opener := map[string][]string{}

		for _, spec := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("read the import path %s of %s: %v", spec.Path.Value, walkPath, unquoteErr)

				continue
			}

			functions, named := socketOpenFunction[importPath]
			if !named {
				continue
			}

			localName := importedPackageName(spec, importPath)

			// A dot import writes a call as a bare identifier, so the reader below reads no
			// selector for it. The guard reports the import itself, because a silent pass is
			// worse than a report of an import that opens no socket.
			if localName == "." {
				site[walkPath] = append(site[walkPath], fset.Position(spec.Pos()).Line)

				continue
			}

			opener[localName] = functions
		}

		if len(opener) == 0 {
			return nil
		}

		ast.Inspect(file, func(node ast.Node) bool {
			selector, isSelector := node.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}

			identifier, isIdentifier := selector.X.(*ast.Ident)
			if !isIdentifier {
				return true
			}

			for _, function := range opener[identifier.Name] {
				if selector.Sel.Name == function {
					site[walkPath] = append(site[walkPath], fset.Position(selector.Pos()).Line)
				}
			}

			return true
		})

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

// writeSocketGuardFixture writes one production Go file into a directory of the root, and it
// returns the root. The guard reads a temporary tree, so no fixture reaches the repository.
func writeSocketGuardFixture(t *testing.T, dir string, name string, source string) string {
	t.Helper()

	root := t.TempDir()
	packageDir := filepath.Join(root, dir)

	if err := os.MkdirAll(packageDir, 0o750); err != nil {
		t.Fatalf("create the fixture directory %s: %v", packageDir, err)
	}

	if err := os.WriteFile(filepath.Join(packageDir, name), []byte(source), 0o600); err != nil {
		t.Fatalf("write the fixture file %s: %v", name, err)
	}

	return root
}

// TestTheSocketReaderReportsAPackageOutsideTheCaptureBackendThatOpensASocket proves that the
// reader fires. A guard that permits every package guards nothing, so the negative case is
// the case that carries the ruling of #613.
func TestTheSocketReaderReportsAPackageOutsideTheCaptureBackendThatOpensASocket(t *testing.T) {
	root := writeSocketGuardFixture(t, "internal/other", "probe.go", `package other

import "syscall"

func probe() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
}
`)

	site := socketOpenSite(t, root, map[string]bool{})

	if len(site) != 1 {
		t.Fatalf("the reader reports %d file that opens a socket, and the fixture holds one", len(site))
	}

	for reported, lines := range site {
		if !strings.HasSuffix(reported, "internal/other/probe.go") {
			t.Errorf("the reader reports %s, and the fixture opens the socket in internal/other/probe.go", reported)
		}

		if len(lines) != 1 {
			t.Errorf("the reader reports %v for %s, and the fixture holds one call", lines, reported)
		}
	}
}

// TestTheSocketReaderReportsADotImportOfASocketPackage holds the one bypass that the selector
// reader cannot see. A dot import writes the call as a bare identifier, so the guard reports
// the import and it passes no file silently.
func TestTheSocketReaderReportsADotImportOfASocketPackage(t *testing.T) {
	root := writeSocketGuardFixture(t, "internal/other", "probe.go", `package other

import . "syscall"

func probe() (int, error) {
	return Socket(AF_INET, SOCK_RAW, 0)
}
`)

	site := socketOpenSite(t, root, map[string]bool{})

	if len(site) != 1 {
		t.Fatalf("the reader reports %d file for a dot import, and the fixture holds one", len(site))
	}

	for reported, lines := range site {
		if len(lines) != 1 || lines[0] != 3 {
			t.Errorf("the reader reports %v for %s, and the dot import sits at line 3", lines, reported)
		}
	}
}

// TestTheSocketReaderReportsNoInterfaceLookup holds the reading that separates the two
// reaches. `net.InterfaceByName` reads the interface list of the host, and it opens no
// socket that the caller reads a packet from. `internal/capture/capture.go` calls it.
func TestTheSocketReaderReportsNoInterfaceLookup(t *testing.T) {
	root := writeSocketGuardFixture(t, "internal/other", "lookup.go", `package other

import "net"

func lookup(name string) error {
	_, err := net.InterfaceByName(name)

	return err
}
`)

	if site := socketOpenSite(t, root, map[string]bool{}); len(site) != 0 {
		t.Errorf("the reader reports %v for an interface lookup, and a lookup opens no socket", site)
	}
}

// TestTheSocketPermitListNamesTheCaptureBackendAlone holds the ruling of #613. A permit list
// that reaches a second package permits every package, and it then guards nothing.
func TestTheSocketPermitListNamesTheCaptureBackendAlone(t *testing.T) {
	for _, path := range []string{
		"lookup.go",
		"ja4db/remote.go",
		"internal/parser/tls.go",
		"internal/capturebackend/open.go",
	} {
		if isPermittedSocketPath(path) {
			t.Errorf("the permit list of #613 permits a socket open in %s, and it permits %s alone",
				path, socketPermittedDir)
		}
	}

	if !isPermittedSocketPath(socketPermittedDir + "open.go") {
		t.Errorf("the permit list of #613 permits no socket open in %s, and the ruling permits that directory",
			socketPermittedDir)
	}
}

// TestTheCaptureBackendOpensASocket proves that the reader above finds the call it looks for.
// A clean result from a broken reader guards nothing.
func TestTheCaptureBackendOpensASocket(t *testing.T) {
	site := socketOpenSite(t, strings.TrimSuffix(socketPermittedDir, "/"), map[string]bool{})

	if len(site) == 0 {
		t.Errorf("no production file of %s opens a socket.\n"+
			"\tThat directory holds the capture backend, so the reader of this guard reads nothing\n"+
			"\tand the clean result of the library proves nothing.", socketPermittedDir)
	}
}

// TestNoProductionFileOutsideTheCaptureBackendOpensASocket holds the ruling of #613. The
// library opens a raw socket in `internal/capture` alone.
func TestNoProductionFileOutsideTheCaptureBackendOpensASocket(t *testing.T) {
	site := socketOpenSite(t, ".", networkBoundarySkipDir)
	reachedTheCaptureBackend := false

	for path, lines := range site {
		if isPermittedSocketPath(path) {
			reachedTheCaptureBackend = true

			continue
		}

		sort.Ints(lines)

		t.Errorf("%s opens a socket at line %v, and it is no test file.\n"+
			"\tThe maintainer ruled on 2026-08-15 that the library opens a socket in %s alone.\n"+
			"\tMove the code to that directory, or record a reversal of that ruling. %s holds the record.",
			path, lines, socketPermittedDir, networkBoundaryRecordPage)
	}

	// A walk that skipped `internal/` still parses the files of the root, so the count of
	// parsed files stays high and the clean result above reports nothing.
	if !reachedTheCaptureBackend {
		t.Fatalf("the walk of the repository root reports no socket open under %s, and that directory holds one.\n"+
			"\tThe walk read no file of it, so the clean result of this guard states a property it never checked.",
			socketPermittedDir)
	}
}

// TestTheNetworkBoundaryRecordNamesTheAmendmentOfTheLibraryExtent holds the rule that a
// ruling record names the date, the issue and the reversal path. A record that names none of
// them is a record the next reader re-litigates.
func TestTheNetworkBoundaryRecordNamesTheAmendmentOfTheLibraryExtent(t *testing.T) {
	record := readRepoFile(t, networkBoundaryRecordPage)

	for _, named := range []string{
		"2026-08-15",
		"#613",
		"internal/capture",
		"TestNoProductionFileOutsideTheCaptureBackendOpensASocket",
	} {
		if !strings.Contains(record, named) {
			t.Errorf("%s names no %s, and the amendment of the boundary states the date, the issue and the guard",
				networkBoundaryRecordPage, named)
		}
	}
}

// TestTheAmendmentCitesAnIdentifierThatTheCaptureBackendDeclares holds the citation rule of
// `.claude/rules/ste.md` `## How a citation names its target`.
//
// The first draft of the record cited a line of `pcapgo_linux.go`, and the sub-merge of #609
// moved that call to another line inside one batch. An identifier survives that edit, and
// this guard fails when the identifier leaves the file.
func TestTheAmendmentCitesAnIdentifierThatTheCaptureBackendDeclares(t *testing.T) {
	record := readRepoFile(t, networkBoundaryRecordPage)

	for identifier, file := range map[string]string{
		"captureRefusal": socketPermittedDir + "permission_linux.go",
		"open":           socketPermittedDir + "pcapgo_linux.go",
	} {
		if !strings.Contains(record, "`"+identifier+"` in `"+file+"`") {
			t.Errorf("%s names no %q in %q, and the amendment cites the identifier rather than the line",
				networkBoundaryRecordPage, identifier, file)

			continue
		}

		if !strings.Contains(readRepoFile(t, file), "\nfunc "+identifier+"(") {
			t.Errorf("%s declares no %s, and %s cites that identifier",
				file, identifier, networkBoundaryRecordPage)
		}
	}
}

// TestNoPageStatesThatTheCaptureBackendSitsOutsideTheLibrary holds the ruling of #613 in the
// documents. One word carries one extent, and the sentence below carried a second one.
func TestNoPageStatesThatTheCaptureBackendSitsOutsideTheLibrary(t *testing.T) {
	const falsifiedSentence = "The library opens no interface."

	for _, page := range []string{
		"CLAUDE.md",
		networkBoundaryRecordPage,
		"docs/specs/features/13-live-capture.md",
		termsTableFile,
	} {
		if strings.Contains(readRepoFile(t, page), falsifiedSentence) {
			t.Errorf("%s states %q, and the ruling of #613 places internal/capture inside the library",
				page, falsifiedSentence)
		}
	}
}

// TestTheSecurityPostureNamesTheRawCaptureSocket holds the second acceptance criterion of
// #613. The `### Security posture` list states what the library reaches, and the raw capture
// socket is one of the two reaches it now names.
func TestTheSecurityPostureNamesTheRawCaptureSocket(t *testing.T) {
	const securityPostureHeading = "\n### Security posture\n"

	page := readRepoFile(t, termsTableFile)

	start := strings.Index(page, securityPostureHeading)
	if start < 0 {
		t.Fatalf("%s holds no %q heading, and the security posture list sits under it",
			termsTableFile, "### Security posture")
	}

	section := page[start+len(securityPostureHeading):]
	if end := strings.Index(section, "\n### "); end >= 0 {
		section = section[:end]
	}

	for _, named := range []string{"internal/capture", "#613"} {
		if !strings.Contains(section, named) {
			t.Errorf("the `### Security posture` list of %s names no %s, and the ruling of #613 makes the raw capture socket the second reach of the library",
				termsTableFile, named)
		}
	}
}

// TestTheTermsTableDefinesTheLibrary holds the third acceptance criterion of #613. Two pages
// gave the word two extents, and `.claude/rules/ste.md` rule 6 states one word, one meaning.
func TestTheTermsTableDefinesTheLibrary(t *testing.T) {
	rows := readTermsTableRows(t)

	row, held := rows["library"]
	if !held {
		t.Fatalf("the `## Terms` table of %s holds no row for %q, and the ruling of #613 states its extent",
			termsTableFile, "library")
	}

	if !strings.Contains(row.Meaning, "internal/capture") {
		t.Errorf("the `library` row of the `## Terms` table of %s names no internal/capture, and the ruling of #613 places that package inside",
			termsTableFile)
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
