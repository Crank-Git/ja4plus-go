package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #510 holds this guard, and `docs/audit/gopacket-tcp-option-panic.md` holds the record.
//
// `layers.TCP.DecodeFromBytes` of `github.com/gopacket/gopacket` v1.6.1 reads two bytes of
// a Multipath TCP option without a length guard, at `layers/tcp.go:347-353`. The `default`
// branch of the same loop guards that read, at `layers/tcp.go:534-538`. So the option kind
// `30` as the last byte of the option region panics.
//
// `gopacket.NewPacket` recovers a panic of a decoder, and it covers no direct call. So a
// production line that calls the method on untrusted bytes adds a crash path. `CLAUDE.md`
// states that every packet is untrusted input, and that a fingerprinter returns a non-fatal
// error and never a panic.
//
// This guard holds a property of this repository, and it triggers no panic. A test that
// triggered the panic would assert third-party behavior, and a dependency bump can change
// that behavior. Such a test would also leave the repository free to add the call this guard
// exists to prevent.

// directDecodeMethod names the method that no production line calls.
//
// The guard reads the method name, and it reads no receiver type. A receiver reaches the
// call site through a variable, an interface value or a type alias. So a type rule would
// miss a call that this rule catches. Every `DecodeFromBytes` of `gopacket` decodes
// untrusted bytes outside the recovery of `gopacket.NewPacket`, so the name is the property.
const directDecodeMethod = "DecodeFromBytes"

// directDecodeSkipDir names each directory the walk declines, as a path from the repository
// root. `testdata/foxio/` holds the fetched FoxIO corpus, and no Go file of this module lives
// below it.
//
// The set names no directory that can hold a production Go file. A skip of such a directory
// would leave a call site unread, and the guard would report a property it never checked.
//
// The rule reads the whole path, and it reads no base name. A base-name rule would skip a
// later `internal/bin/` and report a property it never checked, because `bin` names a
// directory at the root today and a base name carries no depth.
var directDecodeSkipDir = map[string]bool{
	".git":     true,
	".claude":  true,
	".github":  true,
	"bin":      true,
	"docs":     true,
	"testdata": true,
}

// directDecodeRecordPage records the panic, the two cited ranges and the pinned version.
const directDecodeRecordPage = "docs/audit/gopacket-tcp-option-panic.md"

// directDecodeCitedRange names each range of `layers/tcp.go` that the record page cites.
// The first range holds the unguarded read, and the second holds the guard of the `default`
// branch.
var directDecodeCitedRange = []string{
	"layers/tcp.go:347-353",
	"layers/tcp.go:534-538",
}

// directDecodeException records each production file that calls the method, with the reason.
//
// The table is empty on 2026-08-14, because no production line of the tree calls the method.
// One entry states one file, the count of call sites on it, and why the call is safe. A
// stale entry fails TestTheDirectDecodeExceptionTableHoldsNoStaleEntry, so an exception
// cannot outlive the call it excuses.
var directDecodeException = []struct {
	file   string
	count  int
	reason string
}{}

// directDecodeCallSite returns each line of each production file that calls the method,
// keyed by the path. It reads the abstract syntax tree, so a comment that names the method
// reaches no result. #494 wrote one such comment, and a comment is not a call.
//
// The rule reads a call whose function is a selector, which is the form every direct call
// takes. It reads no call that reaches the method through a function value, and no call of
// another package that this repository makes on its behalf.
func directDecodeCallSite(t *testing.T) map[string][]int {
	t.Helper()

	site := map[string][]int{}
	parsed := 0

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		path = filepath.ToSlash(path)

		if entry.IsDir() {
			if directDecodeSkipDir[path] {
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

		file, parseErr := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Errorf("parse %s: %v", path, parseErr)

			return nil
		}

		parsed++

		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != directDecodeMethod {
				return true
			}

			site[path] = append(site[path], fset.Position(call.Lparen).Line)

			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("walk the production files: %v", err)
	}

	// A walk that parsed nothing would pass every test below and read no file.
	if parsed == 0 {
		t.Fatal("the walk parsed no production Go file, and the guard reads every one of them")
	}

	return site
}

// directDecodeExceptionCount returns the recorded count of each excused file.
func directDecodeExceptionCount() map[string]int {
	count := map[string]int{}

	for _, entry := range directDecodeException {
		count[entry.file] += entry.count
	}

	return count
}

// TestNoProductionFileCallsDecodeFromBytesDirectly holds the property that #510 records. A
// production line that calls the method reaches a panic that no recovery covers.
func TestNoProductionFileCallsDecodeFromBytesDirectly(t *testing.T) {
	excused := directDecodeExceptionCount()

	for path, lines := range directDecodeCallSite(t) {
		if len(lines) <= excused[path] {
			continue
		}

		sort.Ints(lines)

		t.Errorf("%s calls %s at line %v, and it is no test file.\n"+
			"\tThe exception table excuses %d call of this file, and the file holds %d.\n"+
			"\t`gopacket.NewPacket` recovers a panic of a decoder, and it covers no direct call.\n"+
			"\tRead the header fields with a bounds check on every length, as #494 does,\n"+
			"\tor record an exception with the reason. %s holds the measurement.",
			path, directDecodeMethod, lines, excused[path], len(lines), directDecodeRecordPage)
	}
}

// TestTheDirectDecodeExceptionTableHoldsNoStaleEntry fails on an entry that excuses a call
// the tree no longer holds. A stale exception hides the next call.
func TestTheDirectDecodeExceptionTableHoldsNoStaleEntry(t *testing.T) {
	site := directDecodeCallSite(t)

	for _, entry := range directDecodeException {
		if entry.reason == "" {
			t.Errorf("the exception for %s states no reason", entry.file)
		}

		if found := len(site[entry.file]); found != entry.count {
			t.Errorf("the exception table records %d call of %s, and the file holds %d.\n"+
				"\tThe recorded reason is: %s", entry.count, entry.file, found, entry.reason)
		}
	}
}

// TestTheGopacketPanicRecordCitesThePinnedVersion holds the record page against `go.mod`.
//
// The page states a reading of `layers/tcp.go` at one version. A dependency bump moves that
// source, so the reading needs a re-read and this test demands one. `.claude/rules/
// external-apis.md` bars a description of an external interface from memory.
func TestTheGopacketPanicRecordCitesThePinnedVersion(t *testing.T) {
	goMod := readRepoFile(t, "go.mod")

	match := regexp.MustCompile(`github\.com/gopacket/gopacket (v\S+)`).FindStringSubmatch(goMod)
	if match == nil {
		t.Fatalf("go.mod names no gopacket version:\n%s", goMod)
	}

	version := match[1]
	record := readRepoFile(t, directDecodeRecordPage)

	if !strings.Contains(record, version) {
		t.Errorf("%s names no %s, and go.mod pins that version.\n"+
			"\tRead `layers/tcp.go` at the pinned version, and write the reading.",
			directDecodeRecordPage, version)
	}

	for _, cited := range directDecodeCitedRange {
		if !strings.Contains(record, cited) {
			t.Errorf("%s cites no %s, and the reading rests on that range",
				directDecodeRecordPage, cited)
		}
	}

	// The page reports a property of this repository, so it names the guard that holds it.
	if !strings.Contains(record, "TestNoProductionFileCallsDecodeFromBytesDirectly") {
		t.Errorf("%s names no guard, and a record without a guard states an unheld property",
			directDecodeRecordPage)
	}
}
