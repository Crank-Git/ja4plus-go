package repocheck

// The maintainer ruled on 2026-09-30 that the active scanner is opt-in and separate.
// `Crank-Git/ja4plus#775` holds the ruling, and #796 built the scanner in package `scan`.
// No passive fingerprinter and no `Processor` can send a packet, and the library changes no
// firewall state. The tests below hold both rules, and #796 is the reversal path.

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// scanImportPath is the import path of the active scanner.
const scanImportPath = "github.com/Crank-Git/ja4plus-go/scan"

// scanImporters names each package that may import the scanner. The command-line program
// holds the opt-in `scan` subcommand, and the scanner imports itself in no sense.
var scanImporters = []string{
	scanImportPath,
	"github.com/Crank-Git/ja4plus-go/cmd/ja4plus",
}

// scanDependents returns each package of the module whose import graph reaches the scanner,
// keyed by import path. It reads `go list -deps` for each package, so a transitive import
// reports as well as a direct one.
func scanDependents(t *testing.T) map[string]bool {
	t.Helper()

	goCommand, lookErr := exec.LookPath("go")
	if lookErr != nil {
		t.Skipf("the go command is absent, so this run reads no import graph: %v", lookErr)
	}

	out, err := exec.Command(goCommand, "list", "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./...: %v\n%s", err, out)
	}

	dependents := map[string]bool{}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && slices.Contains(fields[1:], scanImportPath) {
			dependents[fields[0]] = true
		}
	}

	return dependents
}

// TestNoPassivePackageImportsTheScanner holds the boundary of the ruling. The root package
// holds `Processor` and every passive fingerprinter, and its import graph reaches no
// package that can send a scan SYN.
func TestNoPassivePackageImportsTheScanner(t *testing.T) {
	for dependent := range scanDependents(t) {
		if !slices.Contains(scanImporters, dependent) {
			t.Errorf("%s imports %s, and the ruling of 2026-09-30 keeps the scanner out of every passive package", dependent, scanImportPath)
		}
	}
}

// TestTheImportReaderFindsTheCommandThatImportsTheScanner proves that the reader above reads
// a real import. A reader that finds nothing would pass the boundary test and prove nothing.
func TestTheImportReaderFindsTheCommandThatImportsTheScanner(t *testing.T) {
	if !scanDependents(t)["github.com/Crank-Git/ja4plus-go/cmd/ja4plus"] {
		t.Errorf("the reader finds no import of %s in cmd/ja4plus, and that package holds the scan subcommand", scanImportPath)
	}
}

// firewallTools names each command that changes the firewall state of a host.
var firewallTools = []string{"iptables", "nft", "pfctl"}

// firewallCommandFiles returns each production Go file below the root that imports
// `os/exec` and names a firewall tool. Such a file can change the firewall state of the host.
func firewallCommandFiles(t *testing.T, root string) []string {
	t.Helper()

	var found []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "testdata" || entry.Name() == ".claude" {
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

		text := string(content)
		if !strings.Contains(text, `"os/exec"`) {
			return nil
		}

		for _, tool := range firewallTools {
			if strings.Contains(text, `"`+tool) {
				found = append(found, filepath.ToSlash(path))
				break
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	return found
}

// TestNoProductionFileRunsAFirewallCommand holds the first ruling of 2026-09-30: the library
// and the command change no firewall state. They state the rules, and the operator applies
// them.
func TestNoProductionFileRunsAFirewallCommand(t *testing.T) {
	if found := firewallCommandFiles(t, "."); len(found) > 0 {
		t.Errorf("%v run a host command that names a firewall tool, and the scanner changes no firewall state", found)
	}
}

func TestTheFirewallReaderFindsACommandThatNamesIptables(t *testing.T) {
	root := writeSocketGuardFixture(t, "scan", "rules.go",
		"package scan\n\nimport \"os/exec\"\n\nfunc apply() error { return exec.Command(\"iptables\", \"-A\", \"INPUT\").Run() }\n")

	if found := firewallCommandFiles(t, root); len(found) != 1 {
		t.Errorf("the reader finds %v in a fixture that runs iptables", found)
	}
}

// TestTheScannerImportsNoHostCommand holds the narrower rule: the scan package runs no
// command of the host at all.
func TestTheScannerImportsNoHostCommand(t *testing.T) {
	for _, path := range productionGoFilesOf(t, "scan") {
		if strings.Contains(readRepoFile(t, path), `"os/exec"`) {
			t.Errorf("%s imports os/exec, and the scanner runs no command of the host", path)
		}
	}
}
