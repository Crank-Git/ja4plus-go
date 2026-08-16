//go:build prerelease

package ja4plus

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The published module contents, FR-prerelease-12 through FR-prerelease-17.
//
// Every case of this file reads the module that the proxy publishes, and no case reads the
// working tree. A listing of the working tree proves nothing, because the module zip
// decides what a user receives and the tag decides the module zip.
//
// The `go` command downloads the zip, and `go mod download -json` reports where it landed.
// `go help mod download` at go1.26.5 states the field this file reads:
//
//	Zip      string // absolute path to cached .zip file
//
// The path prefix of every entry comes from the module zip format:
//
//	All file paths within a zip file must start with "<module>@<version>/", where
//	"<module>" is the module path and "<version>" is the version.
//
// Verified against <https://pkg.go.dev/golang.org/x/mod/zip>, retrieved 2026-08-14, and
// against the output of `go help mod download` at go1.26.5, read 2026-08-14.
//
// # The tag these cases read, and the failure that is expected
//
// The maintainer ruled the scope on 2026-08-14, at #94: each case runs against `v0.3.0`,
// and each expected failure is recorded rather than weakened.
//
// **FR-prerelease-14 fails against `v0.3.0`, and that failure is the expected result.**
// `v0.3.0` carries no `LICENSE` and no `NOTICE`, measured on 2026-08-14 by the listing
// below. #593 records the consequence: `pkg.go.dev` detects no license and it renders no
// documentation. The working tree holds both files, so the next tag turns the case green.
//
// Every other case of this file passed against `v0.3.0`, measured on 2026-08-15 UTC.
//
// **#106 moved `publishedModuleVersion` to `v1.0.0` on 2026-08-15 UTC, and #767 moved it to
// `v1.1.0` on 2026-08-16 UTC.** Every case of this file reads `v1.1.0` now. **The proxy
// serves no `v1.1.0` until the maintainer pushes the tag**, so each case reports the absent
// tag until then. That failure names the tag it read, and it is the state of the repository
// rather than a defect of a case.

// publishedModulePath names the module that the proxy publishes.
//
// `prereleaseModulePath` in `prerelease_install_test.go` holds the same string. Its
// `# Five constants carry the module path and the tag` section states the hazard.
const publishedModulePath = "github.com/Crank-Git/ja4plus-go"

// publishedModuleVersion names the tag that these cases read.
//
// **#106 moved this constant from `v0.3.0` to `v1.0.0` on 2026-08-15 UTC**, under Epic 10.
// **#767 moved it to `v1.1.0` on 2026-08-16 UTC.** A reader who moves this constant moves
// every case of this file to the new tag, and it moves no case of another file.
//
// **Two other constants hold the same tag**, and `release_tag_constants_test.go` compares
// the three. `prereleaseInstallVersion` in `prerelease_install_test.go` and
// `defaultReleaseTag` in `prerelease_binaries_test.go` are the two. The
// `# Five constants carry the module path and the tag` section of `prerelease_install_test.go`
// states the hazard, and #106 built the guard.
const publishedModuleVersion = "v1.1.0"

// embeddedDatabase is the file that `//go:embed` in `lookup.go` reads.
const embeddedDatabase = "data/ja4plus-mapping.csv"

// publishedModuleSizeCeiling is the ceiling of FR-prerelease-17, in bytes.
//
// The module zip of `v0.3.0` measures 2253962 bytes compressed and 2444024 bytes
// uncompressed on 2026-08-14. `assets/logo.png` is 2192430 uncompressed bytes, which is
// 89.7 percent of the uncompressed total. So one image carries the module size, and the
// ceiling has to sit above it.
//
// **Read the percentage against the uncompressed total, and never against the zip size.**
// `readZip` reads `file.UncompressedSize64` for an entry and `info.Size()` for the zip, so
// a ratio of the two divides two different measurements. The Epic 16 round repaired that
// ratio on 2026-08-14, and pull request #627 holds both totals.
//
// **The ceiling reads the zip size, and this repair does not move it.** The case below
// compares `listing.zipSize` against the ceiling, and each side is one measurement.
//
// 4 MiB leaves the tag room to grow. It still catches the two defects that this feature
// set guards. A corpus capture and a built site each add more than 2 MiB, so either one
// crosses this ceiling. A ceiling nobody measured is a ceiling that never fails, so
// `TestThePublishedModuleSizeIsBelowTheCeiling` logs the measurement on every run.
const publishedModuleSizeCeiling = 4 << 20

// publishedModuleEntry is one file of the published module zip.
type publishedModuleEntry struct {
	// name is the path of the file inside the module, without the version prefix.
	name string
	// size is the uncompressed size of the file, in bytes.
	size int64
}

// publishedModuleListing is the whole reading of one published module zip.
//
// The clean environment goes when the download returns, so the listing holds every value a
// case needs and it holds no path of the environment.
type publishedModuleListing struct {
	// version is the tag the listing read.
	version string
	// entries holds one row for each file, sorted by name.
	entries []publishedModuleEntry
	// zipSize is the size of the module zip in bytes, which is what a user downloads.
	zipSize int64
	// uncompressedSize is the total size of the files inside the zip, in bytes.
	uncompressedSize int64
	// sum is the go.sum checksum of the module, which names the bytes the case read.
	sum string
}

// readPublishedModule returns the listing of the published module, and it reads the proxy
// once for the whole run.
//
// One download serves every case of this file, because six downloads of one artifact prove
// nothing that one download does not. The listing is a value, so no case can change what a
// later case reads.
var readPublishedModule = sync.OnceValues(func() (*publishedModuleListing, error) {
	listing := &publishedModuleListing{version: publishedModuleVersion}

	err := runInCleanEnvironment("", func(environment *cleanEnvironment) error {
		module, err := downloadPublishedModule(environment)
		if err != nil {
			return err
		}

		listing.sum = module.Sum

		return listing.readZip(module.Zip)
	})
	if err != nil {
		return nil, err
	}

	return listing, nil
})

// downloadedModule holds the fields of `go mod download -json` that these cases read.
type downloadedModule struct {
	Path    string
	Version string
	Error   string
	Zip     string
	Sum     string
}

// downloadPublishedModule downloads the published module into the clean environment.
//
// It returns the report of `go mod download -json`.
//
// It returns an error when the command fails, and it returns an error when the report
// names one. The `go` command reaches the network, so the failure can be a proxy that
// serves no such version, and it can be a network that answers nothing. The message
// carries the standard error of the command, because the exit status separates neither.
//
// The command runs outside a module, because the environment root holds no `go.mod` and
// the harness sets `GOWORK=off`. A module query of the form `path@version` needs no main
// module, measured at go1.26.5 on 2026-08-14.
func downloadPublishedModule(environment *cleanEnvironment) (*downloadedModule, error) {
	query := publishedModulePath + "@" + publishedModuleVersion

	command := environment.command("go", "mod", "download", "-json", query)
	output, err := command.Output()
	if err != nil {
		// The standard error of the `go` command names the reason. The exit status names
		// none of them.
		message := ""
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			message = strings.TrimSpace(string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("the download of %s failed: %w: %s", query, err, message)
	}

	module := &downloadedModule{}
	if err := json.Unmarshal(output, module); err != nil {
		return nil, fmt.Errorf("read the report of go mod download for %s: %w", query, err)
	}
	if module.Error != "" {
		return nil, fmt.Errorf("the module proxy served no %s: %s", query, module.Error)
	}
	if module.Zip == "" {
		return nil, fmt.Errorf("the report of go mod download for %s names no zip file", query)
	}

	return module, nil
}

// readZip fills the listing from the module zip at the named path.
//
// It returns an error when an entry carries no version prefix, because such a zip is not a
// module zip and every case below would then read the wrong names.
func (l *publishedModuleListing) readZip(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	l.zipSize = info.Size()

	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	// The reader holds an open file and no write, so the close reports nothing a case reads.
	defer func() { _ = archive.Close() }()

	prefix := publishedModulePath + "@" + publishedModuleVersion + "/"
	for _, file := range archive.File {
		if !strings.HasPrefix(file.Name, prefix) {
			return fmt.Errorf("the zip entry %q carries no %q prefix", file.Name, prefix)
		}

		size := int64(file.UncompressedSize64)
		l.entries = append(l.entries, publishedModuleEntry{
			name: strings.TrimPrefix(file.Name, prefix),
			size: size,
		})
		l.uncompressedSize += size
	}

	sort.Slice(l.entries, func(i, j int) bool { return l.entries[i].name < l.entries[j].name })

	return nil
}

// holds reports whether the published module holds the named file.
func (l *publishedModuleListing) holds(name string) bool {
	for _, entry := range l.entries {
		if entry.name == name {
			return true
		}
	}

	return false
}

// names returns the name of every file of the published module.
func (l *publishedModuleListing) names() []string {
	names := make([]string, 0, len(l.entries))
	for _, entry := range l.entries {
		names = append(names, entry.name)
	}

	return names
}

// requirePublishedModule returns the listing, and it fails the case when the download
// failed.
//
// It also fails the case on an empty listing. An absence case reads the listing for a name
// it must not find, so an empty listing would pass that case for the wrong reason.
func requirePublishedModule(t *testing.T) *publishedModuleListing {
	t.Helper()

	listing, err := readPublishedModule()
	if err != nil {
		t.Fatalf("read the published module %s@%s: %v", publishedModulePath, publishedModuleVersion, err)
	}
	if len(listing.entries) == 0 {
		t.Fatalf("the published module %s@%s holds no file", publishedModulePath, publishedModuleVersion)
	}

	return listing
}

// TestThePublishedModuleListsItsFiles holds FR-prerelease-12.
//
// The listing is the evidence of every other case of this file, so this case prints it.
// A reader of the pre-release summary then reads what the proxy publishes, and never what
// the working tree holds.
func TestThePublishedModuleListsItsFiles(t *testing.T) {
	listing := requirePublishedModule(t)

	t.Logf("the published module %s@%s holds %d file(s), %d byte(s) compressed, %d byte(s) uncompressed, %s",
		publishedModulePath, listing.version, len(listing.entries), listing.zipSize, listing.uncompressedSize, listing.sum)
	for _, entry := range listing.entries {
		t.Logf("  %9d  %s", entry.size, entry.name)
	}
}

// TestThePublishedModuleHoldsTheEmbeddedDatabase holds FR-prerelease-13.
//
// `lookup.go` carries `//go:embed data/ja4plus-mapping.csv`, so a module that publishes no
// such file compiles for nobody. The edge-case table of the feature file states the same
// order. This case fails first, and it names the missing path.
func TestThePublishedModuleHoldsTheEmbeddedDatabase(t *testing.T) {
	listing := requirePublishedModule(t)

	if !listing.holds(embeddedDatabase) {
		t.Fatalf("the published module %s@%s holds no %s, and `//go:embed` in `lookup.go` needs it",
			publishedModulePath, listing.version, embeddedDatabase)
	}
}

// TestTheEmbeddedDatabaseOfThePublishedModuleHoldsBytes holds FR-prerelease-13 against an
// empty file.
//
// A zip entry states a name and a size, so a module can publish the name of the database
// and none of its rows. `//go:embed` then compiles, and every lookup answers nothing.
func TestTheEmbeddedDatabaseOfThePublishedModuleHoldsBytes(t *testing.T) {
	listing := requirePublishedModule(t)

	for _, entry := range listing.entries {
		if entry.name == embeddedDatabase && entry.size == 0 {
			t.Errorf("the published module %s@%s holds an empty %s", publishedModulePath, listing.version, embeddedDatabase)
		}
	}
}

// TestThePublishedModuleHoldsTheLicenseAndTheNotice holds FR-prerelease-14.
//
// This case fails against `v0.3.0`, and that failure is the expected result. The maintainer
// ruled the scope on 2026-08-14, at #94: the case runs against the tag that exists, and the
// record enumerates the failure.
//
// `v0.3.0` carries neither file, and `v1.0.0` carries both. #593 records the consequence
// that the absent files had: `pkg.go.dev` reported `License: None detected` and it rendered
// no documentation on 2026-08-14. **That page renders the documentation of `v1.0.0` and it
// states `License: BSD-3-Clause`**, read on 2026-08-16 UTC, so the tag turned this case
// green.
//
// Never weaken this assertion. `NOTICE` holds the FoxIO License 1.1 terms, and a module
// that publishes the methods without those terms states the wrong license to every user.
func TestThePublishedModuleHoldsTheLicenseAndTheNotice(t *testing.T) {
	listing := requirePublishedModule(t)

	for _, name := range []string{"LICENSE", "NOTICE"} {
		if !listing.holds(name) {
			t.Errorf("the published module %s@%s holds no %s. #593 records the measurement, and Epic 10 turns this case green at the next tag",
				publishedModulePath, listing.version, name)
		}
	}
}

// TestThePublishedModuleHoldsNoCaptureFile holds FR-prerelease-15.
//
// The corpus is FoxIO-licensed material, and `.claude/rules/external-apis.md` states that
// this project fetches it and commits none of it. So a published module that carried a
// capture would be a license defect, and it would never be a size defect alone.
func TestThePublishedModuleHoldsNoCaptureFile(t *testing.T) {
	listing := requirePublishedModule(t)

	captures := []string{}
	for _, name := range listing.names() {
		if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") || strings.HasSuffix(name, ".cap") {
			captures = append(captures, name)
			continue
		}
		if strings.HasPrefix(name, "testdata/foxio/") {
			captures = append(captures, name)
		}
	}

	if len(captures) != 0 {
		t.Errorf("the published module %s@%s holds %d capture file(s) of the corpus, which this project publishes under no license: %v",
			publishedModulePath, listing.version, len(captures), captures)
	}
}

// TestThePublishedModuleHoldsNoSiteDirectory holds FR-prerelease-16.
//
// `make docs` writes the built site into `site/`, and the `clean` target of the `Makefile`
// removes it. A tag cut over a built site would publish every page twice, once as Markdown
// and once as HTML.
func TestThePublishedModuleHoldsNoSiteDirectory(t *testing.T) {
	listing := requirePublishedModule(t)

	pages := []string{}
	for _, name := range listing.names() {
		if strings.HasPrefix(name, "site/") {
			pages = append(pages, name)
		}
	}

	if len(pages) != 0 {
		t.Errorf("the published module %s@%s holds %d file(s) of the built site: %v",
			publishedModulePath, listing.version, len(pages), pages)
	}
}

// TestThePublishedModuleSizeIsBelowTheCeiling holds FR-prerelease-17.
//
// The size of the zip is the size a user downloads, so the ceiling reads the zip and not
// the working tree. The case logs the measurement on every run, because a ceiling nobody
// measures is a ceiling that never fails.
//
// The module zip format bounds the same value at 500 MiB, and this ceiling is the tighter
// one that this project holds itself to.
func TestThePublishedModuleSizeIsBelowTheCeiling(t *testing.T) {
	listing := requirePublishedModule(t)

	t.Logf("the published module %s@%s measures %d byte(s), and the ceiling is %d byte(s)",
		publishedModulePath, listing.version, listing.zipSize, publishedModuleSizeCeiling)

	if listing.zipSize > publishedModuleSizeCeiling {
		t.Errorf("the published module %s@%s measures %d byte(s), and it crosses the ceiling of %d byte(s). The largest file is %s",
			publishedModulePath, listing.version, listing.zipSize, publishedModuleSizeCeiling, listing.largestEntry())
	}
}

// largestEntry names the largest file of the published module, with its size.
func (l *publishedModuleListing) largestEntry() string {
	largest := publishedModuleEntry{}
	for _, entry := range l.entries {
		if entry.size > largest.size {
			largest = entry
		}
	}

	return fmt.Sprintf("%s at %d byte(s)", largest.name, largest.size)
}
