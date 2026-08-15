//go:build prerelease

package ja4plus

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// The install cases of `docs/specs/features/16-pre-release-validation.md` run here.
// They hold FR-prerelease-6 through FR-prerelease-11.
//
// Two cases run, and they have two shapes. The program case installs the command with
// `go install` and it runs the installed program. The library case creates an empty
// module, it fetches the library with `go get`, and it compiles a program that imports
// the library.
//
// This file stands beside `prerelease_test.go` rather than inside it. #96, #97, #98 and
// #99 each add cases in one batch, and one file for each slice keeps the union of the
// four mechanical.
//
// **The maintainer ruled the scope on 2026-08-14, and #94 holds the ruling.** Each case
// reads `v0.3.0`, because the proxy holds no later tag of this module. A case that fails
// against `v0.3.0` for a stated reason is a correct case, and this file weakens no case
// to make it pass. Each failure below names the reason, the tag it read, and the issue
// that turns it green.

// prereleaseModulePath names the module that each case reads.
//
// `publishedModulePath` in `prerelease_module_contents_test.go` holds the same string, and
// both compile in one package under the `prerelease` tag. See
// `# Five constants carry the module path and the tag` below.
const prereleaseModulePath = "github.com/Crank-Git/ja4plus-go"

// prereleaseInstallVersion names the tag that each case reads.
//
// **#106 moved this constant from `v0.3.0` to `v1.0.0` on 2026-08-15 UTC**, under Epic 10.
// FR-prerelease-7 matches the printed version against this tag, so a reader knows which
// artifact every measurement below describes.
//
// **The proxy holds no `v1.0.0` until the maintainer pushes the tag**, so each case of this
// file fails until then. FR-prerelease-26 states that order. The maintainer pushes the tag
// first. The maintainer then runs `make prerelease` against it. The maintainer promotes the
// release only when every case passes or carries a recorded reason.
//
// # Five constants carry the module path and the tag
//
// **A session that moves one of them leaves the others behind.** The Epic 16 cross-member
// review measured the hazard on 2026-08-14, and the round recorded it here. The five are
// these.
//
//   - `prereleaseModulePath`, above.
//   - `publishedModulePath`, in `prerelease_module_contents_test.go`.
//   - `prereleaseInstallVersion`, below.
//   - `publishedModuleVersion`, in `prerelease_module_contents_test.go`.
//   - `defaultReleaseTag`, in `prerelease_binaries_test.go`.
//
// **Three of the five hold the tag**: this constant, `publishedModuleVersion` and
// `defaultReleaseTag`. Each doc comment describes its own file alone.
//
// **`release_tag_constants_test.go` now compares all five, and #106 built that guard.** It
// reads each declaration as text, so it runs without the `prerelease` build tag. A run that
// read two tags would report a green gate for an artifact nobody published.
const prereleaseInstallVersion = "v1.0.0"

// prereleaseExpectedJA4 states the JA4 value of the capture that `prereleaseCaptureFrame`
// builds.
//
// The value comes from the fingerprinter of this repository, measured on 2026-08-14 over
// the same frame. `make conformance` holds this tree against the FoxIO corpus. So the tree
// states the expected value, and the installed program is the artifact under test.
const prereleaseExpectedJA4 = "t13d0504h2_bf5bdbdbea07_ef5f37ab036a"

// prereleaseInstallRetryWindow bounds the wait for a tag the proxy has not seen.
//
// The `Edge cases & failures` table of the feature file states the rule: `The install
// case retries for a recorded time, then fails with a message that names the proxy.` The
// proxy fetches a new tag on the first request for it, so the wait covers a fetch and not
// an outage.
const prereleaseInstallRetryWindow = 2 * time.Minute

// prereleaseInstallRetryInterval is the wait between two install attempts.
const prereleaseInstallRetryInterval = 10 * time.Second

// prereleaseCaptureFrame returns the bytes of one Ethernet frame that carries a TLS
// ClientHello.
//
// The frame is built here rather than read from a file, because FR-prerelease-11 states
// that the case reads no file of this repository. A capture on disk would be such a file,
// and a copy of it into the clean environment would read it.
func prereleaseCaptureFrame(t *testing.T) []byte {
	t.Helper()

	packet := buildTCPPacketWithPayload(t, buildClientHelloPayload())

	return packet.Data()
}

// writePrereleaseCapture writes one pcap file that holds the frame, and it returns the
// path.
//
// The file lands inside the clean environment, so the installed program reads the
// environment and never the repository.
func writePrereleaseCapture(t *testing.T, directory string, frame []byte) string {
	t.Helper()

	path := filepath.Join(directory, "clienthello.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create the capture: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("close the capture: %v", err)
		}
	}()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write the capture file header: %v", err)
	}
	info := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1755129600, 0).UTC(),
		CaptureLength: len(frame),
		Length:        len(frame),
	}
	if err := writer.WritePacket(info, frame); err != nil {
		t.Fatalf("write the capture packet: %v", err)
	}

	return path
}

// runPrereleaseCommand runs one command of the clean environment and returns its combined
// output.
//
// A case reads the output of a failure and the output of a success. So this helper
// combines the two streams, and it returns the error beside the text.
func runPrereleaseCommand(environment *cleanEnvironment, directory string, name string, arg ...string) (string, error) {
	command := environment.command(name, arg...)
	if directory != "" {
		command.Dir = directory
	}
	output, err := command.CombinedOutput()

	return string(output), err
}

// proxyHasNotSeenTheTag reports whether the output of a failed install names a version the
// proxy cannot resolve.
//
// The install retries on this failure alone. A compile failure and a checksum failure each
// repeat identically. So a retry of one of them spends the whole window, and it reports
// the same message.
func proxyHasNotSeenTheTag(output string) bool {
	for _, symptom := range []string{
		"unknown revision",
		"no matching versions",
		"invalid version",
		"404 Not Found",
		"410 Gone",
	} {
		if strings.Contains(output, symptom) {
			return true
		}
	}

	return false
}

// installFromProxy runs `go install` for the command at the version, and it retries while
// the proxy has not seen the tag.
//
// It returns the combined output of the last attempt. The error names the proxy, because
// the maintainer who reads a failed release check must know which proxy answered.
func installFromProxy(environment *cleanEnvironment, target string) (string, error) {
	deadline := time.Now().Add(prereleaseInstallRetryWindow)
	attempts := 0

	for {
		attempts++
		output, err := runPrereleaseCommand(environment, "", "go", "install", target)
		if err == nil {
			return output, nil
		}

		if !proxyHasNotSeenTheTag(output) || time.Now().After(deadline) {
			proxy, proxyErr := environment.goEnv("GOPROXY")
			if proxyErr != nil {
				proxy = "unread: " + proxyErr.Error()
			}

			return output, fmt.Errorf(
				"go install %s failed after %d attempt(s) over %s, and the proxy is GOPROXY=%s: %w",
				target, attempts, prereleaseInstallRetryWindow, proxy, err)
		}

		time.Sleep(prereleaseInstallRetryInterval)
	}
}

// requireEnvironmentStandsOutsideTheRepository holds FR-prerelease-11 against every path
// the clean environment names.
//
// A case that builds under a directory of the repository reads the working tree, and it
// then proves nothing about the published artifact.
func requireEnvironmentStandsOutsideTheRepository(t *testing.T, environment *cleanEnvironment) {
	t.Helper()

	repository := prereleaseRepositoryRoot(t)

	paths := map[string]string{
		"the environment root": environment.root,
		"GOMODCACHE":           environment.goModCache,
		"GOCACHE":              environment.goCache,
		"GOPATH":               environment.goPath,
		"GOBIN":                environment.goBin,
		"TMPDIR":               environment.tmp,
	}
	for name, path := range paths {
		if isInside(path, repository) {
			t.Errorf("%s is %s, and it stands inside the repository %s", name, path, repository)
		}
	}

	for _, entry := range environment.environ() {
		if strings.HasPrefix(entry, "PATH=") && strings.Contains(entry, repository) {
			t.Errorf("PATH names the repository: %s", entry)
		}
	}
}

// requireNoDependencyOfTheRepository holds FR-prerelease-11 against the packages that a
// build reads.
//
// `go list -deps` reports the directory of every package the build compiles. So this check
// reads the resolution of the `go` command, and never a claim about it. A directory of the
// repository here means the build read the working tree.
// It also requires one directory under the module cache, because a check that finds no
// directory at all would pass over an empty list.
func requireNoDependencyOfTheRepository(t *testing.T, environment *cleanEnvironment, directory string) {
	t.Helper()

	output, err := runPrereleaseCommand(environment, directory, "go", "list", "-deps", "-f", "{{.Dir}}", ".")
	if err != nil {
		t.Fatalf("go list -deps in %s: %v\n%s", directory, err, output)
	}

	repository := prereleaseRepositoryRoot(t)
	fromModuleCache := 0
	for _, line := range strings.Split(output, "\n") {
		packageDir := strings.TrimSpace(line)
		if packageDir == "" {
			continue
		}
		if isInside(packageDir, repository) {
			t.Errorf("the build reads %s, and that directory stands inside the repository %s", packageDir, repository)
		}
		if isInside(packageDir, environment.goModCache) {
			fromModuleCache++
		}
	}

	if fromModuleCache == 0 {
		t.Error("no package of the build comes from the module cache, and the case then reads no published module")
	}

	t.Logf("FR-prerelease-11 — the build of %s reads %d package(s) of the module cache and none of the repository",
		directory, fromModuleCache)
}

// requireModuleCacheHoldsThePublishedModule holds FR-prerelease-11 for the program case.
//
// `go install pkg@version` writes no module of its own, so the module cache is where the
// downloaded source lands. The glob reads the escaped module path, and never a literal.
// The proxy escapes an upper-case letter of the path, and this check states no escape rule
// of its own.
//
// The Go modules reference states the rule that keeps the working tree out of the build:
//
//	Since Go 1.16, if the arguments have version suffixes (like @latest or @v1.0.0),
//	go install builds packages in module-aware mode, ignoring the go.mod file in the
//	current directory or any parent directory if there is one.
//
// Verified against: <https://go.dev/ref/mod> (`go install`), retrieved 2026-08-14.
func requireModuleCacheHoldsThePublishedModule(t *testing.T, environment *cleanEnvironment) {
	t.Helper()

	pattern := filepath.Join(environment.goModCache, "github.com", "*", "ja4plus-go@"+prereleaseInstallVersion)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("read the module cache: %v", err)
	}
	if len(matches) == 0 {
		t.Errorf("the module cache holds no %s at %s, and the program then came from somewhere else",
			prereleaseModulePath, prereleaseInstallVersion)
	}
}

// prereleaseRepositoryRoot returns the directory of this repository.
//
// A test of this package runs in the package directory, which is the repository root.
//
// **Two cases call `os.Getwd` inline for the same value**, in `prerelease_test.go` and in
// `prerelease_site_test.go`. The Epic 16 cross-member review measured that on 2026-08-14,
// and the round recorded it here. The round changed no caller. A caller that adopts this
// helper reads one failure message rather than three.
func prereleaseRepositoryRoot(t *testing.T) string {
	t.Helper()

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("read the working directory: %v", err)
	}

	return root
}

// isInside reports whether the path stands inside the parent directory.
func isInside(path string, parent string) bool {
	return path == parent || strings.HasPrefix(path, parent+string(filepath.Separator))
}

// TestTheInstalledProgramFingerprintsACaptureFromThePublishedModule holds FR-prerelease-6,
// FR-prerelease-7, FR-prerelease-8 and FR-prerelease-11 for the program case.
//
// The case installs the command from the module proxy into a clean environment, and it
// then runs the installed program. Each step reports its own failure, so one broken step
// does not hide the next one.
//
// # FR-prerelease-7 needs no amendment, and #106 read it on 2026-08-15 UTC
//
// **#105 decided FR-release-35g on 2026-08-15 UTC**, and comment 5301284764 of #105 holds
// the decision. The commit and the build date of a released binary reach the Go build info,
// and a reader takes them with `go version -m <binary>`. **That decision named #106 as the
// issue that would carry any amendment to FR-prerelease-7.**
//
// **#106 read the requirement against the program, and the requirement holds without a
// change.** FR-prerelease-7 compares one printed version against the tag, and the program
// prints one name and one version. Measured on 2026-08-15 UTC with go1.26.5 on
// darwin/arm64, over a build of this tree:
//
//	$ ja4plus --version
//	ja4plus v0.3.1-0.20260815043125-3bf88a84a5c4
//	$ go version -m ja4plus
//		build	vcs.revision=3bf88a84a5c4eb46bc59959ee57a27f2de79b00c
//		build	vcs.time=2026-08-15T04:31:25Z
//
// **The printed line carries no commit field and no date field**, so the comparison below
// reads one version. `TestThePrintedLineHoldsOneNameAndOneVersion` in
// `cmd/ja4plus/version_test.go` holds that shape, and `versionLine` in
// `cmd/ja4plus/main.go` writes it. A second field would break this comparison, and #105
// declined the two answers that add one.
func TestTheInstalledProgramFingerprintsACaptureFromThePublishedModule(t *testing.T) {
	frame := prereleaseCaptureFrame(t)
	target := prereleaseModulePath + "/cmd/ja4plus@" + prereleaseInstallVersion

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		requireEnvironmentStandsOutsideTheRepository(t, environment)

		// FR-prerelease-6 — the case installs the command from the proxy.
		output, err := installFromProxy(environment, target)
		if err != nil {
			t.Errorf("FR-prerelease-6 fails at %s: %v\n%s", prereleaseInstallVersion, err, output)
			return nil
		}

		// FR-prerelease-11 — the source of the program came from the module cache.
		requireModuleCacheHoldsThePublishedModule(t, environment)

		program := filepath.Join(environment.goBin, "ja4plus")
		if _, err := os.Stat(program); err != nil {
			t.Errorf("FR-prerelease-6 installed no program at %s: %v", program, err)
			return nil
		}

		// FR-prerelease-7 — the printed version matches the tag that this case read.
		version, err := runPrereleaseCommand(environment, "", program, "--version")
		if err != nil {
			t.Errorf("FR-prerelease-7 cannot run %s --version: %v\n%s", program, err, version)
		} else if printed := strings.TrimSpace(version); printed != "ja4plus "+prereleaseInstallVersion {
			t.Errorf("FR-prerelease-7 fails at %s: the installed program prints %q, and the tag is %s.\n"+
				"`resolveVersion` in `cmd/ja4plus/main.go` reads the module version of the embedded "+
				"build info when no link flag sets `Version`, and "+
				"the `ldflags` key of `.goreleaser.yaml` sets that variable for a released binary. "+
				"Issue #628 added that read on 2026-08-14, so a tag published before #628 prints `dev` here.",
				prereleaseInstallVersion, printed, prereleaseInstallVersion)
		}

		// FR-prerelease-8 — the installed program fingerprints the capture.
		capture := writePrereleaseCapture(t, environment.root, frame)
		analysis, err := runPrereleaseCommand(environment, "", program, "analyze", capture, "--types", "ja4")
		if err != nil {
			t.Errorf("FR-prerelease-8 cannot analyze the capture: %v\n%s", err, analysis)
		} else if !strings.Contains(analysis, prereleaseExpectedJA4) {
			t.Errorf("FR-prerelease-8 fails at %s: the installed program writes no %s for the capture.\n%s",
				prereleaseInstallVersion, prereleaseExpectedJA4, analysis)
		} else {
			t.Logf("FR-prerelease-8 — the program of %s writes %s for the capture",
				prereleaseInstallVersion, prereleaseExpectedJA4)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}

// prereleaseLibraryProgram returns the source of the program that the library case
// compiles.
//
// The program holds the capture as a hexadecimal string, so it reads no file at all. The
// gopacket import path is a parameter, because the module that the library requires
// carries a different path at a different tag.
func prereleaseLibraryProgram(gopacketPath string, frame []byte) string {
	return fmt.Sprintf(`package main

import (
	"encoding/hex"
	"fmt"
	"os"

	ja4plus "%s"
	"%s"
	"%s/layers"
)

// frameHex holds one Ethernet frame that carries a TLS ClientHello.
const frameHex = "%s"

func main() {
	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode the frame: %%v\n", err)
		os.Exit(1)
	}

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	processor := ja4plus.NewProcessor()
	results, errs := processor.ProcessPacket(packet)
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "process the packet: %%v\n", err)
	}
	for _, result := range results {
		fmt.Printf("%%s %%s\n", result.Type, result.Fingerprint)
	}

	for _, result := range processor.CloseOpenWindows() {
		fmt.Printf("window %%s %%s\n", result.Type, result.Fingerprint)
	}
}
`, prereleaseModulePath, gopacketPath, gopacketPath, hex.EncodeToString(frame))
}

// gopacketPathOfTheLibrary returns the module path of gopacket that the library requires.
//
// The library required `github.com/google/gopacket` until #438 moved it to
// `github.com/gopacket/gopacket` on 2026-08-13. So the path depends on the tag, and the
// case reads the module graph of the published module rather than the go.mod of this
// repository.
func gopacketPathOfTheLibrary(t *testing.T, environment *cleanEnvironment, directory string) string {
	t.Helper()

	output, err := runPrereleaseCommand(environment, directory, "go", "list", "-m", "-f", "{{.Path}}", "all")
	if err != nil {
		t.Fatalf("go list -m all: %v\n%s", err, output)
	}

	for _, line := range strings.Split(output, "\n") {
		path := strings.TrimSpace(line)
		if strings.HasSuffix(path, "/gopacket") {
			return path
		}
	}

	t.Fatalf("the module graph of %s names no gopacket module:\n%s", prereleaseModulePath, output)

	return ""
}

// TestAnEmptyModuleCompilesAgainstThePublishedLibrary holds FR-prerelease-9,
// FR-prerelease-10 and FR-prerelease-11 for the library case.
//
// The case creates a module that holds no source of this repository, it fetches the
// library with `go get`, and it compiles a program that calls two exported methods.
func TestAnEmptyModuleCompilesAgainstThePublishedLibrary(t *testing.T) {
	frame := prereleaseCaptureFrame(t)

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		requireEnvironmentStandsOutsideTheRepository(t, environment)

		module := filepath.Join(environment.root, "library")
		if err := os.Mkdir(module, 0o755); err != nil {
			return err
		}

		if output, err := runPrereleaseCommand(environment, module, "go", "mod", "init", "example.com/prerelease-library"); err != nil {
			t.Errorf("FR-prerelease-9 cannot create the empty module: %v\n%s", err, output)
			return nil
		}

		// FR-prerelease-9 — the case fetches the library with `go get`.
		requirement := prereleaseModulePath + "@" + prereleaseInstallVersion
		if output, err := runPrereleaseCommand(environment, module, "go", "get", requirement); err != nil {
			t.Errorf("FR-prerelease-9 fails at %s: go get %s: %v\n%s",
				prereleaseInstallVersion, requirement, err, output)
			return nil
		}

		source := prereleaseLibraryProgram(gopacketPathOfTheLibrary(t, environment, module), frame)
		if err := os.WriteFile(filepath.Join(module, "main.go"), []byte(source), 0o644); err != nil {
			return err
		}

		if output, err := runPrereleaseCommand(environment, module, "go", "mod", "tidy"); err != nil {
			t.Errorf("FR-prerelease-9 cannot resolve the imports of the program: %v\n%s", err, output)
			return nil
		}

		// FR-prerelease-11 — every package of the build stands outside this repository.
		//
		// This check runs before the build, because `go list -deps` resolves a package that
		// does not compile. A check after the build would report nothing at all while the
		// build is red, and FR-prerelease-11 would then rest on an assertion.
		requireNoDependencyOfTheRepository(t, environment, module)

		// FR-prerelease-9 and FR-prerelease-10 — the program compiles, and it calls
		// `Processor.ProcessPacket` and `Processor.CloseOpenWindows`.
		program := filepath.Join(module, "prerelease-library")
		if output, err := runPrereleaseCommand(environment, module, "go", "build", "-o", program, "."); err != nil {
			t.Errorf("FR-prerelease-10 fails at %s: the program does not compile against the published library.\n"+
				"`Processor.CloseOpenWindows` reaches no method of %s at %s, and the module publishes "+
				"`ProcessPacket`, `Reset`, `CleanupConnection` and `GetShardKey` alone. "+
				"#100 cuts the tag that publishes the method, and it turns this case green.\n%v\n%s",
				prereleaseInstallVersion, prereleaseModulePath, prereleaseInstallVersion, err, output)
			return nil
		}

		output, err := runPrereleaseCommand(environment, module, program)
		if err != nil {
			t.Errorf("FR-prerelease-10 cannot run the program: %v\n%s", err, output)
			return nil
		}
		if !strings.Contains(output, prereleaseExpectedJA4) {
			t.Errorf("FR-prerelease-10 fails at %s: the program writes no %s for the capture.\n%s",
				prereleaseInstallVersion, prereleaseExpectedJA4, output)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}
