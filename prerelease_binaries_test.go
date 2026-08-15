//go:build prerelease

package ja4plus

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// The binary cases of `docs/specs/features/16-pre-release-validation.md` run here. They
// hold FR-prerelease-18 through FR-prerelease-22, and #98 built them on 2026-08-14.
//
// Every case reads a published release, and this repository has cut no tag under test. The
// maintainer ruled the scope on 2026-08-14, at #94: each case is written against `v0.3.0`,
// it runs, and it records what it reports. **A case that finds no released artifact names
// the tag it looked for and it names #100**, which is the issue that publishes a release.
// That result is the correct result today, and it is never a case to weaken until it
// passes.
//
// The feature file states one rule for this slice, and the edge-case table states its
// consequence. The rule reads `A binary case runs on the platform it tests.`, and a Linux
// runner therefore proves nothing about the Darwin artifact. The table reads:
//
//	| A binary is built for a platform no runner offers. | The case records the platform as
//	unchecked and names it in the release notes. It does not pass silently. |
//
// So `checkPlatform` below returns false for every platform except the one that runs the
// case, and the case logs one `UNCHECKED` line for each of the others. A translation layer
// reaches no exception: a Darwin amd64 artifact that runs under Rosetta 2 on Darwin arm64
// proves nothing about a Darwin amd64 machine.
//
// FR-prerelease-21 reads the file rather than the machine, so it reaches all five
// artifacts on one runner. `dynamicLibraries` states the one format that gives no answer.

// releaseDirectoryVariable names the environment variable that holds the download
// directory of the release under test.
//
// The cases read a directory rather than the network, because a pre-release check runs on
// the release commit and the maintainer downloads the artifacts once. The doc comment of
// `releaseUnderTest` states the download command.
const releaseDirectoryVariable = "JA4PLUS_RELEASE_DIR"

// releaseTagVariable names the environment variable that overrides the tag under test.
const releaseTagVariable = "JA4PLUS_RELEASE_TAG"

// defaultReleaseTag names the tag that the cases read when the environment names none.
//
// `v0.3.0` is the version of the library today, and `CLAUDE.md` states it. #593 records
// that the maintainer cuts no tag before the Epic 10 freeze, so this value is the newest
// tag that the cases can read.
//
// **Two other constants hold `v0.3.0`, and no guard compares the three.**
// `prereleaseInstallVersion` in `prerelease_install_test.go` and `publishedModuleVersion` in
// `prerelease_module_contents_test.go` are the two. The
// `# Five constants carry the module path and the tag` section of `prerelease_install_test.go`
// states the hazard. That section names #100 as the issue that repairs it.
const defaultReleaseTag = "v0.3.0"

// releaseIssue names the issue that publishes a release for a tag under test.
const releaseIssue = 100

// expectedJA4TValue is the JA4T value of the capture that FR-prerelease-20 writes.
//
// `TestJA4T_SYNWithFullOptions` in `ja4t_test.go` holds the same value for the same packet,
// so a released binary that reports another value differs from the tree. The case builds
// the packet with `buildTCPPacket`, which `ja4t_test.go` also holds.
const expectedJA4TValue = "29200_2-1-3-1-1-8-4-0-0_1460_7"

// releaseUnderTest returns the download directory and the tag of the release under test.
//
// It fails the case when the environment names no directory. The message names the tag and
// the issue, because a reader of a red pre-release run must be able to separate an absent
// release from a broken one.
//
// Download the artifacts of a published tag with one command:
//
//	gh release download <tag> --repo Crank-Git/ja4plus-go --dir <directory>
func releaseUnderTest(t *testing.T) (directory string, tag string) {
	t.Helper()

	tag = os.Getenv(releaseTagVariable)
	if tag == "" {
		tag = defaultReleaseTag
	}

	directory = os.Getenv(releaseDirectoryVariable)
	if directory == "" {
		t.Fatalf("no released artifact reaches this case: %s names no directory, and the case reads the release of tag %s. This repository publishes no release for a tag under test, and #%d publishes one. Download the artifacts with `gh release download %s --repo Crank-Git/ja4plus-go --dir <directory>`.",
			releaseDirectoryVariable, tag, releaseIssue, tag)
	}

	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("%s names %s, and the case reads no directory there: %v", releaseDirectoryVariable, directory, err)
	}

	// The clean environment runs a command from its own root, so a relative path of the
	// download directory would reach no file. The absolute path holds for every command.
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("read the absolute path of %s: %v", directory, err)
	}

	return absolute, tag
}

// checkPlatform states whether this machine runs the named artifact.
//
// A case runs an artifact only when the operating system and the architecture both match
// this machine. Every other artifact is unchecked, and the caller says so.
func checkPlatform(binary releasedBinary) bool {
	return binary.goos == runtime.GOOS && binary.goarch == runtime.GOARCH
}

// reportUnchecked logs one line for an artifact that this machine does not run.
//
// The line opens with `UNCHECKED`, so the maintainer reads the platform out of the
// pre-release summary and names it in the release notes.
func reportUnchecked(t *testing.T, binary releasedBinary, reason string) {
	t.Helper()

	t.Logf("UNCHECKED %s (%s/%s) — %s. This runner is %s/%s.",
		binary.file, binary.goos, binary.goarch, reason, runtime.GOOS, runtime.GOARCH)
}

// nativeBinary returns the artifact that this machine runs, and the path to it.
//
// It reports every other artifact as unchecked, and it reads the whole list before it
// returns. A loop that stopped at the native artifact would leave the rest of the list
// unreported, and the summary would name fewer unchecked platforms than the release holds.
//
// It fails the case when the release builds no artifact for this platform, because a case
// that checks nothing must not report a pass. It fails the case when the file is absent,
// and the message names the tag.
func nativeBinary(t *testing.T, directory string, tag string) (releasedBinary, string) {
	t.Helper()

	native := releasedBinary{}
	found := false

	for _, binary := range releasedBinaries {
		if checkPlatform(binary) {
			native = binary
			found = true

			continue
		}

		reportUnchecked(t, binary, "no runner of this case offers the platform")
	}

	if !found {
		t.Fatalf("the release of tag %s builds no artifact for %s/%s, so this runner checks no binary",
			tag, runtime.GOOS, runtime.GOARCH)
	}

	path := filepath.Join(directory, native.file)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the release of tag %s holds no %s in %s: %v", tag, native.file, directory, err)
	}

	return native, path
}

// runBinary returns the standard output of the released binary, in a clean environment.
//
// The clean environment of FR-prerelease-1 gives the program an empty HOME, so the run
// reads no cached database and no configuration of the person who runs the case. It fails
// the case when the program reports a non-zero status.
//
// The message of that failure holds the standard error stream of the program. A released
// binary that refuses its input writes the reason there, and `exit status 1` alone sends the
// reader back to the machine that ran the case.
func runBinary(t *testing.T, path string, arg ...string) string {
	t.Helper()

	output := ""
	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		// `exec.Cmd.Output` reports the standard error stream inside an `*exec.ExitError`, and
		// it reports that stream for no other error. The case collects both streams itself, so
		// one message holds the reason whatever the program did.
		results := &strings.Builder{}
		diagnostics := &strings.Builder{}
		command := environment.command(path, arg...)
		command.Stdout = results
		command.Stderr = diagnostics

		runErr := command.Run()
		output = results.String()
		if runErr != nil {
			return fmt.Errorf("run %s %s: %w\nstandard error: %s",
				filepath.Base(path), strings.Join(arg, " "), runErr, diagnostics.String())
		}

		return nil
	})
	if err != nil {
		t.Fatalf("%v\nstandard output: %s", err, output)
	}

	return output
}

// TestEveryReleasedBinaryRunsOnItsOwnPlatform holds FR-prerelease-18.
//
// The case runs the artifact of this platform and reads its exit status. It records every
// other artifact as unchecked, because a Linux runner cannot prove that the Darwin binary
// runs.
func TestEveryReleasedBinaryRunsOnItsOwnPlatform(t *testing.T) {
	directory, tag := releaseUnderTest(t)
	binary, path := nativeBinary(t, directory, tag)

	output := runBinary(t, path, "--version")
	if !strings.HasPrefix(output, "ja4plus ") {
		t.Errorf("%s printed %q, and the program prints one line that opens with `ja4plus `", binary.file, output)
	}

	t.Logf("CHECKED %s (%s/%s) — the artifact runs on this machine.", binary.file, binary.goos, binary.goarch)
}

// TestEveryReleasedBinaryPrintsTheTagVersion holds FR-prerelease-19.
//
// The release workflow builds each artifact with `-X main.Version=${GITHUB_REF_NAME}`, so
// the version of a released binary is the tag. **So this case separates a released artifact
// from a local build**, and a `dev` value is a failure rather than a pass.
//
// #95 measured `ja4plus dev` for a local build on 2026-08-14, and #628 moved that value on
// the same day. A local `go build` now prints the pseudo-version that the toolchain stamps,
// such as `ja4plus v0.3.1-0.20260815010712-5cf4a407ddd3`. `go run` and `go test` still print
// `ja4plus dev`. **Each of the three values names no tag**, so this case still separates the
// two kinds of build.
func TestEveryReleasedBinaryPrintsTheTagVersion(t *testing.T) {
	directory, tag := releaseUnderTest(t)
	binary, path := nativeBinary(t, directory, tag)

	output := strings.TrimSpace(runBinary(t, path, "--version"))
	expected := "ja4plus " + tag

	if output != expected {
		t.Errorf("%s printed %q, and the release of tag %s prints %q", binary.file, output, tag, expected)
	}
}

// TestEveryReleasedBinaryFingerprintsACapture holds FR-prerelease-20.
//
// The case writes one capture that holds one TCP SYN packet, and it reads the JA4T value
// that the released binary reports. `TestJA4T_SYNWithFullOptions` in `ja4t_test.go` holds
// the same expected value for the same packet, so a released binary that answers
// differently differs from the tree that the release was cut from.
func TestEveryReleasedBinaryFingerprintsACapture(t *testing.T) {
	directory, tag := releaseUnderTest(t)
	binary, path := nativeBinary(t, directory, tag)

	capture := filepath.Join(t.TempDir(), "capture.pcap")
	writeJA4TCapture(t, capture)

	output := runBinary(t, path, "analyze", capture, "--json", "--types", "ja4t")

	var results []struct {
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		t.Fatalf("%s printed no JSON document: %v\noutput: %s", binary.file, err, output)
	}

	if len(results) != 1 {
		t.Fatalf("%s reported %d JA4T values on the capture, and the capture holds one SYN packet:\n%s",
			binary.file, len(results), output)
	}

	if !strings.EqualFold(results[0].Type, "ja4t") {
		t.Errorf("%s reported the type %q, and the case reads the JA4T value", binary.file, results[0].Type)
	}

	if results[0].Fingerprint != expectedJA4TValue {
		t.Errorf("the release of tag %s reports %q on the capture, and the tree reports %q",
			tag, results[0].Fingerprint, expectedJA4TValue)
	}
}

// writeJA4TCapture writes one capture that holds one TCP SYN packet.
//
// The packet is the packet of `TestJA4T_SYNWithFullOptions`, so the expected value of the
// case has one source in the tree. The link type is Ethernet, because `buildTCPPacket`
// serializes an Ethernet frame.
func writeJA4TCapture(t *testing.T, path string) {
	t.Helper()

	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindEndList, OptionLength: 1},
	}
	packet := buildTCPPacket(t, 12345, 443, true, false, 29200, options)
	data := packet.Data()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write the capture header of %s: %v", path, err)
	}

	info := gopacket.CaptureInfo{
		Timestamp:     packet.Metadata().Timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}
	if err := writer.WritePacket(info, data); err != nil {
		t.Fatalf("write the packet of %s: %v", path, err)
	}
}

// TestNoReleasedBinaryHoldsADynamicLinkToLibpcap holds FR-prerelease-21.
//
// `CLAUDE.md` `## Stack` states the rule: the default build holds no cgo, and no release
// artifact is built with the `libpcap` build tag. #583 set `CGO_ENABLED=0` for all five
// release builds on 2026-08-14, and `release_cgo_test.go` holds that setting. This case
// reads the artifact itself, so it measures the property that the setting produces.
//
// The case reads the file rather than the machine, so it reaches every artifact on one
// runner. An artifact whose format gives no import table is unchecked, and it never passes.
func TestNoReleasedBinaryHoldsADynamicLinkToLibpcap(t *testing.T) {
	directory, tag := releaseUnderTest(t)

	for _, binary := range releasedBinaries {
		path := filepath.Join(directory, binary.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("the release of tag %s holds no %s in %s: %v", tag, binary.file, directory, err)
			continue
		}

		libraries, checked, err := dynamicLibraries(path)
		if err != nil {
			t.Errorf("read the import table of %s: %v", binary.file, err)
			continue
		}

		if !checked {
			reportUnchecked(t, binary, "the format reader of the standard library reads no import table for this artifact")
			continue
		}

		for _, library := range libraries {
			if strings.Contains(strings.ToLower(library), "pcap") {
				t.Errorf("%s links %s at dynamic link time, and no release artifact links libpcap", binary.file, library)
			}
		}

		t.Logf("CHECKED %s (%s/%s) — the import table names these libraries: [%s]",
			binary.file, binary.goos, binary.goarch, strings.Join(libraries, " "))
	}
}

// dynamicLibraries returns the libraries that the named binary links at dynamic link time.
//
// It returns false when it reads no import table for the format, so the caller records the
// artifact as unchecked. It returns an error when no format reader of the standard library
// opens the file.
//
// **The PE path reads `ImportedSymbols` and never `ImportedLibraries`.**
// `debug/pe.ImportedLibraries` is unimplemented at go1.26.5, and it returns an empty list
// for every input:
//
//	func (f *File) ImportedLibraries() ([]string, error) {
//		// TODO
//		// cgo -dynimport don't use this for windows PE, so just return.
//		return nil, nil
//	}
//
// An empty list from that method would read as an artifact that links nothing, which is
// the silent pass that the edge-case table of the feature file forbids. `ImportedSymbols`
// is implemented, and it returns one entry for each imported symbol in the form
// `<symbol>:<library>`. A run of the five artifacts on 2026-08-14 at go1.26.5 recorded
// `GetProcAddress:kernel32.dll` as the first entry of the Windows artifact.
//
// **An empty symbol list is unchecked and never a pass.** A Windows program imports from
// `kernel32.dll`, so an empty list names a reader that found no import table rather than an
// artifact that holds none.
//
// Verified against the output of `go doc debug/elf File.ImportedLibraries`,
// `go doc debug/macho File.ImportedLibraries` and `go doc debug/pe File.ImportedSymbols` at
// go1.26.5, read 2026-08-14.
func dynamicLibraries(path string) ([]string, bool, error) {
	if file, err := elf.Open(path); err == nil {
		defer func() { _ = file.Close() }()

		libraries, err := file.ImportedLibraries()

		return libraries, true, err
	}

	if file, err := macho.Open(path); err == nil {
		defer func() { _ = file.Close() }()

		libraries, err := file.ImportedLibraries()

		return libraries, true, err
	}

	file, err := pe.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("%s holds no ELF, no Mach-O and no PE image: %w", filepath.Base(path), err)
	}
	defer func() { _ = file.Close() }()

	symbols, err := file.ImportedSymbols()
	if err != nil {
		return nil, false, err
	}

	libraries := []string{}
	for _, symbol := range symbols {
		separator := strings.LastIndex(symbol, ":")
		if separator < 0 {
			continue
		}

		library := symbol[separator+1:]
		if !slices.Contains(libraries, library) {
			libraries = append(libraries, library)
		}
	}

	return libraries, len(libraries) > 0, nil
}

// TestEveryPublishedChecksumVerifies holds FR-prerelease-22.
//
// The release publishes `checksums.txt`, which the `Create checksums` step writes with
// `sha256sum`. The case computes the digest of each artifact and compares it against the
// published line, so a truncated download and a replaced artifact both fail here.
//
// **This case verifies the digest of a released binary, and it verifies no module hash.**
// The Go module proxy publishes a hash of the module zip, which is a different artifact and
// a different digest. FR-prerelease-12 through FR-prerelease-17 read the module, and #97
// measured it at `v0.3.0` on 2026-08-14: 56 files, 2253962 bytes and the hash
// `h1:TdhICjAT96tKBBTNPCArJCzuOhZ5LmbtMmLj50gAdIA=`. A reader who compares that hash against
// a line of `checksums.txt` compares two unrelated values.
//
// The case reads the file rather than the machine, so it reaches every artifact on one
// runner.
func TestEveryPublishedChecksumVerifies(t *testing.T) {
	directory, tag := releaseUnderTest(t)

	path := filepath.Join(directory, releaseChecksumFile)
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the release of tag %s holds no %s in %s: %v", tag, releaseChecksumFile, directory, err)
	}

	digests := map[string]string{}
	for _, line := range strings.Split(string(published), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		// `sha256sum` writes `*` before the name of a file that it read in binary mode.
		digests[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}

	for _, binary := range releasedBinaries {
		digest, ok := digests[binary.file]
		if !ok {
			t.Errorf("%s of the release of tag %s names no digest for %s", releaseChecksumFile, tag, binary.file)
			continue
		}

		computed, err := fileDigest(filepath.Join(directory, binary.file))
		if err != nil {
			t.Errorf("compute the digest of %s: %v", binary.file, err)
			continue
		}

		if !strings.EqualFold(computed, digest) {
			t.Errorf("%s holds the digest %s, and %s publishes %s", binary.file, computed, releaseChecksumFile, digest)
		}
	}
}

// fileDigest returns the SHA-256 digest of the named file, in lower-case hexadecimal.
func fileDigest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:]), nil
}
