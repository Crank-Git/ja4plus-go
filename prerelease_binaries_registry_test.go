package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// The released binaries that the pre-release binary cases read, and the guards that hold
// the list against the release build.
//
// This file carries no build tag, so `go test ./...` holds the guards. The cases live in
// `prerelease_binaries_test.go` under the `prerelease` build tag, because each one reads a
// published artifact that this repository does not hold.
//
// **The guards read `.goreleaser.yaml`, and they read no step of the release workflow.**
// #105 moved the build to GoReleaser on 2026-08-15, and FR-release-35a states that the
// workflow holds no inline build matrix. `release_cgo_test.go` reads the same file for a
// different property, so this file reuses `goreleaserConfigPath`, `yamlListItems` and
// `goreleaserBuildPlatforms` rather than stating any of them a second time.

// releasedBinary names one artifact that the release publishes.
type releasedBinary struct {
	// file names the artifact in the release, and it names the file in the download
	// directory that the cases read.
	file string
	// goos names the operating system that the artifact runs on.
	goos string
	// goarch names the architecture that the artifact runs on.
	goarch string
}

// releasedBinaries holds one row for each artifact of the release.
//
// `TestTheReleaseBuildsEveryBinaryThatTheCasesRead` holds this list equal to the build of
// `.goreleaser.yaml`, so a sixth artifact reaches the cases rather than shipping unchecked.
var releasedBinaries = []releasedBinary{
	{file: "ja4plus-linux-amd64", goos: "linux", goarch: "amd64"},
	{file: "ja4plus-linux-arm64", goos: "linux", goarch: "arm64"},
	{file: "ja4plus-darwin-amd64", goos: "darwin", goarch: "amd64"},
	{file: "ja4plus-darwin-arm64", goos: "darwin", goarch: "arm64"},
	{file: "ja4plus-windows-amd64.exe", goos: "windows", goarch: "amd64"},
}

// releaseChecksumFile names the published file that FR-prerelease-22 verifies each
// artifact against.
const releaseChecksumFile = "checksums.txt"

// archiveNameTemplate reads the template that names each published artifact.
//
// GoReleaser applies the template and then appends the binary extension of the platform, so
// the Windows artifact reads `ja4plus-windows-amd64.exe`.
// `internal/pipe/archive/archive.go` of `goreleaser/goreleaser` at `v2.17.1` states it:
// `finalName := name + binary.Ext()`.
var archiveNameTemplate = regexp.MustCompile(`(?m)^\s*name_template: "ja4plus-\{\{ \.Os \}\}-\{\{ \.Arch \}\}"\s*$`)

// releasedBinaryName returns the artifact name that GoReleaser writes for one platform.
//
// It applies the template that `TestTheReleaseBuildsEveryBinaryThatTheCasesRead` proves, and
// it appends `.exe` for Windows.
func releasedBinaryName(goos, goarch string) string {
	name := "ja4plus-" + goos + "-" + goarch
	if goos == "windows" {
		return name + ".exe"
	}

	return name
}

// TestTheReleaseBuildsEveryBinaryThatTheCasesRead holds FR-prerelease-18 against the release
// build.
//
// FR-prerelease-18 runs each released binary, and the cases read the list above rather than
// the release. A build that adds a sixth artifact would otherwise publish a binary that no
// case runs, and the pre-release summary would report a complete run over an incomplete set.
func TestTheReleaseBuildsEveryBinaryThatTheCasesRead(t *testing.T) {
	if !archiveNameTemplate.MatchString(readRepoFile(t, goreleaserConfigPath)) {
		t.Fatalf("%s names no `ja4plus-{{ .Os }}-{{ .Arch }}` archive template, and the cases read that name",
			goreleaserConfigPath)
	}

	built := goreleaserBuildPlatforms(t)
	if len(built) != len(releasedBinaries) {
		t.Fatalf("%s builds %d artifacts, and the cases read %d: %v",
			goreleaserConfigPath, len(built), len(releasedBinaries), built)
	}

	held := map[string]bool{}
	for _, pair := range built {
		held[pair] = true
	}

	for _, binary := range releasedBinaries {
		if !held[binary.goos+"/"+binary.goarch] {
			t.Errorf("the cases read %s, and the release builds no %s/%s artifact",
				binary.file, binary.goos, binary.goarch)
			continue
		}

		if name := releasedBinaryName(binary.goos, binary.goarch); name != binary.file {
			t.Errorf("the release publishes %s for %s/%s, and the cases read %s",
				name, binary.goos, binary.goarch, binary.file)
		}
	}
}

// TestTheReleasePublishesTheChecksumFileThatTheCaseVerifies holds FR-prerelease-22 against
// the release build.
//
// FR-prerelease-22 verifies each artifact against the published checksum file, and the case
// reads that file by name. A renamed file would fail the case with a message about an absent
// file rather than about a checksum, and this guard names the rename instead.
func TestTheReleasePublishesTheChecksumFileThatTheCaseVerifies(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	if !strings.Contains(config, `name_template: "`+releaseChecksumFile+`"`) {
		t.Errorf("%s writes no %s, and FR-prerelease-22 reads that file",
			goreleaserConfigPath, releaseChecksumFile)
	}

	// The case computes a SHA-256 digest, so the release must publish that digest and no
	// other. GoReleaser accepts several algorithms, and a config that named `md5` would pass
	// the check above under the same file name.
	if !regexp.MustCompile(`(?m)^\s*algorithm: sha256\s*$`).MatchString(config) {
		t.Errorf("%s writes no SHA-256 digest, and FR-prerelease-22 computes one",
			goreleaserConfigPath)
	}
}
