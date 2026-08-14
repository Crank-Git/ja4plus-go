package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// The released binaries that the pre-release binary cases read, and the guards that hold
// the list against the release workflow.
//
// This file carries no build tag, so `go test ./...` holds the guards. The cases live in
// `prerelease_binaries_test.go` under the `prerelease` build tag, because each one reads a
// published artifact that this repository does not hold.
//
// `release_cgo_test.go` reads the same workflow for a different property, so this file
// reuses `releaseWorkflowPath`, `releaseWorkflowStep` and `releaseBuildStepName` rather
// than stating any of them a second time.

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
// `TestTheReleaseWorkflowBuildsEveryBinaryThatTheCasesRead` holds this list equal to the
// build step of the workflow, so a sixth artifact reaches the cases rather than shipping
// unchecked.
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

// releaseChecksumStepName names the step that writes the checksum file.
const releaseChecksumStepName = "Create checksums"

// releaseArtifactOutput reads the artifact name and the platform pair of one build command.
//
// The pattern anchors the platform pair to the start of the line, as `releaseArtifactBuild`
// of `release_cgo_test.go` does. A `#` between the indent and `GOOS=` then stops the match,
// because a commented-out build publishes no artifact.
var releaseArtifactOutput = regexp.MustCompile(`(?m)^[ \t]*GOOS=(\S+) GOARCH=(\S+) go build .*-o dist/(\S+)`)

// TestTheReleaseWorkflowBuildsEveryBinaryThatTheCasesRead holds FR-prerelease-18 against
// the workflow.
//
// FR-prerelease-18 runs each released binary, and the cases read the list above rather than
// the release. A workflow that adds a sixth artifact would otherwise publish a binary that
// no case runs, and the pre-release summary would report a complete run over an incomplete
// set.
func TestTheReleaseWorkflowBuildsEveryBinaryThatTheCasesRead(t *testing.T) {
	step := releaseWorkflowStep(t, releaseBuildStepName)

	builds := releaseArtifactOutput.FindAllStringSubmatch(step, -1)
	if len(builds) != len(releasedBinaries) {
		t.Fatalf("the %q step of %s builds %d artifacts, and the cases read %d",
			releaseBuildStepName, releaseWorkflowPath, len(builds), len(releasedBinaries))
	}

	for index, build := range builds {
		binary := releasedBinaries[index]
		if build[1] != binary.goos || build[2] != binary.goarch || build[3] != binary.file {
			t.Errorf("the workflow builds %s for %s/%s, and the cases read %s for %s/%s",
				build[3], build[1], build[2], binary.file, binary.goos, binary.goarch)
		}
	}
}

// TestTheReleasePublishesTheChecksumFileThatTheCaseVerifies holds FR-prerelease-22 against
// the workflow.
//
// FR-prerelease-22 verifies each artifact against the published checksum file, and the case
// reads that file by name. A renamed file would fail the case with a message about an absent
// file rather than about a checksum, and this guard names the rename instead.
func TestTheReleasePublishesTheChecksumFileThatTheCaseVerifies(t *testing.T) {
	step := releaseWorkflowStep(t, releaseChecksumStepName)
	if !strings.Contains(step, releaseChecksumFile) {
		t.Errorf("the %q step of %s writes no %s, and FR-prerelease-22 reads that file",
			releaseChecksumStepName, releaseWorkflowPath, releaseChecksumFile)
	}

	// The case computes a SHA-256 digest, so the workflow must publish that digest and no
	// other. A step that wrote an MD5 file under the same name would pass the check above.
	if !strings.Contains(step, "sha256sum") {
		t.Errorf("the %q step of %s writes no SHA-256 digest, and FR-prerelease-22 computes one",
			releaseChecksumStepName, releaseWorkflowPath)
	}

	workflow := readRepoFile(t, releaseWorkflowPath)
	if !strings.Contains(workflow, "dist/"+releaseChecksumFile) {
		t.Errorf("%s publishes no dist/%s, so the case reads a file that no release holds",
			releaseWorkflowPath, releaseChecksumFile)
	}
}
