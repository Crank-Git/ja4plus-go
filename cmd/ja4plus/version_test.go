package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// buildInfoWithVersion returns build info whose main module holds the version.
//
// `debug.ReadBuildInfo` reads the running binary, so a test cannot change what it returns.
// `resolveVersion` therefore takes the build info as a parameter.
func buildInfoWithVersion(version string) *debug.BuildInfo {
	info := &debug.BuildInfo{}
	info.Main.Path = "github.com/Crank-Git/ja4plus-go"
	info.Main.Version = version

	return info
}

// TestTheVersionKeepsTheLinkFlagValue holds step 1 of the version order.
//
// `.github/workflows/release.yml:118` sets `main.Version` for every released binary, and a
// released binary prints the tag that the workflow read. The module version of the build
// info never displaces it.
func TestTheVersionKeepsTheLinkFlagValue(t *testing.T) {
	resolved := resolveVersion("v1.0.0", buildInfoWithVersion("v0.9.9"))

	if resolved != "v1.0.0" {
		t.Errorf("the link flag set %q, the build info holds %q, and the program prints %q",
			"v1.0.0", "v0.9.9", resolved)
	}
}

// TestTheVersionReadsTheModuleVersionOfTheBuildInfo holds step 2 of the version order.
//
// `go install` applies no link flag, and it stamps the module version into the binary. The
// program reads that version, so an installed program prints the tag it was installed at.
func TestTheVersionReadsTheModuleVersionOfTheBuildInfo(t *testing.T) {
	resolved := resolveVersion(unsetVersion, buildInfoWithVersion("v0.3.0"))

	if resolved != "v0.3.0" {
		t.Errorf("the build info holds %q, and the program prints %q", "v0.3.0", resolved)
	}
}

// TestTheVersionReadsTheStatedValueForADevelopmentBuild holds step 3 of the version order.
//
// `go run` and `go test` each report `(devel)` for the module version, measured on
// 2026-08-14 with go1.26.5. That value names no release, so the program prints the stated
// value instead.
func TestTheVersionReadsTheStatedValueForADevelopmentBuild(t *testing.T) {
	resolved := resolveVersion(unsetVersion, buildInfoWithVersion("(devel)"))

	if resolved != unsetVersion {
		t.Errorf("the build info holds %q, and the program prints %q", "(devel)", resolved)
	}
}

// TestTheVersionReadsTheStatedValueWhenTheBuildInfoIsAbsent holds step 3 of the version
// order for the second input that reaches it.
//
// `debug.ReadBuildInfo` reports no build info for a binary that no module built, and it
// returns a nil pointer with that report. A read of that pointer panics, and the program
// prints the stated value instead.
func TestTheVersionReadsTheStatedValueWhenTheBuildInfoIsAbsent(t *testing.T) {
	resolved := resolveVersion(unsetVersion, nil)

	if resolved != unsetVersion {
		t.Errorf("the build info is absent, and the program prints %q", resolved)
	}
}

// TestTheVersionReadsTheStatedValueWhenTheBuildInfoHoldsNoVersion holds step 3 of the
// version order for the third input that reaches it.
//
// An empty module version names no release, and it reaches the same branch as `(devel)`.
func TestTheVersionReadsTheStatedValueWhenTheBuildInfoHoldsNoVersion(t *testing.T) {
	resolved := resolveVersion(unsetVersion, buildInfoWithVersion(""))

	if resolved != unsetVersion {
		t.Errorf("the build info holds an empty version, and the program prints %q", resolved)
	}
}

// TestTheStatedVersionNamesNoRelease holds acceptance criterion 3 of issue #628.
//
// A tag of this repository opens with `v`, and `git tag` lists `v0.1.0`, `v0.2.0` and
// `v0.3.0` on 2026-08-14. The stated value must name no release, so a reader who sees it
// knows that the build came from a working tree.
func TestTheStatedVersionNamesNoRelease(t *testing.T) {
	if strings.HasPrefix(unsetVersion, "v") {
		t.Errorf("the stated version is %q, and a tag of this repository opens with `v`", unsetVersion)
	}

	if unsetVersion != "dev" {
		t.Errorf("the stated version is %q, and `TestEveryReleasedBinaryPrintsTheTagVersion` reads `dev`", unsetVersion)
	}
}

// TestTheVersionLineOfThisTestBinaryNamesNoRelease reads the live build info of the test
// binary.
//
// The five cases above supply the build info, so no one of them proves what `go test`
// reports. This case runs the whole path that `ja4plus --version` runs.
func TestTheVersionLineOfThisTestBinaryNamesNoRelease(t *testing.T) {
	line := versionLine()

	if line != "ja4plus "+unsetVersion {
		t.Errorf("the test binary prints %q, and a build from a working tree names no release", line)
	}
}
