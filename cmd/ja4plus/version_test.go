package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// noLinkFlag is the value of Version that no link flag has set.
const noLinkFlag = ""

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
// The `Build binaries` step of `.github/workflows/release.yml` sets `main.Version` for every
// released binary, and a released binary prints the tag that the workflow read. The module
// version of the build info never displaces it.
func TestTheVersionKeepsTheLinkFlagValue(t *testing.T) {
	resolved := resolveVersion("v1.0.0", buildInfoWithVersion("v0.9.9"))

	if resolved != "v1.0.0" {
		t.Errorf("the link flag set %q, the build info holds %q, and the program prints %q",
			"v1.0.0", "v0.9.9", resolved)
	}
}

// TestTheVersionKeepsALinkFlagThatStatesTheStatedValue holds step 1 for the one value that
// a sentinel confuses.
//
// `Version` is empty until a link flag sets it, so a link flag that states `dev` keeps
// precedence like every other value. A default of `dev` would send this build to step 2,
// and the program would then print a version that no builder asked for.
func TestTheVersionKeepsALinkFlagThatStatesTheStatedValue(t *testing.T) {
	resolved := resolveVersion(statedVersion, buildInfoWithVersion("v0.9.9"))

	if resolved != statedVersion {
		t.Errorf("the link flag set %q, and the program prints %q", statedVersion, resolved)
	}
}

// TestTheVersionReadsTheModuleVersionOfTheBuildInfo holds step 2 of the version order.
//
// `go install` applies no link flag, and it stamps the module version into the binary. The
// program reads that version, so an installed program prints the tag it was installed at.
func TestTheVersionReadsTheModuleVersionOfTheBuildInfo(t *testing.T) {
	resolved := resolveVersion(noLinkFlag, buildInfoWithVersion("v0.3.0"))

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
	resolved := resolveVersion(noLinkFlag, buildInfoWithVersion("(devel)"))

	if resolved != statedVersion {
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
	resolved := resolveVersion(noLinkFlag, nil)

	if resolved != statedVersion {
		t.Errorf("the build info is absent, and the program prints %q", resolved)
	}
}

// TestTheVersionReadsTheStatedValueWhenTheBuildInfoHoldsNoVersion holds step 3 of the
// version order for the third input that reaches it.
//
// An empty module version names no release, and it reaches the same branch as `(devel)`.
func TestTheVersionReadsTheStatedValueWhenTheBuildInfoHoldsNoVersion(t *testing.T) {
	resolved := resolveVersion(noLinkFlag, buildInfoWithVersion(""))

	if resolved != statedVersion {
		t.Errorf("the build info holds an empty version, and the program prints %q", resolved)
	}
}

// TestTheStatedVersionNamesNoRelease holds acceptance criterion 3 of issue #628.
//
// A tag of this repository opens with `v`, and `git tag` lists `v0.1.0`, `v0.2.0` and
// `v0.3.0` on 2026-08-14. **The value that a working-tree build prints must name no
// release**, so a reader who sees it knows that the build states no release.
//
// The case reads the constant and it reads the resolver, because a constant that names no
// tag proves nothing about the value that the program prints.
func TestTheStatedVersionNamesNoRelease(t *testing.T) {
	if strings.HasPrefix(statedVersion, "v") {
		t.Errorf("the stated version is %q, and a tag of this repository opens with `v`", statedVersion)
	}

	if statedVersion != "dev" {
		t.Errorf("the stated version is %q, and `TestEveryReleasedBinaryPrintsTheTagVersion` reads `dev`", statedVersion)
	}

	for _, moduleVersion := range []string{"(devel)", ""} {
		resolved := resolveVersion(noLinkFlag, buildInfoWithVersion(moduleVersion))

		if strings.HasPrefix(resolved, "v") {
			t.Errorf("the build info holds %q, and the program prints %q, which names a release",
				moduleVersion, resolved)
		}
	}
}

// TestTheVersionLineOfThisTestBinaryNamesNoRelease reads the live build info of the test
// binary.
//
// The six cases above supply the build info, so no one of them proves what `go test`
// reports. This case runs the whole path that `ja4plus --version` runs.
func TestTheVersionLineOfThisTestBinaryNamesNoRelease(t *testing.T) {
	line := versionLine()

	if line != "ja4plus "+statedVersion {
		t.Errorf("the test binary prints %q, and a build from a working tree names no release", line)
	}
}
