package ja4plus

import (
	"regexp"
	"testing"
)

// The five constants of the pre-release cases carry one module path and one tag, and this
// file compares them.
//
// **#106 built this guard on 2026-08-15 UTC, and it moved the three tag constants to
// `v1.0.0` in the same change.** The
// `# Five constants carry the module path and the tag` section of
// `prerelease_install_test.go` recorded the hazard on 2026-08-14. A session that moves one
// constant leaves the others behind. The run then reads two tags, and it reports a green
// gate for an artifact that nobody published.
//
// **This file carries no build tag, and the five constants sit behind the `prerelease`
// tag.** So each case reads the declaration as text, and `go test ./...` runs it. A
// compile-time comparison would run under `make prerelease` alone, and that run is the one
// run which already reads the tag.
//
// **A case fails when it finds no declaration.** A rename that this file does not follow
// would otherwise compare nothing and report a pass.

// releaseTagConstantDeclaration names one constant and the file that declares it.
type releaseTagConstantDeclaration struct {
	name string
	file string
}

// releaseTagConstants names each constant that holds the tag of the release under test.
var releaseTagConstants = []releaseTagConstantDeclaration{
	{name: "prereleaseInstallVersion", file: "prerelease_install_test.go"},
	{name: "publishedModuleVersion", file: "prerelease_module_contents_test.go"},
	{name: "defaultReleaseTag", file: "prerelease_binaries_test.go"},
}

// releaseModulePathConstants names each constant that holds the published module path.
var releaseModulePathConstants = []releaseTagConstantDeclaration{
	{name: "prereleaseModulePath", file: "prerelease_install_test.go"},
	{name: "publishedModulePath", file: "prerelease_module_contents_test.go"},
}

// releaseConstantValue returns the string literal that one declaration holds.
//
// It fails the test when the file holds no such declaration, because a comparison of an
// absent constant proves nothing.
func releaseConstantValue(t *testing.T, declaration releaseTagConstantDeclaration) string {
	t.Helper()

	source := readRepoFile(t, declaration.file)
	pattern := regexp.MustCompile(`(?m)^const ` + regexp.QuoteMeta(declaration.name) + ` = "([^"]*)"$`)

	match := pattern.FindStringSubmatch(source)
	if match == nil {
		t.Fatalf("%s declares no string constant named %s, and this guard compares that declaration",
			declaration.file, declaration.name)
	}

	return match[1]
}

// TestEveryPrereleaseTagConstantHoldsOneTag holds the three tag constants at one value.
//
// The first declaration states the value, and every other declaration matches it. A
// failure names both constants and both values, so a reader repairs the one that lags.
func TestEveryPrereleaseTagConstantHoldsOneTag(t *testing.T) {
	first := releaseTagConstants[0]
	want := releaseConstantValue(t, first)

	for _, declaration := range releaseTagConstants[1:] {
		if got := releaseConstantValue(t, declaration); got != want {
			t.Errorf("%s in %s holds %q, and %s in %s holds %q. The pre-release cases read one tag, "+
				"so a run that reads two of them measures two artifacts.",
				declaration.name, declaration.file, got, first.name, first.file, want)
		}
	}
}

// TestEveryPrereleaseModulePathConstantHoldsOnePath holds the two path constants at one
// value.
//
// A case that reads one path and a case that reads another read two modules, and the run
// reports one result for both.
func TestEveryPrereleaseModulePathConstantHoldsOnePath(t *testing.T) {
	first := releaseModulePathConstants[0]
	want := releaseConstantValue(t, first)

	for _, declaration := range releaseModulePathConstants[1:] {
		if got := releaseConstantValue(t, declaration); got != want {
			t.Errorf("%s in %s holds %q, and %s in %s holds %q. The pre-release cases read one module path.",
				declaration.name, declaration.file, got, first.name, first.file, want)
		}
	}
}

// TestEveryPrereleaseTagConstantStatesASemanticVersion holds each tag at the `vN.N.N` form.
//
// `go install` and the proxy read a tag, and a value that states no version reaches no
// artifact. The case runs beside the equality case above, because three equal typing
// errors pass an equality check.
func TestEveryPrereleaseTagConstantStatesASemanticVersion(t *testing.T) {
	form := regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

	for _, declaration := range releaseTagConstants {
		if value := releaseConstantValue(t, declaration); !form.MatchString(value) {
			t.Errorf("%s in %s holds %q, and a tag of this module states the form vN.N.N",
				declaration.name, declaration.file, value)
		}
	}
}
