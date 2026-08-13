package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// `.github/dependabot.yml` is a build harness file, and no Go code reads it at run time.
// These tests hold FR-supply-6 through FR-supply-10, so that a later edit cannot drop a
// key without a failure.
//
// The schedule decides when the first real pull request arrives, so no test here observes
// one. Each test below reads the configuration, and it reads no result of Dependabot.

// dependabotUpdateBlocks returns the text of each entry under the `updates` key.
// It splits on the `- package-ecosystem:` line, which opens every entry.
// It fails the test when the file holds no entry.
func dependabotUpdateBlocks(t *testing.T) []string {
	t.Helper()

	config := readRepoFile(t, ".github/dependabot.yml")

	parts := regexp.MustCompile(`(?m)^  - package-ecosystem:`).Split(config, -1)
	if len(parts) < 2 {
		t.Fatalf(".github/dependabot.yml holds no update entry:\n%s", config)
	}

	return parts[1:]
}

// FR-supply-6 creates the file, and the version key states the configuration syntax.
// The documentation states `Dependabot configuration syntax to use. Always: 2.`
func TestTheDependabotConfigurationDeclaresVersion2(t *testing.T) {
	config := readRepoFile(t, ".github/dependabot.yml")

	if !regexp.MustCompile(`(?m)^version: 2$`).MatchString(config) {
		t.Errorf(".github/dependabot.yml does not declare version 2:\n%s", config)
	}
}

// FR-supply-7 names `gomod`, and FR-supply-8 names `github-actions`. The documentation
// states each value, and a value this project invents matches no package manager.
func TestTheDependabotConfigurationWatchesTwoEcosystems(t *testing.T) {
	blocks := dependabotUpdateBlocks(t)

	if len(blocks) != 2 {
		t.Fatalf(".github/dependabot.yml holds %d update entries, and FR-supply-7 with FR-supply-8 name two", len(blocks))
	}

	for _, want := range []string{`"gomod"`, `"github-actions"`} {
		found := false
		for _, block := range blocks {
			if strings.HasPrefix(strings.TrimSpace(block), want) {
				found = true
			}
		}
		if !found {
			t.Errorf(".github/dependabot.yml watches no ecosystem named %s", want)
		}
	}
}

// FR-supply-10 states the interval. FR-supply-9 states the target branch, and the
// documentation states `Specify the branch to target for version updates.`
// The `directory` value reaches `go.mod` at the root, and it reaches `.github/workflows`.
func TestEveryDependabotUpdateRunsWeeklyAgainstDev(t *testing.T) {
	for _, block := range dependabotUpdateBlocks(t) {
		ecosystem := strings.TrimSpace(strings.SplitN(block, "\n", 2)[0])

		for _, want := range []string{
			"\n    directory: \"/\"\n",
			"\n      interval: \"weekly\"\n",
			"\n    target-branch: \"dev\"\n",
		} {
			if !strings.Contains(block, want) {
				t.Errorf("the %s entry holds no %s", ecosystem, strings.TrimSpace(want))
			}
		}
	}
}
