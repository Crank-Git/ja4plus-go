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
//
// It removes every comment line first. A comment of one entry sits above the opening line
// of the next entry, so a split of the raw file gives each block the prose of its
// successor. A comment that quotes a key at the indent of a key would then satisfy an
// assertion that the entry itself fails, and the test would pass with the key absent.
//
// It splits the remainder on the `- package-ecosystem:` line, which opens every entry.
// It fails the test when the file holds no entry.
func dependabotUpdateBlocks(t *testing.T) []string {
	t.Helper()

	config := readRepoFile(t, ".github/dependabot.yml")

	var keyLines []string
	for _, line := range strings.Split(config, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		keyLines = append(keyLines, line)
	}
	keys := strings.Join(keyLines, "\n") + "\n"

	parts := regexp.MustCompile(`(?m)^  - package-ecosystem:`).Split(keys, -1)
	if len(parts) < 2 {
		t.Fatalf(".github/dependabot.yml holds no update entry:\n%s", keys)
	}

	return parts[1:]
}

// dependabotEcosystem returns the ecosystem value that opens one update block.
func dependabotEcosystem(block string) string {
	return strings.TrimSpace(strings.SplitN(block, "\n", 2)[0])
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
			if dependabotEcosystem(block) == want {
				found = true
			}
		}
		if !found {
			t.Errorf(".github/dependabot.yml watches no ecosystem named %s", want)
		}
	}
}

// FR-supply-7 names the repository root. The documentation states
// `For GitHub Actions, use the value /.`, and the same value reaches `go.mod` at the root.
func TestEveryDependabotUpdateReadsTheRepositoryRoot(t *testing.T) {
	for _, block := range dependabotUpdateBlocks(t) {
		if !strings.Contains(block, "\n    directory: \"/\"\n") {
			t.Errorf("the %s entry reads no directory of \"/\"", dependabotEcosystem(block))
		}
	}
}

// FR-supply-10 states the interval. The documentation states
// `Define whether to look for version updates: daily, weekly, monthly, quarterly,
// semiannually, yearly, or cron.`
func TestEveryDependabotUpdateRunsWeekly(t *testing.T) {
	for _, block := range dependabotUpdateBlocks(t) {
		if !strings.Contains(block, "\n      interval: \"weekly\"\n") {
			t.Errorf("the %s entry runs at no weekly interval", dependabotEcosystem(block))
		}
	}
}

// FR-supply-9 states the target branch. The documentation states
// `Specify the branch to target for version updates.`
// A security update targets the default branch, and the file records that limit.
func TestEveryDependabotUpdateTargetsDev(t *testing.T) {
	for _, block := range dependabotUpdateBlocks(t) {
		if !strings.Contains(block, "\n    target-branch: \"dev\"\n") {
			t.Errorf("the %s entry targets no branch named dev", dependabotEcosystem(block))
		}
	}
}
