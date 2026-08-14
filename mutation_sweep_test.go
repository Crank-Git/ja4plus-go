package ja4plus

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests hold the mutation sweep harness of Epic 15 (#89), which #90 built.
// No Go code reads the harness at run time, so a later edit could drop it without a
// failure. These tests are that failure.
//
// `docs/specs/features/15-mutation-sweep.md` holds FR-mutation-1 through FR-mutation-5.

// TestTheMakefileRunsTheMutationTool holds FR-mutation-1 and FR-mutation-3.
func TestTheMakefileRunsTheMutationTool(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !regexp.MustCompile(`(?m)^mutate:\s*$`).MatchString(makefile) {
		t.Error("the Makefile holds no mutate recipe, so make mutate exits 2")
	}

	if !strings.Contains(makefile, "gremlins unleash") {
		t.Error("the mutate recipe runs no gremlins unleash, so it sweeps nothing")
	}
}

// TestTheMutateTargetIsPhony holds the `.PHONY` entry of the `mutate` target.
//
// A target that `.PHONY` does not name stops when a file of that name exists. `make docs`
// carries the measured case, because `docs/` is a directory of this repository.
//
// The reading for `mutate`: the repository root holds no path named `mutate`, so the trap
// that `make docs` hits does not apply today. The entry still guards the target, because a
// later change that adds such a path would leave `make mutate` reporting
// `make: Nothing to be done for 'mutate'.` and exiting 0 without a sweep. The second
// assertion below holds the reading, and it fails when the path appears.
func TestTheMutateTargetIsPhony(t *testing.T) {
	phony := regexp.MustCompile(`(?m)^\.PHONY:(.*)$`).FindStringSubmatch(readRepoFile(t, "Makefile"))
	if phony == nil {
		t.Fatal("the Makefile states no .PHONY line")
	}

	if !strings.Contains(" "+strings.TrimSpace(phony[1])+" ", " mutate ") {
		t.Error("the .PHONY line names no mutate target")
	}

	if _, err := os.Stat("mutate"); err == nil {
		t.Error("the repository root now holds a path named mutate, so the reading of this test is stale")
	}
}

// TestTheMakefilePinsTheMutationToolVersion holds FR-mutation-2.
//
// FR-mutation-2 permits the pin in `.gremlins.yaml` or in the `Makefile`. The pin lives in
// the `Makefile`, because the documented `gremlins` configuration schema holds no version
// key. Verified against <https://gremlins.dev/latest/usage/configuration/>, retrieved
// 2026-08-14.
func TestTheMakefilePinsTheMutationToolVersion(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	pin := regexp.MustCompile(`(?m)^GREMLINS_VERSION \?= (v[0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(makefile)
	if pin == nil {
		t.Fatal("the Makefile states no GREMLINS_VERSION pin")
	}

	if !strings.Contains(makefile, "gremlins@$(GREMLINS_VERSION)") {
		t.Errorf("the pin is %s, and no install command reads it, so the pin binds nothing", pin[1])
	}
}

// TestTheMutateTargetSweepsOnePackage holds FR-mutation-5.
//
// `?=` sets the variable only when the environment and the command line state none, so
// `make mutate PKG=./internal/parser` overrides the named set of FR-mutation-4.
func TestTheMutateTargetSweepsOnePackage(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	if !regexp.MustCompile(`(?m)^PKG \?= `).MatchString(makefile) {
		t.Error("the Makefile does not set PKG with ?=, so a command line cannot override it")
	}

	if !strings.Contains(makefile, "unleash $(PKG)") {
		t.Error("the mutate recipe does not pass PKG to gremlins, so PKG selects nothing")
	}
}

// TestTheMutationConfigurationRaisesTheTimeoutCoefficient holds the measured configuration
// of `.gremlins.yaml`.
//
// `gremlins` estimates the timeout of one mutant from a `go test` run that the Go build
// cache serves, so the estimate collapses to the cache-hit time. At the default coefficient
// of 3, every one of the 16 mutants of `internal/dbcache` reported `TIMED OUT`, measured on
// 2026-08-14. `./ja4db` settles at 120, and 240 reports the same verdicts as 120.
func TestTheMutationConfigurationRaisesTheTimeoutCoefficient(t *testing.T) {
	config := readRepoFile(t, ".gremlins.yaml")

	if !regexp.MustCompile(`(?m)^\s+timeout-coefficient: 120$`).MatchString(config) {
		t.Error("the configuration does not set timeout-coefficient to 120, so a fast suite reports a false TIMED OUT")
	}
}

// TestTheMutationConfigurationExcludesTheCommandLineProgram holds
// `docs/specs/features/15-mutation-sweep.md` `## Out of scope`, which declines a sweep of
// `cmd/ja4plus`.
//
// The path argument of `gremlins unleash` reads a whole directory tree, so the default
// `PKG` of `.` reaches `cmd/` without this list.
func TestTheMutationConfigurationExcludesTheCommandLineProgram(t *testing.T) {
	config := readRepoFile(t, ".gremlins.yaml")

	for _, pattern := range []string{"'^cmd/'", "'^examples/'"} {
		if !strings.Contains(config, pattern) {
			t.Errorf("the exclude-files list does not hold %s", pattern)
		}
	}
}
