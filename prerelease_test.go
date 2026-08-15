//go:build prerelease

package ja4plus

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The pre-release cases of `docs/specs/features/16-pre-release-validation.md` run here.
// The `prerelease` build tag keeps them out of `go test ./...`, because a case builds a
// directory tree and some cases reach the module proxy.
//
// This file builds the clean environment, and it runs no case that reads a published
// artifact. #96 through #99 add those cases, and each one calls `runInCleanEnvironment`.
//
// FR-prerelease-1 states that the environment holds no source of this repository. The
// environment is therefore cleared and never extended: `cleanEnvironment.environ` returns
// an explicit list, and it copies no variable of the host.
//
// `go help environment` at go1.26.5 names each variable below, and it states two that a
// reader of the requirement list would miss.
//
//	GOENV
//		The location of the Go environment configuration file.
//		Cannot be set using 'go env -w'.
//		Setting GOENV=off in the environment disables the use of the
//		default configuration file.
//
// So `go env -w GOFLAGS=...` on the host reaches a `go` command that inherits no
// environment variable at all, and `GOENV=off` is the one setting that shuts that path.
//
//	GOWORK
//		In module aware mode, use the given go.work file as a workspace file.
//
// A `go.work` file above the environment would add a module of this repository to the
// build, which is the leak FR-prerelease-11 forbids. `GOWORK=off` shuts that path.
//
// Verified against the output of `go help environment` at go1.26.5, read 2026-08-14.

// cleanEnvironment is one clean environment for one pre-release case.
//
// It holds no source of this repository, an empty module cache and an empty build cache.
// One case owns one environment, and `runInCleanEnvironment` removes it.
type cleanEnvironment struct {
	// root is the directory that holds every other directory of the environment.
	root string
	// goModCache is the value of GOMODCACHE. FR-prerelease-2 states that it starts empty.
	goModCache string
	// goCache is the value of GOCACHE. FR-prerelease-3 states that it starts empty.
	goCache string
	// goPath is the value of GOPATH.
	goPath string
	// goBin is the value of GOBIN. An installed program lands here.
	goBin string
	// home is the value of HOME. The host home directory holds a Go configuration file.
	home string
	// tmp is the value of TMPDIR and of GOTMPDIR.
	tmp string
	// goDir is the directory that holds the `go` command. It is the only host directory
	// that PATH names.
	goDir string
}

// newCleanEnvironment returns a clean environment under the named parent directory.
//
// An empty parent names the system temporary directory. The caller removes the
// environment, and `runInCleanEnvironment` is the supported way to do that.
// It returns an error when the `go` command is absent from PATH, and when a directory
// cannot be created.
func newCleanEnvironment(parent string) (*cleanEnvironment, error) {
	goCommand, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}

	root, err := os.MkdirTemp(parent, "ja4plus-prerelease-")
	if err != nil {
		return nil, err
	}

	environment := &cleanEnvironment{
		root:       root,
		goModCache: filepath.Join(root, "gomodcache"),
		goCache:    filepath.Join(root, "gocache"),
		goPath:     filepath.Join(root, "gopath"),
		goBin:      filepath.Join(root, "bin"),
		home:       filepath.Join(root, "home"),
		tmp:        filepath.Join(root, "tmp"),
		goDir:      filepath.Dir(goCommand),
	}

	for _, directory := range environment.directories() {
		if err := os.Mkdir(directory, 0o755); err != nil {
			// The caller cannot remove an environment it never received, so remove it here.
			_ = os.RemoveAll(root)
			return nil, err
		}
	}

	if err := environment.stopTelemetry(); err != nil {
		_ = environment.remove()
		return nil, err
	}

	return environment, nil
}

// stopTelemetry shuts the Go telemetry collection of the environment.
//
// A `go` command writes a counter file under the directory that `os.UserConfigDir`
// reports, and it writes that file after the command exits. HOME names the environment,
// so the write lands inside the environment and it recreates the tree that `remove`
// deleted. A measurement of go1.26.5 on 2026-08-14 recorded six leaked environments after
// one run, and each one held
// `home/Library/Application Support/go/telemetry/local/go@go1.26.5-...v1.count`.
//
// `go help telemetry` at go1.26.5 states that no environment variable shuts it:
//
//	The current telemetry mode is also available as the value of the
//	non-settable "GOTELEMETRY" go env variable. The directory in the
//	local file system that telemetry data is written to is available
//	as the value of the non-settable "GOTELEMETRYDIR" go env variable.
//
// It states the command that does:
//
//	To disable both collection and uploading, run "go telemetry off".
//
// The mode reaches the environment alone, because HOME names the environment. The setting
// of the person who runs the case does not change.
func (e *cleanEnvironment) stopTelemetry() error {
	return e.command("go", "telemetry", "off").Run()
}

// directories returns every directory that `newCleanEnvironment` creates under the root.
func (e *cleanEnvironment) directories() []string {
	return []string{e.goModCache, e.goCache, e.goPath, e.goBin, e.home, e.tmp}
}

// environ returns the whole environment of a command that the case runs.
//
// It copies no variable of the host, because FR-prerelease-1 clears the environment.
// A leaked GOFLAGS value, or a Go configuration file that GOENV names, would invalidate
// the case.
func (e *cleanEnvironment) environ() []string {
	return []string{
		// PATH names the directory of the `go` command, and no other host directory.
		//
		// This entry reads a Unix path list, and it holds for Linux and for macOS. Windows
		// separates a path list with `;` and holds no `/usr/bin`, so a Windows runner needs
		// `os.PathListSeparator` and a different directory list here. `## Open questions`
		// question 1 of `docs/specs/features/16-pre-release-validation.md` names a Windows
		// runner for the binary case, so #98 reaches this line before any other issue does.
		"PATH=" + e.goDir + ":/usr/bin:/bin",
		"HOME=" + e.home,
		"TMPDIR=" + e.tmp,
		// GOENV=off shuts the per-user Go configuration file, which `go env -w` writes.
		"GOENV=off",
		// GOWORK=off shuts a `go.work` file above the environment.
		"GOWORK=off",
		"GOMODCACHE=" + e.goModCache,
		"GOCACHE=" + e.goCache,
		"GOPATH=" + e.goPath,
		"GOBIN=" + e.goBin,
		"GOTMPDIR=" + e.tmp,
	}
}

// command returns a command that runs in the clean environment.
//
// The working directory is the root of the environment, so a relative path of the command
// reaches no file of this repository.
func (e *cleanEnvironment) command(name string, arg ...string) *exec.Cmd {
	command := exec.Command(name, arg...)
	command.Env = e.environ()
	command.Dir = e.root

	return command
}

// goEnv returns the value that `go env` reports for the named variable, inside the clean
// environment. It returns an error when the command fails.
func (e *cleanEnvironment) goEnv(name string) (string, error) {
	output, err := e.command("go", "env", name).Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// remove deletes the whole environment.
//
// It restores the owner write bit on every directory first, because `go mod download`
// writes the module cache read-only. A measurement of go1.26.5 on 2026-08-14 recorded a
// module directory at mode `555` and a module file at mode `444`. A directory without the
// owner write bit permits no unlink, so `os.RemoveAll` alone leaves the whole module cache
// behind and FR-prerelease-4 fails.
//
// `go help clean` at go1.26.5 states the documented alternative:
//
//	The -modcache flag causes clean to remove the entire module
//	download cache, including unpacked source code of versioned
//	dependencies.
//
// This method calls no subprocess, because a case that failed can leave a `go` command
// that cannot run. A removal path that needs the tool under test is a removal path that
// fails when the case fails, and the failure path is the path FR-prerelease-4 guards.
func (e *cleanEnvironment) remove() error {
	// A path this walk cannot read reaches `os.RemoveAll` below, which reports the error.
	_ = filepath.WalkDir(e.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})

	return os.RemoveAll(e.root)
}

// runInCleanEnvironment builds a clean environment, calls the case, and removes the
// environment.
//
// FR-prerelease-4 states that the case removes the environment when it finishes. A
// deferred call performs the removal, so the environment goes when the case returns an
// error and when the case panics. A panic reaches the caller unchanged.
// It returns the error of the case. When the case returns no error and the removal fails,
// it returns the removal error.
func runInCleanEnvironment(parent string, run func(*cleanEnvironment) error) (err error) {
	environment, err := newCleanEnvironment(parent)
	if err != nil {
		return err
	}

	defer func() {
		removeErr := environment.remove()
		if err == nil {
			err = removeErr
		}
	}()

	return run(environment)
}

// countEntries returns the number of directory entries under the named directory.
func countEntries(t *testing.T, directory string) int {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", directory, err)
	}

	return len(entries)
}

// TestTheCleanEnvironmentHoldsNoSourceOfThisRepository holds FR-prerelease-1.
//
// The environment stands outside the repository, and it holds no regular file at its
// start. A case that reads a file of the repository proves nothing about a published
// artifact, and FR-prerelease-11 states that rule for the install case.
func TestTheCleanEnvironmentHoldsNoSourceOfThisRepository(t *testing.T) {
	repository, err := os.Getwd()
	if err != nil {
		t.Fatalf("read the working directory: %v", err)
	}

	err = runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		if strings.HasPrefix(environment.root, repository+string(filepath.Separator)) {
			t.Errorf("the environment %s stands inside the repository %s", environment.root, repository)
		}

		// The environment holds one file at its start, and the harness writes it. It is the
		// telemetry mode file that `stopTelemetry` writes under HOME. Every other directory
		// of the environment is empty, and a case fills the ones it needs.
		files := []string{}
		walkErr := filepath.WalkDir(environment.root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasPrefix(path, environment.home+string(filepath.Separator)) {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if walkErr != nil {
			return walkErr
		}

		if len(files) != 0 {
			t.Errorf("the environment holds %d file(s) outside HOME at its start: %v", len(files), files)
		}

		if environment.command("go", "version").Dir != environment.root {
			t.Error("a command of the case runs outside the environment")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}

// TestTheCleanEnvironmentClearsAHostVariable holds the edge case of FR-prerelease-1.
//
// The feature file states it: `The clean environment inherits a GOFLAGS value from the
// host. | FR-prerelease-1 clears the environment. A leaked flag would invalidate the
// case.` The environment is cleared and never extended, so a host value reaches no `go`
// command of a case.
func TestTheCleanEnvironmentClearsAHostVariable(t *testing.T) {
	t.Setenv("GOFLAGS", "-mod=vendor")
	t.Setenv("GOPRIVATE", "example.com/private")

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		for _, name := range []string{"GOFLAGS=", "GOPRIVATE=", "GOSUMDB=", "GOPROXY="} {
			for _, entry := range environment.environ() {
				if strings.HasPrefix(entry, name) {
					t.Errorf("the environment names %s, and a case must read the Go default", entry)
				}
			}
		}

		for _, variable := range []string{"GOFLAGS", "GOPRIVATE"} {
			value, err := environment.goEnv(variable)
			if err != nil {
				return err
			}
			if value != "" {
				t.Errorf("go env %s reports %q in the clean environment, and the host value leaked", variable, value)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}

// TestTheCleanEnvironmentHoldsAnEmptyModuleCache holds FR-prerelease-2.
//
// An empty module cache is what makes the install case meaningful: it costs a full
// download, and it proves that the module proxy serves the artifact.
func TestTheCleanEnvironmentHoldsAnEmptyModuleCache(t *testing.T) {
	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		if entries := countEntries(t, environment.goModCache); entries != 0 {
			t.Errorf("the module cache holds %d entries at its start", entries)
		}

		value, err := environment.goEnv("GOMODCACHE")
		if err != nil {
			return err
		}
		if value != environment.goModCache {
			t.Errorf("go env GOMODCACHE reports %q, and the environment names %q", value, environment.goModCache)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}

// TestTheCleanEnvironmentHoldsAnEmptyBuildCache holds FR-prerelease-3.
//
// The build cache of the host holds a compiled package of this repository. A case that
// reads it measures the working tree rather than the published artifact.
func TestTheCleanEnvironmentHoldsAnEmptyBuildCache(t *testing.T) {
	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		if entries := countEntries(t, environment.goCache); entries != 0 {
			t.Errorf("the build cache holds %d entries at its start", entries)
		}

		value, err := environment.goEnv("GOCACHE")
		if err != nil {
			return err
		}
		if value != environment.goCache {
			t.Errorf("go env GOCACHE reports %q, and the environment names %q", value, environment.goCache)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}

// TestTheCaseRemovesTheEnvironmentWhenTheCasePasses holds FR-prerelease-4 on the path
// that passes.
func TestTheCaseRemovesTheEnvironmentWhenTheCasePasses(t *testing.T) {
	root := ""

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		root = environment.root
		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}

	requireAbsent(t, root)
}

// TestTheCaseRemovesTheEnvironmentWhenTheCaseFails holds FR-prerelease-4 on the path that
// fails.
//
// A case that leaves a directory behind on a failure is the defect this requirement
// exists to prevent. A failing case is the common case in a release check, so the path
// that fails is the path that matters.
func TestTheCaseRemovesTheEnvironmentWhenTheCaseFails(t *testing.T) {
	root := ""
	failure := errors.New("the case failed")

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		root = environment.root
		return failure
	})
	if !errors.Is(err, failure) {
		t.Errorf("the case error is %v, and the caller must read the failure of the case", err)
	}

	requireAbsent(t, root)
}

// TestTheCaseRemovesTheEnvironmentWhenTheCasePanics holds FR-prerelease-4 on the path that
// panics.
//
// A case runs an external command and reads its output, so a panic is reachable. The
// panic reaches the caller unchanged, and the environment goes.
func TestTheCaseRemovesTheEnvironmentWhenTheCasePanics(t *testing.T) {
	root := ""

	func() {
		defer func() {
			recovered := recover()
			if recovered == nil {
				t.Error("the panic of the case did not reach the caller")
			}
		}()

		_ = runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
			root = environment.root
			panic("the case panicked")
		})
	}()

	requireAbsent(t, root)
}

// TestTheCaseRemovesTheEnvironmentThatHoldsAReadOnlyModuleCache holds FR-prerelease-4
// against the module cache that a real case downloads.
//
// `go mod download` writes the module cache read-only. A measurement of go1.26.5 on
// 2026-08-14 recorded mode `555` on a module directory and mode `444` on a module file,
// and `rm -rf` then reported `Permission denied` on every one of them. `os.RemoveAll`
// alone leaves the whole cache behind, so the environment of #96 and of #98 would survive
// every run.
//
// This case writes that permission shape rather than downloading a module, so it needs no
// network and it costs no download.
func TestTheCaseRemovesTheEnvironmentThatHoldsAReadOnlyModuleCache(t *testing.T) {
	root := ""

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		root = environment.root

		module := filepath.Join(environment.goModCache, "example.com", "module@v1.0.0")
		if err := os.MkdirAll(module, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(module, "module.go"), []byte("package module\n"), 0o444); err != nil {
			return err
		}
		// The directory loses the owner write bit last, because the file lands inside it.
		return os.Chmod(module, 0o555)
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}

	requireAbsent(t, root)
}

// TestTheCaseRemovesTheEnvironmentAfterAGoCommandRuns holds FR-prerelease-4 against the
// Go telemetry writer.
//
// A `go` command writes a telemetry counter file under HOME after the command exits, and
// HOME names the environment. A measurement of go1.26.5 on 2026-08-14 recorded six leaked
// environments after one `make prerelease` run, and every one of them came from a case
// that ran a `go` command. `remove` reported no error in each of the six, because the
// write landed after the removal.
//
// `newCleanEnvironment` runs `go telemetry off` in the environment, so no counter file is
// written and the removal is final. This case runs two `go` commands, and it then reads
// the environment root.
func TestTheCaseRemovesTheEnvironmentAfterAGoCommandRuns(t *testing.T) {
	root := ""

	err := runInCleanEnvironment(t.TempDir(), func(environment *cleanEnvironment) error {
		root = environment.root

		mode, err := environment.goEnv("GOTELEMETRY")
		if err != nil {
			return err
		}
		if mode != "off" {
			t.Errorf("go env GOTELEMETRY reports %q, and a counter file then survives the removal", mode)
		}

		return environment.command("go", "version").Run()
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}

	requireAbsent(t, root)
}

// requireAbsent fails the test when the named path exists.
func requireAbsent(t *testing.T, path string) {
	t.Helper()

	if path == "" {
		t.Fatal("the case recorded no environment root")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the environment %s survives the case, and FR-prerelease-4 removes it", path)
	}
}

// TestThePrereleaseRunReportsOneSummary holds FR-prerelease-5.
//
// `make prerelease` runs every case of the feature set, and this slice ships the cases it
// has. The summary names each case that asserts nothing today, so a reader separates a case
// that waits from a case that passed.
//
// **The summary printed `absent` for a case that runs, until 2026-08-14.** The Epic 16
// cross-member review measured it: the FR-prerelease-26 case and
// `TestEveryLivedMutationOfTheMostRecentSweepIsSettled` each stood in the tree and each one
// skipped. So the round renamed the state to `waits`, which is what each of the two did.
//
// **Every row of the registry proves a requirement today, and the summary names no waiting
// case.** Batch #645 flipped the last two rows on 2026-08-15 UTC. #633 flipped
// `the pre-release run against the tag`, and `TestTheReleaseGateRunsAgainstTheTagUnderTest`
// now asserts. #642 flipped `the mutation sweep report`, and
// `TestEveryLivedMutationOfTheMostRecentSweepIsSettled` now asserts. **The run reports
// 8 rows, 8 proving cases and 0 waiting cases**, measured on 2026-08-15 UTC by the
// documentation round of that batch.
//
// **The `waits` state stays reachable, and a later row that asserts nothing restores it.**
// So this case reads the registry rather than a written count.
func TestThePrereleaseRunReportsOneSummary(t *testing.T) {
	proved, waiting := 0, 0

	t.Log("pre-release summary — one line for each case of features/16-pre-release-validation.md")
	for _, prereleaseCase := range prereleaseCases {
		state := "waits"
		if prereleaseCase.proves {
			state = "proves"
			proved++
		} else {
			waiting++
		}

		// The width holds the longest row name of the registry. #633 widened it from 30 on
		// 2026-08-15 UTC, because `the pre-release run against the tag` is 35 characters and
		// a shorter width pushes the state column out of line.
		t.Logf("  %-35s %-6s issue #%d  %s",
			prereleaseCase.name, state, prereleaseCase.issue,
			strings.Join(prereleaseCase.requirements, " "))
	}

	t.Logf("pre-release summary — %d case(s) prove a requirement, %d case(s) wait", proved, waiting)

	if proved == 0 {
		t.Error("the registry names no case that proves a requirement, and this target then proves nothing")
	}
}
