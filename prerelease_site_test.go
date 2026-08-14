//go:build prerelease

package ja4plus

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The documentation site case of `docs/specs/features/16-pre-release-validation.md`.
//
// FR-prerelease-23, FR-prerelease-24 and FR-prerelease-25 read `docs/requirements.txt` and
// the generator it pins. **None of the three reads a tag**, so this case passes before the
// maintainer creates one. #94 records the maintainer ruling of 2026-08-14, and it names the
// site half as the half that must pass today.
//
// The case builds one Python environment and runs three subtests in it. A separate
// environment for each requirement would install 29 distributions three times, and the
// three requirements read one installation. #94 records the machine load of a batch that
// runs four members at once.
//
// The environment stands inside the clean environment that #95 built, so
// `runInCleanEnvironment` removes it. HOME names that environment, so the `pip` cache lands
// inside it and no wheel of the host reaches the installation.
//
// The `go` command environment of `cleanEnvironment.environ` does not serve a Python
// command: it names the directory of the `go` command, and `python3` stands elsewhere. A
// measurement on 2026-08-14 read `/opt/homebrew/bin/python3` on darwin/arm64. So this file
// composes its own variable list, and it changes no line that #98 owns.
//
// Verified against the output of `python3 -m venv --help`, `pip install --help`,
// `pip list --help` and `mkdocs build --help` at Python 3.14.3, mkdocs 1.6.1 and pip
// 26.2.1, read 2026-08-14.

// sitePinFile holds every version of the site generator, under FR-documentation-8.
const sitePinFile = "docs/requirements.txt"

// siteConfigFile holds the generator configuration that `mkdocs build` reads.
const siteConfigFile = "mkdocs.yml"

// sitePackageIndexAddress names the package index that the installation reads.
//
// The case dials it before it installs, so a machine with no network reports that it could
// not check rather than a defect of the pin file.
const sitePackageIndexAddress = "pypi.org:443"

// siteEnvironmentBootstrap names each distribution that the Python environment supplies.
//
// `docs/requirements.txt` states the same exemption: `pip` itself is absent from the list,
// because the environment supplies it. FR-prerelease-25 therefore reads every other
// distribution.
var siteEnvironmentBootstrap = map[string]bool{
	"pip":        true,
	"setuptools": true,
	"wheel":      true,
}

// siteEnvironment is one Python environment that holds the pinned site generator.
type siteEnvironment struct {
	// root is the directory of the virtual environment.
	root string
	// python is the interpreter of the virtual environment.
	python string
	// interpreterDir holds the host interpreter that creates the virtual environment.
	interpreterDir string
	// home is the value of HOME. It stands inside the clean environment.
	home string
	// tmp is the value of TMPDIR.
	tmp string
	// output is the directory that `mkdocs build` writes the site into.
	output string
}

// newSiteEnvironment returns an empty Python environment under the clean environment.
//
// It returns an error when `python3` is absent from PATH, and when the creation fails.
// The caller removes nothing: the environment stands under the root that
// `runInCleanEnvironment` removes.
func newSiteEnvironment(clean *cleanEnvironment) (*siteEnvironment, error) {
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		return nil, err
	}

	root := filepath.Join(clean.root, "site")
	environment := &siteEnvironment{
		root:           root,
		python:         filepath.Join(root, "bin", "python3"),
		interpreterDir: filepath.Dir(interpreter),
		home:           clean.home,
		tmp:            clean.tmp,
		output:         filepath.Join(clean.root, "site-output"),
	}

	output, err := environment.command(interpreter, "-m", "venv", root).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create the Python environment: %w\n%s", err, output)
	}

	return environment, nil
}

// environ returns the whole environment of a Python command.
//
// It copies no variable of the host, because FR-prerelease-1 clears the environment. A
// leaked `PIP_INDEX_URL` value would install a distribution that the pin file never names.
func (s *siteEnvironment) environ() []string {
	return []string{
		// PATH names the directory of the host interpreter, and no other host directory.
		// `python3 -m venv` reads it, and every later command names an absolute path.
		//
		// This entry reads a Unix path list, and it holds for Linux and for macOS. The same
		// constraint binds `cleanEnvironment.environ`, and #98 owns the repair there.
		"PATH=" + s.interpreterDir + ":/usr/bin:/bin",
		// HOME stands inside the clean environment, so the `pip` cache goes with it.
		"HOME=" + s.home,
		"TMPDIR=" + s.tmp,
	}
}

// command returns a Python command that runs in the site environment.
func (s *siteEnvironment) command(name string, arg ...string) *exec.Cmd {
	command := exec.Command(name, arg...)
	command.Env = s.environ()
	command.Dir = s.tmp

	return command
}

// run runs the command and returns its combined output.
//
// It returns an error that carries the output, because a `pip` failure states its reason
// there and never in the exit status.
func (s *siteEnvironment) run(name string, arg ...string) (string, error) {
	output, err := s.command(name, arg...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(arg, " "), err)
	}

	return string(output), nil
}

// networkIsAbsent reports whether the named address accepts no connection.
//
// A case that cannot reach its host proves nothing, so the caller skips and states that it
// could not check. A case that failed there would report a defect on a machine that holds
// none, and a machine with no network runs every pre-release case.
//
// The caller names the host that its own requirement reads. A probe of one host says
// nothing about a second host, and the skip message must name the host it dialed.
func networkIsAbsent(address string) bool {
	connection, err := net.DialTimeout("tcp", address, 15*time.Second)
	if err != nil {
		return true
	}

	_ = connection.Close()

	return false
}

// sitePinRequirement returns one pinned version for each distribution of the pin file.
//
// It maps the canonical distribution name to the version. It fails the test when a line
// states no exact version, because FR-prerelease-25 reads no unpinned version.
func sitePinRequirement(t *testing.T) map[string]string {
	t.Helper()

	pinned := map[string]string{}

	for number, line := range strings.Split(readRepoFile(t, sitePinFile), "\n") {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		name, version, found := strings.Cut(text, "==")
		if !found {
			t.Errorf("%s:%d states %q, and FR-prerelease-25 reads an exact version alone",
				sitePinFile, number+1, text)

			continue
		}

		pinned[siteCanonicalName(name)] = strings.TrimSpace(version)
	}

	if len(pinned) == 0 {
		t.Fatalf("%s pins no distribution, and this case would then read nothing", sitePinFile)
	}

	return pinned
}

// siteNameSeparator matches each run of the marks that a distribution name separates with.
var siteNameSeparator = regexp.MustCompile(`[-_.]+`)

// siteCanonicalName returns the canonical form of a distribution name.
//
// PEP 503 states the form: the name is lowercased, and each run of `-`, `_` and `.` becomes
// one `-`. `pip` reports `pyyaml_env_tag` and the pin file states the same spelling, so the
// two agree today. The canonical form holds when one of the two changes its spelling.
//
// Verified against: <https://peps.python.org/pep-0503/>, retrieved 2026-08-14.
func siteCanonicalName(name string) string {
	return siteNameSeparator.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// siteInstalledVersion returns the version of each distribution the environment holds.
//
// `pip list --format=freeze` writes one `name==version` line for each distribution.
func siteInstalledVersion(t *testing.T, environment *siteEnvironment) map[string]string {
	t.Helper()

	output, err := environment.run(environment.python, "-m", "pip", "list", "--format=freeze",
		"--disable-pip-version-check")
	if err != nil {
		t.Fatalf("read the installed distributions: %v\n%s", err, output)
	}

	installed := map[string]string{}

	for _, line := range strings.Split(output, "\n") {
		name, version, found := strings.Cut(strings.TrimSpace(line), "==")
		if !found {
			continue
		}

		installed[siteCanonicalName(name)] = strings.TrimSpace(version)
	}

	if len(installed) == 0 {
		t.Fatalf("the environment reports no installed distribution:\n%s", output)
	}

	return installed
}

// TestTheDocumentationSiteBuildsFromItsPins holds FR-prerelease-23, FR-prerelease-24 and
// FR-prerelease-25.
//
// The three requirements read one installation, so the case installs once and runs three
// subtests against it. A failure of the installation stops the case, because the two later
// subtests read what the installation produced.
//
// **This case reads no tag.** #94 records the maintainer ruling of 2026-08-14, and this is
// the half of #99 that passes before the release.
func TestTheDocumentationSiteBuildsFromItsPins(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("this case reads no pin file: the host holds no python3 command (%v)", err)
	}

	if networkIsAbsent(sitePackageIndexAddress) {
		t.Skipf("this case checked no pin of %s: it reached no connection to %s",
			sitePinFile, sitePackageIndexAddress)
	}

	repository, err := os.Getwd()
	if err != nil {
		t.Fatalf("read the working directory: %v", err)
	}

	err = runInCleanEnvironment(t.TempDir(), func(clean *cleanEnvironment) error {
		environment, err := newSiteEnvironment(clean)
		if err != nil {
			return err
		}

		// FR-prerelease-23. The environment is empty, and the pin file fills it.
		installed := t.Run("the pin file installs into an empty environment", func(t *testing.T) {
			output, installErr := environment.run(environment.python, "-m", "pip", "install",
				"--no-input", "--disable-pip-version-check",
				"--requirement", filepath.Join(repository, sitePinFile))
			if installErr != nil {
				t.Fatalf("%s does not install into an empty environment: %v\n%s",
					sitePinFile, installErr, output)
			}
		})

		if !installed {
			// The two subtests below read the installation, so a failed installation makes
			// each of them report a second symptom of one defect.
			return nil
		}

		// FR-prerelease-24. The site builds, and a warning fails the build.
		t.Run("the site build succeeds in strict mode", func(t *testing.T) {
			output, buildErr := environment.run(filepath.Join(environment.root, "bin", "mkdocs"),
				"build", "--strict",
				"--config-file", filepath.Join(repository, siteConfigFile),
				"--site-dir", environment.output)
			if buildErr != nil {
				t.Fatalf("mkdocs build --strict does not succeed: %v\n%s", buildErr, output)
			}

			index := filepath.Join(environment.output, "index.html")
			if _, statErr := os.Stat(index); statErr != nil {
				t.Errorf("the build wrote no %s, and the run reported success: %v", index, statErr)
			}
		})

		// FR-prerelease-25. Every version the environment holds stands in the pin file.
		t.Run("the environment holds no unpinned generator version", func(t *testing.T) {
			pinned := sitePinRequirement(t)

			for name, version := range siteInstalledVersion(t, environment) {
				if siteEnvironmentBootstrap[name] {
					continue
				}

				pin, held := pinned[name]
				switch {
				case !held:
					t.Errorf("the environment holds %s %s, and %s pins no such distribution",
						name, version, sitePinFile)
				case pin != version:
					t.Errorf("the environment holds %s %s, and %s pins %s",
						name, version, sitePinFile, pin)
				}
			}
		})

		return nil
	})
	if err != nil {
		t.Fatalf("run the case: %v", err)
	}
}
