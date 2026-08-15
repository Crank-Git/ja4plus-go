package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// These tests hold the release build of `docs/specs/features/10-release.md` against the
// tree. #105 rewrote the file on 2026-08-15, and the reason is a moved build.
//
// The release workflow held an inline matrix of five `go build` commands until that date,
// and FR-release-35a states that GoReleaser builds the release. So `.goreleaser.yaml` now
// holds the build, and every assertion about a platform, about cgo and about a build tag
// reads that file rather than the workflow. The workflow keeps the conformance gate, the
// release notes and the pins.
//
// **No pull request runs the release workflow**, because a tag push is its only trigger.
// The `goreleaser` job of `.github/workflows/ci.yml` reads `.goreleaser.yaml` on every pull
// request, and these tests read both files in the tree. A test in the tree is the earliest
// reader of either one.
//
// The shape follows `go_toolchain_statement_test.go`, which guards the other build claim of
// this repository. Every case reads a file as text, because no test of this module parses
// YAML and the module depends on no YAML package.

// releaseWorkflowPath names the workflow that publishes every released binary.
const releaseWorkflowPath = ".github/workflows/release.yml"

// goreleaserConfigPath names the file that holds the release build.
const goreleaserConfigPath = ".goreleaser.yaml"

// ciWorkflowPath names the workflow that reads the release build on a pull request.
const ciWorkflowPath = ".github/workflows/ci.yml"

// goreleaserVersion is the GoReleaser release that both workflows install.
//
// FR-release-35j pins the version, because a range moves the build tool under an unchanged
// tree. `TestEveryGoreleaserStepNamesThePinnedVersion` holds each step at this value.
const goreleaserVersion = "v2.17.1"

// releaseBuildPlatforms names the five platforms that FR-release-35b requires.
//
// Each entry is one `GOOS/GOARCH` pair. `releasedBinaries` in
// `prerelease_binaries_registry_test.go` holds the artifact name of each pair, and
// `TestTheReleaseBuildsEveryBinaryThatTheCasesRead` holds the two lists equal.
var releaseBuildPlatforms = []string{
	"linux/amd64",
	"linux/arm64",
	"darwin/amd64",
	"darwin/arm64",
	"windows/amd64",
}

// cgoDisabled matches the environment entry that sets the variable to zero.
//
// GoReleaser reads the `env` key of a build as a list of `NAME=value` entries, so the entry
// carries no YAML mapping colon. The pattern rejects any other value, and an edit to
// `CGO_ENABLED=1` therefore fails rather than passing on the name alone.
var cgoDisabled = regexp.MustCompile(`(?m)^\s*- CGO_ENABLED=0\s*$`)

// cgoAnyValue matches the GitHub Actions mapping key at any value.
//
// A workflow that sets the key at any scope reaches the race detector of a test step, and
// `TestNoWorkflowSetsCgoEnabled` reads that.
var cgoAnyValue = regexp.MustCompile(`(?m)^\s*CGO_ENABLED:\s*\S+\s*$`)

// inlineArtifactBuild matches a build command that writes an artifact into `dist/`.
//
// FR-release-35a states that the workflow holds no inline build matrix, and this pattern
// finds one. It anchors the platform pair to the start of the line, so a `#` between the
// indent and `GOOS=` stops the match. **A commented-out build is not a build**, and the
// self-review of #583 measured that trap on 2026-08-14.
var inlineArtifactBuild = regexp.MustCompile(`(?m)^[ \t]*GOOS=\S+ GOARCH=\S+ go build .*-o dist/\S+`)

// yamlListItems returns the items of the named YAML list of the text.
//
// The list starts at the `<key>:` line and it ends at the first line that is neither a `- `
// item nor a comment at a deeper indent. It returns the trimmed item text of each entry.
//
// It fails the test when the text holds no such key, because an absent key silently empties
// every assertion that reads the list.
func yamlListItems(t *testing.T, text, key string) []string {
	t.Helper()

	lines := strings.Split(text, "\n")

	start := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == key+":" {
			start = index
			break
		}
	}

	if start < 0 {
		t.Fatalf("%s holds no %q key, and this case reads that list", goreleaserConfigPath, key)
	}

	var items []string
	for _, line := range lines[start+1:] {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !strings.HasPrefix(trimmed, "- ") {
			break
		}

		items = append(items, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
	}

	return items
}

// goreleaserBuildPlatforms returns the `GOOS/GOARCH` pairs that the configuration builds.
//
// It reads the `goos` list and the `goarch` list, it forms the cross product, and it removes
// each pair that the `ignore` list names. GoReleaser builds that same set.
//
// Verified against <https://goreleaser.com/customization/builds/go/>, retrieved 2026-08-15.
// The page names the `goos`, `goarch` and `ignore` keys of a build.
func goreleaserBuildPlatforms(t *testing.T) []string {
	t.Helper()

	config := readRepoFile(t, goreleaserConfigPath)

	ignored := map[string]bool{}
	ignoreBlock := regexp.MustCompile(`(?m)^\s*- goos: (\S+)\n\s*goarch: (\S+)\s*$`)
	for _, entry := range ignoreBlock.FindAllStringSubmatch(config, -1) {
		ignored[entry[1]+"/"+entry[2]] = true
	}

	var pairs []string
	for _, goos := range yamlListItems(t, config, "goos") {
		for _, goarch := range yamlListItems(t, config, "goarch") {
			pair := goos + "/" + goarch
			if !ignored[pair] {
				pairs = append(pairs, pair)
			}
		}
	}

	return pairs
}

// TestTheReleaseBuildDisablesCgo holds FR-release-35c.
//
// A released binary that links the C name resolver reads `nsswitch.conf` and the glibc
// modules of the machine that runs it, and a static binary does not. #583 measured on
// 2026-08-14 that one artifact of five linked glibc dynamically, because the runner's native
// platform took the Go default of `CGO_ENABLED=1`.
//
// GoReleaser cross compiles every artifact from one environment, so one entry now covers all
// five.
func TestTheReleaseBuildDisablesCgo(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	if !cgoDisabled.MatchString(config) {
		t.Errorf("%s sets no CGO_ENABLED=0 environment entry, and FR-release-35c requires it",
			goreleaserConfigPath)
	}
}

// TestNoWorkflowSetsCgoEnabled holds the setting where the race detector cannot reach it.
//
// The `Run tests` step of the release workflow runs `go test -race`, and the race detector
// needs cgo. Measured on 2026-08-14 for the runner's platform:
//
//	$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -race -o /dev/null ./cmd/ja4plus
//	go: -race requires cgo
//
// So a job-level or workflow-level setting turns the release red at the test step, and it
// never reaches the build it was written for. The build environment of `.goreleaser.yaml`
// reaches the build alone, so no workflow of this repository needs the key at all.
//
// **The assertion reads every workflow, and not the release workflow alone.** A snapshot
// build runs in `.github/workflows/ci.yml`, and a setting there would carry the same trap
// into the `test` job.
//
// Verified against
// <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions>,
// retrieved 2026-08-14. It states the precedence: `When more than one environment variable
// is defined with the same name, GitHub uses the most specific variable. For example, an
// environment variable defined in a step will override job and workflow environment
// variables with the same name, while the step executes.`
func TestNoWorkflowSetsCgoEnabled(t *testing.T) {
	for _, path := range []string{releaseWorkflowPath, ciWorkflowPath} {
		settings := cgoAnyValue.FindAllString(readRepoFile(t, path), -1)
		if len(settings) != 0 {
			t.Errorf("%s holds %d CGO_ENABLED settings, and %s owns that variable",
				path, len(settings), goreleaserConfigPath)
		}
	}
}

// TestTheReleaseBuildsTheFivePlatforms holds FR-release-35b.
//
// The configuration names three operating systems and two architectures, which is six pairs.
// The `ignore` entry removes Windows arm64, and no requirement names that pair. A test that
// read the two lists alone would report six, so this case reads the removal too.
func TestTheReleaseBuildsTheFivePlatforms(t *testing.T) {
	built := goreleaserBuildPlatforms(t)

	if len(built) != len(releaseBuildPlatforms) {
		t.Fatalf("%s builds %d platforms, and FR-release-35b names %d: %v",
			goreleaserConfigPath, len(built), len(releaseBuildPlatforms), built)
	}

	held := map[string]bool{}
	for _, pair := range built {
		held[pair] = true
	}

	for _, pair := range releaseBuildPlatforms {
		if !held[pair] {
			t.Errorf("%s builds no %s artifact, and FR-release-35b names that platform",
				goreleaserConfigPath, pair)
		}
	}
}

// TestTheReleaseWorkflowHoldsNoInlineBuildMatrix holds FR-release-35a.
//
// The workflow held five `go build` commands until 2026-08-15, and
// `docs/specs/features/10-release.md` recorded the requirement as unbuilt. A build that
// returns to the workflow would read no line of `.goreleaser.yaml`, so every guard of this
// file would pass over an artifact that no configuration describes.
func TestTheReleaseWorkflowHoldsNoInlineBuildMatrix(t *testing.T) {
	builds := inlineArtifactBuild.FindAllString(readRepoFile(t, releaseWorkflowPath), -1)
	if len(builds) != 0 {
		t.Errorf("%s holds %d inline artifact builds, and FR-release-35a states that GoReleaser builds the release:\n%s",
			releaseWorkflowPath, len(builds), strings.Join(builds, "\n"))
	}
}

// TestNoReleaseArtifactUsesTheLibpcapBuildTag holds FR-release-35d.
//
// `internal/capture/libpcap.go` imports cgo, and the `libpcap` build tag selects it. It
// exists so that `ja4plus watch` reaches macOS, because the pure-Go capture handle of
// `pcapgo` is Linux-only. A release artifact that carried the tag would need a C toolchain
// for each of the five platforms, and it would link the C name resolver.
//
// **The case reads the configuration lines, and it reads no comment.** The file states the
// rule in prose, and a case that read the whole text would fail on the sentence that states
// the rule.
func TestNoReleaseArtifactUsesTheLibpcapBuildTag(t *testing.T) {
	for _, line := range strings.Split(readRepoFile(t, goreleaserConfigPath), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if strings.Contains(line, "libpcap") {
			t.Errorf("%s names the libpcap build tag, and FR-release-35d keeps it out of every artifact: %q",
				goreleaserConfigPath, line)
		}
	}
}

// TestTheReleaseRunsTheConformanceSuiteBeforeTheBuild holds FR-release-35 and FR-release-36.
//
// The suite exits 2 on a deviation, so a step that runs it and holds back no exit status
// fails the job. The `conformance` job of `.github/workflows/ci.yml` holds that status back
// deliberately, and this workflow must not.
//
// The suite runs in a job of its own, and the `release` job names it in `needs:`. The suite
// rewrites `docs/audit/conformance.md` on every run, so a run in the release job would leave
// the git tree dirty and GoReleaser would refuse the release.
func TestTheReleaseRunsTheConformanceSuiteBeforeTheBuild(t *testing.T) {
	workflow := readRepoFile(t, releaseWorkflowPath)

	if !regexp.MustCompile(`(?m)^ *run: make conformance$`).MatchString(workflow) {
		t.Errorf("%s runs no bare `make conformance`, and FR-release-36 fails the release on a deviation",
			releaseWorkflowPath)
	}

	if !regexp.MustCompile(`(?m)^ *needs: conformance$`).MatchString(workflow) {
		t.Errorf("%s holds no job that needs the conformance job, so the build does not wait for the suite",
			releaseWorkflowPath)
	}
}

// TestTheReleaseAttachesTheLicenseAndTheNotice holds FR-release-38.
//
// `NOTICE` holds the FoxIO License 1.1 terms, and FoxIO licenses every method except JA4
// under terms that permit non-commercial use only. A release that publishes a binary without
// that file states the wrong license to every person who downloads it.
func TestTheReleaseAttachesTheLicenseAndTheNotice(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	for _, file := range []string{"LICENSE", "NOTICE"} {
		if !strings.Contains(config, "- glob: ./"+file) {
			t.Errorf("%s attaches no %s, and FR-release-38 attaches it to the release",
				goreleaserConfigPath, file)
		}
	}
}

// TestTheReleaseReadsTheNotesFromTheChangelog holds FR-release-39.
//
// The workflow reads the section of the tag from `CHANGELOG.md` and it passes the file to
// GoReleaser. GoReleaser generates a changelog of its own when no file reaches it, and that
// generated list names each commit rather than the recorded release.
//
// Verified against <https://goreleaser.com/customization/release/>, retrieved 2026-08-15. It
// states the flag: `You can specify a file containing your custom release notes, and pass it
// with the --release-notes=FILE flag.`
func TestTheReleaseReadsTheNotesFromTheChangelog(t *testing.T) {
	workflow := readRepoFile(t, releaseWorkflowPath)

	if !strings.Contains(workflow, "CHANGELOG.md") {
		t.Errorf("%s reads no CHANGELOG.md, and FR-release-39 reads the release notes from it",
			releaseWorkflowPath)
	}

	if !strings.Contains(workflow, "--release-notes=") {
		t.Errorf("%s passes no --release-notes flag, so GoReleaser generates the notes instead",
			releaseWorkflowPath)
	}
}

// TestThePullRequestChecksAndBuildsTheReleaseConfiguration holds FR-release-35h and
// FR-release-35i.
//
// A tag push is the only trigger of the release workflow, so a defect in `.goreleaser.yaml`
// would otherwise first appear on the tag that publishes `v1.0.0`. `goreleaser check` reads
// the schema, and a snapshot runs every build, every checksum and every bill of materials.
// A snapshot publishes nothing, and the job passes no token for that reason.
func TestThePullRequestChecksAndBuildsTheReleaseConfiguration(t *testing.T) {
	workflow := readRepoFile(t, ciWorkflowPath)

	if !regexp.MustCompile(`(?m)^ *args: check$`).MatchString(workflow) {
		t.Errorf("%s runs no `goreleaser check`, and FR-release-35h gates a pull request with it",
			ciWorkflowPath)
	}

	if !regexp.MustCompile(`(?m)^ *args: release --snapshot --clean$`).MatchString(workflow) {
		t.Errorf("%s runs no `goreleaser release --snapshot --clean`, and FR-release-35i runs one on a pull request",
			ciWorkflowPath)
	}
}

// TestEveryGoreleaserStepNamesThePinnedVersion holds FR-release-35j.
//
// A range moves the build tool under an unchanged tree, and a pull request that checks one
// version while a tag releases with another checks nothing. This case reads both workflows,
// so the two cannot drift apart.
func TestEveryGoreleaserStepNamesThePinnedVersion(t *testing.T) {
	pin := regexp.MustCompile(`(?m)^ *version: '(v\d+\.\d+\.\d+)'$`)

	for _, path := range []string{releaseWorkflowPath, ciWorkflowPath} {
		found := pin.FindAllStringSubmatch(readRepoFile(t, path), -1)
		if found == nil {
			t.Errorf("%s pins no GoReleaser version, and FR-release-35j pins one", path)
			continue
		}

		for _, version := range found {
			if version[1] != goreleaserVersion {
				t.Errorf("%s installs GoReleaser %s, and the pin is %s",
					path, version[1], goreleaserVersion)
			}
		}
	}
}

// TestTheReleaseWorkflowPinsEveryAction holds FR-release-35k. A tag moves and a commit hash
// does not.
//
// The shape follows `TestTheMutationWorkflowPinsEveryAction` of `mutation_schedule_test.go`,
// which holds the same rule for the file that #93 added.
func TestTheReleaseWorkflowPinsEveryAction(t *testing.T) {
	workflow := readRepoFile(t, releaseWorkflowPath)

	uses := regexp.MustCompile(`(?m)^ *(?:- )?uses: (\S+)`).FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatalf("%s names no action", releaseWorkflowPath)
	}

	pinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, reference := range uses {
		if !pinned.MatchString(reference[1]) {
			t.Errorf("the action reference %q names no 40-character commit hash", reference[1])
		}
	}
}

// TestTheReleaseWritesAChecksumFileAndABillOfMaterials holds FR-release-35e and
// FR-release-35f.
//
// FR-prerelease-22 verifies each downloaded artifact against `checksums.txt`, and
// `releaseChecksumFile` names that file. `syft` writes the bill of materials, and both
// workflows install it before they run GoReleaser.
func TestTheReleaseWritesAChecksumFileAndABillOfMaterials(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	if !strings.Contains(config, `name_template: "`+releaseChecksumFile+`"`) {
		t.Errorf("%s writes no %s, and FR-release-35e writes one checksum file",
			goreleaserConfigPath, releaseChecksumFile)
	}

	if !regexp.MustCompile(`(?m)^sboms:$`).MatchString(config) {
		t.Errorf("%s holds no sboms block, and FR-release-35f writes a bill of materials for every artifact",
			goreleaserConfigPath)
	}

	// The generator is not part of a runner image, so a workflow that runs GoReleaser and
	// installs no `syft` fails on the tool rather than on the configuration.
	for _, path := range []string{releaseWorkflowPath, ciWorkflowPath} {
		if !strings.Contains(readRepoFile(t, path), "download-syft@") {
			t.Errorf("%s installs no syft, and %s names it as the bill of materials generator",
				path, goreleaserConfigPath)
		}
	}
}

// TestTheReleaseStampsTheVersionAndKeepsTheBuildInfo holds FR-release-35g.
//
// **The requirement names three values, and one link flag carries one of them.** #105
// measured on 2026-08-15 with go1.26.5 on darwin/arm64 that a link flag into a variable the
// program never reads reaches nothing. The linker removes the variable, and it reports no
// error:
//
//	$ go build -trimpath -ldflags "-s -w -X main.Commit=ZZZTESTZZZ" -o probe ./cmd/ja4plus
//	$ grep -c -a ZZZTESTZZZ probe
//	0
//
// `main.Version` is different, because `resolveVersion` in `cmd/ja4plus/main.go` reads it
// and `ja4plus --version` prints it. So this case reads the link flag and the variable
// together.
//
// The commit and the build date reach the build info that the Go command writes.
// `go version -m` printed `vcs.revision` and `vcs.time` for the GoReleaser snapshot of
// 2026-08-15. A `-buildvcs=false` flag would remove both, so this case refuses that flag.
func TestTheReleaseStampsTheVersionAndKeepsTheBuildInfo(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	if !strings.Contains(config, "-X main.Version=") {
		t.Errorf("%s stamps no main.Version, and FR-release-35g stamps the version",
			goreleaserConfigPath)
	}

	if !strings.Contains(readRepoFile(t, "cmd/ja4plus/main.go"), `var Version = ""`) {
		t.Errorf(`cmd/ja4plus/main.go declares no "var Version = \"\"", so the link flag that names it reaches nothing`)
	}

	if strings.Contains(config, "-buildvcs=false") {
		t.Errorf("%s disables the build info, and FR-release-35g reads the commit and the build date from it",
			goreleaserConfigPath)
	}
}
