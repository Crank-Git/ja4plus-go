package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// A snapshot build must identify itself as a snapshot, and a tagged release must not.
//
// #724 moved the link flag of `.goreleaser.yaml` from `{{ .Version }}` to `{{ .Tag }}`, so
// that a released binary keeps the leading `v` of its tag. **`.Tag` names the last
// reachable tag, and it carries no snapshot suffix.** So a snapshot binary printed the
// version of the previous release, measured on 2026-08-15 UTC with GoReleaser v2.17.1:
//
//	$ goreleaser build --snapshot --clean --single-target
//	$ ./dist/ja4plus_darwin_arm64_v8.0/ja4plus --version
//	ja4plus v0.3.0
//
// **The maintainer ruled on 2026-08-15 UTC that the snapshot marker returns, and that the
// `v` prefix of #724 stays.** #736 holds the ruling, and it is the reversal path.
//
// **Every earlier case passed the defect.** `TestTheReleaseStampsTheVersionAndKeepsTheBuildInfo`
// reads the substring `-X main.Version=` and it pins no template field.
// `TestEveryReleasedBinaryRunsOnItsOwnPlatform` reads the `ja4plus ` prefix alone. So the
// cases below pin the two branches of the template by name.
//
// Verified against <https://goreleaser.com/customization/templates/>, retrieved 2026-08-15.
// The page states one meaning for each of the three fields below.
//   - `.IsSnapshot` is `true if --snapshot is set, false otherwise`.
//   - `.ShortCommit` is `the git commit short hash`.
//   - `.Tag` is `the current git tag`.

// snapshotLinkFlagPattern reads the whole link flag line of `.goreleaser.yaml`.
//
// The pattern names each template field of the flag, so a change that drops one turns this
// case red. It reads the file as text, because no test of this module parses YAML.
var snapshotLinkFlagPattern = regexp.MustCompile(
	`(?m)^ *- -s -w -X main\.Version=\{\{ if \.IsSnapshot \}\}\{\{ \.Tag \}\}-SNAPSHOT-\{\{ \.ShortCommit \}\}\{\{ else \}\}\{\{ \.Tag \}\}\{\{ end \}\}$`)

// TestTheSnapshotBuildIdentifiesItselfAsASnapshot holds the #736 ruling in the template.
//
// **A case that reads the marker alone would pass a template that drops the release
// branch**, and that branch is the #724 ruling. So this case reads both branches.
func TestTheSnapshotBuildIdentifiesItselfAsASnapshot(t *testing.T) {
	config := readRepoFile(t, goreleaserConfigPath)

	if !snapshotLinkFlagPattern.MatchString(config) {
		t.Errorf("%s stamps no snapshot marker, and #736 rules that a snapshot binary identifies itself as a snapshot",
			goreleaserConfigPath)
	}

	// The plain `{{ .Tag }}` template is the defect that #736 repairs. It reaches the flag
	// only as the `else` branch above, so a bare occurrence is the reversal.
	if strings.Contains(config, "-X main.Version={{ .Tag }}") {
		t.Errorf("%s stamps a bare {{ .Tag }}, so a snapshot binary prints the previous release version",
			goreleaserConfigPath)
	}

	// #724 rules that a released binary prints its tag verbatim, with the leading `v`.
	// `prerelease_binaries_test.go` reads the printed line as `"ja4plus " + tag`, so the
	// release branch writes `{{ .Tag }}` and never `{{ .Version }}`.
	if strings.Contains(config, "-X main.Version={{ .Version }}") {
		t.Errorf("%s stamps {{ .Version }}, and GoReleaser strips the leading v from that field, which reverses #724",
			goreleaserConfigPath)
	}
}

// TestTheSnapshotJobReadsTheBinaryItBuilds holds the wider gap that #736 measured.
//
// **The `goreleaser` job of `.github/workflows/ci.yml` built a snapshot and it ran no
// binary.** So the job proved that the build succeeds, and it proved nothing about what the
// build stamps. A case that reads the configuration reads intent, and the job reads output.
func TestTheSnapshotJobReadsTheBinaryItBuilds(t *testing.T) {
	workflow := readRepoFile(t, ciWorkflowPath)

	if !strings.Contains(workflow, "Read the version line of the snapshot binary") {
		t.Fatalf("%s runs no step that reads the snapshot binary, and #736 rules that the job reads what it builds",
			ciWorkflowPath)
	}

	// The step matches the printed line against this pattern. The pattern holds both
	// rulings: the `v` prefix of #724 and the snapshot marker of #736.
	if !strings.Contains(workflow, `"ja4plus v"*-SNAPSHOT-*`) {
		t.Errorf("%s reads the snapshot binary against no pattern that names the v prefix and the SNAPSHOT marker",
			ciWorkflowPath)
	}
}
