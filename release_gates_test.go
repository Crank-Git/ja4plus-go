package ja4plus

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The release gate of `docs/specs/features/10-release.md` holds nine requirements, and
// this file records who holds each one.
//
// **#106 built this record on 2026-08-15 UTC, under Epic 10.** Each requirement of the
// `### The release gate` section states one sentence of the form `The release does not
// proceed until X`. Before this file, no Go file of the tree named one of the nine, so a
// requirement that lost its check lost it silently.
//
// **This file fires no gate, and it asserts no release is ready.** It asserts that every
// gate reaches a holder that the tree still carries. FR-release-40 gives the tag to the
// maintainer, and the maintainer runs each command gate against the release commit.
//
// **Three kinds of holder reach a gate, and the record names the kind of each one.**
//
//   - A test of this tree. The record names the test and its file, and a case below reads
//     the declaration.
//   - A command. The record names the `Makefile` target, and a case below reads the recipe.
//   - The maintainer. The record names the document that the maintainer reads. **One gate
//     has this holder today**, and its row states the reason.
//
// # The bill of materials is configured and unverified, and this record holds no gate for it
//
// **FR-release-35f names a software bill of materials, and no run of this project has
// produced one.** The `sboms` block of `.goreleaser.yaml` names `artifacts: binary`, and
// both workflows install `syft`. **#105 ran the local snapshot with `--skip=sbom`, because
// `syft` is not installed on the machine that ran it**, measured on 2026-08-15 UTC. Comment
// 5301284764 of #105 holds that measurement.
//
// **So this record adds no row for it, and this file states the reason rather than the
// silence.** The `### The release gate` section names nine requirements, and FR-release-35f
// is not one of them. A row that reported an unverified step as a held gate would report a
// state that nobody has observed. **The first tag run produces the first bill of materials**,
// and the maintainer reads the result of that run.

// releaseFeatureFile holds the requirements that this record covers.
const releaseFeatureFile = "docs/specs/features/10-release.md"

// releaseGateSentence is the opening of every gate requirement, verbatim.
//
// The `### The release gate` section also holds FR-release-51 and FR-release-52, and each
// one states a rule about `CHANGELOG.md` rather than a gate. So the record reads this
// sentence and never the section alone.
const releaseGateSentence = "The release does not proceed until"

// releaseGateHolderKind states who holds one gate.
type releaseGateHolderKind int

const (
	// heldByTest names a test of this tree.
	heldByTest releaseGateHolderKind = iota
	// heldByCommand names a `Makefile` target that the maintainer runs.
	heldByCommand
	// heldByMaintainer names a document that the maintainer reads.
	heldByMaintainer
)

// releaseGate records one requirement of the release gate and its holder.
type releaseGate struct {
	// requirement names the requirement, as `docs/specs/features/10-release.md` writes it.
	requirement string
	// kind states who holds the gate.
	kind releaseGateHolderKind
	// holder names the test, the `Makefile` target, or the document.
	holder string
	// file names the file that carries the holder. A command holder names the `Makefile`.
	file string
	// note states one fact that the holder does not state itself.
	note string
}

// releaseGates holds one row for each requirement of the `### The release gate` section.
var releaseGates = []releaseGate{
	{
		requirement: "FR-release-42",
		kind:        heldByTest,
		holder:      "TestLicenseDecisionRecordCitesTheSpecRowsItTranscribes",
		file:        "licensing_test.go",
		note:        "The record transcribes a decision that the maintainer made, and it makes none.",
	},
	{
		requirement: "FR-release-43",
		kind:        heldByCommand,
		holder:      "conformance",
		file:        "Makefile",
		note:        "Run `make corpus` first. The suite skips its comparison without the corpus.",
	},
	{
		requirement: "FR-release-44",
		kind:        heldByTest,
		holder:      "TestEveryExclusionNamesTheMaintainerAndADate",
		file:        "conformance_exclusions_test.go",
		note:        "The maintainer alone writes an acceptance, and the case reads the name and the date.",
	},
	{
		requirement: "FR-release-45",
		kind:        heldByCommand,
		holder:      "test",
		file:        "Makefile",
		note:        "The recipe runs the race detector.",
	},
	{
		requirement: "FR-release-46",
		kind:        heldByCommand,
		holder:      "vuln",
		file:        "Makefile",
		note:        "The scanner reads the Go version of the `go` command on the PATH, so a second toolchain reports a second result.",
	},
	{
		requirement: "FR-release-47",
		kind:        heldByCommand,
		holder:      "prerelease",
		file:        "Makefile",
		note:        "FR-prerelease-26 runs this target against the tag under test, so the maintainer pushes the tag first.",
	},
	{
		requirement: "FR-release-48",
		kind:        heldByTest,
		holder:      "TestTheRegisterHoldsNoEntryWhoseComparisonNowMatches",
		file:        "prerelease_gate_test.go",
		note:        "The conformance suite fails on a closed entry, and this case reads the report that the suite writes.",
	},
	{
		requirement: "FR-release-49",
		kind:        heldByMaintainer,
		holder:      "docs/specs/features/08-python-parity.md",
		file:        "docs/specs/features/08-python-parity.md",
		note:        "No test of this tree reads the closure of every register row. Acceptance criterion 1 of that file states the gate, and the maintainer reads it. #106 measured the absence on 2026-08-15 UTC.",
	},
	{
		requirement: "FR-release-50",
		kind:        heldByCommand,
		holder:      "docs",
		file:        "Makefile",
		note:        "Install the pins of `docs/requirements.txt` first, or override the generator with `MKDOCS`.",
	},
}

// releaseRequirementBullet matches the opening of one requirement bullet.
//
// **The pattern bounds no requirement text**, because a bound drops a long requirement and
// the record then reports a green result for a gate that reaches no holder. The first
// review of #106 measured that defect on 2026-08-15 UTC. So the reader below takes the text
// between one bullet and the next.
var releaseRequirementBullet = regexp.MustCompile(`(?m)^- \*\*(FR-release-\d+)\*\* — `)

// releaseGatesInDocument returns each requirement that the document states as a gate.
//
// It reads the sentence of releaseGateSentence rather than a section boundary. The section
// also holds two requirements that state no gate.
func releaseGatesInDocument(document string) []string {
	bullets := releaseRequirementBullet.FindAllStringSubmatchIndex(document, -1)
	found := []string{}

	for position, bullet := range bullets {
		end := len(document)
		if position+1 < len(bullets) {
			end = bullets[position+1][0]
		}

		statement := strings.Join(strings.Fields(document[bullet[1]:end]), " ")
		if strings.HasPrefix(statement, releaseGateSentence) {
			found = append(found, document[bullet[2]:bullet[3]])
		}
	}

	return found
}

// releaseGateRequirements returns each gate that the feature file states.
//
// It fails the test when the file states none, because an extractor that reads nothing
// passes every comparison below.
func releaseGateRequirements(t *testing.T) []string {
	t.Helper()

	found := releaseGatesInDocument(readRepoFile(t, releaseFeatureFile))
	if len(found) == 0 {
		t.Fatalf("%s states no requirement that opens %q, and this record reads that sentence",
			releaseFeatureFile, releaseGateSentence)
	}

	return found
}

// TestTheGateExtractorReadsALongRequirementThatWraps holds the extractor against the defect
// that the first review of #106 measured.
//
// The requirement below states 40 words, it wraps over three lines, and it holds a period
// inside a file name. **An extractor that bounds the sentence drops it**, and the record
// then names no holder and reports no failure.
func TestTheGateExtractorReadsALongRequirementThatWraps(t *testing.T) {
	document := "### The release gate\n\n" +
		"- **FR-release-99** — The release does not proceed until the maintainer reads\n" +
		"  `docs/audit/conformance-exclusions.md` and `docs/specs/features/08-python-parity.md`,\n" +
		"  and records one acceptance for each entry that the two documents hold today.\n" +
		"- **FR-release-98** — The CHANGELOG records the name of every method.\n"

	found := releaseGatesInDocument(document)

	if len(found) != 1 || found[0] != "FR-release-99" {
		t.Errorf("the extractor reads %v, and the document states FR-release-99 as its one gate", found)
	}
}

// TestTheReleaseGateRecordHoldsEveryGateOfTheFeatureFile compares the record against the
// feature file.
//
// A requirement that the feature file adds reaches this record, and a row that names no
// requirement of the file fails. So a gate cannot enter the specification without a holder.
func TestTheReleaseGateRecordHoldsEveryGateOfTheFeatureFile(t *testing.T) {
	recorded := map[string]bool{}
	for _, gate := range releaseGates {
		if recorded[gate.requirement] {
			t.Errorf("the record holds %s twice, and each requirement reaches one row", gate.requirement)
		}

		recorded[gate.requirement] = true
	}

	stated := map[string]bool{}

	for _, requirement := range releaseGateRequirements(t) {
		stated[requirement] = true

		if !recorded[requirement] {
			t.Errorf("%s states %s as a release gate, and the record names no holder for it",
				releaseFeatureFile, requirement)
		}
	}

	for _, gate := range releaseGates {
		if !stated[gate.requirement] {
			t.Errorf("the record holds %s, and %s states no gate of that number",
				gate.requirement, releaseFeatureFile)
		}
	}
}

// TestEveryReleaseGateHolderReachesTheTree reads the holder of each gate.
//
// A test holder reaches a declaration of its file. A command holder reaches a recipe of the
// `Makefile`. A maintainer holder reaches a document. A gate whose holder moved fails here,
// and the maintainer then reads a gate that gates nothing before the release rather than
// after it.
func TestEveryReleaseGateHolderReachesTheTree(t *testing.T) {
	for _, gate := range releaseGates {
		content := readRepoFile(t, gate.file)

		switch gate.kind {
		case heldByTest:
			declaration := fmt.Sprintf("func %s(t *testing.T)", gate.holder)
			if !strings.Contains(content, declaration) {
				t.Errorf("%s names %s in %s, and that file declares no such test",
					gate.requirement, gate.holder, gate.file)
			}
		case heldByCommand:
			recipe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(gate.holder) + `:`)
			if !recipe.MatchString(content) {
				t.Errorf("%s names the `make %s` target, and %s holds no such target",
					gate.requirement, gate.holder, gate.file)
			}
		case heldByMaintainer:
			if strings.TrimSpace(content) == "" {
				t.Errorf("%s names %s, and that document is empty", gate.requirement, gate.holder)
			}
		}
	}
}

// TestEveryReleaseGateRowStatesANote holds the record readable.
//
// A row without a note states a requirement number and a holder, and a reader then learns
// nothing that the two names do not carry. The note states the fact that the holder hides:
// a prerequisite, an order, or an absence.
func TestEveryReleaseGateRowStatesANote(t *testing.T) {
	for _, gate := range releaseGates {
		if strings.TrimSpace(gate.note) == "" {
			t.Errorf("the %s row states no note", gate.requirement)
		}
	}
}
