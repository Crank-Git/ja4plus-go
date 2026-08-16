package repocheck

import (
	"strings"
	"testing"
)

// The license records are a compliance gate, and no Go code reads them at run time.
// These tests hold the gate, so that a later edit cannot drop it without a failure.
//
// FR-licensing-14 permits a header comment in `data/ja4plus-mapping.csv` or an adjacent
// `data/README.md`. `loadDB` of `lookup.go` reads the first line as the column
// header, so a comment line would become the header and every lookup would fail. This
// slice takes the `data/README.md` option for that reason.

func TestMappingCSVFirstLineHoldsTheColumnHeader(t *testing.T) {
	mapping := readRepoFile(t, "data/ja4plus-mapping.csv")

	first, _, found := strings.Cut(mapping, "\n")
	if !found {
		t.Fatalf("data/ja4plus-mapping.csv holds no line break")
	}

	first = strings.TrimSpace(first)
	if first != "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes" {
		t.Errorf("the first line of data/ja4plus-mapping.csv is %q, and the loader reads it as the column header", first)
	}
}

func TestDataREADMENamesFoxIOAsTheMappingSource(t *testing.T) {
	readme := readRepoFile(t, "data/README.md")

	for _, want := range []string{
		"FoxIO",
		"data/ja4plus-mapping.csv",
		"FoxIO License 1.1",
		"non-commercial",
		"NOTICE",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("data/README.md does not name %q, and FR-licensing-14 needs the source of the mapping file", want)
		}
	}
}

// An embed directive of `lookup.go` reads `data/ja4plus-mapping.csv`, so every binary that links this
// package carries FoxIO material. `NOTICE:47` states the license of that file, and
// `doc.go` is the package documentation that `go doc` prints.
func TestDocGoStatesThatFoxIOLicensesTheEmbeddedMappingFile(t *testing.T) {
	docGo := readRepoFile(t, "doc.go")

	for _, want := range []string{
		"embeds",
		"data/ja4plus-mapping.csv",
		"FoxIO License 1.1",
		"data/README.md",
	} {
		if !strings.Contains(docGo, want) {
			t.Errorf("doc.go does not name %q, and the package embeds FoxIO material", want)
		}
	}
}

// theMethodCountPhrase is the form both records use for the count of FoxIO-licensed
// methods. It states the subset and the total, so a reader counts neither one.
// Epic 12 added JA4LS to the enumerations, which raised the subset from nine to ten.
const theMethodCountPhrase = "ten of the eleven methods"

// theMethodCountFormula is the form that issue #121 deletes. A formula makes a reader
// compute the count, and an enumeration names each method.
const theMethodCountFormula = "except JA4"

// `NOTICE`, `README.md` and `doc.go` each enumerate the same methods, and `noticeMethods`
// holds that list. These two records state the count of that list.
func TestTheLicenseRecordsCountTheFoxIOLicensedMethods(t *testing.T) {
	for _, path := range []string{"CHANGELOG.md", "docs/audit/license-decision.md"} {
		record := readRepoFile(t, path)

		if strings.Contains(record, theMethodCountFormula) {
			t.Errorf("%s states the license split as a formula, and an enumeration names each method", path)
		}

		if !strings.Contains(record, theMethodCountPhrase) {
			t.Errorf("%s does not hold %q, and the enumerations name %d methods", path, theMethodCountPhrase, len(noticeMethods))
		}
	}
}

func TestChangelogRecordsTheLicenseCorrectionUnderUnreleased(t *testing.T) {
	changelog := readRepoFile(t, "CHANGELOG.md")

	_, rest, found := strings.Cut(changelog, "## [Unreleased]")
	if !found {
		t.Fatalf("CHANGELOG.md holds no `## [Unreleased]` section")
	}
	unreleased, _, _ := strings.Cut(rest, "\n## [")

	for _, want := range []string{
		"FoxIO License 1.1",
		"non-commercial",
		"NOTICE",
		"docs/audit/license-decision.md",
	} {
		if !strings.Contains(unreleased, want) {
			t.Errorf("the `[Unreleased]` section does not name %q, and FR-licensing-15 needs the license correction", want)
		}
	}
}

func TestLicenseDecisionRecordCitesTheSpecRowsItTranscribes(t *testing.T) {
	record := readRepoFile(t, "docs/audit/license-decision.md")

	// The record transcribes a decision the maintainer already made. Each quotation is
	// verbatim from the `## Changelog` table of `docs/specs/spec.md`, and a reworded
	// quotation is no longer evidence.
	for _, want := range []string{
		"docs/specs/spec.md",
		"R1 resolved: the dual BSD 3-Clause and FoxIO `NOTICE` model is sufficient for `v1.0.0`.",
		"R6 resolved: the license correction waits for the full `v1.0.0`, and no `v0.4.0` ships first.",
		"2026-08-06",
		"2026-08-11",
	} {
		if !strings.Contains(record, want) {
			t.Errorf("docs/audit/license-decision.md does not hold %q, and the record must cite the decision it transcribes", want)
		}
	}
}
