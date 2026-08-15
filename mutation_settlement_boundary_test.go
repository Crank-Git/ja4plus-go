package ja4plus

import (
	"strings"
	"testing"
)

// These tests hold the FR-mutation-11 amendment of #634.
//
// **The maintainer ruled the settlement scope on 2026-08-14, in issue #92.** Before that
// ruling FR-mutation-11 settled every `LIVED` mutation, and one swept package holds 227
// mutations that the rule reached. The ruling narrows the settlement to the mutations that
// can move a fingerprint value, and it counts the rest.
//
// **The pre-amendment rule reached four surfaces, and one of them writes itself again.**
// `internal/mutationreport` prints the rule into every report it renders, so a later sweep
// reproduces a sentence that a documentation round repaired. These tests read the generator
// source, and not the generated report alone.

// mutationSettlementRule states the ruled rule. It is verbatim from `docs/mutation_sweep.md`,
// under `## Which mutations the project settles`.
const mutationSettlementRule = "**A LIVED mutation on code that can move a fingerprint value is settled. " +
	"Every other LIVED mutation is counted and recorded.**"

// mutationSettlementRuleFiles names each file that states the rule in its own words.
//
// **A test file holds no entry here.** A guard quotes the sentence it bars, so a scan of a
// test file reports the guard itself. `TestTheReportStatesTheAmendedSettlementRule` of
// `internal/mutationreport` holds the rendered half of this check.
var mutationSettlementRuleFiles = []string{
	"docs/mutation_sweep.md",
	"docs/specs/features/15-mutation-sweep.md",
	"internal/mutationreport/main.go",
	"internal/mutationdiff/main.go",
	"docs/mutation_reports/2026-08-14-internal-parser.md",
}

// preAmendmentSettlementStatements names each sentence that states the rule FR-mutation-11
// held before the ruling.
//
// **The edge-case table of `docs/specs/features/15-mutation-sweep.md` states
// `It is settled like a `LIVED` mutation.`, and no entry below matches it.** That sentence
// states which verdicts the rule reads, and it states no settlement scope. `unsettledVerdicts`
// of `internal/mutationdiff` quotes it verbatim, so a repair of it would destroy evidence.
var preAmendmentSettlementStatements = []string{
	"Every mutation with the verdict `LIVED` is settled.",
	"every `LIVED` mutation is settled",
	"That count sizes the settlement work",
	"FR-mutation-11 settles it.",
	"FR-mutation-11 settles it like a `LIVED` mutation",
	"names each verdict that FR-mutation-11 settles",
	"FR-mutation-11 settles a `LIVED` mutation by reading",
	"FR-mutation-11 settles each row below, and",
	"Every `LIVED` mutation of the most recent report has a settlement.",
}

// TestTheSettlementRuleReadsTheFingerprintRisk holds the amendment of FR-mutation-11.
func TestTheSettlementRuleReadsTheFingerprintRisk(t *testing.T) {
	feature := readRepoFile(t, "docs/specs/features/15-mutation-sweep.md")

	if !strings.Contains(feature, "can move a fingerprint value") {
		t.Error("FR-mutation-11 states no fingerprint boundary, so the file holds the pre-amendment rule")
	}
	if !strings.Contains(feature, "counted and recorded") {
		t.Error("the feature file states no count of the remainder, and the ruling counts every other mutation")
	}
}

// TestTheSettlementRuleReadsOneWordingEverywhere holds the site page as the one wording.
//
// **A rule that two files state in two forms gives one reader two rules.** The site page
// shipped the ruled sentence first, so the feature file quotes that sentence and states no
// second form of it.
func TestTheSettlementRuleReadsOneWordingEverywhere(t *testing.T) {
	for _, path := range []string{"docs/mutation_sweep.md", "docs/specs/features/15-mutation-sweep.md"} {
		if !strings.Contains(readRepoFile(t, path), mutationSettlementRule) {
			t.Errorf("%s does not state the ruled rule verbatim: %s", path, mutationSettlementRule)
		}
	}
}

// TestTheSettlementRuleRecordsItsRulingAndItsReversalPath holds the ruling record.
//
// `.claude/rules/rulings.md` `## Where a ruling is recorded` states that a ruling which
// records nothing is a ruling the next reader re-litigates.
func TestTheSettlementRuleRecordsItsRulingAndItsReversalPath(t *testing.T) {
	feature := readRepoFile(t, "docs/specs/features/15-mutation-sweep.md")

	for _, want := range []string{"2026-08-14", "#92", "#634"} {
		if !strings.Contains(feature, want) {
			t.Errorf("the feature file names no %s, so a reader cannot find the ruling or its reversal path", want)
		}
	}
}

// TestNoFileStatesThePreAmendmentSettlementRule holds every surface of the rule at once.
//
// **The generator source is in this list, and the generated report alone is not enough.**
// `render` of `internal/mutationreport` writes the rule into each report, so a repair of the
// tracked report leaves the next sweep to write the pre-amendment sentence again.
func TestNoFileStatesThePreAmendmentSettlementRule(t *testing.T) {
	for _, path := range mutationSettlementRuleFiles {
		text := readRepoFile(t, path)
		for _, statement := range preAmendmentSettlementStatements {
			if strings.Contains(text, statement) {
				t.Errorf("%s states the pre-amendment rule: %q", path, statement)
			}
		}
	}
}
