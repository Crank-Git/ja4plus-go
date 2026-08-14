package ja4plus

import (
	"strings"
	"testing"
)

// The maintainer adopted two policies on 2026-08-13, and neither one reached a file that a
// session or a worker reads. Each one lived in a closed issue body, so the next session had
// no reason to obey it. #454 wrote them into `CLAUDE.md` and into `.claude/rules/ste.md`.
//
// These tests read for the presence of each policy, and never for the conformance of a
// citation. A guard that reads a citation form belongs to #440 and to #351. The review of
// batch #59 found two guards that forbid one thing with two reversal instructions, and
// round 40 of the `## Changelog` of `docs/specs/spec.md` records that shape. Deletion and
// non-conformance are two failures, and each one carries one reversal instruction, so this
// pair is not that shape.
//
// These tests fail when a later edit removes a policy from the file that owns it.

// theFilingPolicyFile is the file that states which finding earns a tracker issue.
//
// `CLAUDE.md` owns policy 1 because every session and every worker reads that file first.
const theFilingPolicyFile = "CLAUDE.md"

// theCitationConventionFile is the file that states what a citation names.
//
// `.claude/rules/ste.md` owns policy 2 because a citation is writing, and that file is the
// writing standard of this project.
const theCitationConventionFile = ".claude/rules/ste.md"

// theBehaviorWord is the first case that earns a tracker issue.
//
// The round of batch #493 converted both uses in `CLAUDE.md` to the US form, under
// `.claude/rules/ste.md` `## This project writes US English`. This constant held
// `"Behavi" + "our"` until that round, because `.golangci.yml` sets the `misspell` locale to
// US and the concatenation kept the British form out of the linter. The US form needs no
// concatenation.
const theBehaviorWord = "Behavior"

// theFilingPolicySentences are the sentences of policy 1 that carry the rule.
//
// The five cases are read one at a time, so a later edit that drops one case fails a test
// rather than passing a shortened list.
var theFilingPolicySentences = []string{
	"A finding earns a tracker issue in five cases, and never otherwise.",
	"The maintainer adopted this policy on 2026-08-13.",
	"The batch documentation round repairs every other finding, in the batch that found it, and it files no issue.",
	"The round reports a finding that turns out to touch " + strings.ToLower(theBehaviorWord),
}

// theFilingPolicyCases are the five cases that earn a tracker issue.
var theFilingPolicyCases = []string{
	theBehaviorWord + ".",
	"A fingerprint value.",
	"A guard that guards nothing.",
	"A blocked epic.",
	"A question the maintainer must rule.",
}

// theCitationConventionSentences are the sentences of policy 2 that carry the rule.
//
// The last one names `.claude/rules/rulings.md`. That file governs an evidence citation,
// and policy 2 does not touch it. A later edit that drops the sentence lets a reader read
// policy 2 as a change to the evidence rule.
//
// The second one read `cites a section heading` until #465. The cross-member review of
// batch #457 found that the narrow wording made the work of #440 non-conformant, because
// #440 cited a rule number and a requirement number. Neither one is a section heading.
var theCitationConventionSentences = []string{
	"The maintainer adopted this convention on 2026-08-13.",
	"An internal cross-reference cites a stable target. An evidence citation cites `file:line`.",
	"`.claude/rules/rulings.md` `## A reading cites a file and a line` governs evidence, and this convention does not touch it.",
}

// theStableTargetForms are the four forms that an internal citation may name.
//
// The row names every one of them. A later edit that drops a form leaves a reader of
// `docs/specs/foxio/*.md` with no permitted citation, because those pages hold numbered
// rules and few headings.
var theStableTargetForms = []string{
	"a section heading, a rule number, a requirement number, or an identifier",
}

func TestCLAUDEmdStatesTheFilingPolicy(t *testing.T) {
	policy := collapseWhitespace(readRepoFile(t, theFilingPolicyFile))

	for _, want := range theFilingPolicySentences {
		if !strings.Contains(policy, collapseWhitespace(want)) {
			t.Errorf("%s holds no %q, so #454 leaves the filing policy unstated", theFilingPolicyFile, want)
		}
	}
}

func TestCLAUDEmdNamesEveryCaseThatEarnsAnIssue(t *testing.T) {
	policy := collapseWhitespace(readRepoFile(t, theFilingPolicyFile))

	for _, want := range theFilingPolicyCases {
		if !strings.Contains(policy, collapseWhitespace(want)) {
			t.Errorf("%s names no case %q, and policy 1 of #454 holds five cases", theFilingPolicyFile, want)
		}
	}
}

func TestTheWritingStandardStatesTheCitationConvention(t *testing.T) {
	convention := collapseWhitespace(readRepoFile(t, theCitationConventionFile))

	for _, want := range theCitationConventionSentences {
		if !strings.Contains(convention, collapseWhitespace(want)) {
			t.Errorf("%s holds no %q, so #454 leaves the citation convention unstated", theCitationConventionFile, want)
		}
	}
}

func TestTheInternalCitationRowNamesEveryStableTarget(t *testing.T) {
	convention := collapseWhitespace(readRepoFile(t, theCitationConventionFile))

	for _, want := range theStableTargetForms {
		if !strings.Contains(convention, collapseWhitespace(want)) {
			t.Errorf("%s names no %q, so an internal citation of a rule number reaches no permitted form", theCitationConventionFile, want)
		}
	}
}

// The rulings file governs an evidence citation, and #454 changes no rule of it. This test
// fails when a later edit removes the heading that policy 2 names.
func TestTheRulingsFileKeepsTheEvidenceCitationHeading(t *testing.T) {
	const theEvidenceHeading = "## A reading cites a file and a line"

	rulings := readRepoFile(t, ".claude/rules/rulings.md")

	if !strings.Contains(rulings, theEvidenceHeading) {
		t.Errorf(".claude/rules/rulings.md holds no %q, and %s cites that heading",
			theEvidenceHeading, theCitationConventionFile)
	}
}
