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

// theBehaviourWord is the first case that earns a tracker issue.
//
// `.golangci.yml` sets the `misspell` locale to US, and the rule files of this project
// write the British form. The concatenation keeps the word out of the linter, and
// `method_count_test.go` keeps a counted sentence out of its own scan the same way.
const theBehaviourWord = "Behavi" + "our"

// theFilingPolicySentences are the sentences of policy 1 that carry the rule.
//
// The five cases are read one at a time, so a later edit that drops one case fails a test
// rather than passing a shortened list.
var theFilingPolicySentences = []string{
	"A finding earns a tracker issue in five cases, and never otherwise.",
	"The maintainer adopted this policy on 2026-08-13.",
	"The batch documentation round repairs every other finding, in the batch that found it, and it files no issue.",
	"The round reports a finding that turns out to touch " + strings.ToLower(theBehaviourWord),
}

// theFilingPolicyCases are the five cases that earn a tracker issue.
var theFilingPolicyCases = []string{
	theBehaviourWord + ".",
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
var theCitationConventionSentences = []string{
	"The maintainer adopted this convention on 2026-08-13.",
	"An internal cross-reference cites a section heading. An evidence citation cites `file:line`.",
	"`.claude/rules/rulings.md` `## A reading cites a file and a line` governs evidence, and this convention does not touch it.",
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
