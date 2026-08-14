package ja4plus

import (
	"os"
	"strings"
	"testing"
)

// A JA4 reference implementation runs inside a host, and the host decides what the
// implementation sees. A reading that traces a plugin field into a Wireshark core
// dissector, or a record field into the Zeek analyzer, therefore reads a source that no
// pin named until #537.
//
// These tests bind the two version rows in two directions. One direction reads this
// repository, and it fails when a row loses its version. The other direction reads the
// fetched FoxIO corpus, and it fails when a moved `testdata/foxio.pin` names a commit that
// builds against a different host. A test that read the rule file alone would pass
// forever, because the rule file states what the rule file states.
//
// `docs/audit/upstream-versions.md` holds the measurement and every citation.

// upstreamWiresharkVersion is the Wireshark core version that the FoxIO pin records.
// `.github/workflows/wireshark-release.yml` of the FoxIO tree builds the released plugin
// against this tag, so it is the core that the shipped plugin reads fields from.
const upstreamWiresharkVersion = "v4.6.0"

// upstreamZeekVersion is the Zeek analyzer version that the FoxIO pin records.
// `.github/workflows/zeek-test.yml` of the FoxIO tree runs the FoxIO Zeek tests in this
// container, so it is the analyzer the FoxIO package is known to pass under.
const upstreamZeekVersion = "8.0.0"

// upstreamVersionsRecordPage holds the measurement that produced the two versions.
const upstreamVersionsRecordPage = "docs/audit/upstream-versions.md"

// upstreamInterfaceRuleFile holds the interface table that names each pinned interface.
const upstreamInterfaceRuleFile = ".claude/rules/external-apis.md"

// upstreamWiresharkCorpusFile is the FoxIO workflow that hard-codes the Wireshark tag.
const upstreamWiresharkCorpusFile = foxioCorpusReferenceDir + "/.github/workflows/wireshark-release.yml"

// upstreamZeekCorpusFile is the FoxIO workflow that names the Zeek container.
const upstreamZeekCorpusFile = foxioCorpusReferenceDir + "/.github/workflows/zeek-test.yml"

// upstreamZeekCorpusText is the exact container reference the FoxIO workflow states. The
// bare version would match a different key of the same file, so the guard reads the whole
// reference.
const upstreamZeekCorpusText = "zeek/zeek:" + upstreamZeekVersion

// upstreamCorpusAbsentMessage states that the version guard read no corpus.
//
// The sentence carries no word of `conformanceSkipMarker`, because
// `.github/workflows/ci.yml` fails the conformance job on that marker and this skip means
// something else. TestTheCISkipDetectorMatchesNoUntaggedSkipMessage holds that separation.
const upstreamCorpusAbsentMessage = "the upstream version guard read no corpus at " +
	foxioCorpusReferenceDir + "; run `make corpus` to read the FoxIO workflows. " +
	"The rule-file check and the record-page check ran, and neither one needs a corpus."

// upstreamCorpusFile returns the content of a corpus file, and it reports whether the
// corpus holds it. An absent corpus is a skip, and never a failure.
func upstreamCorpusFile(t *testing.T, path string) (string, bool) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false
		}

		t.Fatalf("read %s: %v", path, err)
	}

	return string(content), true
}

// The rule file names each pinned interface, and #537 added a row for each host. A reader
// who checks a version reads one table, so a row that loses its version sends that reader
// to a moving branch.
func TestTheInterfaceTableNamesTheWiresharkCoreAndTheZeekAnalyzer(t *testing.T) {
	rules := readRepoFile(t, upstreamInterfaceRuleFile)

	for _, want := range []struct {
		row     string
		version string
	}{
		{row: "Wireshark core dissectors", version: upstreamWiresharkVersion},
		{row: "Zeek analyzer", version: upstreamZeekVersion},
	} {
		row, found := upstreamTableRow(rules, want.row)
		if !found {
			t.Errorf("%s holds no interface row named %q, and #537 records one",
				upstreamInterfaceRuleFile, want.row)

			continue
		}

		if !strings.Contains(row, want.version) {
			t.Errorf("the %q row of %s names no version %q:\n\t%s",
				want.row, upstreamInterfaceRuleFile, want.version, row)
		}
	}
}

// upstreamTableRow returns the first table row whose first cell holds the label.
func upstreamTableRow(document string, label string) (string, bool) {
	for _, line := range strings.Split(document, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}

		cell, _, found := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "|"), "|")
		if found && strings.TrimSpace(cell) == label {
			return line, true
		}
	}

	return "", false
}

// A version with no recorded measurement is a version the next reader cannot check. The
// record page states what the measurement searched, so the two must name one version each.
func TestTheUpstreamVersionRecordPageNamesBothVersions(t *testing.T) {
	page := readRepoFile(t, upstreamVersionsRecordPage)

	for _, want := range []string{upstreamWiresharkVersion, upstreamZeekCorpusText} {
		if !strings.Contains(page, want) {
			t.Errorf("%s names no %q, and the rule file records that version",
				upstreamVersionsRecordPage, want)
		}
	}
}

// This is the direction that makes the row a pin rather than a sentence. FoxIO moves its
// own host version without a change to this repository, so a moved `testdata/foxio.pin`
// must redden a test rather than leave the rule file describing a commit nobody reads.
func TestTheFoxioCorpusStillBuildsAgainstThePinnedWiresharkCore(t *testing.T) {
	workflow, present := upstreamCorpusFile(t, upstreamWiresharkCorpusFile)
	if !present {
		t.Skip(upstreamCorpusAbsentMessage)
	}

	if !strings.Contains(workflow, upstreamWiresharkVersion) {
		t.Errorf("%s names no %q, so the FoxIO commit that testdata/foxio.pin holds builds "+
			"the plugin against a different Wireshark core.\n"+
			"\tRe-measure the version, and repair the row of %s and the record of %s.",
			upstreamWiresharkCorpusFile, upstreamWiresharkVersion,
			upstreamInterfaceRuleFile, upstreamVersionsRecordPage)
	}
}

// The Zeek half of the same guard. The container reference is exact, so a FoxIO bump of
// the test image fails this test on the commit that made it.
func TestTheFoxioCorpusStillTestsAgainstThePinnedZeekAnalyzer(t *testing.T) {
	workflow, present := upstreamCorpusFile(t, upstreamZeekCorpusFile)
	if !present {
		t.Skip(upstreamCorpusAbsentMessage)
	}

	if !strings.Contains(workflow, upstreamZeekCorpusText) {
		t.Errorf("%s names no %q, so the FoxIO commit that testdata/foxio.pin holds tests "+
			"against a different Zeek analyzer.\n"+
			"\tRe-measure the version, and repair the row of %s and the record of %s.",
			upstreamZeekCorpusFile, upstreamZeekCorpusText,
			upstreamInterfaceRuleFile, upstreamVersionsRecordPage)
	}
}
