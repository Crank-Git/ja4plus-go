package ja4plus

import (
	"regexp"
	"strings"
	"testing"
)

// These tests hold the ruling of #356. The maintainer ruled on 2026-08-13 that
// `generate_ja4l` and `generate_ja4ssh` are `not applicable`, and that this library exports
// no `ComputeJA4L` and no `ComputeJA4SSH`.
//
// `.claude/rules/rulings.md` states that a ruling carries a register entry or a test. This
// ruling moves no fingerprint value, so no entry of `testdata/deviations.json` reaches it,
// and these tests are the record a later reader finds.
//
// The reversal path is #356, and the freeze at `v1.0.0` makes a reversal after the freeze a
// breaking change.

// oneShotDeclinedPortNames holds the two port names that the ruling of #356 declines.
//
// Each one is a one-shot function for a method that reads more than one packet. JA4L reads
// the SYN and the SYN-ACK, and JA4SSH reads a window of packets.
var oneShotDeclinedPortNames = []string{
	"generate_ja4l",
	"generate_ja4ssh",
}

// oneShotDeclinedGoNames holds the two Go names that the ruling of #356 declines. An
// exported one-shot function of either name would carry connection state across the package
// boundary, and `.claude/rules/concurrency.md` keeps that state unexported.
var oneShotDeclinedGoNames = []string{
	"ComputeJA4L",
	"ComputeJA4SSH",
}

// oneShotDeclineWord is the applicability word that the ruling of #356 writes on both rows.
const oneShotDeclineWord = "`none`, not applicable"

// notApplicableHeadingPattern matches the heading that states how many rows of the table
// record `not applicable`. The heading states a count about the page itself, and a stale
// count makes the page contradict its own table.
var notApplicableHeadingPattern = regexp.MustCompile("(?m)^## The ([a-z]+) `not applicable` rows?,")

// englishCounts maps each count word that the heading may hold onto its number. The table
// holds 25 rows, so no larger word reaches the heading.
var englishCounts = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
	"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}

// The ruling of #356 — a row that reverts to `applicable` reopens a question the maintainer
// closed on 2026-08-13.
func TestTheParityTableRecordsTheTwoOneShotRowsAsNotApplicable(t *testing.T) {
	rows := readParityTableRows(t)

	found := map[string]bool{}

	for _, row := range rows {
		for _, declined := range oneShotDeclinedPortNames {
			if row.PortName != declined {
				continue
			}

			found[declined] = true

			if row.Equivalent != oneShotDeclineWord {
				t.Errorf("the row for %q records the Go equivalent %q, and the ruling of #356 records %q",
					row.PortName, row.Equivalent, oneShotDeclineWord)
			}

			if !strings.Contains(row.Reason, "#356") {
				t.Errorf("the row for %q records the reason %q, and the ruling of #356 names that issue on the row",
					row.PortName, row.Reason)
			}
		}
	}

	for _, declined := range oneShotDeclinedPortNames {
		if !found[declined] {
			t.Errorf("%s holds no row for the port name %q, and the ruling of #356 records one", parityTableFile, declined)
		}
	}
}

// The ruling of #356 — an exported one-shot function exports the connection state that
// `JA4LFingerprinter` and `JA4SSHFingerprinter` hold. `v1.0.0` freezes the exported API, so
// the exposure would be permanent.
func TestPackageJa4plusExportsNoOneShotFunctionForJA4LOrJA4SSH(t *testing.T) {
	exported := readExportedPackageNames(t)

	for _, declined := range oneShotDeclinedGoNames {
		if exported[declined] {
			t.Errorf("package ja4plus exports %q, and the ruling of #356 records no such name. Reverse the ruling in #356 before you add it",
				declined)
		}
	}
}

// The page states a count about its own table, and #260 records three batches where a stale
// count of that shape reached the tree.
func TestTheParityPageStatesTheCountOfNotApplicableRowsThatItHolds(t *testing.T) {
	page := readRepoFile(t, parityTableFile)

	held := 0
	for _, row := range readParityTableRows(t) {
		if row.Equivalent == oneShotDeclineWord {
			held++
		}
	}

	match := notApplicableHeadingPattern.FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("%s holds no heading that states the count of `not applicable` rows, and the page records that count", parityTableFile)
	}

	stated, known := englishCounts[match[1]]
	if !known {
		t.Fatalf("the heading states the count word %q, and this test reads no such word", match[1])
	}

	if stated != held {
		t.Errorf("%s states %d `not applicable` rows in the heading %q, and the table holds %d",
			parityTableFile, stated, match[0], held)
	}
}
