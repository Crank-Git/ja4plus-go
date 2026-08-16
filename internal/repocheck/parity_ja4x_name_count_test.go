package repocheck

import (
	"regexp"
	"strings"
	"testing"
)

// This test holds the repair of #378. `docs/parity.md` stated that three Go names answer
// one port name, and the next sentence of the same paragraph named three port names.
//
// The paragraph states a count about the table above it, and no test read the prose. #260
// records three batches where a stale count of that shape reached the tree, and
// `parity_one_shot_not_applicable_test.go` guards the other count of this page.

// ja4xNameCountPattern matches the sentence that counts the JA4X names of the table. The
// sentence states two counts, and the table decides both of them.
var ja4xNameCountPattern = regexp.MustCompile(`(?m)^\*\*([A-Za-z]+) port names and ([A-Za-z]+) Go names answer the one JA4X method\.\*\*`)

// ja4xRowKind names the kind cell that a JA4X one-shot row holds. `JA4XFingerprinter` is a
// class, and it answers no count of this sentence.
const ja4xRowKind = "function"

// ja4xRowMarker is the token that a JA4X port name holds. Each port name of the list is
// lower case, so the test folds the case before it reads the token.
const ja4xRowMarker = "ja4x"

// The paragraph states a count about its own table, and a reader who trusts a stale count
// reads the mapping backwards.
func TestTheParityPageStatesTheJA4XNameCountThatTheTableHolds(t *testing.T) {
	portNames := 0
	goNames := 0

	for _, row := range readParityTableRows(t) {
		if row.Kind != ja4xRowKind || !strings.Contains(strings.ToLower(row.PortName), ja4xRowMarker) {
			continue
		}

		portNames++

		if parityGoNamePattern.MatchString(row.Equivalent) {
			goNames++
		}
	}

	page := readRepoFile(t, parityTableFile)

	match := ja4xNameCountPattern.FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("%s holds no sentence that counts the JA4X names, and the page records that count", parityTableFile)
	}

	statedPortNames, known := englishCounts[strings.ToLower(match[1])]
	if !known {
		t.Fatalf("the sentence states the count word %q for the port names, and this test reads no such word", match[1])
	}

	statedGoNames, known := englishCounts[strings.ToLower(match[2])]
	if !known {
		t.Fatalf("the sentence states the count word %q for the Go names, and this test reads no such word", match[2])
	}

	if statedPortNames != portNames {
		t.Errorf("%s states %d JA4X port names in %q, and the table holds %d",
			parityTableFile, statedPortNames, match[0], portNames)
	}

	if statedGoNames != goNames {
		t.Errorf("%s states %d JA4X Go names in %q, and the table holds %d",
			parityTableFile, statedGoNames, match[0], goNames)
	}
}
