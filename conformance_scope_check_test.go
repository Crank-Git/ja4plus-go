//go:build conformance

package ja4plus

import (
	"slices"
	"strings"
	"testing"
)

// These tests hold the comparison scope of the bare vector key. Issue #209 states the
// defect, and round 20 of the `## Changelog` of `docs/specs/spec.md` records the narrower
// rule.
//
// A method emits twice on one stream for two different reasons, and one rule cannot serve
// both. A measurement point that moves reports the same connection twice, and the last
// report holds the value the reference publishes. A method that emits once per protocol, or
// once per request, reports two different values, and the second is a surplus.
//
// The tests read `conformanceStreamMethodKey` with a fixture, because the producer counts
// the occurrence and the key form decides which value reaches the comparison.

// The library produces a TLS value and a QUIC value for JA4S on stream 0 of
// `chrome-cloudflare-quic-with-secrets.pcapng`. The per-stream vector writes the bare key
// `JA4S`, and it holds the TLS value `t130200_1301_234ea6891581`.
//
// `docs/audit/conformance.md` recorded the deviation `the two values differ` with the vector
// value `t130200_1301_234ea6891581` and the library value `q130200_1301_234ea6891581`. The
// bare key kept the last value, so the correct value never reached the comparison.
func TestTheHarnessNumbersTheSecondJA4SValueOfOneStream(t *testing.T) {
	if got := conformanceStreamMethodKey("JA4S", 1, false); got != "JA4S" {
		t.Errorf("the harness writes %q for the first JA4S value of one stream, and the vector writes `JA4S`", got)
	}

	if got := conformanceStreamMethodKey("JA4S", 2, false); got != "JA4S.2" {
		t.Errorf("the harness writes %q for the second JA4S value of one stream, and a surplus value reports as `JA4S.2`", got)
	}
}

// FoxIO writes one per-stream entry for each HTTP request. A vector that holds one entry for
// a stream still reaches a stream that carries more than one request.
//
// `CVE-2018-6794.pcap/0/JA4H` fell from 12 deviations to 2 under the bare key, and the
// second value and each later one reached no comparison. Those surplus values are
// retransmission values, and never request values. Each HTTP connection of that capture
// carries one request and five TCP retransmissions of it, and #233 holds the measurement.
// `ja4h_retransmitted_capture_test.go` holds the count the library produces today.
func TestTheHarnessNumbersTheSecondAndLaterJA4HValuesOfOneStream(t *testing.T) {
	for occurrence, want := range map[int]string{
		1: "JA4H",
		2: "JA4H.2",
		3: "JA4H.3",
		4: "JA4H.4",
	} {
		if got := conformanceStreamMethodKey("JA4H", occurrence, false); got != want {
			t.Errorf("the harness writes %q for JA4H value %d of one stream, and the value reports as %q",
				got, occurrence, want)
		}
	}
}

// The maintainer ruled on 2026-08-12 in issue #196 that the harness compares the last JA4L
// emission of one stream. Round 15 states the ruling, and round 20 reverses no part of it.
//
// `docs/specs/foxio/JA4L.md` R33 names the measurement point that moves. The reference is a
// batch program that publishes the final state of its cache, so the last report holds the
// value the reference publishes.
func TestTheHarnessComparesTheLastJA4LValueOfOneStream(t *testing.T) {
	for _, method := range []string{"JA4L-C", "JA4L-S"} {
		t.Run(method, func(t *testing.T) {
			for _, occurrence := range []int{1, 2, 7} {
				if got := conformanceStreamMethodKey(method, occurrence, false); got != method {
					t.Errorf("the harness writes %q for value %d of %s, and round 15 compares the last emission",
						got, occurrence, method)
				}
			}
		})
	}
}

// A vector key that carries an occurrence number keeps that form for every method. The
// last-emission rule therefore reaches no stream whose vector numbers the values.
func TestTheHarnessKeepsTheOccurrenceFormForEveryMethodTheVectorNumbers(t *testing.T) {
	for _, method := range []string{"JA4L-C", "JA4S", "JA4X"} {
		t.Run(method, func(t *testing.T) {
			if got := conformanceStreamMethodKey(method, 3, true); got != method+".3" {
				t.Errorf("the harness writes %q for value 3 of %s, and the vector writes %q", got, method, method+".3")
			}
		})
	}
}

// conformanceCollapsingMethods returns every per-stream method whose second value of one
// stream replaces the first under a bare vector key.
//
// The set derives from `conformanceStreamMethodKeys` and from `conformanceStreamMethodKey`,
// so no third list states it. Issue #148 requires a derived list, because a hardcoded one
// leaves a new method behind.
//
// `conformanceStreamMethodKeys` already holds each raw form as its own key, for example
// `JA4H_r`. This loop therefore synthesizes no suffix. A synthesized form could repeat a key
// the map already holds. The caller compares two sorted lists, so one repeated member would
// fail the test for the wrong reason.
func conformanceCollapsingMethods() []string {
	var collapsing []string

	for method := range conformanceStreamMethodKeys {
		if conformanceStreamMethodKey(method, 2, false) == method {
			collapsing = append(collapsing, method)
		}
	}

	slices.Sort(collapsing)

	return collapsing
}

// The last-emission rule reaches the two JA4L methods and no other method.
//
// This test fails when a second method joins the bare-key set. A method that joins it hides
// every value after the first, and the suite then reports a count it does not measure.
// Issue #209 measured that: one match was lost and three JA4H values reached no comparison.
func TestTheLastEmissionSetHoldsTheTwoJA4LMethodsAlone(t *testing.T) {
	want := []string{"JA4L-C", "JA4L-S"}

	if got := conformanceCollapsingMethods(); !slices.Equal(got, want) {
		t.Errorf("the harness compares the last emission of %v, and round 15 rules that for %v", got, want)
	}
}

// Every member of the last-emission set names a per-stream vector key. A typo in the set
// therefore fails the suite, and it widens the rule on no method.
func TestEveryLastEmissionMethodNamesAPerStreamVectorKey(t *testing.T) {
	for method := range conformanceLastEmissionMethods {
		if !conformanceStreamMethodKeys[method] {
			t.Errorf("the last-emission set names %q, and the per-stream vector key set does not hold it", method)
		}
	}
}

// Every member of the last-emission set names the fingerprinter whose measurement point
// moves. The stem derives from `Processor.fingerprinters`. A rename of that fingerprinter
// therefore fails this test, and the rule stays on no name that the processor no longer runs.
func TestEveryLastEmissionMethodNamesTheFingerprinterWhosePointMoves(t *testing.T) {
	stem := methodNameOfFingerprinter(conformanceMovingPointFingerprinter)

	if !slices.Contains(processorFingerprinterNames(), conformanceMovingPointFingerprinter) {
		t.Fatalf("the processor runs no %s, and the last-emission rule names it", conformanceMovingPointFingerprinter)
	}

	for method := range conformanceLastEmissionMethods {
		label, _, _ := strings.Cut(method, "-")
		if strings.ToLower(label) != stem {
			t.Errorf("the last-emission set names %q, and the rule covers the fingerprinter %q alone",
				method, conformanceMovingPointFingerprinter)
		}
	}
}

// A surplus value keeps the match of the value the vector names.
//
// This is the behavior that issue #209 repairs. The bare key lost a real match on
// `chrome-cloudflare-quic-with-secrets.pcapng/0/JA4S`, and the loss is what made #209 a
// defect and not a missing guard.
//
// The surplus value still reports, which FR-conformance-17 names. Over-emission is a defect
// this project has had, and issue #33 measured 617 values for `ssh-r.pcap` where the vector
// holds 11.
func TestASurplusValueKeepsTheMatch(t *testing.T) {
	capture := "chrome-cloudflare-quic-with-secrets.pcapng"

	produced := map[conformanceKey]string{
		{Capture: capture, Stream: "0", Method: "JA4S"}:   "t130200_1301_234ea6891581",
		{Capture: capture, Stream: "0", Method: "JA4S.2"}: "q130200_1301_234ea6891581",
	}
	expected := map[conformanceKey]string{
		{Capture: capture, Stream: "0", Method: "JA4S"}: "t130200_1301_234ea6891581",
	}

	comparison := compareConformance(produced, expected, nil)

	if comparison.Matches != 1 {
		t.Errorf("the engine reports %d matches, and the vector value reaches the bare key", comparison.Matches)
	}

	if len(comparison.Deviations) != 1 {
		t.Fatalf("the engine reports %d deviations, and the surplus value is the one deviation", len(comparison.Deviations))
	}

	if kind := comparison.Deviations[0].Kind; kind != conformanceExtraValue {
		t.Errorf("the engine reports the surplus value as %q, and FR-conformance-17 names it %q", kind, conformanceExtraValue)
	}
}
