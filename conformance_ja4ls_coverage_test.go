//go:build conformance

package ja4plus

import (
	"strings"
	"testing"
)

// These tests hold FR-ja4ls-21. The conformance harness compares every published JA4LS
// value.
//
// The two vector sets name JA4LS by two different keys, and neither key is the string
// `JA4LS`. The per-stream set writes the key `JA4L-S`, and the per-packet set writes the
// field `ja4.ja4ls`. `conformanceStreamMethodKeys` holds the first, and
// `conformancePacketMethods` maps the second to the method name `JA4LS`.
//
// A published value is a value the vector file holds. The harness compares such a value
// when it reaches the expected map of the set, because `compareConformance` reads that map.
// A published value that reaches no expected map reaches no comparison, and the run then
// reports neither a match nor a deviation for it.
//
// Each test below counts the published values from the raw vector, and it counts the
// compared values from the expected map. The two counts come from two different readings of
// one file, so a test failure names a value the harness drops.

// conformancePerStreamJA4LSKey names the per-stream vector key for JA4LS.
const conformancePerStreamJA4LSKey = "JA4L-S"

// conformancePerPacketJA4LSMethod names the method that the per-packet adapter writes for
// JA4LS. `conformancePacketMethods` maps the field `ja4.ja4ls` to it.
const conformancePerPacketJA4LSMethod = "JA4LS"

// conformancePerPacketJA4LSField names the per-packet vector field for JA4LS.
const conformancePerPacketJA4LSField = "ja4.ja4ls"

// conformancePublishedJA4LSStreamValues counts the JA4LS values that the corpus publishes in
// the per-stream set at the pin of `testdata/foxio.pin`.
//
// A pin move changes this count. Re-measure the corpus. Write the new count here.
const conformancePublishedJA4LSStreamValues = 58

// conformancePublishedJA4LSPacketValues counts the JA4LS values that the corpus publishes in
// the per-packet set at the pin of `testdata/foxio.pin`.
//
// A pin move changes this count. Re-measure the corpus. Write the new count here.
const conformancePublishedJA4LSPacketValues = 44

// conformanceKeyNamesMethod reports whether the comparison key names the method.
// The key of a method carries an occurrence number, so the test reads the stem.
func conformanceKeyNamesMethod(key conformanceKey, method string) bool {
	return conformanceMethodOfComparisonKey(key) == method
}

// conformanceCountComparedJA4LS returns the number of keys of the expected map that name the
// method.
func conformanceCountComparedJA4LS(expected map[conformanceKey]string, method string) int {
	count := 0

	for key := range expected {
		if conformanceKeyNamesMethod(key, method) {
			count++
		}
	}

	return count
}

// conformanceCountPublishedStreamJA4LS returns the number of JA4LS values that the per-stream
// vector holds.
//
// The count reads the raw entry, and it calls no adapter. A count that read the adapter would
// pass whatever the adapter did, so it would prove nothing.
func conformanceCountPublishedStreamJA4LS(entries []conformanceStreamEntry) int {
	count := 0

	for _, entry := range entries {
		for key := range entry {
			stem, _, held := strings.Cut(key, ".")
			if !held {
				stem = key
			}

			if stem == conformancePerStreamJA4LSKey {
				count++
			}
		}
	}

	return count
}

// conformanceCountPublishedPacketJA4LS returns the number of JA4LS values that the per-packet
// vector holds.
//
// One frame holds a list of values for one field, so the count reads the length of the list.
func conformanceCountPublishedPacketJA4LS(records []conformancePacketRecord) int {
	count := 0

	for _, record := range records {
		count += len(record.Source.Layers[conformancePerPacketJA4LSField])
	}

	return count
}

// The per-stream expected map holds every JA4LS value that the per-stream vector publishes.
//
// The adapter collects the values of one stream and one method, and it numbers them when one
// stream holds more than one. A single map write would keep the last value alone, and the
// other values would then reach no comparison. Issue #209 measured that loss on JA4H.
func TestTheHarnessComparesEveryPublishedPerStreamJA4LSValue(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	published, compared := 0, 0

	for _, capture := range conformanceCaptureNames(t) {
		path := conformanceVectorPath(conformanceStreamVectorDir, capture)
		if path == "" {
			continue
		}

		entries := conformanceReadStreamVector(t, path)

		shape, err := conformanceExpectedFromStreamVector(capture, entries)
		if err != nil {
			t.Fatalf("the per-stream vector for %s does not read: %v", capture, err)
		}

		capturePublished := conformanceCountPublishedStreamJA4LS(entries)
		captureCompared := conformanceCountComparedJA4LS(shape.Expected, conformancePerStreamJA4LSKey)

		if capturePublished != captureCompared {
			t.Errorf("the per-stream vector for %s publishes %d JA4LS values, and the harness compares %d",
				capture, capturePublished, captureCompared)
		}

		published += capturePublished
		compared += captureCompared
	}

	if published != conformancePublishedJA4LSStreamValues {
		t.Errorf("the per-stream set publishes %d JA4LS values, and the corpus at the pin holds %d",
			published, conformancePublishedJA4LSStreamValues)
	}

	if compared != published {
		t.Errorf("the harness compares %d per-stream JA4LS values, and the set publishes %d", compared, published)
	}
}

// The per-packet expected map holds every JA4LS value that the per-packet vector publishes.
//
// The adapter numbers the values of one frame, so a frame that holds two values reaches two
// comparisons.
func TestTheHarnessComparesEveryPublishedPerPacketJA4LSValue(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	published, compared := 0, 0

	for _, capture := range conformanceCaptureNames(t) {
		path := conformanceVectorPath(conformancePacketVectorDir, capture)
		if path == "" {
			continue
		}

		records := conformanceReadPacketVector(t, path)
		expected := conformanceExpectedFromPacketVector(t, capture, records)

		capturePublished := conformanceCountPublishedPacketJA4LS(records)
		captureCompared := conformanceCountComparedJA4LS(expected, conformancePerPacketJA4LSMethod)

		if capturePublished != captureCompared {
			t.Errorf("the per-packet vector for %s publishes %d JA4LS values, and the harness compares %d",
				capture, capturePublished, captureCompared)
		}

		published += capturePublished
		compared += captureCompared
	}

	if published != conformancePublishedJA4LSPacketValues {
		t.Errorf("the per-packet set publishes %d JA4LS values, and the corpus at the pin holds %d",
			published, conformancePublishedJA4LSPacketValues)
	}

	if compared != published {
		t.Errorf("the harness compares %d per-packet JA4LS values, and the set publishes %d", compared, published)
	}
}

// The two adapters name JA4LS, so neither vector set drops the method.
//
// A removal of either name stops the harness from comparing a whole set of JA4LS values.
// `conformanceRecognizeStreamKey` and `conformanceRecognizePacketField` each fail the suite
// for an unrecognized key, so a removal reports as a harness defect and never as a deviation.
func TestBothConformanceAdaptersNameJA4LS(t *testing.T) {
	if !conformanceStreamMethodKeys[conformancePerStreamJA4LSKey] {
		t.Errorf("the per-stream key set does not hold %q, and the per-stream vector writes that key",
			conformancePerStreamJA4LSKey)
	}

	method, mapped := conformancePacketMethods[conformancePerPacketJA4LSField]
	if !mapped {
		t.Fatalf("the per-packet field map does not hold %q, and the per-packet vector writes that field",
			conformancePerPacketJA4LSField)
	}

	if method != conformancePerPacketJA4LSMethod {
		t.Errorf("the per-packet field map writes %q for %q, and the method name is %q",
			method, conformancePerPacketJA4LSField, conformancePerPacketJA4LSMethod)
	}
}

// The library reports a JA4LS value under the label `JA4L-S`, and each adapter reads that
// label.
//
// `JA4LFingerprinter` writes both JA4L and JA4LS, and it reports the type `ja4l` for the two.
// The label names which of the two the value holds. An adapter that misread the label would
// compare a JA4LS value against a JA4L key. The run would then report two deviations for one
// correct value.
func TestBothConformanceAdaptersReadTheJA4LSLabelOfTheLibrary(t *testing.T) {
	result := FingerprintResult{Type: "ja4l", Fingerprint: "JA4L-S=12517_53"}

	streamMethod, streamValue, streamHeld := conformanceStreamMethodOfResult(result)
	if !streamHeld || streamMethod != conformancePerStreamJA4LSKey || streamValue != "12517_53" {
		t.Errorf("the per-stream adapter reads %q and %q for the label `JA4L-S`, and the key is %q with the value `12517_53`",
			streamMethod, streamValue, conformancePerStreamJA4LSKey)
	}

	packetMethod, packetValue, packetHeld := conformanceMethodOfResultType(result)
	if !packetHeld || packetMethod != conformancePerPacketJA4LSMethod || packetValue != "12517_53" {
		t.Errorf("the per-packet adapter reads %q and %q for the label `JA4L-S`, and the method is %q with the value `12517_53`",
			packetMethod, packetValue, conformancePerPacketJA4LSMethod)
	}
}
