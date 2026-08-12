//go:build conformance

package ja4plus

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/gopacket"
)

// The guard on the register key namespace. It holds FR-reference-29 and FR-reference-30.
//
// The middle part of a register key holds a stream number in the per-stream set and a frame
// number in the per-packet set. Both are small integers, so a reader cannot tell the two
// apart. #217 records the consequence: a per-stream entry and a per-packet entry could hold
// one identical key and name two different comparisons. `compareConformance` reads one
// register map for both sets, so such a pair would accept a comparison the maintainer never
// ruled on.
//
// The guard proves the collision is unreachable. It compares the key space of the two sets
// on every capture the suite compares, and it fails on a key that both sets hold.

// conformanceSharedKeys returns every key that both key sets hold, sorted.
// It returns nil when the two sets share no key.
func conformanceSharedKeys(stream, packet []conformanceKey) []conformanceKey {
	held := make(map[conformanceKey]struct{}, len(stream))
	for _, key := range stream {
		held[key] = struct{}{}
	}

	var shared []conformanceKey

	// The check removes the key from the set after it reports it. A caller that passed one
	// key twice in the second set would otherwise report one collision twice.
	for _, key := range packet {
		if _, both := held[key]; both {
			shared = append(shared, key)

			delete(held, key)
		}
	}

	slices.SortFunc(shared, func(first, second conformanceKey) int {
		return strings.Compare(first.String(), second.String())
	})

	return shared
}

func TestTheSharedKeyCheckFindsAKeyThatBothSetsHold(t *testing.T) {
	stream := []conformanceKey{
		{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L-C"},
		{Capture: "tls3.pcapng", Stream: "22", Method: "JA4X.1"},
	}
	packet := []conformanceKey{
		{Capture: "tls3.pcapng", Stream: "22", Method: "JA4X.1"},
		{Capture: "tls3.pcapng", Stream: "63", Method: "JA4L.1"},
	}

	shared := conformanceSharedKeys(stream, packet)
	if len(shared) != 1 {
		t.Fatalf("the check reports %d shared keys, and the two sets share `tls3.pcapng/22/JA4X.1`", len(shared))
	}

	if got := shared[0].String(); got != "tls3.pcapng/22/JA4X.1" {
		t.Errorf("the check reports the shared key %q, and the two sets share `tls3.pcapng/22/JA4X.1`", got)
	}
}

func TestTheSharedKeyCheckReportsNothingForTwoDisjointSets(t *testing.T) {
	stream := []conformanceKey{{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L-C"}}
	packet := []conformanceKey{{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L.1"}}

	if shared := conformanceSharedKeys(stream, packet); len(shared) != 0 {
		t.Errorf("the check reports the shared key %q, and the two sets share none", shared[0])
	}
}

// TestNoKeyNamesBothAPerStreamAndAPerPacketComparison holds FR-reference-30.
//
// A key that both sets hold makes one register entry accept two comparisons. The register
// grows on every session, so the guard reads the whole corpus and never a sample.
func TestNoKeyNamesBothAPerStreamAndAPerPacketComparison(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	shared := 0
	near := 0
	streamKeys := 0
	packetKeys := 0

	for _, capture := range conformanceCaptureNames(t) {
		// FoxIO marks such a capture `notest`, so the suite makes no comparison for it and
		// the register can hold no key for it.
		if strings.Contains(capture, conformanceNotestMarker) {
			continue
		}

		outcome := conformanceCheckOneCaptureKeySpace(t, capture)

		shared += outcome.shared
		near += outcome.near
		streamKeys += outcome.streamKeys
		packetKeys += outcome.packetKeys
	}

	// A guard that compares two empty key spaces passes and proves nothing. A broken vector
	// path would reach that state, so the test reads the size of each space.
	if streamKeys == 0 || packetKeys == 0 {
		t.Errorf("the corpus reports %d per-stream keys and %d per-packet keys, and the suite compares a value in each set",
			streamKeys, packetKeys)
	}

	// The near count is the measurement #217 asks for, and it fails nothing. It counts the
	// pairs that the method name alone keeps apart, so it states how much of the key space
	// the middle part already shares.
	t.Logf("the corpus holds %d per-stream keys and %d per-packet keys, %d keys that both sets name, and %d pairs that the method name alone separates",
		streamKeys, packetKeys, shared, near)
}

// conformanceKeySpaceOutcome holds the counts of one capture.
type conformanceKeySpaceOutcome struct {
	// streamKeys counts the keys the per-stream comparison reads.
	streamKeys int
	// packetKeys counts the keys the per-packet comparison reads.
	packetKeys int
	// shared counts the keys that both sets hold.
	shared int
	// near counts the pairs that hold one capture and one middle part, and two method
	// names.
	near int
}

// conformanceCheckOneCaptureKeySpace compares the key space of the two sets on one capture.
// It returns the counts, and it fails the test for each key that both sets hold.
func conformanceCheckOneCaptureKeySpace(t *testing.T, capture string) conformanceKeySpaceOutcome {
	t.Helper()

	packets := loadPCAP(t, conformanceCaptureDir+"/"+capture)

	stream := conformanceStreamKeySpace(t, capture, packets)
	packet := conformancePacketKeySpace(t, capture, packets)

	shared := conformanceSharedKeys(stream, packet)
	for _, key := range shared {
		t.Errorf("the key %s names a comparison in the per-stream set and in the per-packet set, and FR-reference-29 gives one meaning to the middle part of one key",
			key)
	}

	return conformanceKeySpaceOutcome{
		streamKeys: len(stream),
		packetKeys: len(packet),
		shared:     len(shared),
		near:       conformanceCountNearKeys(stream, packet),
	}
}

// conformanceCountNearKeys returns the count of key pairs that hold one capture and one
// middle part, and that two method names keep apart.
func conformanceCountNearKeys(stream, packet []conformanceKey) int {
	middle := make(map[string]int, len(stream))
	for _, key := range stream {
		middle[key.Stream]++
	}

	near := 0

	for _, key := range packet {
		near += middle[key.Stream]
	}

	return near
}

// conformanceStreamKeySpace returns every key the per-stream comparison of the capture
// reads. It returns nil when the corpus holds no per-stream vector for the capture.
//
// The comparison reads the register at the key of every value that either side holds, so
// the key space holds the produced keys and the expected keys together.
func conformanceStreamKeySpace(t *testing.T, capture string, packets []gopacket.Packet) []conformanceKey {
	t.Helper()

	path := conformanceVectorPath(conformanceStreamVectorDir, capture)
	if path == "" {
		return nil
	}

	shape, err := conformanceExpectedFromStreamVector(capture, conformanceReadStreamVector(t, path))
	if err != nil {
		t.Fatalf("the per-stream adapter fails for %s: %v", capture, err)
	}

	if len(shape.Expected) == 0 {
		return nil
	}

	return conformanceComparedKeys(conformanceProducedByStream(t, capture, packets, shape), shape.Expected)
}

// conformancePacketKeySpace returns every key the per-packet comparison of the capture
// reads. It returns nil when the corpus holds no per-packet vector for the capture.
func conformancePacketKeySpace(t *testing.T, capture string, packets []gopacket.Packet) []conformanceKey {
	t.Helper()

	path := conformanceVectorPath(conformancePacketVectorDir, capture)
	if path == "" {
		return nil
	}

	expected := conformanceExpectedFromPacketVector(t, capture, conformanceReadPacketVector(t, path))
	if len(expected) == 0 {
		return nil
	}

	return conformanceComparedKeys(conformanceProducedByFrame(t, capture, packets, conformanceCoveredMethods(expected)), expected)
}
