package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"
)

// These tests hold three rulings of #60, and each one fails when its ruling is reversed.
// FR-parity-3 states that rule.
//
// The maintainer ruled on 2026-08-13 that the JA4LS result keeps `Type: "ja4l"`.
// `docs/specs/features/12-ja4ls.md:143-144` states that one fingerprinter writes two
// methods, and a reader tells the two apart by the `JA4L-S=` label.
//
// The two value rulings below are PROVISIONAL, under
// `.claude/rules/rulings.md` `## What a delegated session may rule`. The maintainer confirms
// them or reverses them, and #60 is the reversal path for each one.

// serverMeasurementTTL is the time-to-live that the server SYN-ACK of these tests carries.
// The value sits below 64, so a hop count and an observed time-to-live separate.
const serverMeasurementTTL uint8 = 57

// serverMeasurementInterval is the time between the SYN and the SYN-ACK of these tests.
// The value is a round number of milliseconds, so the expected microsecond count is exact.
const serverMeasurementInterval = 100 * time.Millisecond

// serverValueOfATCPHandshake returns the results that the SYN-ACK of one TCP handshake gives.
//
// The handshake carries the time-to-live of serverMeasurementTTL on the SYN-ACK, and it
// carries serverMeasurementInterval between the two packets. The client SYN carries the
// time-to-live 64, which no server value reads.
func serverValueOfATCPHandshake(t *testing.T) []FingerprintResult {
	t.Helper()

	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime

	if _, err := fp.ProcessPacket(synPkt); err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, serverMeasurementTTL, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(serverMeasurementInterval)

	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}

	return results
}

// The ruling of #60 — the SYN-ACK reaches the server measurement point, and the
// fingerprinter reports the server value from that packet. `docs/specs/foxio/JA4L.md` R26
// states that part a of JA4LS measures the SYN-ACK against the SYN. A change that stops the
// emission fails this test.
func TestTheSynAckEmitsOneServerValueWithTheJA4LSLabel(t *testing.T) {
	results := serverValueOfATCPHandshake(t)

	if len(results) != 1 {
		t.Fatalf("SYN-ACK: got %d results, want 1", len(results))
	}

	if !strings.HasPrefix(results[0].Fingerprint, "JA4L-S=") {
		t.Errorf("SYN-ACK: Fingerprint = %q, want the prefix %q", results[0].Fingerprint, "JA4L-S=")
	}
}

// The ruling of #60 — the maintainer ruled on 2026-08-13 that JA4LS reaches no type of its
// own. One connection has one owner, and a second type would split it across two.
// `ja4plus/processor.py` at `v1.1.0` registers `("ja4l", JA4LFingerprinter)`, so the port
// writes one type for both methods. A change that writes `ja4ls` fails this test.
func TestTheServerResultAndTheClientResultCarryOneType(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	if _, err := fp.ProcessPacket(synPkt); err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, serverMeasurementTTL, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(serverMeasurementInterval)
	serverResults, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}

	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(2 * serverMeasurementInterval)
	clientResults, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("ACK: unexpected error: %v", err)
	}

	if len(serverResults) != 1 || len(clientResults) != 1 {
		t.Fatalf("the handshake gives %d server results and %d client results, and it gives 1 of each",
			len(serverResults), len(clientResults))
	}

	if serverResults[0].Type != "ja4l" {
		t.Errorf("the server result carries the type %q, and the ruling of #60 records %q. Reverse the ruling in #60 before you change it",
			serverResults[0].Type, "ja4l")
	}

	if clientResults[0].Type != serverResults[0].Type {
		t.Errorf("the client result carries the type %q and the server result carries %q, and one fingerprinter writes one type",
			clientResults[0].Type, serverResults[0].Type)
	}
}

// PROVISIONAL ruling of #60 — part b holds the time-to-live that the packet carries, and the
// value subtracts it from no initial time-to-live. `docs/specs/foxio/JA4L.md` R13 at :90-92
// and R18 at :114-116 state the unanimous reading. A hop count would write `7` here, because
// the image states the initial time-to-live 64 for this group. The maintainer confirms this
// ruling or reverses it, and #60 is the reversal path.
func TestTheServerValueWritesTheObservedTimeToLive(t *testing.T) {
	results := serverValueOfATCPHandshake(t)

	if len(results) != 1 {
		t.Fatalf("SYN-ACK: got %d results, want 1", len(results))
	}

	parts := strings.Split(results[0].Fingerprint, "_")
	if len(parts) != 2 {
		t.Fatalf("SYN-ACK: Fingerprint = %q, want two parts", results[0].Fingerprint)
	}

	if parts[1] != "57" {
		t.Errorf("part b = %q, want %q. A hop count writes %q, and no FoxIO implementation writes one",
			parts[1], "57", "7")
	}
}

// PROVISIONAL ruling of #60 — part a is half of the measured time, and no propagation factor
// reaches it. `docs/specs/foxio/JA4L.md` R6 at :57-61 states that four implementations
// divide by 2, and R22 at :137-139 states that no implementation computes a distance. The
// propagation factor belongs to the distance formula that R19 states, and
// `CalculateDistance` holds it. The propagation factor 1.6 would write `62500` here. The
// maintainer confirms this ruling or reverses it, and #60 is the reversal path.
func TestTheServerValueHalvesTheMeasuredTime(t *testing.T) {
	results := serverValueOfATCPHandshake(t)

	if len(results) != 1 {
		t.Fatalf("SYN-ACK: got %d results, want 1", len(results))
	}

	if results[0].Fingerprint != "JA4L-S=50000_57" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q. The propagation factor 1.6 writes %q",
			results[0].Fingerprint, "JA4L-S=50000_57", "JA4L-S=62500_57")
	}
}
