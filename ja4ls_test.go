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
// The rules section of `docs/specs/features/12-ja4ls.md` states that one fingerprinter writes
// two methods and that JA4LS gets no type of its own, and a reader tells the two apart by the
// `JA4L-S=` label. The rule is cited by its section rather than by a line number, because a
// sibling member of this batch moved that line twice. The heading is not quoted here, because
// it carries a spelling that `misspell` rejects in a Go file, and #388 holds that cleanup.
//
// The two value rulings below are PROVISIONAL, under
// `.claude/rules/rulings.md` `## What a delegated session may rule`. The maintainer confirms
// them or reverses them, and #60 is the reversal path for each one.

// serverMeasurementTTL is the time-to-live that the server SYN-ACK of these tests carries.
// The value sits below 64, so a hop count and an observed time-to-live separate.
const serverMeasurementTTL uint8 = 57

// serverMeasurementInterval is the interval between the SYN and the SYN-ACK of these tests.
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

// PROVISIONAL ruling of #60 — part b writes the time-to-live that the packet carries,
// unchanged. `docs/specs/foxio/JA4L.md` R13 at :90-92 and R18 at :114-116 state the
// unanimous reading. A hop count would write `7` here, because the image states the initial
// time-to-live 64 for this group. The maintainer confirms this ruling or reverses it, and
// #60 is the reversal path.
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

// PROVISIONAL ruling of #60 — part a is half of the interval between the two measurement
// points, and no propagation factor reaches it. `docs/specs/foxio/JA4L.md` R6 at :57-61
// states that four implementations divide by 2, and R22 at :137-139 states that no
// implementation computes a distance. The propagation factor belongs to the distance formula
// that R19 states, and `CalculateDistance` holds it. The propagation factor 1.6 would write
// `62500` here. The maintainer confirms this ruling or reverses it, and #60 is the reversal
// path.
func TestTheServerValueHalvesTheIntervalBetweenTheMeasurementPoints(t *testing.T) {
	results := serverValueOfATCPHandshake(t)

	if len(results) != 1 {
		t.Fatalf("SYN-ACK: got %d results, want 1", len(results))
	}

	if results[0].Fingerprint != "JA4L-S=50000_57" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q. The propagation factor 1.6 writes %q",
			results[0].Fingerprint, "JA4L-S=50000_57", "JA4L-S=62500_57")
	}
}

// The reference emits the QUIC server value on the frame that fills point D.
// `wireshark/source/packet-ja4.c:1432-1451` writes `hf_ja4ls` and `hf_ja4l` inside the
// branch that fills `timestamp_D`, so one frame carries both values. The library emitted
// the server value on the frame that fills point B, and the per-packet vector then held
// the same value at another frame. Issue #447 holds the measurement.

// TestJA4LSReachesTheClientHandshakeFrameOfAQUICConnection holds the emission frame of the
// QUIC server value. It fails when the emission moves back to the point B frame.
func TestJA4LSReachesTheClientHandshakeFrameOfAQUICConnection(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// Point A. The client Initial packet carries a time-to-live that the client value
	// reports, and no other packet of the flow carries it.
	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("point A reports %d results, and the reference reports none", len(results))
	}

	// Point B. The server Initial packet fills the server point, and the reference emits
	// no value on this frame.
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	bResults, err := fp.ProcessPacket(b)
	if err != nil {
		t.Fatalf("point B returns the error %v, and a fingerprinter returns none here", err)
	}
	if len(bResults) != 0 {
		t.Fatalf("point B reports %d results, and the reference reports none: %v", len(bResults), bResults)
	}

	// Point C. The server Handshake packet fills the last server point.
	c := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	c.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("point C reports %d results, and the reference reports none", len(results))
	}

	// Point D. The client Handshake packet carries both values.
	d := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicHandshakePayload())
	d.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	dResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("point D returns the error %v, and a fingerprinter returns none here", err)
	}
	if len(dResults) != 2 {
		t.Fatalf("point D reports %d results, and the reference reports the server value and the client value: %v",
			len(dResults), dResults)
	}

	// The reference writes the server value first.
	// `wireshark/source/packet-ja4.c:1443` updates `hf_ja4ls`, and `:1449` updates `hf_ja4l`.
	if !strings.HasPrefix(dResults[0].Fingerprint, "JA4L-S=") {
		t.Errorf("point D reports %q first, and the reference reports the server value first",
			dResults[0].Fingerprint)
	}
	if !strings.HasPrefix(dResults[1].Fingerprint, "JA4L-C=") {
		t.Errorf("point D reports %q second, and the reference reports the client value second",
			dResults[1].Fingerprint)
	}

	// The server value keeps the point B measurement and the server time-to-live. The
	// frame moves, and the value does not.
	if dResults[0].Fingerprint != "JA4L-S=25000_64_quic" {
		t.Errorf("the server value reads %q, and the two points span 50 ms with a server time-to-live of 64",
			dResults[0].Fingerprint)
	}
	if dResults[1].Fingerprint != "JA4L-C=25000_55_quic" {
		t.Errorf("the client value reads %q, and the two points span 50 ms with a client time-to-live of 55",
			dResults[1].Fingerprint)
	}
}

// TestJA4LSReachesNoFrameWhenAQUICConnectionFillsNoPointD holds the second half of the
// rule. `wireshark/source/packet-ja4.c:1432-1451` reaches the emission only inside the
// branch that fills `timestamp_D`, so a connection that fills no point D publishes no
// server value.
func TestJA4LSReachesNoFrameWhenAQUICConnectionFillsNoPointD(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("point A reports %d results, and the reference reports none", len(results))
	}

	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	if results, _ := fp.ProcessPacket(b); len(results) != 0 {
		t.Fatalf("point B reports %d results, and the connection fills no point D", len(results))
	}

	c := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	c.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("point C reports %d results, and the connection fills no point D", len(results))
	}
}

// TestJA4LSStaysAtTheSynAckFrameOfATCPConnection bounds the change of issue #447 to a QUIC
// connection. The library emits the TCP server value on the SYN-ACK frame, and issue #447
// moves that frame nowhere. The TCP emission frame of the reference is a separate
// question, because `wireshark/source/packet-ja4.c:1339-1350` emits the TCP server value
// on the first server application packet after point D.
func TestJA4LSStaysAtTheSynAckFrameOfATCPConnection(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	syn := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, true, false)
	syn.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(syn); len(results) != 0 {
		t.Fatalf("the SYN frame reports %d results, and the reference reports none", len(results))
	}

	synAck := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, true, true)
	synAck.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	results, err := fp.ProcessPacket(synAck)
	if err != nil {
		t.Fatalf("the SYN-ACK frame returns the error %v, and a fingerprinter returns none here", err)
	}
	if len(results) != 1 || !strings.HasPrefix(results[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("the SYN-ACK frame reports %v, and the reference reports the server value there", results)
	}
}
