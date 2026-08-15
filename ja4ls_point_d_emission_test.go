package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"
)

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
