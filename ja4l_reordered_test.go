package ja4plus

import (
	"net"
	"testing"
	"time"
)

// TestJA4LReportsNoServerValueOnAReorderedCapture records what this library does today when
// a capture delivers the SYN-ACK before the SYN. It builds the packet sequence that separates
// the two packet orders, because no FoxIO vector reaches it.
//
// This test asserts the present behavior, and it states no rule. Issue #212 holds an open
// question that only the maintainer settles, so this test fails when a repair lands without
// that ruling. `.claude/rules/rulings.md` names the stop condition, because the three FoxIO
// reference implementations disagree on a reordered capture.
//
// The three references at the commit in `testdata/foxio.pin` behave as follows.
// `wireshark/source/packet-ja4.c:1346` measures `timestamp_B` against `timestamp_A` and
// reports the value on a later application packet. `python/ja4.py:154` reads
// `if 'B' in conn and 'A' in conn` and reports the value on the bare ACK at
// `python/ja4.py:572`. `zeek/ja4l/main.zeek:152-156` returns before it assigns `ja4l_s` when
// the interval is below zero, and `zeek/ja4l/main.zeek:7` states
// `# NOTE: JA4L can not work when traffic is out of order`.
//
// The Python port at `Crank-Git/ja4plus` reports the value on the SYN, at
// `ja4plus/fingerprinters/ja4l.py:442-449`. No FoxIO reference reports it there.
func TestJA4LReportsNoServerValueOnAReorderedCapture(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const (
		clientISN uint32 = 1000
		serverISN uint32 = 2000
	)

	// The capture delivers the SYN-ACK first. The connection holds point B alone, so this
	// packet reports no value.
	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 58, 443, 12345, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(12504 * time.Microsecond)
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SYN-ACK: expected no results, got %v", results)
	}

	// The capture delivers the SYN second, and it carries the earlier timestamp. The packet
	// fills point A, and the connection now holds both server points. This library reports no
	// value here today.
	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	results, err = fp.ProcessPacket(synPkt)
	if err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SYN: expected no results, got %v", results)
	}
}

// TestJA4LReportsOnlyTheClientValueOnTheBareACKOfAReorderedCapture records the gap that
// issue #212 measures against `python/ja4.py`.
//
// `python/ja4.py:572` calls `calculate_ja4_latency` on the bare ACK, and
// `python/ja4.py:154-157` reports JA4L-S there whenever the connection holds both server
// points. The packet order moves neither test. This library reports the client value alone on
// that packet, so a reordered capture reaches no server value at all.
//
// This test asserts the present behavior, and it states no rule. Issue #212 holds the open
// question.
func TestJA4LReportsOnlyTheClientValueOnTheBareACKOfAReorderedCapture(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const (
		clientISN uint32 = 1000
		serverISN uint32 = 2000
	)

	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 58, 443, 12345, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(12504 * time.Microsecond)
	if _, err := fp.ProcessPacket(synAckPkt); err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}

	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	if _, err := fp.ProcessPacket(synPkt); err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}

	// The bare ACK completes the handshake. It reports the client value, and it reports no
	// server value.
	ackPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, false, true, clientISN+1, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(24000 * time.Microsecond)
	results, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("bare ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=5748_64" {
		t.Errorf("bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=5748_64")
	}
}
