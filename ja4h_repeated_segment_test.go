package ja4plus

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// The bytes of frame 6 and frame 15 of `CVE-2018-6794.pcap`. The two frames carry the same
// payload on the same four-tuple, and `docs/audit/ja4h-deviation-cluster.md` `## Cause 3`
// records the repeat. `testdata/foxio/wireshark/CVE-2018-6794.pcap.json` publishes a JA4H
// value for frame 6 and for frame 16, and for no other frame of the capture.
const ja4hRepeatedRequest = "GET / HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n"

// ja4hSegmentAt builds one TCP segment of the repeat test, at the sequence number and the
// packet timestamp the caller states.
//
// The age pass reads the packet timestamp, so every packet of these tests carries one.
func ja4hSegmentAt(t *testing.T, seq uint32, offsetSeconds int, payload string) gopacket.Packet {
	t.Helper()

	packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
		54321, 8089, seq, []byte(payload))
	packet.Metadata().Timestamp = time.Unix(int64(1500000000+offsetSeconds), 0)
	return packet
}

// TestJA4H_ProducesOneValueForARepeatedTCPSegment holds the repair of #446.
//
// The reassembler drops the stream after each value, so the repeat rebuilt the same request
// and produced a second value. The guard fails when a reader removes it, because the second
// call then returns one result.
func TestJA4H_ProducesOneValueForARepeatedTCPSegment(t *testing.T) {
	fingerprinter := NewJA4H()

	first, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("the first segment produced %d values, and the reference holds 1", len(first))
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the repeated segment returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the repeated segment produced %d values, and the reference holds 0: %q",
			len(repeat), repeat[0].Fingerprint)
	}
}

// TestJA4H_ProducesOneValueForARepeatOfAReassembledRequest holds the repair of #446 on the
// path that reads more than one segment.
//
// The consumed range covers the whole buffer, so a repeat of the first segment of a
// reassembled request reaches the guard too.
func TestJA4H_ProducesOneValueForARepeatOfAReassembledRequest(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hRepeatedRequest[:10]
	tail := ja4hRepeatedRequest[10:]

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, head)); err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}

	assembled, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(assembled) != 1 {
		t.Fatalf("the reassembled request produced %d values, and the reference holds 1",
			len(assembled))
	}

	// The two segments repeat in the order they first arrived, because a repeat of the first
	// segment alone rebuilds no request and reaches no emission.
	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 2, head)); err != nil {
		t.Fatalf("the first repeated segment returned an error: %v", err)
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 3, tail))
	if err != nil {
		t.Fatalf("the second repeated segment returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the repeated request produced %d values, and the reference holds 0", len(repeat))
	}
}

// TestJA4H_ReadsASecondRequestOfTheSameStream holds the limit of the guard of #446.
//
// A client that keeps the connection open sends a second request at a higher sequence
// number. That request lies outside the consumed range, and it produces its own value.
func TestJA4H_ReadsASecondRequestOfTheSameStream(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first request returned an error: %v", err)
	}

	next := uint32(1000 + len(ja4hRepeatedRequest))
	second, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, next, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the second request returned an error: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("the second request produced %d values, and the reference holds 1", len(second))
	}
}

// TestJA4H_ReadsTheFirstRequestOfAReusedFourTuple holds the second limit of the guard.
//
// A second connection reuses the address pair and the port pair, and it starts at its own
// initial sequence number. That number sits below the stored one about half the time. So a
// guard that reads the end alone loses the first request of the second connection.
// `ja4plus/fingerprinters/ja4h.py:213-220` states the same limit.
func TestJA4H_ReadsTheFirstRequestOfAReusedFourTuple(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 900000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first connection returned an error: %v", err)
	}

	reused, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 500, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the second connection returned an error: %v", err)
	}
	if len(reused) != 1 {
		t.Fatalf("the second connection produced %d values, and the reference holds 1", len(reused))
	}
}

// TestJA4H_RemovesTheConsumedRangeOfACleanedConnection holds the removal path of #446.
//
// `.claude/rules/concurrency.md` states that a new state map has a removal path in
// `CleanupConnection` and in `Reset`. The repeat produces a value again after each one,
// because the entry that suppresses it is gone.
func TestJA4H_RemovesTheConsumedRangeOfACleanedConnection(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		remove func(*JA4HFingerprinter)
	}{
		{
			name: "CleanupConnection",
			remove: func(f *JA4HFingerprinter) {
				f.CleanupConnection("192.168.235.137", 54321, "192.168.235.136", 8089, "tcp")
			},
		},
		{
			name:   "Reset",
			remove: func(f *JA4HFingerprinter) { f.Reset() },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := NewJA4H()

			if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
				t.Fatalf("the first segment returned an error: %v", err)
			}
			if length := len(fingerprinter.ranges); length != 1 {
				t.Fatalf("the range table holds %d entries, and one segment states 1", length)
			}

			testCase.remove(fingerprinter)

			if length := len(fingerprinter.ranges); length != 0 {
				t.Fatalf("the range table holds %d entries after the removal, and the rule states 0",
					length)
			}
		})
	}
}

// TestJA4H_HoldsTheRangeTableAtTheStreamBound holds the entry bound of #446.
//
// #432 records nine state tables that reach no bound, and this table is not the tenth. The
// insert that reaches the bound removes the entry that received no segment for the longest
// time.
func TestJA4H_HoldsTheRangeTableAtTheStreamBound(t *testing.T) {
	fingerprinter := NewJA4H()

	for index := 0; index < ja4hMaxStreams+50; index++ {
		packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
			uint16(20000+index), 8089, 1000, []byte(ja4hRepeatedRequest))
		packet.Metadata().Timestamp = time.Unix(int64(1500000000+index), 0)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("stream %d returned an error: %v", index, err)
		}
	}

	if length := len(fingerprinter.ranges); length > ja4hMaxStreams {
		t.Fatalf("the range table holds %d entries, and the bound states %d at most",
			length, ja4hMaxStreams)
	}
}

// TestJA4H_ProducesOneValueForARepeatThatTheStreamBoundSeparates holds the second repair of
// #446.
//
// The range table and the reassembler each hold a bound of their own, and the fast path
// fills the range table alone. So the range table can reach its bound while the reassembler
// still holds the buffer of an earlier stream. The entry that leaves therefore takes the
// buffer with it, and the two tables name one set of streams.
func TestJA4H_ProducesOneValueForARepeatThatTheStreamBoundSeparates(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hRepeatedRequest[:10]
	tail := ja4hRepeatedRequest[10:]
	values := 0

	sendToTheSlowStream := func(offsetSeconds int, seq uint32, payload string) {
		t.Helper()

		results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, seq, offsetSeconds, payload))
		if err != nil {
			t.Fatalf("the slow stream returned an error: %v", err)
		}
		values += len(results)
	}

	sendToTheSlowStream(0, 1000, head)

	// Each of these streams reaches the fast path, so each one writes a range entry and no
	// buffer. The count passes the entry bound, so the entry of the slow stream leaves.
	for index := 0; index < ja4hMaxStreams+10; index++ {
		packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
			uint16(30000+index), 8089, 1000, []byte(ja4hRepeatedRequest))
		packet.Metadata().Timestamp = time.Unix(int64(1500000001+index), 0)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("stream %d returned an error: %v", index, err)
		}
	}

	sendToTheSlowStream(2000, uint32(1000+len(head)), tail)
	sendToTheSlowStream(2001, 1000, head)
	sendToTheSlowStream(2002, uint32(1000+len(head)), tail)

	if values > 1 {
		t.Fatalf("the slow stream produced %d values for one request, and the reference holds 1 at most",
			values)
	}
}

// TestJA4H_RemovesARangeThatReachesTheMaximumAge holds the age bound of #446.
//
// The pass reads the packet timestamp, and never the wall clock. A capture replays faster
// than the wall clock, so a wall clock removes state that the capture still needs.
func TestJA4H_RemovesARangeThatReachesTheMaximumAge(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}

	aged := int(ja4hMaxStreamAge/time.Second) + 1
	other := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
		54322, 8089, 1000, []byte(ja4hRepeatedRequest))
	other.Metadata().Timestamp = time.Unix(int64(1500000000+aged), 0)
	if _, err := fingerprinter.ProcessPacket(other); err != nil {
		t.Fatalf("the later segment returned an error: %v", err)
	}

	if _, present := fingerprinter.ranges["192.168.235.137:54321->192.168.235.136:8089"]; present {
		t.Fatal("the range table holds the aged entry, and the age bound states no entry")
	}
}
