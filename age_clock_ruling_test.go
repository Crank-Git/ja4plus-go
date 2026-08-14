package ja4plus

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// The age clock of a bounded state table, under a packet timestamp that a sender chooses.
//
// **The maintainer ruled this question on 2026-08-14, and issue #577 holds the ruling.** The
// library accepts the property, and it documents it. No line of the age pass changes, and no
// clamp, no monotonic clock and no quorum reaches the tree. Each declined answer invents a
// rule that no FoxIO source states.
//
// The property: an age pass reads the capture timestamp of the packet that arrives. It
// compares that one timestamp against the last packet time of every key of the table. So one
// packet dated far in the future ages every key at once, and the pass removes all of them.
//
// Four sites of this repository hold it, and each test below drives one of them.
//
//   - `state_bound.go` `agedKeys`, which serves JA4, JA4L and JA4S.
//   - `ja4ssh.go` `evictAgedConnections`.
//   - `ja4ts.go` `evictAgedConnections`.
//   - `ja4h.go` `evictAgedRanges`.
//
// The port holds the same clock at `ja4plus/utils/state_table.py:414` of tag `v1.1.0`:
// `if now - entry[_LAST_SEEN] > self.max_connection_age:`. So a reader of either repository
// finds one property. `Crank-Git/ja4plus#618` carries the port half of this ruling.
//
// **Each test asserts the accepted behavior**, so a later change that hardens the clock fails
// it. That failure is the point: it sends the reader to issue #577, which is the reversal
// path.
//
// No vector of the FoxIO corpus reaches this value, so `.claude/rules/rulings.md`
// `## Where a ruling is recorded` puts the ruling in a test that builds the separating input.

// ageClockForwardJump is the forward jump that one crafted packet states.
//
// The ruling names no number. The value sits above every age bound of the tree, which is 600
// seconds at most, so one jump of this size ages every key of every table.
const ageClockForwardJump = 100 * 365 * 24 * time.Hour

// ageClockSeedPorts names the three connections that each test opens before the crafted
// packet arrives. Three keys prove that the pass reads every other key, and two do not
// separate "every other key" from "the one other key".
var ageClockSeedPorts = []uint16{1, 2, 3}

// ageClockHTTPRequest is the whole HTTP request that each segment of the JA4H test carries.
const ageClockHTTPRequest = "GET / HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n"

// TestOnePacketDatedFarInTheFutureEmptiesTheJA4FragmentTable drives `state_bound.go`
// `agedKeys` through the fragment table of JA4.
//
// JA4 runs the age pass on each datagram, so the crafted datagram reaches the pass at once.
func TestOnePacketDatedFarInTheFutureEmptiesTheJA4FragmentTable(t *testing.T) {
	fingerprinter := NewJA4()
	handshake := buildClientHelloPayload()[5:45]

	for index := range ageClockSeedPorts {
		packet := stateBoundQUICPacket(t, uint16(50000+index), stateBoundDCID(index), handshake,
			stateBoundStart())
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for seed connection %d", err, index)
		}
	}

	if got := len(fingerprinter.quicFragments); got != len(ageClockSeedPorts) {
		t.Fatalf("the fragment table holds %d connections before the crafted datagram, want %d",
			got, len(ageClockSeedPorts))
	}

	crafted := stateBoundQUICPacket(t, 50099, stateBoundDCID(99), handshake,
		stateBoundStart().Add(ageClockForwardJump))
	if _, err := fingerprinter.ProcessPacket(crafted); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the crafted datagram", err)
	}

	if got := len(fingerprinter.quicFragments); got != 1 {
		t.Errorf("the fragment table holds %d connections after the crafted datagram, and the ruling of #577 states 1",
			got)
	}
}

// TestOnePacketDatedFarInTheFutureEmptiesTheJA4SSHConnectionTable drives `ja4ssh.go`
// `evictAgedConnections`.
//
// JA4SSH runs the age pass every `sshEvictionInterval` packets, so the crafted connection
// sends the packets that reach the interval. Every packet of that connection carries the same
// crafted timestamp, and one such packet is what the pass reads.
func TestOnePacketDatedFarInTheFutureEmptiesTheJA4SSHConnectionTable(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	crafted := time.Unix(1700000000, 0).Add(ageClockForwardJump)

	for _, port := range ageClockSeedPorts {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024+port, time.Unix(1700000000, 0))); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for seed connection %d", err, port)
		}
	}

	if got := len(fingerprinter.connections); got != len(ageClockSeedPorts) {
		t.Fatalf("the state table holds %d connections before the crafted packet, want %d",
			got, len(ageClockSeedPorts))
	}

	for index := len(ageClockSeedPorts); index < sshEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(2000, crafted)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d of the crafted connection", err, index)
		}
	}

	for _, port := range ageClockSeedPorts {
		if _, held := fingerprinter.connections[sshBoundConnKey(1024+port)]; held {
			t.Errorf("the state table holds seed connection %d, and the ruling of #577 removes every key the crafted timestamp ages",
				port)
		}
	}

	if got := len(fingerprinter.connections); got != 1 {
		t.Errorf("the state table holds %d connections after the crafted packet, and the ruling of #577 states 1",
			got)
	}
}

// TestOnePacketDatedFarInTheFutureEmptiesTheJA4TSConnectionTable drives `ja4ts.go`
// `evictAgedConnections`.
//
// JA4TS runs the age pass on each SYN-ACK, so the crafted SYN-ACK reaches the pass at once.
func TestOnePacketDatedFarInTheFutureEmptiesTheJA4TSConnectionTable(t *testing.T) {
	fingerprinter := NewJA4TS()

	for _, port := range ageClockSeedPorts {
		packet := buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
			ja4tsServerPort, 20000+port, true, true, false, 65535, ja4tsOptions, ja4tsAt(0))
		_ = ja4tsValue(t, fingerprinter, packet)
	}

	if got := len(fingerprinter.connections); got != len(ageClockSeedPorts) {
		t.Fatalf("the table holds %d connections before the crafted SYN-ACK, want %d",
			got, len(ageClockSeedPorts))
	}

	crafted := buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
		ja4tsServerPort, 20099, true, true, false, 65535, ja4tsOptions,
		ja4tsAt(0).Add(ageClockForwardJump))
	_ = ja4tsValue(t, fingerprinter, crafted)

	if got := len(fingerprinter.connections); got != 1 {
		t.Errorf("the table holds %d connections after the crafted SYN-ACK, and the ruling of #577 states 1",
			got)
	}
}

// TestOnePacketDatedFarInTheFutureEmptiesTheJA4HRangeTable drives `ja4h.go`
// `evictAgedRanges`.
//
// JA4H runs the age pass on each segment, so the crafted segment reaches the pass at once.
func TestOnePacketDatedFarInTheFutureEmptiesTheJA4HRangeTable(t *testing.T) {
	fingerprinter := NewJA4H()
	start := time.Unix(1500000000, 0)

	for _, port := range ageClockSeedPorts {
		if _, err := fingerprinter.ProcessPacket(ageClockHTTPSegment(t, 54000+port, start)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for seed stream %d", err, port)
		}
	}

	if got := len(fingerprinter.ranges); got != len(ageClockSeedPorts) {
		t.Fatalf("the range table holds %d streams before the crafted segment, want %d",
			got, len(ageClockSeedPorts))
	}

	crafted := ageClockHTTPSegment(t, 54099, start.Add(ageClockForwardJump))
	if _, err := fingerprinter.ProcessPacket(crafted); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the crafted segment", err)
	}

	if got := len(fingerprinter.ranges); got != 1 {
		t.Errorf("the range table holds %d streams after the crafted segment, and the ruling of #577 states 1",
			got)
	}
}

// ageClockHTTPSegment returns one TCP segment that carries a whole HTTP request, at the client
// port and the capture timestamp the caller names.
//
// The client port names the stream, so a caller reaches a new range entry with a new port.
func ageClockHTTPSegment(t *testing.T, clientPort uint16, at time.Time) gopacket.Packet {
	t.Helper()

	packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
		clientPort, 8089, 1000, []byte(ageClockHTTPRequest))
	packet.Metadata().Timestamp = at

	return packet
}

// TestTheEntryBoundHoldsTheMemoryWhateverTheTimestampStates holds the mitigation that the
// ruling of #577 records beside the property.
//
// The entry bound reads the recency order and no timestamp, so a crafted timestamp moves no
// entry count above the bound. The loss of the age property is the tracked state, and it is
// never the memory.
//
// The call states an eviction interval of 1, so the age pass runs on every key. Each key
// carries a timestamp further ahead than the key before it, so the pass ages the whole table
// on every call. The count stays at the bound whatever the pass removes.
func TestTheEntryBoundHoldsTheMemoryWhateverTheTimestampStates(t *testing.T) {
	var table boundedKeys

	drop := func(string) {}

	for index := 0; index < 100; index++ {
		key := fmt.Sprintf("connection-%d", index)
		table.admit(key, time.Unix(1700000000, 0).Add(ageClockForwardJump*time.Duration(index)),
			4, 600*time.Second, 1, drop)

		if got := table.count(); got > 4 {
			t.Fatalf("the table holds %d keys after key %d, and the entry bound of this call states 4 at most",
				got, index)
		}
	}
}
