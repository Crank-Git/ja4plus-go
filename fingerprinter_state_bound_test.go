package ja4plus

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// The state bound of issue #565. `JA4Fingerprinter`, `JA4LFingerprinter` and
// `JA4SFingerprinter` hold eight maps between them, and no one of the eight reached a bound
// before this change.
//
// Every packet is untrusted input. A sender opens one entry of each map at the cost of one
// datagram, so an unbounded map is a memory-exhaustion path.
//
// `.claude/rules/parity.md` rule 2 gives the port the interface where this project shipped
// none, and no FoxIO source addresses a state table. The port bounds the same three
// fingerprinters, and `TestJA4HoldsThePortValuesOfTheQUICFragmentBound`,
// `TestJA4LHoldsThePortValuesOfTheStateBound` and
// `TestJA4SHoldsThePortValuesOfTheStateBound` read the six values against it.
//
// Each other test below drives a bound with packets, and it reads the entry count of every
// map the bound reaches. A test that reads a constant alone proves no eviction.

// stateBoundClientIP names the client of every untunneled connection of these tests.
const stateBoundClientIP = "192.168.1.100"

// stateBoundServerIP names the server of every untunneled connection of these tests.
const stateBoundServerIP = "10.0.0.1"

// stateBoundBasePort is the lowest client port that a test of the entry bound uses.
//
// A test of the entry bound opens 10001 connections, so it reads 10001 consecutive ports.
// `(UDPPort).LayerType` of `github.com/gopacket/gopacket@v1.6.1/layers/ports.go` maps 22 port
// numbers to a layer type of their own, and gopacket then decodes the datagram as that
// protocol. Port 4789 is VXLAN and port 6081 is Geneve, so the range 1024 to 11024 opens two
// fewer connections than the loop counts. The range 10000 to 20000 holds no such port.
const stateBoundBasePort = 10000

// stateBoundStart is the capture timestamp of the first packet of every test below.
// The eviction clock reads the capture timestamp, so a test states every time it needs.
func stateBoundStart() time.Time {
	return time.Unix(1700000000, 0)
}

// stateBoundDCID returns the destination connection identifier of one QUIC connection.
// RFC 9000 Section 7.2 states that a client Initial carries at least 8 bytes.
// The Initial keys read this value, so each connection reads its own identifier.
func stateBoundDCID(index int) []byte {
	return []byte{
		0x83, 0x94, 0xc8, 0xf0,
		byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index),
	}
}

// stateBoundQUICPacket returns one plain QUIC client Initial datagram at the named time.
// The client port names the JA4S connection, and the connection identifier names the JA4
// connection. So a caller reaches a new entry with a new value of either one.
func stateBoundQUICPacket(
	t *testing.T, clientPort uint16, dcid []byte, handshake []byte, at time.Time,
) gopacket.Packet {
	t.Helper()

	initial := buildQUICClientInitial(t, dcid, []byte{0x01, 0x02, 0x03, 0x04}, handshake)
	packet := buildUDPPacketWithIPs(t,
		net.ParseIP(stateBoundClientIP), net.ParseIP(stateBoundServerIP), 64, clientPort, 443, initial)
	packet.Metadata().Timestamp = at

	return packet
}

// stateBoundJA4LPacket returns one QUIC long-header datagram that opens a JA4L connection.
// The client port names the connection, so a caller reaches a new connection with a new port.
func stateBoundJA4LPacket(t *testing.T, clientPort uint16, at time.Time) gopacket.Packet {
	t.Helper()

	packet := buildUDPPacketWithIPs(t,
		net.ParseIP(stateBoundClientIP), net.ParseIP(stateBoundServerIP), 64,
		clientPort, quicPort, quicLongHeaderPayload())
	packet.Metadata().Timestamp = at

	return packet
}

// stateBoundJA4SConnKey returns the JA4S state key of the connection the client port names.
func stateBoundJA4SConnKey(clientPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:443", stateBoundClientIP, clientPort, stateBoundServerIP)
}

// TestJA4HoldsThePortValuesOfTheQUICFragmentBound reads the three JA4 values against the port.
// The port bounds the QUIC fragment table below the default of its state table.
// A sender names a new connection identifier on each datagram at no cost.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface, so a change to
// one of the three values is a parity change.
func TestJA4HoldsThePortValuesOfTheQUICFragmentBound(t *testing.T) {
	if maxJA4QUICFragmentConnections != 1000 {
		t.Errorf("the entry bound is %d, and `ja4plus/fingerprinters/ja4.py:26` states 1000",
			maxJA4QUICFragmentConnections)
	}

	if ja4QUICFragmentAge != 30*time.Second {
		t.Errorf("the age bound is %v, and `ja4plus/fingerprinters/ja4.py:31` states 30 seconds",
			ja4QUICFragmentAge)
	}

	if ja4QUICFragmentEvictionInterval != 1 {
		t.Errorf("the eviction interval is %d, and `ja4plus/fingerprinters/ja4.py:47` states 1",
			ja4QUICFragmentEvictionInterval)
	}
}

// TestJA4LHoldsThePortValuesOfTheStateBound reads the three JA4L values against the port.
// `ja4plus/fingerprinters/ja4l.py:100` and `ja4plus/fingerprinters/ja4l.py:104` each build a
// `BoundedStateTable` with no argument, so the two maps hold the default of that class.
func TestJA4LHoldsThePortValuesOfTheStateBound(t *testing.T) {
	if maxJA4LConnections != 10000 {
		t.Errorf("the entry bound is %d, and `ja4plus/utils/state_table.py:52` states 10000",
			maxJA4LConnections)
	}

	if ja4lConnectionAge != 600*time.Second {
		t.Errorf("the age bound is %v, and `ja4plus/utils/state_table.py:58` states 600 seconds",
			ja4lConnectionAge)
	}

	if ja4lEvictionInterval != 1000 {
		t.Errorf("the eviction interval is %d, and `ja4plus/utils/state_table.py:62` states 1000",
			ja4lEvictionInterval)
	}
}

// TestJA4SHoldsThePortValuesOfTheStateBound reads the three JA4S values against the port.
// `ja4plus/fingerprinters/ja4s.py:58` builds a `BoundedStateTable` with no argument, and the
// comment above it states that the connection identifier outlives the fragments.
func TestJA4SHoldsThePortValuesOfTheStateBound(t *testing.T) {
	if maxJA4SConnections != 10000 {
		t.Errorf("the entry bound is %d, and `ja4plus/utils/state_table.py:52` states 10000",
			maxJA4SConnections)
	}

	if ja4sConnectionAge != 600*time.Second {
		t.Errorf("the age bound is %v, and `ja4plus/utils/state_table.py:58` states 600 seconds",
			ja4sConnectionAge)
	}

	if ja4sEvictionInterval != 1000 {
		t.Errorf("the eviction interval is %d, and `ja4plus/utils/state_table.py:62` states 1000",
			ja4sEvictionInterval)
	}
}

// TestJA4RemovesTheLeastRecentConnectionAtTheEntryBound drives the JA4 entry bound with one
// connection more than the bound holds.
//
// The three maps of the fingerprinter name one set of connections, so the test reads all
// three. A bound that removes one map and leaves its partner moves the leak, and it does not
// close it.
func TestJA4RemovesTheLeastRecentConnectionAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4()
	at := stateBoundStart()

	// The CRYPTO frame carries 40 bytes of the handshake message, so no packet completes a
	// client hello. A completed client hello removes its own connection, and the table would
	// then never reach the bound.
	handshake := buildClientHelloPayload()[5:45]

	for index := 0; index <= maxJA4QUICFragmentConnections; index++ {
		packet := stateBoundQUICPacket(t, 50000, stateBoundDCID(index), handshake, at)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	if got := len(fingerprinter.quicFragments); got != maxJA4QUICFragmentConnections {
		t.Fatalf("the fragment table holds %d entries, and the entry bound holds %d",
			got, maxJA4QUICFragmentConnections)
	}
	if got := len(fingerprinter.dcidToTuple); got != maxJA4QUICFragmentConnections {
		t.Errorf("the connection identifier table holds %d entries, and the entry bound holds %d",
			got, maxJA4QUICFragmentConnections)
	}
	if got := len(fingerprinter.dcidToReported); got != maxJA4QUICFragmentConnections {
		t.Errorf("the index holds %d entries, and the entry bound holds %d",
			got, maxJA4QUICFragmentConnections)
	}

	first := fmt.Sprintf("%x", stateBoundDCID(0))
	if _, held := fingerprinter.quicFragments[first]; held {
		t.Errorf("the fragment table holds the first connection, and the entry bound removes the least recent one")
	}
	if _, held := fingerprinter.dcidToTuple[first]; held {
		t.Errorf("the connection identifier table holds the first connection, and one removal path serves the three maps")
	}
	if _, held := fingerprinter.dcidToReported[first]; held {
		t.Errorf("the index holds the first connection, and one removal path serves the three maps")
	}

	last := fmt.Sprintf("%x", stateBoundDCID(maxJA4QUICFragmentConnections))
	if _, held := fingerprinter.quicFragments[last]; !held {
		t.Errorf("the fragment table holds no last connection, and the packet that crosses the bound opens one")
	}
}

// TestJA4RemovesTheQUICFragmentsOlderThanTheAgeBound drives the JA4 age bound with the packet
// timestamp. The eviction interval is 1, so the second packet runs the age pass.
func TestJA4RemovesTheQUICFragmentsOlderThanTheAgeBound(t *testing.T) {
	fingerprinter := ja4OfTwoQUICConnections(t, stateBoundStart(),
		stateBoundStart().Add(ja4QUICFragmentAge+time.Second))

	first := fmt.Sprintf("%x", stateBoundDCID(0))
	if _, held := fingerprinter.quicFragments[first]; held {
		t.Errorf("the fragment table holds a connection of age 31 seconds, and the age bound is 30 seconds")
	}
	if _, held := fingerprinter.dcidToTuple[first]; held {
		t.Errorf("the connection identifier table holds the aged connection, and one removal path serves the three maps")
	}
	if _, held := fingerprinter.dcidToReported[first]; held {
		t.Errorf("the index holds the aged connection, and one removal path serves the three maps")
	}

	if got := len(fingerprinter.quicFragments); got != 1 {
		t.Errorf("the fragment table holds %d connections, and the age pass removes 1 of the 2", got)
	}
}

// TestJA4KeepsTheQUICFragmentsInsideTheAgeBound holds the other half of the JA4 age bound.
// A connection of age 29 seconds stays, so the pass removes no connection inside the bound.
func TestJA4KeepsTheQUICFragmentsInsideTheAgeBound(t *testing.T) {
	fingerprinter := ja4OfTwoQUICConnections(t, stateBoundStart(),
		stateBoundStart().Add(ja4QUICFragmentAge-time.Second))

	if got := len(fingerprinter.quicFragments); got != 2 {
		t.Errorf("the fragment table holds %d connections, and the age pass removes no connection inside the bound",
			got)
	}
	if got := len(fingerprinter.dcidToTuple); got != 2 {
		t.Errorf("the connection identifier table holds %d connections, and the age pass removes none", got)
	}
}

// ja4OfTwoQUICConnections returns a JA4 fingerprinter of two incomplete QUIC handshakes.
// The first connection reads one datagram at the start time, and the second reads one
// datagram at the later time. The second datagram runs the age pass.
func ja4OfTwoQUICConnections(t *testing.T, start time.Time, later time.Time) *JA4Fingerprinter {
	t.Helper()

	fingerprinter := NewJA4()
	handshake := buildClientHelloPayload()[5:45]

	for index, at := range []time.Time{start, later} {
		packet := stateBoundQUICPacket(t, uint16(50000+index), stateBoundDCID(index), handshake, at)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	return fingerprinter
}

// TestJA4LRemovesTheLeastRecentConnectionAtTheEntryBound drives the JA4L entry bound with one
// connection more than the bound holds.
//
// The index holds one entry for each connection, so the two maps hold one count. A bound that
// removes the connection and leaves the index entry moves the leak of issue #193 into the
// eviction path.
func TestJA4LRemovesTheLeastRecentConnectionAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4L()
	at := stateBoundStart()

	for index := 0; index <= maxJA4LConnections; index++ {
		packet := stateBoundJA4LPacket(t, uint16(stateBoundBasePort+index), at)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	if got := len(fingerprinter.connections); got != maxJA4LConnections {
		t.Fatalf("the state table holds %d connections, and the entry bound holds %d",
			got, maxJA4LConnections)
	}
	if got := len(fingerprinter.groupingKeys); got != maxJA4LConnections {
		t.Errorf("the index holds %d entries, and the entry bound removes the index entry of every removed connection",
			got)
	}

	firstKey, _ := fingerprinter.normalizeKey("udp", stateBoundClientIP, stateBoundBasePort, stateBoundServerIP, quicPort)
	if _, held := fingerprinter.connections[firstKey]; held {
		t.Errorf("the state table holds the first connection, and the entry bound removes the least recent one")
	}
	if _, held := fingerprinter.groupingKeys[firstKey]; held {
		t.Errorf("the index holds the first connection, and one removal path serves the two maps")
	}

	lastKey, _ := fingerprinter.normalizeKey("udp",
		stateBoundClientIP, uint16(stateBoundBasePort+maxJA4LConnections), stateBoundServerIP, quicPort)
	if _, held := fingerprinter.connections[lastKey]; !held {
		t.Errorf("the state table holds no last connection, and the packet that crosses the bound opens one")
	}
}

// TestJA4LRemovesTheIndexEntryOfATunneledConnectionAtTheAgeBound holds the trap of this
// issue. A tunneled connection groups under its inner address pair, and the index holds its
// outer address pair, so the two keys differ. An eviction that removes the connection first
// can then reach no index entry, and it leaks the partner.
//
// The removal reads the reported pair of the connection, which is why `dropConnection` exists.
// Issue #193 records the same leak on the removal path of a caller.
func TestJA4LRemovesTheIndexEntryOfATunneledConnectionAtTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4L()
	start := stateBoundStart()

	tunneled := buildVXLANTCPSYNPacket(t)
	tunneled.Metadata().Timestamp = start
	if _, err := fingerprinter.ProcessPacket(tunneled); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the tunneled connection", err)
	}

	if len(fingerprinter.connections) != 1 || len(fingerprinter.groupingKeys) != 1 {
		t.Fatalf("the fingerprinter holds %d connections and %d index entries, and the packet opens one of each",
			len(fingerprinter.connections), len(fingerprinter.groupingKeys))
	}

	groupingKey, _ := fingerprinter.normalizeKey("tcp",
		tunnelInnerSrcIP, tunnelInnerSrcPort, tunnelInnerDstIP, tunnelInnerDstPort)
	reportedKey, _ := fingerprinter.normalizeKey("tcp",
		tunnelOuterSrcIP, tunnelInnerSrcPort, tunnelOuterDstIP, tunnelInnerDstPort)
	if groupingKey == reportedKey {
		t.Fatalf("the grouping key and the reported key hold one value %q, and the test needs two", groupingKey)
	}

	// The age pass runs on the eviction interval, so the second connection carries the packets
	// that reach it.
	later := start.Add(ja4lConnectionAge + time.Second)
	for index := 1; index < ja4lEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(stateBoundJA4LPacket(t, (stateBoundBasePort + 1), later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d", err, index)
		}
	}

	if _, held := fingerprinter.connections[groupingKey]; held {
		t.Errorf("the state table holds a connection of age 601 seconds, and the age bound is 600 seconds")
	}
	if _, held := fingerprinter.groupingKeys[reportedKey]; held {
		t.Errorf("the index holds the reported key of an evicted connection, and the eviction leaks its partner")
	}
	if got := len(fingerprinter.groupingKeys); got != 1 {
		t.Errorf("the index holds %d entries, and the two maps hold one count", got)
	}
}

// TestJA4LKeepsAConnectionInsideTheAgeBound holds the other half of the JA4L age bound.
func TestJA4LKeepsAConnectionInsideTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4L()
	start := stateBoundStart()

	if _, err := fingerprinter.ProcessPacket(stateBoundJA4LPacket(t, stateBoundBasePort, start)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first connection", err)
	}

	later := start.Add(ja4lConnectionAge - time.Second)
	for index := 1; index < ja4lEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(stateBoundJA4LPacket(t, (stateBoundBasePort + 1), later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d", err, index)
		}
	}

	if got := len(fingerprinter.connections); got != 2 {
		t.Errorf("the state table holds %d connections, and the age pass removes no connection inside the bound",
			got)
	}
	if got := len(fingerprinter.groupingKeys); got != 2 {
		t.Errorf("the index holds %d entries, and the two maps hold one count", got)
	}
}

// TestJA4SRemovesTheLeastRecentConnectionAtTheEntryBound drives the JA4S entry bound with one
// connection more than the bound holds. The three maps name one set of connections, so the
// test reads all three.
func TestJA4SRemovesTheLeastRecentConnectionAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4S()
	at := stateBoundStart()

	// One connection identifier serves every connection, because JA4S keys its state with the
	// address pair. The client port therefore names the connection.
	handshake := buildClientHelloPayload()[5:]
	initial := buildQUICClientInitial(t, stateBoundDCID(0), []byte{0x01, 0x02, 0x03, 0x04}, handshake)

	for index := 0; index <= maxJA4SConnections; index++ {
		packet := buildUDPPacketWithIPs(t,
			net.ParseIP(stateBoundClientIP), net.ParseIP(stateBoundServerIP), 64,
			uint16(stateBoundBasePort+index), 443, initial)
		packet.Metadata().Timestamp = at

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	if got := len(fingerprinter.quicDCIDs); got != maxJA4SConnections {
		t.Fatalf("the connection identifier table holds %d entries, and the entry bound holds %d",
			got, maxJA4SConnections)
	}
	if got := len(fingerprinter.groupingKeys); got != maxJA4SConnections {
		t.Errorf("the grouping key index holds %d entries, and one removal path serves the three maps", got)
	}
	if got := len(fingerprinter.reportedKeys); got != maxJA4SConnections {
		t.Errorf("the reported key index holds %d entries, and one removal path serves the three maps", got)
	}

	first := stateBoundJA4SConnKey(stateBoundBasePort)
	if _, held := fingerprinter.quicDCIDs[first]; held {
		t.Errorf("the connection identifier table holds the first connection, and the entry bound removes the least recent one")
	}
	if _, held := fingerprinter.reportedKeys[first]; held {
		t.Errorf("the reported key index holds the first connection, and one removal path serves the three maps")
	}
	if _, held := fingerprinter.groupingKeys[first]; held {
		t.Errorf("the grouping key index holds the first connection, and one removal path serves the three maps")
	}

	last := stateBoundJA4SConnKey(uint16(stateBoundBasePort + maxJA4SConnections))
	if _, held := fingerprinter.quicDCIDs[last]; !held {
		t.Errorf("the connection identifier table holds no last connection, and the packet that crosses the bound opens one")
	}
}

// TestJA4SRemovesAConnectionOlderThanTheAgeBound drives the JA4S age bound with the packet
// timestamp. The age pass runs on the eviction interval, so the second connection carries the
// packets that reach it.
func TestJA4SRemovesAConnectionOlderThanTheAgeBound(t *testing.T) {
	start := stateBoundStart()
	fingerprinter := ja4sOfTwoQUICConnections(t, start, start.Add(ja4sConnectionAge+time.Second))

	first := stateBoundJA4SConnKey(stateBoundBasePort)
	if _, held := fingerprinter.quicDCIDs[first]; held {
		t.Errorf("the connection identifier table holds a connection of age 601 seconds, and the age bound is 600 seconds")
	}
	if _, held := fingerprinter.reportedKeys[first]; held {
		t.Errorf("the reported key index holds the aged connection, and one removal path serves the three maps")
	}

	if got := len(fingerprinter.groupingKeys); got != 1 {
		t.Errorf("the grouping key index holds %d entries, and the age pass removes 1 of the 2", got)
	}
}

// TestJA4SKeepsAConnectionInsideTheAgeBound holds the other half of the JA4S age bound.
func TestJA4SKeepsAConnectionInsideTheAgeBound(t *testing.T) {
	start := stateBoundStart()
	fingerprinter := ja4sOfTwoQUICConnections(t, start, start.Add(ja4sConnectionAge-time.Second))

	if got := len(fingerprinter.quicDCIDs); got != 2 {
		t.Errorf("the connection identifier table holds %d connections, and the age pass removes no connection inside the bound",
			got)
	}
	if got := len(fingerprinter.groupingKeys); got != 2 {
		t.Errorf("the grouping key index holds %d entries, and the age pass removes none", got)
	}
}

// ja4sOfTwoQUICConnections returns a JA4S fingerprinter of two connections.
// The first connection reads one datagram at the start time. The second connection reads the
// eviction interval of datagrams at the later time, and the last one runs the age pass.
func ja4sOfTwoQUICConnections(t *testing.T, start time.Time, later time.Time) *JA4SFingerprinter {
	t.Helper()

	fingerprinter := NewJA4S()
	handshake := buildClientHelloPayload()[5:]
	initial := buildQUICClientInitial(t, stateBoundDCID(0), []byte{0x01, 0x02, 0x03, 0x04}, handshake)

	process := func(clientPort uint16, at time.Time, index int) {
		packet := buildUDPPacketWithIPs(t,
			net.ParseIP(stateBoundClientIP), net.ParseIP(stateBoundServerIP), 64, clientPort, 443, initial)
		packet.Metadata().Timestamp = at

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d", err, index)
		}
	}

	process(stateBoundBasePort, start, 0)

	for index := 1; index < ja4sEvictionInterval; index++ {
		process((stateBoundBasePort + 1), later, index)
	}

	return fingerprinter
}

// TestResetEmptiesTheRecencyOrderOfEveryBoundedFingerprinter holds the removal path of Reset.
// A recency order that keeps a removed key removes the wrong key at the entry bound.
func TestResetEmptiesTheRecencyOrderOfEveryBoundedFingerprinter(t *testing.T) {
	at := stateBoundStart()

	ja4 := NewJA4()
	if _, err := ja4.ProcessPacket(
		stateBoundQUICPacket(t, 50000, stateBoundDCID(0), buildClientHelloPayload()[5:45], at)); err != nil {
		t.Fatalf("the JA4 fingerprinter returns the error %v", err)
	}
	ja4.Reset()
	if got := ja4.keys.count(); got != 0 {
		t.Errorf("the JA4 recency order holds %d keys after Reset, and the three maps hold none", got)
	}

	ja4l := NewJA4L()
	if _, err := ja4l.ProcessPacket(stateBoundJA4LPacket(t, stateBoundBasePort, at)); err != nil {
		t.Fatalf("the JA4L fingerprinter returns the error %v", err)
	}
	ja4l.Reset()
	if got := ja4l.keys.count(); got != 0 {
		t.Errorf("the JA4L recency order holds %d keys after Reset, and the two maps hold none", got)
	}

	ja4s := NewJA4S()
	if _, err := ja4s.ProcessPacket(
		stateBoundQUICPacket(t, stateBoundBasePort, stateBoundDCID(0), buildClientHelloPayload()[5:], at)); err != nil {
		t.Fatalf("the JA4S fingerprinter returns the error %v", err)
	}
	ja4s.Reset()
	if got := ja4s.keys.count(); got != 0 {
		t.Errorf("the JA4S recency order holds %d keys after Reset, and the three maps hold none", got)
	}
}

// TestCleanupConnectionEmptiesTheRecencyOrderOfEveryBoundedFingerprinter holds the removal
// path of CleanupConnection. The recency order and the state maps name one set of keys.
func TestCleanupConnectionEmptiesTheRecencyOrderOfEveryBoundedFingerprinter(t *testing.T) {
	at := stateBoundStart()

	ja4 := NewJA4()
	if _, err := ja4.ProcessPacket(
		stateBoundQUICPacket(t, 50000, stateBoundDCID(0), buildClientHelloPayload()[5:45], at)); err != nil {
		t.Fatalf("the JA4 fingerprinter returns the error %v", err)
	}
	ja4.CleanupConnection(stateBoundClientIP, 50000, stateBoundServerIP, 443, "udp")
	if got := ja4.keys.count(); got != 0 {
		t.Errorf("the JA4 recency order holds %d keys after CleanupConnection, and the three maps hold none", got)
	}

	ja4l := NewJA4L()
	if _, err := ja4l.ProcessPacket(stateBoundJA4LPacket(t, stateBoundBasePort, at)); err != nil {
		t.Fatalf("the JA4L fingerprinter returns the error %v", err)
	}
	ja4l.CleanupConnection(stateBoundClientIP, stateBoundBasePort, stateBoundServerIP, quicPort, "udp")
	if got := ja4l.keys.count(); got != 0 {
		t.Errorf("the JA4L recency order holds %d keys after CleanupConnection, and the two maps hold none", got)
	}

	ja4s := NewJA4S()
	if _, err := ja4s.ProcessPacket(
		stateBoundQUICPacket(t, stateBoundBasePort, stateBoundDCID(0), buildClientHelloPayload()[5:], at)); err != nil {
		t.Fatalf("the JA4S fingerprinter returns the error %v", err)
	}
	ja4s.CleanupConnection(stateBoundClientIP, stateBoundBasePort, stateBoundServerIP, 443, "udp")
	if got := ja4s.keys.count(); got != 0 {
		t.Errorf("the JA4S recency order holds %d keys after CleanupConnection, and the three maps hold none", got)
	}
}
