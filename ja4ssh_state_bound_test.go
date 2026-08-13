package ja4plus

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/gopacket"
)

// The state bound of issue #239. `JA4SSHFingerprinter` holds one entry for each connection,
// and the entry count reached no bound before this change.
//
// Issue #221 raised the cost. A bare ACK on TCP port 22 opens an entry, so every completed
// TCP handshake to port 22 opens one. A port scan of that port therefore opens one entry for
// each connection it opens.
//
// The port bounds the same state, and `.claude/rules/parity.md` rule 2 states that the port
// decides the interface where this project shipped nothing. No FoxIO source addresses a state
// table. `ja4plus/utils/state_table.py:52` sets `DEFAULT_MAX_CONNECTIONS = 10000`,
// `ja4plus/utils/state_table.py:58` sets `DEFAULT_MAX_CONNECTION_AGE = 600`, and
// `ja4plus/utils/state_table.py:62` sets `DEFAULT_EVICTION_INTERVAL = 1000`.
// `ja4plus/fingerprinters/ja4ssh.py:122` announces the packet timestamp to the table, so the
// eviction clock reads the capture and never the wall clock.
//
// Each test below drives the bound with packets, and it reads the entry count of the state
// table. A test that reads a constant alone proves no eviction.

// sshBoundClientIP names the client of every connection of these tests.
const sshBoundClientIP = "192.168.1.100"

// sshBoundServerIP names the server of every connection of these tests.
const sshBoundServerIP = "10.0.0.1"

// sshBoundPacketAt returns one bare ACK to TCP port 22 at the timestamp the caller names.
// A bare ACK on that port opens a connection, and it advances no window.
// The client port names the connection, so a caller reaches a new connection with a new port.
func sshBoundPacketAt(clientPort uint16, timestamp time.Time) gopacket.Packet {
	packet := buildSSHPacket(sshBoundClientIP, sshBoundServerIP, clientPort, 22, nil, true)
	packet.Metadata().Timestamp = timestamp
	return packet
}

// sshBoundConnKey returns the state-table key of the connection the client port names.
func sshBoundConnKey(clientPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:22", sshBoundClientIP, clientPort, sshBoundServerIP)
}

// TestJA4SSHHoldsThePortValuesOfTheStateBound reads the three values against the port.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface. A change to one
// of the three values is therefore a parity change.
func TestJA4SSHHoldsThePortValuesOfTheStateBound(t *testing.T) {
	if maxSSHConnections != 10000 {
		t.Errorf("the entry bound is %d, and `ja4plus/utils/state_table.py:52` states 10000", maxSSHConnections)
	}

	if maxSSHConnectionAge != 600*time.Second {
		t.Errorf("the age bound is %v, and `ja4plus/utils/state_table.py:58` states 600 seconds", maxSSHConnectionAge)
	}

	if sshEvictionInterval != 1000 {
		t.Errorf("the eviction interval is %d, and `ja4plus/utils/state_table.py:62` states 1000", sshEvictionInterval)
	}
}

// TestJA4SSHRemovesTheLeastRecentConnectionAtTheEntryBound drives the entry bound with one
// connection more than the bound holds. The state table keeps the bound, and it removes the
// connection that received no packet for the longest time.
func TestJA4SSHRemovesTheLeastRecentConnectionAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	for index := 0; index <= maxSSHConnections; index++ {
		clientPort := uint16(1024 + index)
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(clientPort, timestamp)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	if len(fingerprinter.connections) != maxSSHConnections {
		t.Fatalf("the state table holds %d connections, and the entry bound holds %d",
			len(fingerprinter.connections), maxSSHConnections)
	}

	if _, held := fingerprinter.connections[sshBoundConnKey(1024)]; held {
		t.Errorf("the state table holds the first connection, and the entry bound removes the least recent one")
	}

	if _, held := fingerprinter.connections[sshBoundConnKey(uint16(1024+maxSSHConnections))]; !held {
		t.Errorf("the state table holds no last connection, and the packet that crosses the bound opens one")
	}
}

// TestJA4SSHRemovesAConnectionOlderThanTheAgeBound drives the age bound with the packet
// timestamp. The age pass runs on the eviction interval, so the second connection carries the
// packets that reach it.
func TestJA4SSHRemovesAConnectionOlderThanTheAgeBound(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fingerprinter := sshBoundFingerprinterOfTwoConnections(t, start, start.Add(601*time.Second))

	if _, held := fingerprinter.connections[sshBoundConnKey(1024)]; held {
		t.Errorf("the state table holds a connection of age 601 seconds, and the age bound is 600 seconds")
	}

	if len(fingerprinter.connections) != 1 {
		t.Errorf("the state table holds %d connections, and the age pass removes 1 of the 2",
			len(fingerprinter.connections))
	}
}

// TestJA4SSHKeepsAConnectionInsideTheAgeBound holds the other half of the age bound. A
// connection of age 599 seconds stays, so the pass removes no connection inside the bound.
func TestJA4SSHKeepsAConnectionInsideTheAgeBound(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fingerprinter := sshBoundFingerprinterOfTwoConnections(t, start, start.Add(599*time.Second))

	if len(fingerprinter.connections) != 2 {
		t.Errorf("the state table holds %d connections, and the age pass removes no connection inside the bound",
			len(fingerprinter.connections))
	}
}

// sshBoundFingerprinterOfTwoConnections returns a fingerprinter of two connections.
// The first connection reads one packet at the start time. The second connection reads the
// eviction interval of packets at the later time.
// The last packet reaches the age pass, because the fingerprinter runs that pass on the
// eviction interval.
func sshBoundFingerprinterOfTwoConnections(
	t *testing.T, start time.Time, later time.Time,
) *JA4SSHFingerprinter {
	t.Helper()

	fingerprinter := NewJA4SSH(2)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, start)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first connection", err)
	}

	for index := 1; index < sshEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1025, later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d of the second connection", err, index)
		}
	}

	return fingerprinter
}

// TestJA4SSHCountsANewWindowForAConnectionThatReturnsAfterTheAgeBound states what an eviction
// costs. The age pass precedes the connection of the packet, so it can remove the connection
// that the packet continues. The packet then opens that connection again, and the window
// counts from zero.
// The port counts such a connection as a returned connection, at
// `ja4plus/utils/state_table.py:95`.
func TestJA4SSHCountsANewWindowForAConnectionThatReturnsAfterTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	start := time.Unix(1700000000, 0)
	later := start.Add(601 * time.Second)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, start)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first packet", err)
	}

	// The pass runs on the packet that completes the eviction interval, so the second
	// connection carries every packet up to that one.
	for index := 2; index < sshEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1025, later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d", err, index)
		}
	}

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, later)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the packet that returns", err)
	}

	conn, held := fingerprinter.connections[sshBoundConnKey(1024)]
	if !held {
		t.Fatalf("the state table holds no connection, and the packet that returns opens one")
	}

	if conn.clientACKs != 1 {
		t.Errorf("the connection counts %d client bare ACKs, and a connection that returns counts 1",
			conn.clientACKs)
	}
}

// TestJA4SSHResetEmptiesTheOrderList holds the removal path of Reset.
// An order list that keeps a removed connection removes the wrong connection at the entry
// bound.
func TestJA4SSHResetEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.Reset()

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after Reset, and the state table holds none",
			fingerprinter.order.Len())
	}
}

// TestJA4SSHCleanupConnectionEmptiesTheOrderList holds the removal path of
// CleanupConnection. It reads the order list, because the state table and the order list name
// one set of connections.
func TestJA4SSHCleanupConnectionEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.CleanupConnection(sshBoundClientIP, 1024, sshBoundServerIP, 22, "tcp")

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after CleanupConnection, and the state table holds none",
			fingerprinter.order.Len())
	}
}

// TestJA4SSHCloseConnectionWindowEmptiesTheOrderList holds the removal path of
// CloseConnectionWindow. That method removes the connection after it emits the open window.
func TestJA4SSHCloseConnectionWindowEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.CloseConnectionWindow(sshBoundClientIP, 1024, sshBoundServerIP, 22, "tcp")

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after CloseConnectionWindow, and the state table holds none",
			fingerprinter.order.Len())
	}
}
