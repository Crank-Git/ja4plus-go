package ja4plus

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
)

// Step 2 of the JA4SSH client direction, which issue #413 builds.
//
// The maintainer ruled the three-step order on 2026-08-11, in the second comment of #129.
// Step 1 reads port 22, step 2 reads the TCP handshake originator, and step 3 reads the lower
// port. The project manager ruled #346 on 2026-08-13, under the widened delegation of
// `.claude/rules/rulings.md`. That ruling is provisional, and the maintainer confirms it or
// reverses it.
//
// A connection with no port 22 whose SYN sender holds the lower port separates step 2 from
// step 3. Step 3 names the higher port as the client, which transposes the direction of that
// shape. No capture of the corpus reaches it, so each test below builds the packets by hand.
//
// A SYN sender on the higher port separates nothing, because step 3 reaches the same answer.
// No test below builds that shape.

// The two endpoints of the separating shape. The client sends the SYN, and it holds the lower
// port.
const (
	sshStep2ClientIP   = "10.0.0.1"
	sshStep2ClientPort = uint16(2222)
	sshStep2ServerIP   = "10.0.0.2"
	sshStep2ServerPort = uint16(40000)
)

// sshStep2SYN returns the SYN of the separating shape. The client sends it, so the client
// holds the lower port of the connection.
func sshStep2SYN(t *testing.T) gopacket.Packet {
	t.Helper()

	packet := buildTCPPacketWithIPs(
		t,
		net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
		64, sshStep2ClientPort, sshStep2ServerPort, true, false)
	packet.Metadata().Timestamp = time.Unix(1700000000, 0)

	return packet
}

// TestJA4SSHNamesTheSYNSenderAsTheClientOnANonStandardPort holds step 2.
//
// The client sends three SSH packets of 36 bytes, and the server sends two of 100 bytes. The
// value therefore names the client mode 36 and the client packet count 3.
// Step 3 alone reads the higher port as the client, so it reports `c100s36_c2s3_c0s0` on the
// same packets. The test fails when a later change removes step 2.
func TestJA4SSHNamesTheSYNSenderAsTheClientOnANonStandardPort(t *testing.T) {
	fingerprinter := NewJA4SSH(5)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	clientPayload := sshPayloadOfSize(36)
	serverPayload := sshPayloadOfSize(100)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			clientPayload, sshSeqOfPacket(index, clientPayload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	var results []FingerprintResult

	for index := 0; index < 2; index++ {
		packet := buildSSHSegment(
			sshStep2ServerIP, sshStep2ClientIP, sshStep2ServerPort, sshStep2ClientPort,
			serverPayload, sshSeqOfPacket(index, serverPayload))

		emitted, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for server packet %d", err, index)
		}

		if len(emitted) > 0 {
			results = emitted
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 5 packets emits 1", len(results))
	}

	const expected = "c36s100_c3s2_c0s0"

	if results[0].Fingerprint != expected {
		t.Errorf("the value is %q, and the SYN sender is the client, so the value is %q",
			results[0].Fingerprint, expected)
	}
}

// TestJA4SSHNamesTheSYNACKReceiverAsTheClientOnANonStandardPort holds the second half of step 2.
//
// A capture that starts after the SYN still holds the SYN+ACK. The server sends that packet,
// so its destination is the client.
func TestJA4SSHNamesTheSYNACKReceiverAsTheClientOnANonStandardPort(t *testing.T) {
	fingerprinter := NewJA4SSH(5)

	synACK := buildTCPPacketWithIPs(
		t,
		net.ParseIP(sshStep2ServerIP), net.ParseIP(sshStep2ClientIP),
		64, sshStep2ServerPort, sshStep2ClientPort, true, true)
	synACK.Metadata().Timestamp = time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(synACK); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN+ACK", err)
	}

	clientPayload := sshPayloadOfSize(36)
	serverPayload := sshPayloadOfSize(100)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			clientPayload, sshSeqOfPacket(index, clientPayload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	var results []FingerprintResult

	for index := 0; index < 2; index++ {
		packet := buildSSHSegment(
			sshStep2ServerIP, sshStep2ClientIP, sshStep2ServerPort, sshStep2ClientPort,
			serverPayload, sshSeqOfPacket(index, serverPayload))

		emitted, _ := fingerprinter.ProcessPacket(packet)
		if len(emitted) > 0 {
			results = emitted
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 5 packets emits 1", len(results))
	}

	const expected = "c36s100_c3s2_c0s0"

	if results[0].Fingerprint != expected {
		t.Errorf("the value is %q, and the SYN+ACK receiver is the client, so the value is %q",
			results[0].Fingerprint, expected)
	}
}

// TestJA4SSHCleanupConnectionRemovesTheConnectionThatStep2Named holds the second site.
//
// `sshConnKeyOfEndpoints` holds no packet, and step 2 changes which endpoint is the client. A
// key that misses the connection leaves the entry, which is a leak. The caller names the two
// endpoints in the server-to-client order, and the state table then holds no connection.
func TestJA4SSHCleanupConnectionRemovesTheConnectionThatStep2Named(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	fingerprinter.CleanupConnection(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort, "tcp")

	if len(fingerprinter.connections) != 0 {
		t.Errorf("the state table holds %d connections, and CleanupConnection removes the one connection",
			len(fingerprinter.connections))
	}

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries, and CleanupConnection empties it",
			fingerprinter.order.Len())
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and CleanupConnection removes the entry of the connection",
			len(fingerprinter.handshakes))
	}
}

// TestJA4SSHCloseConnectionWindowReadsTheClientThatStep2Named holds the other reader of
// `sshConnKeyOfEndpoints`. It names the client of the connection as the source of the result.
func TestJA4SSHCloseConnectionWindowReadsTheClientThatStep2Named(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	results := fingerprinter.CloseConnectionWindow(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort, "tcp")

	if len(results) != 1 {
		t.Fatalf("the method returns %d values, and the connection holds one open window", len(results))
	}

	if results[0].SrcIP != sshStep2ClientIP || results[0].SrcPort != sshStep2ClientPort {
		t.Errorf("the result names the source %s:%d, and the client of the connection is %s:%d",
			results[0].SrcIP, results[0].SrcPort, sshStep2ClientIP, sshStep2ClientPort)
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and the method removes the entry of the connection",
			len(fingerprinter.handshakes))
	}
}

// sshStep2FingerprinterOfOneConnection returns a fingerprinter that holds the separating shape
// as one connection. The window holds 200 packets, so the three client packets emit no value.
func sshStep2FingerprinterOfOneConnection(t *testing.T) *JA4SSHFingerprinter {
	t.Helper()

	fingerprinter := NewJA4SSH(200)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	payload := sshPayloadOfSize(36)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			payload, sshSeqOfPacket(index, payload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	if len(fingerprinter.connections) != 1 {
		t.Fatalf("the state table holds %d connections, and these packets open 1",
			len(fingerprinter.connections))
	}

	return fingerprinter
}

// TestJA4SSHWritesNoHandshakeEntryForAPairThatHoldsPort22 holds the guard that keeps the corpus
// value. Step 1 decides a connection of port 22, so an entry would hold state that nothing
// reads. Every SSH capture of the corpus holds port 22 on one side.
func TestJA4SSHWritesNoHandshakeEntryForAPairThatHoldsPort22(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	packet := buildTCPPacketWithIPs(
		t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP), 64, 54321, 22, true, false)
	packet.Metadata().Timestamp = time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(packet); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and port 22 decides the direction",
			len(fingerprinter.handshakes))
	}
}

// TestJA4SSHHoldsThePortValueOfTheHandshakeEntryBound reads the bound against the port.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface, and no FoxIO
// source addresses a state table.
func TestJA4SSHHoldsThePortValueOfTheHandshakeEntryBound(t *testing.T) {
	if maxSSHHandshakes != 1000 {
		t.Errorf("the handshake entry bound is %d, and `ja4plus/fingerprinters/ja4ssh.py:53` states 1000",
			maxSSHHandshakes)
	}
}

// TestJA4SSHRemovesTheLeastRecentHandshakeAtTheEntryBound drives the handshake table with one
// SYN more than the bound holds. A SYN on a non-standard port carries no SSH data and opens no
// connection, so the handshake table needs a bound of its own.
func TestJA4SSHRemovesTheLeastRecentHandshakeAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	timestamp := time.Unix(1700000000, 0)

	for index := 0; index <= maxSSHHandshakes; index++ {
		packet := buildTCPPacketWithIPs(
			t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
			64, uint16(2000+index), sshStep2ServerPort, true, false)
		packet.Metadata().Timestamp = timestamp

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SYN %d", err, index)
		}
	}

	if len(fingerprinter.handshakes) != maxSSHHandshakes {
		t.Fatalf("the handshake table holds %d entries, and the entry bound holds %d",
			len(fingerprinter.handshakes), maxSSHHandshakes)
	}

	if fingerprinter.handshakeOrder.Len() != maxSSHHandshakes {
		t.Errorf("the handshake order list holds %d entries, and the table holds %d",
			fingerprinter.handshakeOrder.Len(), maxSSHHandshakes)
	}

	if len(fingerprinter.connections) != 0 {
		t.Errorf("the state table holds %d connections, and a SYN opens none",
			len(fingerprinter.connections))
	}

	first := sshHandshakeKey(sshStep2ClientIP, 2000, sshStep2ServerIP, sshStep2ServerPort)
	if _, held := fingerprinter.handshakes[first]; held {
		t.Errorf("the handshake table holds the first entry, and the entry bound removes the least recent one")
	}
}

// TestJA4SSHRemovesAHandshakeOlderThanTheAgeBound drives the age bound of the handshake table.
// The age pass runs on the eviction interval, so the later packets reach it.
func TestJA4SSHRemovesAHandshakeOlderThanTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	start := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	later := start.Add(601 * time.Second)

	for index := 1; index < sshEvictionInterval; index++ {
		packet := buildTCPPacketWithIPs(
			t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
			64, 3000, sshStep2ServerPort, true, false)
		packet.Metadata().Timestamp = later

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SYN %d", err, index)
		}
	}

	aged := sshHandshakeKey(
		sshStep2ClientIP, sshStep2ClientPort, sshStep2ServerIP, sshStep2ServerPort)
	if _, held := fingerprinter.handshakes[aged]; held {
		t.Errorf("the handshake table holds an entry of age 601 seconds, and the age bound is 600 seconds")
	}
}

// TestJA4SSHResetEmptiesTheHandshakeTable holds the removal path that
// `.claude/rules/concurrency.md` states. A new state map reaches CleanupConnection and Reset.
func TestJA4SSHResetEmptiesTheHandshakeTable(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	fingerprinter.Reset()

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and Reset empties it",
			len(fingerprinter.handshakes))
	}

	if fingerprinter.handshakeOrder.Len() != 0 {
		t.Errorf("the handshake order list holds %d entries, and Reset empties it",
			fingerprinter.handshakeOrder.Len())
	}
}

// TestJA4SSHHandshakeKeyReadsTheTwoDirectionsAsOneKey holds the rule that solves the second
// site. The state-table key encodes the direction, and the handshake key encodes none. A
// caller that holds four endpoint values and no packet therefore reaches the entry the packet
// path wrote.
func TestJA4SSHHandshakeKeyReadsTheTwoDirectionsAsOneKey(t *testing.T) {
	forward := sshHandshakeKey(
		sshStep2ClientIP, sshStep2ClientPort, sshStep2ServerIP, sshStep2ServerPort)
	reverse := sshHandshakeKey(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort)

	if forward != reverse {
		t.Errorf("the two directions give the keys %q and %q, and one connection holds one key",
			forward, reverse)
	}
}
