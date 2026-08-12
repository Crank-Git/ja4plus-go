package ja4plus

import "testing"

// Issue #193 records the defect that every test in this file holds. JA4 and JA4S key their
// QUIC state with the grouping key, which reads the inner address pair, and each
// FingerprintResult carries the reported key, which reads the outer address pair.
// `types.go:20-25` documents the CleanupConnection tuple as the pair a FingerprintResult
// carries, so a caller that follows the document names the reported key. Without an index
// from the reported key to the grouping key, the removal reaches no entry, and one entry
// leaks for every tunneled connection.
//
// No capture of the FoxIO corpus carries QUIC inside a tunnel, so every test here builds the
// separating packet. `quic_tunnel_test.go` holds the packet builder, and the tunnel is VXLAN.
//
// #169 repaired JA4L, and `ja4plus/fingerprinters/ja4l.py:216` holds the same fallback in the
// Python port. The port carries no such index on its JA4 fingerprinter and on its JA4S
// fingerprinter, so this repository leads the port on those two methods.

// tunneledConnectionCount is the number of tunneled connections each leak test opens.
// One connection proves the removal, and three prove that one entry leaks for every
// connection.
const tunneledConnectionCount = 3

// tunneledClientPort returns the inner source port of one tunneled connection.
// Each connection reads its own port, so each one reaches its own state entry.
func tunneledClientPort(index int) uint16 {
	return uint16(tunnelInnerSrcPort + index)
}

// tunneledDCID returns the destination connection identifier of one tunneled connection.
// The QUIC Initial keys read this value, so each connection reads its own identifier.
func tunneledDCID(index int) []byte {
	return []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, byte(0x20 + index)}
}

// openTunneledJA4Connections processes one tunneled QUIC client Initial for every
// connection, and it returns the inner source port of each one.
//
// The CRYPTO frame of each packet delivers 40 bytes of the handshake message. Issue #42
// makes an absent fragment an ordinary intermediate state of the reassembly, so the
// fingerprinter keeps the entry that names the connection.
func openTunneledJA4Connections(t *testing.T, fingerprinter *JA4Fingerprinter) []uint16 {
	t.Helper()

	ports := make([]uint16, 0, tunneledConnectionCount)

	for index := 0; index < tunneledConnectionCount; index++ {
		port := tunneledClientPort(index)
		handshake := buildClientHelloPayload()[5:45]
		initial := buildQUICClientInitial(t, tunneledDCID(index), []byte{0x01, 0x02, 0x03, 0x04}, handshake)
		packet := buildVXLANQUICPacketOnPort(t, port, initial)

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("ProcessPacket returns the error %v, and an absent fragment is no error", err)
		}

		ports = append(ports, port)
	}

	return ports
}

// openTunneledJA4SConnections processes one tunneled QUIC client Initial for every
// connection, and it returns the inner source port of each one.
// JA4S stores the connection identifier of a client Initial, and it returns no result for it.
func openTunneledJA4SConnections(t *testing.T, fingerprinter *JA4SFingerprinter) []uint16 {
	t.Helper()

	ports := make([]uint16, 0, tunneledConnectionCount)

	for index := 0; index < tunneledConnectionCount; index++ {
		port := tunneledClientPort(index)
		handshake := buildClientHelloPayload()[5:]
		initial := buildQUICClientInitial(t, tunneledDCID(index), []byte{0x01, 0x02, 0x03, 0x04}, handshake)
		packet := buildVXLANQUICPacketOnPort(t, port, initial)

		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returns the error %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("ProcessPacket returns %d results for a client Initial, and it produces none", len(results))
		}

		ports = append(ports, port)
	}

	return ports
}

// cleanupByTheReportedKey removes each connection by the address pair a FingerprintResult
// carries. That pair holds the outer addresses and the inner ports.
// The last connection reads the two endpoints in the reverse order, because a caller names
// them in either order.
func cleanupByTheReportedKey(fingerprinter Fingerprinter, ports []uint16) {
	for index, port := range ports {
		if index == len(ports)-1 {
			fingerprinter.CleanupConnection(tunnelOuterDstIP, tunnelInnerDstPort, tunnelOuterSrcIP, port, "udp")

			continue
		}

		fingerprinter.CleanupConnection(tunnelOuterSrcIP, port, tunnelOuterDstIP, tunnelInnerDstPort, "udp")
	}
}

// JA4 removes every tunneled connection that a caller names by the reported key.
//
// The reported key holds the outer pair `100.20.9.2` and `100.20.9.1`, and the grouping key
// holds the inner pair `10.16.27.12` and `10.16.27.131`.
// `TestJA4ReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial` proves that a result reports the
// outer pair with the inner ports.
func TestJA4CleanupByTheReportedKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4()
	ports := openTunneledJA4Connections(t, fingerprinter)

	if got := len(fingerprinter.dcidToTuple); got != tunneledConnectionCount {
		t.Fatalf("the connection identifier table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.quicFragments); got != tunneledConnectionCount {
		t.Fatalf("the fragment table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.dcidToReported); got != tunneledConnectionCount {
		t.Fatalf("the index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}

	cleanupByTheReportedKey(fingerprinter, ports)

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the fragment table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.dcidToReported); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the index, and one leaks for every tunneled connection",
			got)
	}
}

// JA4 removes a tunneled connection that a caller names by the grouping key.
//
// A caller that reads GetShardKey holds the grouping key, and the index holds the reported
// key alone. The removal therefore falls back to the key the caller gave.
// `ja4plus/fingerprinters/ja4l.py:216` falls back the same way.
func TestJA4CleanupByTheGroupingKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4()
	ports := openTunneledJA4Connections(t, fingerprinter)

	for _, port := range ports {
		fingerprinter.CleanupConnection(tunnelInnerSrcIP, port, tunnelInnerDstIP, tunnelInnerDstPort, "udp")
	}

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the fragment table", got)
	}
	if got := len(fingerprinter.dcidToReported); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the index, and the caller cannot name the reported key",
			got)
	}
}

// JA4S removes every tunneled connection that a caller names by the reported key.
//
// `TestJA4SReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial` proves that JA4S stores the
// connection identifier under the grouping key, which holds the inner pair.
func TestJA4SCleanupByTheReportedKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4S()
	ports := openTunneledJA4SConnections(t, fingerprinter)

	if got := len(fingerprinter.quicDCIDs); got != tunneledConnectionCount {
		t.Fatalf("the connection identifier table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.groupingKeys); got != tunneledConnectionCount {
		t.Fatalf("the grouping key index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.reportedKeys); got != tunneledConnectionCount {
		t.Fatalf("the reported key index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}

	cleanupByTheReportedKey(fingerprinter, ports)

	if got := len(fingerprinter.quicDCIDs); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the grouping key index, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.reportedKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the reported key index, and one leaks for every tunneled connection",
			got)
	}
}

// JA4S removes a tunneled connection that a caller names by the grouping key.
func TestJA4SCleanupByTheGroupingKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4S()
	ports := openTunneledJA4SConnections(t, fingerprinter)

	for _, port := range ports {
		fingerprinter.CleanupConnection(tunnelInnerSrcIP, port, tunnelInnerDstIP, tunnelInnerDstPort, "udp")
	}

	if got := len(fingerprinter.quicDCIDs); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the grouping key index, and the caller cannot name the reported key",
			got)
	}
	if got := len(fingerprinter.reportedKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the reported key index", got)
	}
}

// Reset clears every table that a tunneled connection fills, for JA4 and for JA4S.
// A table the index does not reach is a table Reset may not clear.
func TestResetClearsEveryTunneledTableOfJA4AndJA4S(t *testing.T) {
	ja4 := NewJA4()
	openTunneledJA4Connections(t, ja4)
	ja4.Reset()

	if got := len(ja4.dcidToTuple); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4 connection identifier table", got)
	}
	if got := len(ja4.quicFragments); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4 fragment table", got)
	}
	if got := len(ja4.dcidToReported); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4 index", got)
	}

	ja4s := NewJA4S()
	openTunneledJA4SConnections(t, ja4s)
	ja4s.Reset()

	if got := len(ja4s.quicDCIDs); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4S connection identifier table", got)
	}
	if got := len(ja4s.groupingKeys); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4S grouping key index", got)
	}
	if got := len(ja4s.reportedKeys); got != 0 {
		t.Errorf("Reset leaves %d entries in the JA4S reported key index", got)
	}
}
