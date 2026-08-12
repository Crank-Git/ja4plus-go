package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The FIN+ACK rules of issue #222. A connection that closes emits the window it holds open,
// and the emission starts a new window.
//
// Three sources state the emission. `wireshark/source/packet-ja4.c:1400` tests the TCP flags
// and `wireshark/source/packet-ja4.c:1402` writes the value. `python/ja4.py:555` tests the two
// flags and `python/ja4.py:556` calls `finalize_ja4ssh`, which `python/ja4.py:370` defines.
// The port emits the window at `ja4plus/fingerprinters/ja4ssh.py:268`.
//
// Two of the three sources clear the counters, and Wireshark clears none of them.
// `python/ja4.py:377` deletes the stream from the cache, so no later packet of the stream
// reads a counter of the emitted window. The port clears the four counters at
// `ja4plus/fingerprinters/ja4ssh.py:439` through `ja4plus/fingerprinters/ja4ssh.py:442`.
// `wireshark/source/packet-ja4.c:1485` clears the counters of a filled window alone, so
// Wireshark writes one value twice on `ssh-r.pcap`, at frame 1850 and at frame 1851. This
// library follows the port, and the maintainer's rule of 2026-08-12 states that order.
//
// The flag test reads the two flags, and it reads no other flag.
// `python/ja4.py:555` and `ja4plus/fingerprinters/ja4ssh.py:268` both test the FIN bit and the
// ACK bit, so a FIN+PSH+ACK packet reaches the emission.
// `wireshark/source/packet-ja4.c:1400` tests `tcp_flags == 0x011` instead, and this library
// follows the port.
//
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_window_test.go`. `buildSSHPacket`
// and `buildSSHSegment` live in `ja4ssh_test.go`. Both set the ACK flag alone, so a packet
// with no payload is a bare ACK.

// buildSSHFINACK returns one TCP packet that carries the FIN flag and the ACK flag.
//
// The packet carries no payload, which is the shape of the close of a capture. A FIN+ACK
// packet never reaches the bare ACK counter, because FoxIO counts a bare ACK only where the
// TCP flags equal `0x0010`.
func buildSSHFINACK(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		FIN:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	return pkt
}

// buildSSHFINPSHACK returns one TCP packet that carries the FIN flag, the PSH flag, the ACK
// flag and one SSH payload.
//
// `python/ja4.py:555` and `ja4plus/fingerprinters/ja4ssh.py:268` each test the FIN bit and the
// ACK bit, so this packet reaches the emission.
// `wireshark/source/packet-ja4.c:1400` tests `tcp_flags == 0x011`, which this packet fails.
func buildSSHFINPSHACK(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, seq uint32) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		FIN:     true,
		PSH:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	return pkt
}

// ja4sshBareACKPart returns part c of one JA4SSH value, which holds the two bare ACK counts.
func ja4sshBareACKPart(t *testing.T, value string) string {
	t.Helper()

	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		t.Fatalf("the value %q holds %d parts, and a JA4SSH value holds three", value, len(parts))
	}

	return parts[2]
}

// TestJA4SSHEmitsTheOpenWindowOnAFINACKPacket holds the emission of issue #222. A window
// below the threshold reaches ProcessPacket on the packet that closes the connection.
func TestJA4SSHEmitsTheOpenWindowOnAFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for index := 0; index < 2; index++ {
		results, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emits %d values on 2 SSH packets, and the window holds 200", len(results))
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and the connection holds one window open", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s0" {
		t.Errorf("the fingerprinter produces %q, and the open window of 2 client SSH packets reads `c36s0_c2s0_c0s0`", results[0].Fingerprint)
	}

	if results[0].Type != "ja4ssh" {
		t.Errorf("the result names the type %q, and the method is `ja4ssh`", results[0].Type)
	}
}

// TestJA4SSHCountsNoBareACKForTheFINACKPacket holds the flag rule of part c. FoxIO counts a
// bare ACK only where the TCP flags equal `0x0010`, so the packet that closes the connection
// reaches no counter of part c.
func TestJA4SSHCountsNoBareACKForTheFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the handshake ACK", err)
	}

	for index := 0; index < 2; index++ {
		if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload))); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and the connection holds one window open", len(results))
	}

	if produced := ja4sshBareACKPart(t, results[0].Fingerprint); produced != "c1s0" {
		t.Errorf("part c reads %s, and the handshake ACK is the one bare ACK of the window", produced)
	}
}

// TestJA4SSHClearsTheWindowOnAFINACKPacket holds the clear of issue #222. The port clears the
// four counters of the emitted window, so the second FIN+ACK packet of a close reaches an
// empty window and emits nothing.
func TestJA4SSHClearsTheWindowOnAFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for index := 0; index < 2; index++ {
		if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload))); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	first, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first FIN+ACK packet", err)
	}

	if len(first) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the first FIN+ACK packet, and it emits 1", len(first))
	}

	second, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("10.0.0.1", "192.168.1.100", 22, 54321, 1))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the second FIN+ACK packet", err)
	}

	if len(second) != 0 {
		t.Fatalf("the fingerprinter emits %d values on the second FIN+ACK packet %v, and the first one emptied the window",
			len(second), second)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and the FIN+ACK packet emptied the window",
			len(closed), closed)
	}
}

// TestJA4SSHCountsTheBareACKThatFollowsAFINACKPacketInTheNextWindow holds the reading that
// issue #221 recorded for issue #222. `ssh-r.pcap` stream 1 holds 5 client bare ACKs, and the
// reference counts the first 4. Frame 335 carries a FIN+ACK packet, and frame 340 carries the
// fifth bare ACK, which the new window counts.
//
// The new window holds no SSH packet, so no emission reaches that count.
func TestJA4SSHCountsTheBareACKThatFollowsAFINACKPacketInTheNextWindow(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the handshake ACK", err)
	}

	if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(0, payload))); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SSH segment", err)
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 37))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and it emits 1", len(results))
	}

	if produced := ja4sshBareACKPart(t, results[0].Fingerprint); produced != "c1s0" {
		t.Errorf("part c reads %s, and the window holds the handshake ACK alone", produced)
	}

	// The bare ACK that follows the close reaches the new window.
	trailing, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the trailing bare ACK", err)
	}

	if len(trailing) != 0 {
		t.Fatalf("the fingerprinter emits %d values %v on the trailing bare ACK, and that window holds no SSH packet",
			len(trailing), trailing)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and a window of bare ACKs alone emits nothing",
			len(closed), closed)
	}
}

// TestJA4SSHEmitsTheOpenWindowOnAFINPSHACKPacket holds the flag test of issue #222. The test
// reads the FIN bit and the ACK bit alone, so a packet that also carries the PSH flag closes
// the window. The payload of that packet reaches the window first.
func TestJA4SSHEmitsTheOpenWindowOnAFINPSHACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(0, payload))); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SSH segment", err)
	}

	results, err := fingerprinter.ProcessPacket(buildSSHFINPSHACK(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(1, payload)))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+PSH+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+PSH+ACK packet, and it emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s0" {
		t.Errorf("the fingerprinter produces %q, and the window counts the payload of the closing packet",
			results[0].Fingerprint)
	}
}

// TestJA4SSHEmitsNoValueOnAFINACKPacketOfAnUnknownConnection holds the state rule. A FIN+ACK
// packet opens no connection, because the counters of a connection the library never read
// hold nothing.
func TestJA4SSHEmitsNoValueOnAFINACKPacketOfAnUnknownConnection(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 1))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values %v on a FIN+ACK packet of an unknown connection",
			len(results), results)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and the FIN+ACK packet opened no connection",
			len(closed), closed)
	}
}

// TestJA4SSHEmitsTheOpenWindowOnAFINACKPacketOfSshRPcap holds FR-gaps-2 for `ssh-r.pcap` and
// JA4SSH. Stream 1 of that capture holds one value, and the FoxIO per-stream vector at
// `testdata/foxio/python/ssh-r.pcap.json` holds `"JA4SSH.1": "c64s64_c6s5_c4s5"`.
//
// The window holds 11 SSH packets, which is below the threshold of 200, so the value reaches
// ProcessPacket on the FIN+ACK packet at frame 335. Part c reads `c4s5`, because the fifth
// client bare ACK arrives at frame 340 and the new window counts it.
//
// Part a reads `c48s21` and the vector holds `c64s64`. Issue #223 records that difference,
// and this issue closes no part of it.
func TestJA4SSHEmitsTheOpenWindowOnAFINACKPacketOfSshRPcap(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh-r.pcap", 46394)

	if len(run.Window) != 1 {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the FIN+ACK packet emits 1",
			len(run.Window), run.Window)
	}

	if produced := ja4sshBareACKPart(t, run.Window[0]); produced != "c4s5" {
		t.Errorf("part c reads %s, and the FoxIO vector reads c4s5", produced)
	}

	if produced := ja4sshPacketCountPart(t, run.Window[0]); produced != "c6s5" {
		t.Errorf("part b reads %s, and the FoxIO vector reads c6s5", produced)
	}

	if len(run.Closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d JA4SSH values %v, and the FIN+ACK packet emptied the window",
			len(run.Closed), run.Closed)
	}
}
