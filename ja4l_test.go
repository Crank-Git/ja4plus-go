package ja4plus

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// handshakeSequenceNumbers returns the sequence number and the acknowledgment number that
// one packet of a three-way handshake carries.
//
// The client measurement point reads the relative sequence number and the relative
// acknowledgment number, so a packet that carries no realistic number reaches no client
// point. Both endpoints open at the initial sequence number 0, which makes every relative
// number of the handshake read 1.
func handshakeSequenceNumbers(syn, ack bool) (uint32, uint32) {
	switch {
	case syn && !ack:
		return 0, 0
	case syn && ack:
		return 0, 1
	default:
		return 1, 1
	}
}

// buildTCPPacketWithIPs builds a TCP packet with specified IPs and TTL.
func buildTCPPacketWithIPs(t testing.TB, srcIP, dstIP net.IP, ttl uint8, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	t.Helper()
	seq, acknum := handshakeSequenceNumbers(syn, ack)
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      ttl,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Seq:     seq,
		Ack:     acknum,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestJA4L_FullHandshake(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// SYN: client -> server at t=0
	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	results, err := fp.ProcessPacket(synPkt)
	if err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %d", len(results))
	}

	// SYN-ACK: server -> client at t=100ms
	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, err = fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SYN-ACK: expected 1 result, got %d", len(results))
	}
	if !strings.HasPrefix(results[0].Fingerprint, "JA4L-S=") {
		t.Errorf("SYN-ACK: expected JA4L-S prefix, got %q", results[0].Fingerprint)
	}
	expected := "JA4L-S=50000_64"
	if results[0].Fingerprint != expected {
		t.Errorf("SYN-ACK: got %q, want %q", results[0].Fingerprint, expected)
	}
	if results[0].Type != "ja4l" {
		t.Errorf("SYN-ACK: type got %q, want %q", results[0].Type, "ja4l")
	}

	// ACK: client -> server at t=200ms
	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(200 * time.Millisecond)
	results, err = fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ACK: expected 1 result, got %d", len(results))
	}
	expected = "JA4L-C=50000_64"
	if results[0].Fingerprint != expected {
		t.Errorf("ACK: got %q, want %q", results[0].Fingerprint, expected)
	}
}

func TestJA4L_SYNOnly(t *testing.T) {
	fp := NewJA4L()
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}
	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 80, true, false)
	synPkt.Metadata().Timestamp = time.Now()
	results, err := fp.ProcessPacket(synPkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SYN only: expected no results, got %d", len(results))
	}
}

func TestJA4L_MissingSYN(t *testing.T) {
	fp := NewJA4L()
	serverIP := net.IP{10, 0, 0, 1}
	clientIP := net.IP{192, 168, 1, 1}
	// Send SYN-ACK without prior SYN
	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 80, 12345, true, true)
	synAckPkt.Metadata().Timestamp = time.Now()
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("missing SYN: expected no results, got %d", len(results))
	}
}

func TestJA4L_MinimumLatency(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// SYN at t=0
	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	// SYN-ACK at same time (zero diff) -> should clamp to 1
	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	expected := "JA4L-S=1_64"
	if results[0].Fingerprint != expected {
		t.Errorf("min latency: got %q, want %q", results[0].Fingerprint, expected)
	}
}

// TestJA4LMovesTheClientPointToARepeatedBareACK holds the client point rule on a repeated
// bare ACK.
//
// A repeated bare ACK holds the relative sequence number `1` and the relative
// acknowledgment number `1`, so it meets the rule that
// `python/ja4.py:570` states.
// `python/common.py:101` omits `C` from the fields it declines to
// update, so the second packet replaces the point and the reference reports the later value.
// Issue #196 holds the reading, and it replaces the earlier expectation that the second
// packet reports nothing.
func TestJA4LMovesTheClientPointToARepeatedBareACK(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	_, _ = fp.ProcessPacket(synAckPkt)

	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, _ := fp.ProcessPacket(ackPkt)
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=25000_64" {
		t.Errorf("first bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=25000_64")
	}

	ackPkt2 := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt2.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	results, _ = fp.ProcessPacket(ackPkt2)
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=50000_64" {
		t.Errorf("second bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=50000_64")
	}
}

func TestJA4L_Reset(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	_, _ = fp.ProcessPacket(synAckPkt)

	// Issue #25 removed the results slice, so the connection table is the only state that
	// Reset clears.
	if len(fp.connections) != 1 {
		t.Fatalf("expected 1 connection before reset, got %d", len(fp.connections))
	}

	fp.Reset()

	if len(fp.connections) != 0 {
		t.Errorf("expected 0 connections after reset, got %d", len(fp.connections))
	}
}

func buildTCPPacketWithIPv6(t *testing.T, srcIP, dstIP net.IP, hopLimit uint8, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{SrcIP: srcIP, DstIP: dstIP, NextHeader: layers.IPProtocolTCP, HopLimit: hopLimit}
	seq, acknum := handshakeSequenceNumbers(syn, ack)
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, Seq: seq, Ack: acknum, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize IPv6 packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestJA4L_IPv6Handshake(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:db8::2")

	// SYN: client -> server at t=0
	synPkt := buildTCPPacketWithIPv6(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	results, err := fp.ProcessPacket(synPkt)
	if err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %d", len(results))
	}

	// SYN-ACK: server -> client at t=100ms
	synAckPkt := buildTCPPacketWithIPv6(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, err = fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SYN-ACK: expected 1 result, got %d", len(results))
	}
	expected := "JA4L-S=50000_64"
	if results[0].Fingerprint != expected {
		t.Errorf("SYN-ACK: got %q, want %q", results[0].Fingerprint, expected)
	}
	if results[0].Type != "ja4l" {
		t.Errorf("SYN-ACK: type got %q, want %q", results[0].Type, "ja4l")
	}

	// ACK: client -> server at t=200ms
	ackPkt := buildTCPPacketWithIPv6(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(200 * time.Millisecond)
	results, err = fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ACK: expected 1 result, got %d", len(results))
	}
	expected = "JA4L-C=50000_64"
	if results[0].Fingerprint != expected {
		t.Errorf("ACK: got %q, want %q", results[0].Fingerprint, expected)
	}
}

func TestJA4L_DistanceUtils(t *testing.T) {
	// CalculateDistance: latency_us * 0.128 / propagationFactor
	dist := CalculateDistance(1000, 1.6)
	expectedDist := (1000.0 * 0.128) / 1.6 // = 80.0
	if dist != expectedDist {
		t.Errorf("CalculateDistance(1000, 1.6) = %f, want %f", dist, expectedDist)
	}

	// CalculateDistanceKm: latency_us * 0.206 / propagationFactor
	distKm := CalculateDistanceKm(1000, 1.6)
	expectedDistKm := (1000.0 * 0.206) / 1.6 // = 128.75
	if distKm != expectedDistKm {
		t.Errorf("CalculateDistanceKm(1000, 1.6) = %f, want %f", distKm, expectedDistKm)
	}

	// EstimateOS
	osTests := []struct {
		ttl  uint8
		want string
	}{
		{50, "Mac, Linux, Phone, or IoT device (initial TTL: 64)"},
		{100, "Windows (initial TTL: 128)"},
		{200, "Cisco, F5, or Networking Device (initial TTL: 255)"},
	}
	for _, tt := range osTests {
		got := EstimateOS(tt.ttl)
		if got != tt.want {
			t.Errorf("EstimateOS(%d) = %q, want %q", tt.ttl, got, tt.want)
		}
	}

	// EstimateHopCount
	hopTests := []struct {
		ttl      uint8
		wantHops int
	}{
		{50, 14},  // 64 - 50
		{100, 28}, // 128 - 100
		{200, 55}, // 255 - 200
	}
	for _, tt := range hopTests {
		got := EstimateHopCount(tt.ttl)
		if got != tt.wantHops {
			t.Errorf("EstimateHopCount(%d) = %d, want %d", tt.ttl, got, tt.wantHops)
		}
	}
}

// TestJA4L_ServerAndClientAreDistinct is the canonical verification
// that JA4L emits BOTH a server-side latency fingerprint (JA4L-S) and a
// client-side latency fingerprint (JA4L-C) as distinct, distinguishable
// values. This covers what some documentation calls "JA4LS"... there is
// no separate JA4LS fingerprint type in the FoxIO spec; the server
// variant is already emitted by NewJA4L() as JA4L-S.
//
// Added in v0.3 as part of the ja4monitor forensic workbench work. If
// JA4L ever stops emitting the -S variant, the downstream detail view's
// server-latency display will silently break, so this test exists as a
// regression gate.
func TestJA4L_ServerAndClientAreDistinct(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// Full three-way handshake.
	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	if _, err := fp.ProcessPacket(synPkt); err != nil {
		t.Fatalf("SYN: %v", err)
	}

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	synAckResults, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: %v", err)
	}

	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	ackResults, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("ACK: %v", err)
	}

	// 1. Both results should be emitted.
	if len(synAckResults) != 1 {
		t.Fatalf("SYN-ACK should emit 1 result, got %d", len(synAckResults))
	}
	if len(ackResults) != 1 {
		t.Fatalf("ACK should emit 1 result, got %d", len(ackResults))
	}

	// 2. The server-side result must be JA4L-S.
	if !strings.HasPrefix(synAckResults[0].Fingerprint, "JA4L-S=") {
		t.Errorf("server fingerprint = %q, want JA4L-S= prefix",
			synAckResults[0].Fingerprint)
	}

	// 3. The client-side result must be JA4L-C.
	if !strings.HasPrefix(ackResults[0].Fingerprint, "JA4L-C=") {
		t.Errorf("client fingerprint = %q, want JA4L-C= prefix",
			ackResults[0].Fingerprint)
	}

	// 4. Both results carry the same Type ("ja4l"). Consumers distinguish
	// them by the value prefix, not by Type. This matters for the
	// detail view, which displays all JA4L events on one timeline row.
	if synAckResults[0].Type != "ja4l" {
		t.Errorf("server Type = %q, want ja4l", synAckResults[0].Type)
	}
	if ackResults[0].Type != "ja4l" {
		t.Errorf("client Type = %q, want ja4l", ackResults[0].Type)
	}

	// 5. Server and client values must be textually different.
	if synAckResults[0].Fingerprint == ackResults[0].Fingerprint {
		t.Errorf("server and client fingerprints should differ, got %q for both",
			synAckResults[0].Fingerprint)
	}
}

// quicLongHeaderPayload returns the bytes of a QUIC version 1 long-header datagram.
// JA4L reads a UDP flow only when the flow carries a QUIC long header, so a UDP test of
// JA4L supplies this payload.
func quicLongHeaderPayload() []byte {
	return []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
}

// quicHandshakePayload returns the bytes of a QUIC version 1 Handshake datagram.
// The two client measurement points read a Handshake packet only, so a test of those two
// points supplies this payload. RFC 9000 Section 17.2 gives the type `0b10`.
func quicHandshakePayload() []byte {
	return []byte{0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
}

// ntpPayload returns the bytes of an NTP client message.
// `gre-sample.pcap` carries six such messages on port 123.
func ntpPayload() []byte {
	payload := make([]byte, 48)
	payload[0] = 0x1b
	return payload
}

// buildUDPPacketWithIPs builds a UDP packet with specified IPs/TTL/ports and payload.
func buildUDPPacketWithIPs(t *testing.T, srcIP, dstIP net.IP, ttl uint8, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      ttl,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize udp packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestJA4LTimesAQUICFlowThatRunsAgainstTheKeyDirection regresses the bug where processUDP
// started the QUIC 4-point timing only for a packet in the lexicographic forward
// direction. The client address is the lexicographic larger one here, so every client
// packet runs against the direction of the key.
func TestJA4LTimesAQUICFlowThatRunsAgainstTheKeyDirection(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// Packet 1 (A): client -> server at t=0
	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("A: expected no results, got %d (%q)", len(results), results[0].Fingerprint)
	}

	// Packet 2 (B): server -> client at t=50ms — the frame carries no value, because
	// issue #447 moved the server emission to the point D frame.
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	bResults, err := fp.ProcessPacket(b)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if len(bResults) != 0 {
		t.Fatalf("B: expected no results, got %v", bResults)
	}

	// Packet 3 (C): server -> client at t=100ms (no result yet)
	c := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	c.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("C: expected no results, got %d", len(results))
	}

	// Packet 4 (D): client -> server at t=150ms — should emit JA4L-S and JA4L-C
	d := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicHandshakePayload())
	d.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	dResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("D: %v", err)
	}
	if len(dResults) != 2 {
		t.Fatalf("D: expected two results, got %v", dResults)
	}
	if !strings.HasPrefix(dResults[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("D: expected the JA4L-S result first, got %v", dResults)
	}
	if !strings.HasPrefix(dResults[1].Fingerprint, "JA4L-C=") {
		t.Fatalf("D: expected the JA4L-C result second, got %v", dResults)
	}
}

// TestJA4LFillsTheQUICClientPointsInTheReferenceDirection holds the rule that the
// reference states. `ja4plus/fingerprinters/ja4l.py:589-599` fills point C from a server
// packet and point D from a client packet, and the client packet completes the value.
// The three `tls3.pcapng` JA4L-C entries reach no value while the two points are
// reversed. Issue #186 holds the reading.
func TestJA4LFillsTheQUICClientPointsInTheReferenceDirection(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// Point A. The client packet carries a TTL that no other packet of the flow carries,
	// so the client value proves which TTL it reports.
	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("A: expected no results, got %v", results)
	}

	// Point B. The server packet fills the server point, and the point D frame carries the
	// server value. Issue #447 holds that frame.
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	bResults, err := fp.ProcessPacket(b)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if len(bResults) != 0 {
		t.Fatalf("B: expected no results, got %v", bResults)
	}

	// Point C. The server Handshake packet fills the point, and it completes no value.
	c := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	c.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("C: expected no results, got %v", results)
	}

	// Point D. The client Handshake packet completes the client value.
	d := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicHandshakePayload())
	d.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	dResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("D: %v", err)
	}
	if len(dResults) != 2 {
		t.Fatalf("D: expected two results, got %v", dResults)
	}
	if dResults[1].Fingerprint != "JA4L-C=25000_55_quic" {
		t.Errorf("D: Fingerprint = %q, want %q", dResults[1].Fingerprint, "JA4L-C=25000_55_quic")
	}
}

// TestJA4LMovesTheQUICClientPointToTheLastServerPacket holds the rule that the reference
// states. `ja4plus/fingerprinters/ja4l.py:591-593` writes point C for every server packet
// that leads point D, so the last server packet supplies the point.
// Issue #186 holds the reading.
func TestJA4LMovesTheQUICClientPointToTheLastServerPacket(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("A: expected no results, got %v", results)
	}

	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(10 * time.Millisecond)
	if results, _ := fp.ProcessPacket(b); len(results) != 0 {
		t.Fatalf("B: expected no results, got %v", results)
	}

	// The server sends two more Handshake packets. The second of them supplies point C.
	for _, offset := range []time.Duration{20, 30} {
		server := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
		server.Metadata().Timestamp = baseTime.Add(offset * time.Millisecond)
		if results, _ := fp.ProcessPacket(server); len(results) != 0 {
			t.Fatalf("server packet at %dms: expected no results, got %v", offset, results)
		}
	}

	// The client packet measures against the last server packet, at 30ms and not at 20ms.
	d := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicHandshakePayload())
	d.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	dResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("D: %v", err)
	}
	if len(dResults) != 2 {
		t.Fatalf("D: expected two results, got %v", dResults)
	}
	if dResults[1].Fingerprint != "JA4L-C=10000_55_quic" {
		t.Errorf("D: Fingerprint = %q, want %q", dResults[1].Fingerprint, "JA4L-C=10000_55_quic")
	}

	// Point C stops at point D, so a later server packet moves nothing.
	late := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	late.Metadata().Timestamp = baseTime.Add(60 * time.Millisecond)
	if results, _ := fp.ProcessPacket(late); len(results) != 0 {
		t.Fatalf("late server packet: expected no results, got %v", results)
	}
}

// TestJA4LFillsTheQUICClientPointsOnlyFromAHandshakePacket holds the rule that the
// reference states. `ja4plus/fingerprinters/ja4l.py:580-581` returns None for every
// long-header packet type except a Handshake packet, so an Initial packet fills neither
// client point. `tls3.pcapng` stream 25 holds a JA4L-C value that the vector does not
// hold while the gate is absent. Issue #186 holds the reading.
func TestJA4LFillsTheQUICClientPointsOnlyFromAHandshakePacket(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("A: expected no results, got %v", results)
	}

	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(10 * time.Millisecond)
	if results, _ := fp.ProcessPacket(b); len(results) != 0 {
		t.Fatalf("B: expected no results, got %v", results)
	}

	// A second server Initial packet fills no point, so the client packet that follows it
	// completes no value.
	serverInitial := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	serverInitial.Metadata().Timestamp = baseTime.Add(20 * time.Millisecond)
	if results, _ := fp.ProcessPacket(serverInitial); len(results) != 0 {
		t.Fatalf("server Initial: expected no results, got %v", results)
	}

	clientInitial := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicLongHeaderPayload())
	clientInitial.Metadata().Timestamp = baseTime.Add(30 * time.Millisecond)
	if results, _ := fp.ProcessPacket(clientInitial); len(results) != 0 {
		t.Fatalf("client Initial: expected no results, got %v", results)
	}

	// The two Handshake packets do fill the two points, which proves the packet type is the
	// one thing that separates the two pairs.
	serverHandshake := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	serverHandshake.Metadata().Timestamp = baseTime.Add(40 * time.Millisecond)
	if results, _ := fp.ProcessPacket(serverHandshake); len(results) != 0 {
		t.Fatalf("server Handshake: expected no results, got %v", results)
	}

	clientHandshake := buildUDPPacketWithIPs(t, clientIP, serverIP, 55, 50000, 443, quicHandshakePayload())
	clientHandshake.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	results, err := fp.ProcessPacket(clientHandshake)
	if err != nil {
		t.Fatalf("client Handshake: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("client Handshake: expected two results, got %v", results)
	}
	if results[1].Fingerprint != "JA4L-C=5000_55_quic" {
		t.Errorf("client Handshake: Fingerprint = %q, want %q", results[1].Fingerprint, "JA4L-C=5000_55_quic")
	}
}

// TestJA4LReadsTheDirectionOfAUDPFlowFromThePort holds the rule that the reference
// states. `ja4plus/fingerprinters/ja4l.py:561-562` reads the direction from the UDP port
// alone, so a server packet that leads its client packet starts no measurement.
// Issue #173 holds the reading.
func TestJA4LReadsTheDirectionOfAUDPFlowFromThePort(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	serverIP := net.IP{10, 0, 0, 1}
	clientIP := net.IP{192, 168, 1, 1}

	// The server packet leads, and the port names it as the server.
	p1 := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	p1.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(p1); len(results) != 0 {
		t.Fatalf("p1: expected no results, got %v", results)
	}

	// The client packet fills the first measurement point, and it completes no value.
	p2 := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicLongHeaderPayload())
	p2.Metadata().Timestamp = baseTime.Add(20 * time.Millisecond)
	if results, _ := fp.ProcessPacket(p2); len(results) != 0 {
		t.Fatalf("p2: expected no results, got %v", results)
	}

	// The next server packet fills the server point.
	p3 := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	p3.Metadata().Timestamp = baseTime.Add(40 * time.Millisecond)
	if r3, _ := fp.ProcessPacket(p3); len(r3) != 0 {
		t.Fatalf("p3: expected no results, got %v", r3)
	}

	// The two Handshake packets complete the connection, and the point D frame carries the
	// server value. Issue #447 holds that frame.
	p4 := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	p4.Metadata().Timestamp = baseTime.Add(60 * time.Millisecond)
	if r4, _ := fp.ProcessPacket(p4); len(r4) != 0 {
		t.Fatalf("p4: expected no results, got %v", r4)
	}

	p5 := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicHandshakePayload())
	p5.Metadata().Timestamp = baseTime.Add(80 * time.Millisecond)
	r5, _ := fp.ProcessPacket(p5)
	if len(r5) != 2 || !strings.HasPrefix(r5[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("p5: expected JA4L-S, got %v", r5)
	}

	// The server value measures the client packet against the server packet that follows
	// it, and never the server packet that leads it. 20 milliseconds halve to 10000.
	if r5[0].Fingerprint != "JA4L-S=10000_64_quic" {
		t.Errorf("p5: Fingerprint = %q, want %q", r5[0].Fingerprint, "JA4L-S=10000_64_quic")
	}
}

// TestJA4LProducesNoJA4LSForTheNTPFlowOfGreSamplePcap holds the rule that the reference
// states. `ja4plus/fingerprinters/ja4l.py:554-558` returns None when the UDP payload
// carries no QUIC long header, and an NTP message carries none.
// `gre-sample.pcap` carries six NTP messages on port 123, and the FoxIO vector holds no
// JA4L value and no JA4LS value for them. Issue #173 holds the reading.
func TestJA4LProducesNoJA4LSForTheNTPFlowOfGreSamplePcap(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	packets := []gopacket.Packet{
		buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 123, ntpPayload()),
		buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 123, 50000, ntpPayload()),
		buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 123, ntpPayload()),
		buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 123, 50000, ntpPayload()),
	}
	for i, packet := range packets {
		packet.Metadata().Timestamp = baseTime.Add(time.Duration(i) * 20 * time.Millisecond)
		results, err := fp.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if len(results) != 0 {
			t.Fatalf("packet %d: expected no results, got %v", i, results)
		}
	}
}

// TestJA4LProducesNoValueForANonQUICPayloadOnPort443 isolates the QUIC long-header gate.
// The two ports name a direction here, so the port rule admits this flow and the payload
// alone decides. The test fails when the gate goes away.
// `ja4plus/fingerprinters/ja4l.py:554-558` states the rule. Issue #173 holds the reading.
func TestJA4LProducesNoValueForANonQUICPayloadOnPort443(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// The client packet carries no QUIC long header, so it fills no measurement point.
	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, ntpPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("a: expected no results, got %v", results)
	}

	// The server packet completes no value, because the first packet filled no point.
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, ntpPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	if results, _ := fp.ProcessPacket(b); len(results) != 0 {
		t.Fatalf("b: expected no results, got %v", results)
	}

	// The same two ports with a QUIC long header do produce a value, which proves the
	// payload is the one thing that separates the two runs. The point D frame carries the
	// server value, and issue #447 holds that frame.
	fp = NewJA4L()
	c := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicLongHeaderPayload())
	c.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("c: expected no results, got %v", results)
	}
	d := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	d.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	if dResults, _ := fp.ProcessPacket(d); len(dResults) != 0 {
		t.Fatalf("d: expected no results, got %v", dResults)
	}

	e := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicHandshakePayload())
	e.Metadata().Timestamp = baseTime.Add(70 * time.Millisecond)
	if results, _ := fp.ProcessPacket(e); len(results) != 0 {
		t.Fatalf("e: expected no results, got %v", results)
	}

	f := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicHandshakePayload())
	f.Metadata().Timestamp = baseTime.Add(90 * time.Millisecond)
	fResults, _ := fp.ProcessPacket(f)
	if len(fResults) != 2 || !strings.HasPrefix(fResults[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("f: expected the JA4L-S result first, got %v", fResults)
	}
}

// TestJA4LProducesNoValueWhenBothUDPPortsAre443 holds the rule that the reference states.
// `ja4plus/fingerprinters/ja4l.py:563-566` returns None for such a flow, because the two
// ports name no server. Issue #173 holds the reading.
func TestJA4LProducesNoValueWhenBothUDPPortsAre443(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	one := net.IP{192, 168, 1, 1}
	two := net.IP{10, 0, 0, 1}

	p1 := buildUDPPacketWithIPs(t, one, two, 64, 443, 443, quicLongHeaderPayload())
	p1.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(p1); len(results) != 0 {
		t.Fatalf("p1: expected no results, got %v", results)
	}

	p2 := buildUDPPacketWithIPs(t, two, one, 64, 443, 443, quicLongHeaderPayload())
	p2.Metadata().Timestamp = baseTime.Add(20 * time.Millisecond)
	if results, _ := fp.ProcessPacket(p2); len(results) != 0 {
		t.Fatalf("p2: expected no results, got %v", results)
	}
}

// TestJA4LHalvesTheServerLatencyOfBadcurveballPcap holds the rule that the reference
// states. `docs/specs/foxio/JA4L.md` R6 states that part a is half of the measured time.
// R6 cites four FoxIO reference implementations that each divide by 2.
// The test builds the handshake of `badcurveball.pcap` stream 0 rather than reads the
// capture. That handshake spans 1563 microseconds and carries the server TTL 238.
// The FoxIO per-stream vector holds `JA4L-S` of `781_238`, and 1563 / 2 truncates to 781.
// A rounded half gives 782, so this handshake separates the two rounding rules.
// Issue #166 holds the reading.
func TestJA4LHalvesTheServerLatencyOfBadcurveballPcap(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(synPkt); len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %v", results)
	}

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 238, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(1563 * time.Microsecond)
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SYN-ACK: expected 1 result, got %d", len(results))
	}
	if results[0].Fingerprint != "JA4L-S=781_238" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", results[0].Fingerprint, "JA4L-S=781_238")
	}
}

// TestJA4LHalvesTheClientLatency holds the same rule on the client value.
// `docs/specs/foxio/JA4L.md` R7 states that part a of a TCP connection measures the ACK
// against the SYN-ACK. The time here is 4355 microseconds, which truncates to 2177.
// Issue #166 holds the reading.
func TestJA4LHalvesTheClientLatency(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	synPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPPacketWithIPs(t, serverIP, clientIP, 238, 443, 12345, true, true)
	synAckPkt.Metadata().Timestamp = baseTime.Add(1563 * time.Microsecond)
	_, _ = fp.ProcessPacket(synAckPkt)

	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add((1563 + 4355) * time.Microsecond)
	results, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("ACK: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ACK: expected 1 result, got %d", len(results))
	}
	if results[0].Fingerprint != "JA4L-C=2177_64" {
		t.Errorf("ACK: Fingerprint = %q, want %q", results[0].Fingerprint, "JA4L-C=2177_64")
	}
}

// buildTCPStreamPacket builds one TCP packet with explicit sequence numbers and a payload.
// The client measurement point reads the relative sequence number, the relative
// acknowledgment number and the payload, so a test of that rule states all three.
// The function reads the address family from srcIP.
func buildTCPStreamPacket(
	t testing.TB,
	srcIP, dstIP net.IP,
	ttl uint8,
	srcPort, dstPort uint16,
	syn, ack bool,
	seq, acknum uint32,
	payload []byte,
) gopacket.Packet {
	t.Helper()

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Seq:     seq,
		Ack:     acknum,
		Window:  65535,
	}

	eth := &layers.Ethernet{
		SrcMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
	}

	var network gopacket.SerializableLayer
	if srcIP.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			TTL:      ttl,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		network = ip
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{
			SrcIP:      srcIP,
			DstIP:      dstIP,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   ttl,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		network = ip
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, network, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// ja4lLastFingerprint returns the fingerprint of the one result the packet gives.
// It fails the test when the packet gives more than one result, because JA4L reports one
// value for one packet.
func ja4lLastFingerprint(t *testing.T, results []FingerprintResult) string {
	t.Helper()

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	return results[0].Fingerprint
}

// TestJA4LMovesTheClientPointToTheClientHelloOfBadcurveballPcap holds the client point rule
// of the reference on the four frames that open stream 0 of `badcurveball.pcap`.
//
// `python/ja4.py:570` records the client point on every packet that
// carries `ACK`, carries no `SYN`, and holds the relative sequence number `1` and the
// relative acknowledgment number `1`. `python/common.py:101` omits
// `C` from the fields it declines to update, so a later packet moves the point.
//
// The bare ACK arrives at `+0.005918s` and the Client Hello at `+0.005925s`, so the point
// moves 7 microseconds and the value moves from `2177_64` to `2181_64`. The per-stream
// vector holds `2181_64`. Issue #196 holds the reading.
func TestJA4LMovesTheClientPointToTheClientHelloOfBadcurveballPcap(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{172, 130, 128, 76}
	serverIP := net.IP{54, 226, 182, 138}

	const (
		clientISN uint32 = 2717333804
		serverISN uint32 = 1253214926
	)

	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 55318, 443, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(synPkt); len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %v", results)
	}

	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 238, 443, 55318, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(1563 * time.Microsecond)
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=781_238" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=781_238")
	}

	ackPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 55318, 443, false, true, clientISN+1, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(5918 * time.Microsecond)
	results, err = fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("bare ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=2177_64" {
		t.Errorf("bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=2177_64")
	}

	// The Client Hello carries the first payload byte of the client, so it holds the
	// relative sequence number `1` and it moves the point.
	clientHello := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc}
	helloPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 55318, 443, false, true, clientISN+1, serverISN+1, clientHello)
	helloPkt.Metadata().Timestamp = baseTime.Add(5925 * time.Microsecond)
	results, err = fp.ProcessPacket(helloPkt)
	if err != nil {
		t.Fatalf("Client Hello: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=2181_64" {
		t.Errorf("Client Hello: Fingerprint = %q, want %q", got, "JA4L-C=2181_64")
	}
}

// TestJA4LMovesNoClientPointForAPacketThatAcknowledgesPayload holds the second half of the
// relative number rule. Frame 5 of `badcurveball.pcap` acknowledges the 517 payload bytes of
// the Client Hello, so its relative acknowledgment number is 518 and it moves no point.
// `python/ja4.py:570` states the rule. Issue #196 holds the reading.
func TestJA4LMovesNoClientPointForAPacketThatAcknowledgesPayload(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{172, 130, 128, 76}
	serverIP := net.IP{54, 226, 182, 138}

	const (
		clientISN uint32 = 2717333804
		serverISN uint32 = 1253214926
	)

	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 55318, 443, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 238, 443, 55318, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(1563 * time.Microsecond)
	_, _ = fp.ProcessPacket(synAckPkt)

	ackPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 55318, 443, false, true, clientISN+1, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(5918 * time.Microsecond)
	_, _ = fp.ProcessPacket(ackPkt)

	// The server acknowledges 517 payload bytes, so the relative acknowledgment number
	// reads 518.
	serverAck := buildTCPStreamPacket(t, serverIP, clientIP, 238, 443, 55318, false, true, serverISN+1, clientISN+518, nil)
	serverAck.Metadata().Timestamp = baseTime.Add(21617 * time.Microsecond)
	results, err := fp.ProcessPacket(serverAck)
	if err != nil {
		t.Fatalf("server ACK: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("server ACK: expected no results, got %v", results)
	}
}

// TestJA4LKeepsTheClientPointOnTheBareACKOfLatestPcapngStream6 holds the first half of the
// complete request rule.
//
// `python/common.py:77-83` returns a separate cache for a packet
// whose highest layer is `http` or `http2`. That cache holds no point `A` and no point `B`,
// so a packet carrying a whole HTTP request moves the client point of no connection.
//
// Stream 6 of `latest.pcapng` sends one complete `GET` request. The reference `JA4L-C` is
// `32_128`, which is the bare ACK. Issue #196 holds the reading.
func TestJA4LKeepsTheClientPointOnTheBareACKOfLatestPcapngStream6(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{172, 16, 225, 48}
	serverIP := net.IP{23, 43, 242, 57}

	const (
		clientISN uint32 = 2970935134
		serverISN uint32 = 3731049676
	)

	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 128, 52939, 80, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 57, 80, 52939, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(7831 * time.Microsecond)
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=3915_57" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=3915_57")
	}

	ackPkt := buildTCPStreamPacket(t, clientIP, serverIP, 128, 52939, 80, false, true, clientISN+1, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(7896 * time.Microsecond)
	results, err = fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("bare ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=32_128" {
		t.Errorf("bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=32_128")
	}

	// The request holds the blank line that ends the header block, so it moves no point.
	request := []byte("GET /roots/dstrootcax3.crl HTTP/1.1\r\nHost: crl.identrust.com\r\n\r\n")
	requestPkt := buildTCPStreamPacket(t, clientIP, serverIP, 128, 52939, 80, false, true, clientISN+1, serverISN+1, request)
	requestPkt.Metadata().Timestamp = baseTime.Add(8091 * time.Microsecond)
	results, err = fp.ProcessPacket(requestPkt)
	if err != nil {
		t.Fatalf("complete request: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("complete request: expected no results, got %v", results)
	}
}

// TestJA4LMovesTheClientPointToThePartialRequestOfHttpEmptyUseragentPcap holds the second
// half of the complete request rule, and it holds the TTL rule of the client point.
//
// `http-empty-useragent.pcap` sends the request line, the header and the blank line in three
// packets. The request line holds no blank line, so the dissector reports it as a TCP packet
// and it moves the client point. The reference `JA4L-C` is `177863_64`.
//
// Frame 4 is a bare ACK the server sends, and it holds the relative sequence number `1` and
// the relative acknowledgment number `1`. It moves the point, and
// `python/ja4.py:159` reads `client_ttl` for every client value.
// Issue #196 holds the reading.
func TestJA4LMovesTheClientPointToThePartialRequestOfHttpEmptyUseragentPcap(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	loopback := net.ParseIP("::1")

	const (
		clientISN uint32 = 2654111798
		serverISN uint32 = 3940423380
	)

	synPkt := buildTCPStreamPacket(t, loopback, loopback, 64, 57722, 9200, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPStreamPacket(t, loopback, loopback, 55, 9200, 57722, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(53 * time.Microsecond)
	_, _ = fp.ProcessPacket(synAckPkt)

	ackPkt := buildTCPStreamPacket(t, loopback, loopback, 64, 57722, 9200, false, true, clientISN+1, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(63 * time.Microsecond)
	results, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("client bare ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=5_64" {
		t.Errorf("client bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=5_64")
	}

	// The server sends this bare ACK, and the client TTL of 64 fills the value. The hop
	// limit of this packet is 55, so a value of `10_55` reads the wrong TTL.
	serverAck := buildTCPStreamPacket(t, loopback, loopback, 55, 9200, 57722, false, true, serverISN+1, clientISN+1, nil)
	serverAck.Metadata().Timestamp = baseTime.Add(74 * time.Microsecond)
	results, err = fp.ProcessPacket(serverAck)
	if err != nil {
		t.Fatalf("server bare ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=10_64" {
		t.Errorf("server bare ACK: Fingerprint = %q, want %q", got, "JA4L-C=10_64")
	}

	// The request line holds no blank line, so it moves the point.
	requestLine := buildTCPStreamPacket(t, loopback, loopback, 64, 57722, 9200, false, true,
		clientISN+1, serverISN+1, []byte("GET / HTTP/1.0\n"))
	requestLine.Metadata().Timestamp = baseTime.Add(355780 * time.Microsecond)
	results, err = fp.ProcessPacket(requestLine)
	if err != nil {
		t.Fatalf("request line: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=177863_64" {
		t.Errorf("request line: Fingerprint = %q, want %q", got, "JA4L-C=177863_64")
	}

	// The header line starts at the relative sequence number 16, so it moves no point.
	headerLine := buildTCPStreamPacket(t, loopback, loopback, 64, 57722, 9200, false, true,
		clientISN+16, serverISN+1, []byte("User-Agent:\n"))
	headerLine.Metadata().Timestamp = baseTime.Add(355849 * time.Microsecond)
	results, err = fp.ProcessPacket(headerLine)
	if err != nil {
		t.Fatalf("header line: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("header line: expected no results, got %v", results)
	}
}

// TestJA4LMovesNoServerPointForARepeatedSynAck holds the rule that point B never moves.
//
// `python/common.py:101` names `A` and `B` among the fields that the reference declines to
// update, so a repeated SYN-ACK keeps the first timestamp. A second server value would repeat
// the first, and the reference publishes one server value for one connection.
// `ja4plus/fingerprinters/ja4l.py:456-461` holds the same rule, and the port measured the
// repeat on `ssh2.pcapng` stream 15 in its issue #272.
//
// Every FoxIO reference agrees here, so this is a reading and not a ruling. The maintainer
// ruled on 2026-08-12 in issue #196 that the conformance harness compares the last emission,
// which is what makes a repeated server value reach the comparison.
//
// The test holds FR-parity-17, FR-parity-18 and FR-parity-23. It builds two SYN-ACK packets,
// and it asserts one server value.
func TestJA4LMovesNoServerPointForARepeatedSynAck(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const (
		clientISN uint32 = 1000
		serverISN uint32 = 2000
	)

	synPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, clientISN, 0, nil)
	synPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synPkt)

	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 58, 443, 12345, true, true, serverISN, clientISN+1, nil)
	synAckPkt.Metadata().Timestamp = baseTime.Add(12504 * time.Microsecond)
	results, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=6252_58" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=6252_58")
	}

	// The server repeats the SYN-ACK. The packet moves no point, and it reports no value.
	repeatPkt := buildTCPStreamPacket(t, serverIP, clientIP, 58, 443, 12345, true, true, serverISN, clientISN+1, nil)
	repeatPkt.Metadata().Timestamp = baseTime.Add(18334 * time.Microsecond)
	results, err = fp.ProcessPacket(repeatPkt)
	if err != nil {
		t.Fatalf("repeated SYN-ACK: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("repeated SYN-ACK: expected no results, got %v", results)
	}
}

// TestJA4LMovesNoClientPointWhenTheCaptureHoldsNoSYN holds the guard that a relative number
// needs. `python/ja4.py:570` reads the relative sequence number that
// the dissector counts from the initial sequence number of each endpoint. A capture that
// holds no SYN for one endpoint reaches no relative number, so it reaches no client point.
// Issue #196 holds the reading.
func TestJA4LMovesNoClientPointWhenTheCaptureHoldsNoSYN(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const serverISN uint32 = 1253214926

	// The capture starts at the SYN-ACK, so the initial sequence number of the client is
	// unknown.
	synAckPkt := buildTCPStreamPacket(t, serverIP, clientIP, 64, 443, 12345, true, true, serverISN, 99, nil)
	synAckPkt.Metadata().Timestamp = baseTime
	_, _ = fp.ProcessPacket(synAckPkt)

	ackPkt := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, false, true, 100, serverISN+1, nil)
	ackPkt.Metadata().Timestamp = baseTime.Add(100 * time.Microsecond)
	results, err := fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("bare ACK: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("bare ACK: expected no results, got %v", results)
	}
}

// TestJA4LWritesTwoPartsOnATCPConnectionInGeneve holds the TCP half of the ruling of
// issue #127 in this repository. The port's issue #127 rules the JA4 ALPN value instead,
// so a reader who reads that number bare reaches the wrong ruling. Issue #255 records the
// collision. The ruling writes two parts on a TCP connection, and it declines the third part
// that Wireshark writes there. Every candidate answer to the open QUIC question keeps this
// part count, so this test holds under each one. `docs/specs/foxio/JA4L.md` R29 records the
// split, R30 records the `tcp` literal that this project declines, and R35 records the open
// question.
//
// The `tcpdump-geneve.pcap` frame 13 per-packet vector holds `ja4.ja4l` as `93_64_124` and
// `ja4.ja4ls` as `24_64_380`. The third number of each one is the Wireshark part c, which
// `docs/specs/foxio/JA4L.md` R24 names as the numerator of `ja4.ja4l_delta`. The vector
// holds that delta as `1.3`, and `124 / 93` reads `1.3`. This test holds the part count,
// so it fails when a repair writes a marker on a TCP connection. Port issue #225 holds the
// other half.
//
// The test holds FR-parity-19. TestJA4LWritesNoTCPLiteralInAnyValue holds FR-parity-21, which
// reads the same ruling over a TCP connection and a QUIC connection together.
func TestJA4LWritesTwoPartsOnATCPConnectionInGeneve(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	syn := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, true, false)
	syn.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(syn); len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %v", results)
	}

	synAck := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, true, true)
	synAck.Metadata().Timestamp = baseTime.Add(48 * time.Microsecond)
	serverResults, err := fp.ProcessPacket(synAck)
	if err != nil {
		t.Fatalf("SYN-ACK: %v", err)
	}
	if len(serverResults) != 1 {
		t.Fatalf("SYN-ACK: expected one result, got %v", serverResults)
	}
	if serverResults[0].Fingerprint != "JA4L-S=24_64" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", serverResults[0].Fingerprint, "JA4L-S=24_64")
	}

	bareACK := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, false, true)
	bareACK.Metadata().Timestamp = baseTime.Add(234 * time.Microsecond)
	clientResults, err := fp.ProcessPacket(bareACK)
	if err != nil {
		t.Fatalf("bare ACK: %v", err)
	}
	if len(clientResults) != 1 {
		t.Fatalf("bare ACK: expected one result, got %v", clientResults)
	}
	if clientResults[0].Fingerprint != "JA4L-C=93_64" {
		t.Errorf("bare ACK: Fingerprint = %q, want %q", clientResults[0].Fingerprint, "JA4L-C=93_64")
	}
}

// TestJA4LWritesThreePartsOnAQUICConnectionInSsh2Pcapng holds the ruling of issue #197.
// A JA4L value of a QUIC connection carries the marker `quic` as the third part.
//
// The `ssh2.pcapng` frame 1147 per-packet vector holds `ja4.ja4l` as `169_128_quic` and
// `ja4.ja4ls` as `5389_57_quic`. This test builds the four measurement points that reach
// those two values, so it names the capture and the two methods that FR-gaps-2 requires.
// The client time-to-live is 128 and the server time-to-live is 57, which separates the
// two values.
//
// `ja4plus/fingerprinters/ja4l.py:62` defines `QUIC_MARKER = "quic"`, and the port writes
// three parts at `:549` and at `:602`. Port issue #225 holds the other half.
//
// The test holds FR-parity-20, FR-parity-24 and FR-ja4ls-4.
func TestJA4LWritesThreePartsOnAQUICConnectionInSsh2Pcapng(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2023, 7, 6, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	// Point A. The client Initial packet starts the server measurement.
	a := buildUDPPacketWithIPs(t, clientIP, serverIP, 128, 50000, 443, quicLongHeaderPayload())
	a.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(a); len(results) != 0 {
		t.Fatalf("A: expected no results, got %v", results)
	}

	// Point B. The server Initial packet fills the server point, and 10778 microseconds
	// halve to the 5389 that the vector holds. The point D frame carries that value, and
	// issue #447 holds the frame.
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 57, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(10778 * time.Microsecond)
	serverResults, err := fp.ProcessPacket(b)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if len(serverResults) != 0 {
		t.Fatalf("B: expected no results, got %v", serverResults)
	}

	// Point C. The server Handshake packet fills the point, and it completes no value.
	c := buildUDPPacketWithIPs(t, serverIP, clientIP, 57, 443, 50000, quicHandshakePayload())
	c.Metadata().Timestamp = baseTime.Add(20000 * time.Microsecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("C: expected no results, got %v", results)
	}

	// Point D. The client Handshake packet completes the client value, and 338 microseconds
	// halve to the 169 that the vector holds.
	d := buildUDPPacketWithIPs(t, clientIP, serverIP, 128, 50000, 443, quicHandshakePayload())
	d.Metadata().Timestamp = baseTime.Add(20338 * time.Microsecond)
	clientResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("D: %v", err)
	}
	if len(clientResults) != 2 {
		t.Fatalf("D: expected two results, got %v", clientResults)
	}
	if clientResults[0].Fingerprint != "JA4L-S=5389_57_quic" {
		t.Errorf("D: Fingerprint = %q, want %q", clientResults[0].Fingerprint, "JA4L-S=5389_57_quic")
	}
	if clientResults[1].Fingerprint != "JA4L-C=169_128_quic" {
		t.Errorf("D: Fingerprint = %q, want %q", clientResults[1].Fingerprint, "JA4L-C=169_128_quic")
	}
}

// TestJA4LTimesASecondConnectionOnOneGroupingKeyFromItsOwnPoints holds the restart rule of the
// reference on a grouping key that two connections reach.
//
// A SYN that carries an initial sequence number the connection does not hold opens another
// connection on the same endpoints. `ja4plus/fingerprinters/ja4l.py:433-437` holds the test.
// `ja4plus/fingerprinters/ja4l.py:406-417` clears the state.
//
// The corpus holds no capture that reaches one grouping key twice, so this test builds the
// separating packet sequence. Issue #211 holds the reading, and port issue #272 holds the guard
// that makes the second value stale without the restart.
func TestJA4LTimesASecondConnectionOnOneGroupingKeyFromItsOwnPoints(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const (
		firstClientISN  uint32 = 1000
		firstServerISN  uint32 = 5000
		secondClientISN uint32 = 900000
		secondServerISN uint32 = 700000
	)

	// The first connection completes, and it reports both values.
	syn := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, firstClientISN, 0, nil)
	syn.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(syn); len(results) != 0 {
		t.Fatalf("first SYN: expected no results, got %v", results)
	}

	synAck := buildTCPStreamPacket(t, serverIP, clientIP, 64, 443, 12345, true, true, firstServerISN, firstClientISN+1, nil)
	synAck.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, err := fp.ProcessPacket(synAck)
	if err != nil {
		t.Fatalf("first SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=50000_64" {
		t.Errorf("first SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=50000_64")
	}

	ack := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, false, true, firstClientISN+1, firstServerISN+1, nil)
	ack.Metadata().Timestamp = baseTime.Add(200 * time.Millisecond)
	results, err = fp.ProcessPacket(ack)
	if err != nil {
		t.Fatalf("first ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=50000_64" {
		t.Errorf("first ACK: Fingerprint = %q, want %q", got, "JA4L-C=50000_64")
	}

	// The second connection reuses the grouping key 10 seconds later, and no caller calls
	// CleanupConnection between the two.
	secondStart := baseTime.Add(10 * time.Second)

	syn2 := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, secondClientISN, 0, nil)
	syn2.Metadata().Timestamp = secondStart
	if results, _ := fp.ProcessPacket(syn2); len(results) != 0 {
		t.Fatalf("second SYN: expected no results, got %v", results)
	}

	// The second server value measures the second SYN and the second SYN-ACK. Without the
	// restart the point B guard keeps the first timestamp, and the packet reports nothing.
	synAck2 := buildTCPStreamPacket(t, serverIP, clientIP, 64, 443, 12345, true, true, secondServerISN, secondClientISN+1, nil)
	synAck2.Metadata().Timestamp = secondStart.Add(150 * time.Millisecond)
	results, err = fp.ProcessPacket(synAck2)
	if err != nil {
		t.Fatalf("second SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=75000_64" {
		t.Errorf("second SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=75000_64")
	}

	// The second client value measures the second SYN-ACK and the second bare ACK. Without
	// the restart it measures the first SYN-ACK, and the value grows with the age of the
	// state.
	ack2 := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, false, true, secondClientISN+1, secondServerISN+1, nil)
	ack2.Metadata().Timestamp = secondStart.Add(320 * time.Millisecond)
	results, err = fp.ProcessPacket(ack2)
	if err != nil {
		t.Fatalf("second ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-C=85000_64" {
		t.Errorf("second ACK: Fingerprint = %q, want %q", got, "JA4L-C=85000_64")
	}
}

// TestJA4LKeepsPointAWhenARepeatedSYNCarriesTheSameInitialSequenceNumber holds the point A
// guard against the restart rule.
//
// A retransmitted SYN carries the initial sequence number the connection already holds, so it
// opens no second connection. `ja4plus/fingerprinters/ja4l.py:435` tests the sequence number
// before it restarts, and `python/common.py:101` names `A` among the fields that the reference
// declines to update. Issue #211 holds the reading, and issue #196 measured the guard on
// `ssh2.pcapng` stream 15.
func TestJA4LKeepsPointAWhenARepeatedSYNCarriesTheSameInitialSequenceNumber(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	const (
		clientISN uint32 = 1000
		serverISN uint32 = 5000
	)

	syn := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, clientISN, 0, nil)
	syn.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(syn); len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %v", results)
	}

	repeated := buildTCPStreamPacket(t, clientIP, serverIP, 64, 12345, 443, true, false, clientISN, 0, nil)
	repeated.Metadata().Timestamp = baseTime.Add(40 * time.Millisecond)
	if results, _ := fp.ProcessPacket(repeated); len(results) != 0 {
		t.Fatalf("repeated SYN: expected no results, got %v", results)
	}

	// The value measures the first SYN. A restart here would measure the repeated SYN, and
	// the value would read 30000.
	synAck := buildTCPStreamPacket(t, serverIP, clientIP, 64, 443, 12345, true, true, serverISN, clientISN+1, nil)
	synAck.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, err := fp.ProcessPacket(synAck)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}
	if got := ja4lLastFingerprint(t, results); got != "JA4L-S=50000_64" {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, "JA4L-S=50000_64")
	}
}

// TestJA4LHoldsOneClientValueForOneConnection holds FR-parity-16.
//
// The connection holds one client measurement point, and a later packet replaces the value of
// that point. Every emission carries the endpoints that `report()` fixed, so a caller that
// keys on the connection holds one client value.
//
// `ja4plus/fingerprinters/ja4l.py:177-180` states the rule:
//
//	# The reference holds one client value for one connection and overwrites it
//	# while the measurement point moves. A later packet therefore replaces the
//	# value this fingerprinter already reported, and it adds no second value.
//
// The port keeps the index of the value it reported, and it overwrites that entry. This
// library keeps no such index, because ProcessPacket returns each result to the caller.
// Issue #25 removed the results slice. The maintainer ruled in issue #196 that the
// conformance harness compares the last emission. That last emission carries the one client
// value of the connection.
//
// This test reads the count of results and the reported endpoints.
// TestJA4LMovesTheClientPointToARepeatedBareACK reads the two values instead, through
// ja4lLastFingerprint, which admits more than one result. Port issue #272 holds the other
// half.
func TestJA4LHoldsOneClientValueForOneConnection(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	syn := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, true, false)
	syn.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(syn); len(results) != 0 {
		t.Fatalf("SYN: expected no results, got %v", results)
	}

	synAck := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, true, true)
	synAck.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	if results, _ := fp.ProcessPacket(synAck); len(results) != 1 {
		t.Fatalf("SYN-ACK: expected one result, got %v", results)
	}

	firstACK := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	firstACK.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	firstResults, err := fp.ProcessPacket(firstACK)
	if err != nil {
		t.Fatalf("first bare ACK: unexpected error: %v", err)
	}
	if len(firstResults) != 1 {
		t.Fatalf("first bare ACK: expected one result, got %v", firstResults)
	}

	// The second packet runs from the server to the client. The client point moves in either
	// direction, at `ja4l.go:288`, so this packet reports the client value of the same
	// connection. A connection that did not fix its endpoints would name the reverse pair
	// here, and the caller would hold two client values.
	secondACK := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 12345, false, true)
	secondACK.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	secondResults, err := fp.ProcessPacket(secondACK)
	if err != nil {
		t.Fatalf("second bare ACK: unexpected error: %v", err)
	}
	if len(secondResults) != 1 {
		t.Fatalf("second bare ACK: expected one result, got %v", secondResults)
	}

	// The second value replaces the first one. Two equal values would read as one value that
	// the second packet repeated, and the point would then not have moved.
	if firstResults[0].Fingerprint == secondResults[0].Fingerprint {
		t.Errorf("the two emissions carry one value %q, and the client point did not move",
			firstResults[0].Fingerprint)
	}

	// The two emissions describe one connection, so each one carries the endpoints that the
	// first packet fixed. A second endpoint pair would name a second connection, and the
	// caller would then hold two client values.
	if firstResults[0].SrcIP != secondResults[0].SrcIP ||
		firstResults[0].DstIP != secondResults[0].DstIP ||
		firstResults[0].SrcPort != secondResults[0].SrcPort ||
		firstResults[0].DstPort != secondResults[0].DstPort {
		t.Errorf("the two emissions name two connections: %s:%d-%s:%d and %s:%d-%s:%d",
			firstResults[0].SrcIP, firstResults[0].SrcPort,
			firstResults[0].DstIP, firstResults[0].DstPort,
			secondResults[0].SrcIP, secondResults[0].SrcPort,
			secondResults[0].DstIP, secondResults[0].DstPort)
	}

	// The connection holds one client point, so the state map holds one entry for `C`.
	conn, held := fp.connections["tcp_10.0.0.1:443_192.168.1.1:12345"]
	if !held {
		t.Fatalf("the fingerprinter holds no connection, and it holds %v", fp.connections)
	}
	if _, held := conn.timestamps["C"]; !held {
		t.Errorf("the connection holds no client point, and it holds %v", conn.timestamps)
	}
}

// TestJA4LWritesNoTCPLiteralInAnyValue holds FR-parity-21.
//
// `docs/specs/foxio/JA4L.md` R30 records the split that this project declines. Wireshark
// writes the format `"%d_%d_tcp"` at `wireshark/source/packet-ja4.c:1348` and at
// `wireshark/source/packet-ja4.c:1354`, and Zeek writes no such marker at
// `zeek/ja4l/main.zeek:133`. The maintainer ruled on issue #247, and round 25 of the
// `## Changelog` of `docs/specs/spec.md` records it: "The maintainer ruled on #247, and
// `#127` stands."
//
// The library writes a marker for a QUIC connection alone, at `ja4l.go:487-489`. This test
// reads a TCP connection and a QUIC connection together, so it fails when a repair writes the
// literal `tcp` on either one. Port issue #225 holds the other half.
func TestJA4LWritesNoTCPLiteralInAnyValue(t *testing.T) {
	fp := NewJA4L()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	syn := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, true, false)
	syn.Metadata().Timestamp = baseTime
	synAck := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, true, true)
	synAck.Metadata().Timestamp = baseTime.Add(48 * time.Microsecond)
	bareACK := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, false, true)
	bareACK.Metadata().Timestamp = baseTime.Add(234 * time.Microsecond)

	tcpValues := ja4lCollectValues(t, fp, syn, synAck, bareACK)
	if len(tcpValues) != 2 {
		t.Fatalf("the TCP connection reports %d values, and it must report the server value and the client value: %v",
			len(tcpValues), tcpValues)
	}

	pointA := buildUDPPacketWithIPs(t, clientIP, serverIP, 128, 50000, 443, quicLongHeaderPayload())
	pointA.Metadata().Timestamp = baseTime
	pointB := buildUDPPacketWithIPs(t, serverIP, clientIP, 57, 443, 50000, quicLongHeaderPayload())
	pointB.Metadata().Timestamp = baseTime.Add(10778 * time.Microsecond)
	pointC := buildUDPPacketWithIPs(t, serverIP, clientIP, 57, 443, 50000, quicHandshakePayload())
	pointC.Metadata().Timestamp = baseTime.Add(20000 * time.Microsecond)
	pointD := buildUDPPacketWithIPs(t, clientIP, serverIP, 128, 50000, 443, quicHandshakePayload())
	pointD.Metadata().Timestamp = baseTime.Add(20338 * time.Microsecond)

	quicValues := ja4lCollectValues(t, NewJA4L(), pointA, pointB, pointC, pointD)
	if len(quicValues) != 2 {
		t.Fatalf("the QUIC connection reports %d values, and it must report the server value and the client value: %v",
			len(quicValues), quicValues)
	}

	for _, value := range append(tcpValues, quicValues...) {
		if strings.Contains(value, "tcp") {
			t.Errorf("the value %q holds the literal tcp, and R30 records the split that this project declines", value)
		}
	}
}

// TestTheRegisterHoldsAJA4LDeclineForEveryFileThatPublishesNoJA4LKey holds the maintainer's
// ruling of 2026-08-13 on #361, and it reverses the guard that #52 wrote on 2026-08-12.
//
// #52 held that the register could hold no such decline. The harness dropped a value whose
// vector file names no key for its method. No comparison reached the key, and
// `conformanceCheckOrphans` failed the run for the entry. That doc comment named #361 as the
// reversal path, and this is that reversal.
//
// The harness now compares the value and reports it as an uncovered value, which is neither a
// match nor a deviation. `conformance_engine_test.go` holds `conformanceSplitUncovered`, and
// the register therefore holds one decline for each such comparison.
//
// The port declines the same values. `Crank-Git/ja4plus` holds five rows in
// `tests/foxio_deviations.json` at the tag `v1.1.0`, on lines 2, 8, 452, 458 and 674. Each row
// carries `"issue": 272`, `"decided": true` and `"capability": false`, and the port's issue
// #272 decided them on 2026-08-08. **The port names a capture and a method in one key.** This
// repository names a capture, a stream and a method, so one port row covers more than one
// entry here.
//
// The two libraries now agree on the bookkeeping as well as on the observable behavior.
//
// The mechanism is not specific to JA4L. `testdata/foxio/python/socks4-https.pcap.json`
// publishes no JA4X key, and issue #57 owns FR-parity-50 and the JA4X entries.
func TestTheRegisterHoldsAJA4LDeclineForEveryFileThatPublishesNoJA4LKey(t *testing.T) {
	// The three reference files that publish no JA4L key. `python/ja4.py:340` runs
	// `delete_keys(['JA4L-S', 'JA4L-C'], final)` when the run names another method, so the
	// method filter removed the key from each file.
	captures := []string{"CVE-2018-6794.pcap", "https-connect.pcap", "tls-handshake.pcapng"}

	// A decline records a value the library produces, so a capture where the library
	// produces no JA4L value needs none. `tls-handshake.pcapng` holds QUIC Initial packets
	// alone, so no connection of it fills point C or point D, and issue #447 moved the
	// server emission to the point D frame. Issue #447 therefore removed the 20 entries of
	// that capture, and the run now reaches no JA4L comparison for it.
	declineCaptures := []string{"CVE-2018-6794.pcap", "https-connect.pcap"}

	declines := make(map[string]int, len(captures))

	for _, entry := range readDeviationRegister(t) {
		if entry.Ruling != "#361" {
			continue
		}

		capture, rest, held := strings.Cut(entry.Key, "/")
		if !held {
			t.Errorf("the entry %q names no stream and no method", entry.Key)

			continue
		}

		method := rest
		if _, tail, cut := strings.Cut(rest, "/"); cut {
			method = tail
		}

		// Both the `JA4L` spelling and the `JA4L-C` spelling start with `JA4L`.
		if !strings.HasPrefix(method, "JA4L") {
			t.Errorf("the entry %q names the method %q, and #361 declines a JA4L value alone", entry.Key, method)

			continue
		}

		if !slices.Contains(captures, capture) {
			t.Errorf("the entry %q names the capture %q, and that file publishes a JA4L key", entry.Key, capture)

			continue
		}

		declines[capture]++
	}

	for _, capture := range declineCaptures {
		if declines[capture] == 0 {
			t.Errorf("the register holds no #361 decline for %s, and the library produces a JA4L value for it", capture)
		}
	}

	if declines["tls-handshake.pcapng"] != 0 {
		t.Errorf("the register holds %d #361 declines for tls-handshake.pcapng, and the library produces no JA4L value for it",
			declines["tls-handshake.pcapng"])
	}
}

// ja4lCollectValues returns the fingerprint of every result that the packets report, in
// packet order. It fails the test when a packet reports an error.
func ja4lCollectValues(t *testing.T, fp *JA4LFingerprinter, packets ...gopacket.Packet) []string {
	t.Helper()

	var values []string

	for index, packet := range packets {
		results, err := fp.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("packet %d: unexpected error: %v", index, err)
		}

		for _, result := range results {
			values = append(values, result.Fingerprint)
		}
	}

	return values
}
