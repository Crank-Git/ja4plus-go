package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPacketWithIPs builds a TCP packet with specified IPs and TTL.
func buildTCPPacketWithIPs(t testing.TB, srcIP, dstIP net.IP, ttl uint8, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	t.Helper()
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
	expected := "JA4L-S=100000_64"
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
	expected = "JA4L-C=100000_64"
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

func TestJA4L_DuplicateACK(t *testing.T) {
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

	// First ACK — should produce JA4L-C
	ackPkt := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	results, _ := fp.ProcessPacket(ackPkt)
	if len(results) != 1 {
		t.Fatalf("first ACK: expected 1 result, got %d", len(results))
	}

	// Second ACK — should be ignored
	ackPkt2 := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 443, false, true)
	ackPkt2.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	results, _ = fp.ProcessPacket(ackPkt2)
	if len(results) != 0 {
		t.Errorf("duplicate ACK: expected no results, got %d", len(results))
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
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, Window: 65535}
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
	expected := "JA4L-S=100000_64"
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
	expected = "JA4L-C=100000_64"
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

	// Packet 2 (B): server -> client at t=50ms — should emit JA4L-S
	b := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	b.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	bResults, err := fp.ProcessPacket(b)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if len(bResults) != 1 || !strings.HasPrefix(bResults[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("B: expected one JA4L-S result, got %v", bResults)
	}

	// Packet 3 (C): client -> server at t=100ms (no result yet)
	c := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicLongHeaderPayload())
	c.Metadata().Timestamp = baseTime.Add(100 * time.Millisecond)
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("C: expected no results, got %d", len(results))
	}

	// Packet 4 (D): server -> client at t=150ms — should emit JA4L-C
	d := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	d.Metadata().Timestamp = baseTime.Add(150 * time.Millisecond)
	dResults, err := fp.ProcessPacket(d)
	if err != nil {
		t.Fatalf("D: %v", err)
	}
	if len(dResults) != 1 || !strings.HasPrefix(dResults[0].Fingerprint, "JA4L-C=") {
		t.Fatalf("D: expected one JA4L-C result, got %v", dResults)
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

	// The next server packet completes the server value.
	p3 := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	p3.Metadata().Timestamp = baseTime.Add(40 * time.Millisecond)
	r3, _ := fp.ProcessPacket(p3)
	if len(r3) != 1 || !strings.HasPrefix(r3[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("p3: expected JA4L-S, got %v", r3)
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
	// payload is the one thing that separates the two runs.
	fp = NewJA4L()
	c := buildUDPPacketWithIPs(t, clientIP, serverIP, 64, 50000, 443, quicLongHeaderPayload())
	c.Metadata().Timestamp = baseTime
	if results, _ := fp.ProcessPacket(c); len(results) != 0 {
		t.Fatalf("c: expected no results, got %v", results)
	}
	d := buildUDPPacketWithIPs(t, serverIP, clientIP, 64, 443, 50000, quicLongHeaderPayload())
	d.Metadata().Timestamp = baseTime.Add(50 * time.Millisecond)
	dResults, _ := fp.ProcessPacket(d)
	if len(dResults) != 1 || !strings.HasPrefix(dResults[0].Fingerprint, "JA4L-S=") {
		t.Fatalf("d: expected one JA4L-S result, got %v", dResults)
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
