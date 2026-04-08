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
func buildTCPPacketWithIPs(t *testing.T, srcIP, dstIP net.IP, ttl uint8, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
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

	if len(fp.results) != 1 {
		t.Fatalf("expected 1 result before reset, got %d", len(fp.results))
	}
	if len(fp.connections) != 1 {
		t.Fatalf("expected 1 connection before reset, got %d", len(fp.connections))
	}

	fp.Reset()

	if len(fp.results) != 0 {
		t.Errorf("expected 0 results after reset, got %d", len(fp.results))
	}
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
