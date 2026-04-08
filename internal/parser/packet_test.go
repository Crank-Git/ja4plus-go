package parser

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildIPv4Packet(t *testing.T, srcIP, dstIP string, ttl uint8) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildIPv6Packet(t *testing.T, srcIP, dstIP string, hopLimit uint8) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   hopLimit,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildEthernetOnlyPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeLLC,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildUDPPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
	}
	udp := &layers.UDP{
		SrcPort: 5000,
		DstPort: 5001,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("hello"))); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestGetIPInfo_IPv4(t *testing.T) {
	pkt := buildIPv4Packet(t, "192.168.1.10", "10.0.0.1", 128)
	srcIP, dstIP, ttl, ok := GetIPInfo(pkt)
	if !ok {
		t.Fatal("expected ok=true for IPv4 packet")
	}
	if srcIP != "192.168.1.10" {
		t.Errorf("srcIP = %q, want %q", srcIP, "192.168.1.10")
	}
	if dstIP != "10.0.0.1" {
		t.Errorf("dstIP = %q, want %q", dstIP, "10.0.0.1")
	}
	if ttl != 128 {
		t.Errorf("ttl = %d, want %d", ttl, 128)
	}
}

func TestGetIPInfo_IPv6(t *testing.T) {
	pkt := buildIPv6Packet(t, "2001:db8::1", "2001:db8::2", 64)
	srcIP, dstIP, ttl, ok := GetIPInfo(pkt)
	if !ok {
		t.Fatal("expected ok=true for IPv6 packet")
	}
	if srcIP != "2001:db8::1" {
		t.Errorf("srcIP = %q, want %q", srcIP, "2001:db8::1")
	}
	if dstIP != "2001:db8::2" {
		t.Errorf("dstIP = %q, want %q", dstIP, "2001:db8::2")
	}
	if ttl != 64 {
		t.Errorf("ttl (HopLimit) = %d, want %d", ttl, 64)
	}
}

func TestGetIPInfo_NoIP(t *testing.T) {
	pkt := buildEthernetOnlyPacket(t)
	srcIP, dstIP, ttl, ok := GetIPInfo(pkt)
	if ok {
		t.Fatal("expected ok=false for ethernet-only packet")
	}
	if srcIP != "" || dstIP != "" || ttl != 0 {
		t.Errorf("expected zero values, got srcIP=%q dstIP=%q ttl=%d", srcIP, dstIP, ttl)
	}
}

func TestGetUDPLayer(t *testing.T) {
	udpPkt := buildUDPPacket(t)
	udp := GetUDPLayer(udpPkt)
	if udp == nil {
		t.Fatal("expected non-nil UDP layer")
	}
	if udp.SrcPort != 5000 {
		t.Errorf("SrcPort = %d, want 5000", udp.SrcPort)
	}
	if udp.DstPort != 5001 {
		t.Errorf("DstPort = %d, want 5001", udp.DstPort)
	}

	// TCP packet should return nil for UDP
	tcpPkt := buildIPv4Packet(t, "1.2.3.4", "5.6.7.8", 64)
	if got := GetUDPLayer(tcpPkt); got != nil {
		t.Errorf("expected nil UDP layer for TCP packet, got %v", got)
	}
}

func TestGetTCPLayer(t *testing.T) {
	pkt := buildIPv4Packet(t, "1.2.3.4", "5.6.7.8", 64)
	tcp := GetTCPLayer(pkt)
	if tcp == nil {
		t.Fatal("expected non-nil TCP layer")
	}
	if tcp.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", tcp.SrcPort)
	}
	if tcp.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", tcp.DstPort)
	}

	// UDP packet should return nil for TCP
	udpPkt := buildUDPPacket(t)
	if got := GetTCPLayer(udpPkt); got != nil {
		t.Errorf("expected nil TCP layer for UDP packet, got %v", got)
	}
}

func TestGetTCPPayload(t *testing.T) {
	// SYN packet with no payload
	pkt := buildIPv4Packet(t, "1.2.3.4", "5.6.7.8", 64)
	if got := GetTCPPayload(pkt); got != nil {
		t.Errorf("expected nil payload for SYN packet, got %v", got)
	}

	// UDP packet should return nil
	udpPkt := buildUDPPacket(t)
	if got := GetTCPPayload(udpPkt); got != nil {
		t.Errorf("expected nil payload for UDP packet, got %v", got)
	}
}
