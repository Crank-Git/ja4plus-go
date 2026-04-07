package ja4plus

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildSYNPacket(srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
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
		SYN:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestProcessor_SYNPacket(t *testing.T) {
	proc := NewProcessor()
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	// A SYN packet should produce at least a JA4T result
	found := false
	for _, r := range results {
		if r.Type == "ja4t" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected JA4T result from SYN packet")
	}
}

func TestProcessor_NonApplicablePacket(t *testing.T) {
	proc := NewProcessor()

	// Build a plain ACK packet with no payload — not part of any tracked connection
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("10.0.0.1"),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(80),
		ACK:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(results) > 0 {
		t.Errorf("expected no results for plain ACK, got %d: %+v", len(results), results)
	}
}

func TestProcessor_Reset(t *testing.T) {
	proc := NewProcessor()

	// Process a SYN so state accumulates
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	_, _ = proc.ProcessPacket(pkt)

	// Reset should not panic
	proc.Reset()

	// After reset, processing should still work
	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors after reset: %v", errs)
	}
	// Should still get JA4T
	found := false
	for _, r := range results {
		if r.Type == "ja4t" {
			found = true
		}
	}
	if !found {
		t.Error("expected JA4T result after reset")
	}
}
