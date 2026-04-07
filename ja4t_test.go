package ja4plus

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPPacket(t *testing.T, srcPort, dstPort uint16, syn, ack bool, window uint16, options []layers.TCPOption) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  window,
		Options: options,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mssOptionData(val uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, val)
	return b
}

func TestJA4T_SYNWithFullOptions(t *testing.T) {
	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindEndList, OptionLength: 1},
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 29200, options)

	result := ComputeJA4T(pkt)
	expected := "29200_2-1-3-1-1-8-4-0_1460_7"
	if result != expected {
		t.Errorf("JA4T full options: got %q, want %q", result, expected)
	}
}

func TestJA4T_NonSYNPacket(t *testing.T) {
	// ACK only, no SYN
	pkt := buildTCPPacket(t, 12345, 80, false, true, 65535, nil)
	result := ComputeJA4T(pkt)
	if result != "" {
		t.Errorf("JA4T ACK-only: expected empty, got %q", result)
	}
}

func TestJA4T_SYNACKPacket(t *testing.T) {
	// SYN-ACK should not match JA4T
	pkt := buildTCPPacket(t, 80, 12345, true, true, 29200, nil)
	result := ComputeJA4T(pkt)
	if result != "" {
		t.Errorf("JA4T SYN-ACK: expected empty, got %q", result)
	}
}

func TestJA4T_NoOptions(t *testing.T) {
	pkt := buildTCPPacket(t, 12345, 80, true, false, 65535, nil)
	result := ComputeJA4T(pkt)
	expected := "65535_0_0_0"
	if result != expected {
		t.Errorf("JA4T no options: got %q, want %q", result, expected)
	}
}

func TestJA4T_MSSOnly(t *testing.T) {
	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1400)},
	}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)
	result := ComputeJA4T(pkt)
	expected := "8192_2_1400_0"
	if result != expected {
		t.Errorf("JA4T MSS only: got %q, want %q", result, expected)
	}
}

func TestJA4T_Reset(t *testing.T) {
	fp := NewJA4T()
	pkt := buildTCPPacket(t, 12345, 80, true, false, 65535, nil)
	fp.ProcessPacket(pkt)
	if len(fp.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(fp.results))
	}
	fp.Reset()
	if len(fp.results) != 0 {
		t.Errorf("expected 0 results after reset, got %d", len(fp.results))
	}
}
