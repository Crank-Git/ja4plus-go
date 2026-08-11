package ja4plus

import (
	"errors"
	"net"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// tunnelSerializeOptions fills the length fields and the checksums, so each builder below
// states the fields the test reads and no other field.
var tunnelSerializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// tunnelSerialize returns the bytes of the layers, or it fails the test.
func tunnelSerialize(t *testing.T, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, tunnelSerializeOptions, parts...); err != nil {
		t.Fatalf("the builder does not serialize the layers: %v", err)
	}

	return buffer.Bytes()
}

// tunnelInnerFrame returns one Ethernet frame that carries one TCP SYN packet.
// The five-layer test reads this frame as the innermost packet.
func tunnelInnerFrame(t *testing.T) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 51000,
		DstPort: 443,
		SYN:     true,
		Window:  8192,
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder does not set the network layer for the checksum: %v", err)
	}

	return tunnelSerialize(t, ethernet, ip, tcp)
}

// tunnelWrapInGRE returns the payload inside one IPv4 header and one GRE header.
// The protocol names the payload, so the caller states an Ethernet type the GRE header
// carries.
func tunnelWrapInGRE(t *testing.T, payload []byte, protocol layers.EthernetType) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolGRE,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	gre := &layers.GRE{Protocol: protocol}

	return tunnelSerialize(t, ip, gre, gopacket.Payload(payload))
}

// tunnelOuterFrame returns the payload inside one Ethernet header that names IPv4.
func tunnelOuterFrame(t *testing.T, payload []byte) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	return tunnelSerialize(t, ethernet, gopacket.Payload(payload))
}

// tunnelNestedGREPacket returns one packet that nests the named count of GRE tunnel layers.
// Each GRE layer carries one IPv4 packet, and the innermost packet carries one TCP SYN.
func tunnelNestedGREPacket(t *testing.T, depth int) gopacket.Packet {
	t.Helper()

	// The innermost GRE layer carries an IPv4 packet, so the builder drops the Ethernet
	// header of the inner frame and keeps the IPv4 packet it holds.
	inner := tunnelInnerFrame(t)[14:]

	for range depth {
		inner = tunnelWrapInGRE(t, inner, layers.EthernetTypeIPv4)
	}

	return gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)
}

// The parser stops at a depth of four tunnel layers, because a crafted packet can
// nest one tunnel inside another without a bound. FR-gaps-12 states the limit.
func TestTheProcessorProducesNoFingerprintWhenAPacketNestsFiveTunnelLayers(t *testing.T) {
	packet := tunnelNestedGREPacket(t, 5)

	if depth := parser.TunnelDepth(packet); depth != 5 {
		t.Fatalf("the builder nests %d tunnel layers, and the test needs 5", depth)
	}

	processor := NewProcessor()
	results, errs := processor.ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints, and FR-gaps-12 allows none", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelDepthExceeded) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the depth limit", errs)
	}
}

// FR-gaps-11 reads a nested tunnel to a depth of four layers.
func TestTheProcessorReadsAPacketThatNestsFourTunnelLayers(t *testing.T) {
	packet := tunnelNestedGREPacket(t, 4)

	if depth := parser.TunnelDepth(packet); depth != 4 {
		t.Fatalf("the builder nests %d tunnel layers, and the test needs 4", depth)
	}

	_, errs := NewProcessor().ProcessPacket(packet)

	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelDepthExceeded) {
			t.Errorf("the processor rejects a depth of four, and FR-gaps-11 allows it")
		}
	}
}

// A GRE packet that carries an unknown protocol type holds no inner packet the parser
// reads, so the processor returns a non-fatal error and produces no fingerprint.
func TestTheProcessorProducesNoFingerprintWhenAGREPacketCarriesAnUnknownProtocolType(t *testing.T) {
	// `0x9999` reaches no entry of the gopacket Ethernet type table at v1.1.19, so the GRE
	// layer names a payload the parser does not decode.
	const unknownProtocol = layers.EthernetType(0x9999)

	inner := tunnelWrapInGRE(t, tunnelInnerFrame(t)[14:], unknownProtocol)
	packet := gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)

	results, errs := NewProcessor().ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints from an unread tunnel payload", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelPayloadUnread) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the unread tunnel payload", errs)
	}
}

// A VXLAN packet with a truncated inner frame holds no inner packet the parser reads. The
// processor returns a non-fatal error, and it does not panic.
func TestTheProcessorProducesNoFingerprintWhenAVXLANPacketCarriesATruncatedInnerFrame(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	udp := &layers.UDP{SrcPort: 41000, DstPort: 4789}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder does not set the network layer for the checksum: %v", err)
	}

	// The inner Ethernet header needs 14 bytes, and this frame holds 6 of them.
	truncated := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	vxlan := &layers.VXLAN{ValidIDFlag: true, VNI: 42}

	inner := tunnelSerialize(t, ip, udp, vxlan, gopacket.Payload(truncated))
	packet := gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)

	results, errs := NewProcessor().ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints from a truncated inner frame", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelPayloadUnread) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the unread tunnel payload", errs)
	}
}

// TunnelDepth counts every tunnel layer of the packet, and it counts none for a packet
// that carries no tunnel.
func TestTunnelDepthCountsNoLayerForAPacketThatCarriesNoTunnel(t *testing.T) {
	packet := gopacket.NewPacket(tunnelInnerFrame(t), layers.LayerTypeEthernet, gopacket.Default)

	if depth := parser.TunnelDepth(packet); depth != 0 {
		t.Errorf("TunnelDepth returns %d for a packet that carries no tunnel, and 0 is the count", depth)
	}
}
