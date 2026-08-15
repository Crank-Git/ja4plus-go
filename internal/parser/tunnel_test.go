package parser

import (
	"errors"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// tunnelTestOptions fills the length fields and the checksums, so each builder below
// states the fields the test reads and no other field.
var tunnelTestOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// tunnelTestSerialize returns the bytes of the layers, or it fails the test.
func tunnelTestSerialize(t *testing.T, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, tunnelTestOptions, parts...); err != nil {
		t.Fatalf("the builder does not serialize the layers: %v", err)
	}

	return buffer.Bytes()
}

// tunnelTestIPv4Packet returns one IPv4 packet that carries one TCP SYN.
func tunnelTestIPv4Packet(t *testing.T) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, Window: 8192}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder does not set the network layer for the checksum: %v", err)
	}

	return tunnelTestSerialize(t, ip, tcp)
}

// tunnelTestGREPacket returns one packet that nests the named count of GRE tunnel layers
// around one IPv4 packet.
func tunnelTestGREPacket(t *testing.T, depth int, protocol layers.EthernetType) gopacket.Packet {
	t.Helper()

	inner := tunnelTestIPv4Packet(t)

	for range depth {
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolGRE,
			SrcIP:    net.IPv4(192, 168, 0, 1),
			DstIP:    net.IPv4(192, 168, 0, 2),
		}
		inner = tunnelTestSerialize(t, ip, &layers.GRE{Protocol: protocol}, gopacket.Payload(inner))
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	frame := tunnelTestSerialize(t, ethernet, gopacket.Payload(inner))

	return gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
}

func TestTunnelDepthCountsEveryTunnelLayerOfThePacket(t *testing.T) {
	for _, depth := range []int{0, 1, 3, 5} {
		packet := tunnelTestGREPacket(t, depth, layers.EthernetTypeIPv4)

		if counted := TunnelDepth(packet); counted != depth {
			t.Errorf("TunnelDepth returns %d for a packet of %d tunnel layers", counted, depth)
		}
	}
}

func TestCheckTunnelAcceptsAPacketThatCarriesNoTunnel(t *testing.T) {
	packet := tunnelTestGREPacket(t, 0, layers.EthernetTypeIPv4)

	if err := CheckTunnel(packet); err != nil {
		t.Errorf("CheckTunnel returns %v for a packet that carries no tunnel", err)
	}
}

func TestCheckTunnelAcceptsAPacketAtTheDepthLimit(t *testing.T) {
	packet := tunnelTestGREPacket(t, MaxTunnelDepth, layers.EthernetTypeIPv4)

	if err := CheckTunnel(packet); err != nil {
		t.Errorf("CheckTunnel returns %v at the depth limit of %d", err, MaxTunnelDepth)
	}
}

func TestCheckTunnelRejectsAPacketPastTheDepthLimit(t *testing.T) {
	packet := tunnelTestGREPacket(t, MaxTunnelDepth+1, layers.EthernetTypeIPv4)

	if err := CheckTunnel(packet); !errors.Is(err, ErrTunnelDepthExceeded) {
		t.Errorf("CheckTunnel returns %v past the depth limit, and it names no limit", err)
	}
}

// A GRE header that names an unknown protocol type carries no inner packet the parser
// reads. `0x9999` reaches no entry of the gopacket Ethernet type table at v1.1.19.
func TestCheckTunnelRejectsAGREPacketThatNamesAnUnknownProtocolType(t *testing.T) {
	packet := tunnelTestGREPacket(t, 1, layers.EthernetType(0x9999))

	if err := CheckTunnel(packet); !errors.Is(err, ErrTunnelPayloadUnread) {
		t.Errorf("CheckTunnel returns %v for an unknown GRE protocol type", err)
	}
}
