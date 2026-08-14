package parser

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// fuzzTunnelSerialize returns the bytes of the layers, or it fails the caller.
//
// `tunnelTestSerialize` in `tunnel_test.go` does the same work, and it takes a
// `*testing.T`. A fuzz target adds its seeds from a `*testing.F`, so this helper takes a
// `testing.TB`.
func fuzzTunnelSerialize(tb testing.TB, parts ...gopacket.SerializableLayer) []byte {
	tb.Helper()

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buffer, options, parts...); err != nil {
		tb.Fatalf("the helper does not serialize the layers: %v", err)
	}

	return buffer.Bytes()
}

// fuzzGREFrame returns one Ethernet frame that nests the named count of GRE tunnel layers
// around one IPv4 packet that carries one TCP SYN.
func fuzzGREFrame(tb testing.TB, depth int) []byte {
	tb.Helper()

	inner := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, Window: 8192}

	if err := tcp.SetNetworkLayerForChecksum(inner); err != nil {
		tb.Fatalf("the helper does not set the network layer for the checksum: %v", err)
	}

	payload := fuzzTunnelSerialize(tb, inner, tcp)

	for range depth {
		outer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolGRE,
			SrcIP:    net.IPv4(192, 168, 0, 1),
			DstIP:    net.IPv4(192, 168, 0, 2),
		}
		gre := &layers.GRE{Protocol: layers.EthernetTypeIPv4}

		payload = fuzzTunnelSerialize(tb, outer, gre, gopacket.Payload(payload))
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	return fuzzTunnelSerialize(tb, ethernet, gopacket.Payload(payload))
}

// FuzzCheckTunnelReadsAnyFrame proves that the tunnel reader of `packet.go` returns for
// any Ethernet frame. FR-fuzz-13 states the requirement.
//
// FR-fuzz-13 names "each tunnel decoder that `features/05-conformance-gaps.md` adds". That
// file names `internal/parser/tunnel.go` as a new file, and it names four decoders that the
// file holds.
//   - A GRE decoder.
//   - An ERSPAN decoder.
//   - A VXLAN decoder.
//   - A Geneve decoder.
//
// **The tree holds no such file, and it holds no such decoder.** `isTunnelLayerType` in
// `packet.go` states the reason. `gopacket` registers a decoder for each of the four types,
// and this package adds none. So this target reads the decapsulation code that this
// repository does hold, and it invents no decoder. Issue #44 records the reading.
func FuzzCheckTunnelReadsAnyFrame(f *testing.F) {
	// The reader accepts each seed below. The first carries no tunnel. The second carries
	// one GRE layer. The third carries four GRE layers, which is MaxTunnelDepth.
	f.Add(fuzzGREFrame(f, 0))
	f.Add(fuzzGREFrame(f, 1))
	f.Add(fuzzGREFrame(f, MaxTunnelDepth))

	// The reader rejects each seed below. The first nests one layer past MaxTunnelDepth.
	// The second holds no byte.
	f.Add(fuzzGREFrame(f, MaxTunnelDepth+1))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, frame []byte) {
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		_ = TunnelDepth(packet)
		_ = CheckTunnel(packet)
		_ = GetTCPLayer(packet)
		_ = GetUDPLayer(packet)
		_ = GetTCPPayload(packet)
		_, _, _, _ = GetIPInfo(packet)
		_, _, _ = GetGroupingIPInfo(packet)
	})
}
