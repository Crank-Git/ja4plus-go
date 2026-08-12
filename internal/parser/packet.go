package parser

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MaxTunnelDepth is the count of tunnel layers the parser reads inside one packet.
// A crafted packet nests one tunnel inside another without a bound, so the parser stops
// here. The limit is a security control, and `docs/specs/features/05-conformance-gaps.md`
// FR-gaps-11 and FR-gaps-12 state it.
const MaxTunnelDepth = 4

// ErrTunnelDepthExceeded reports that the packet nests more tunnel layers than
// MaxTunnelDepth allows. The caller produces no fingerprint from such a packet.
var ErrTunnelDepthExceeded = fmt.Errorf("the packet nests more than %d tunnel layers", MaxTunnelDepth)

// ErrTunnelPayloadUnread reports that the packet carries a tunnel layer and that the
// parser reads no network layer inside it. A GRE header that names an unknown protocol
// type reaches this error, and so does a truncated inner frame.
var ErrTunnelPayloadUnread = errors.New("the parser reads no inner packet inside the tunnel")

// isTunnelLayerType reports whether the layer type carries another packet inside it.
// The four types are the ones FR-gaps-7 to FR-gaps-10 name. `gopacket` at v1.1.19
// registers a decoder for each one, so the standard decode chain already reads the inner
// packet and this package adds no decoder.
func isTunnelLayerType(layerType gopacket.LayerType) bool {
	switch layerType {
	case layers.LayerTypeGRE, layers.LayerTypeERSPANII, layers.LayerTypeVXLAN, layers.LayerTypeGeneve:
		return true
	default:
		return false
	}
}

// TunnelDepth returns the count of tunnel layers the packet carries.
// It returns 0 for a packet that carries no tunnel.
func TunnelDepth(packet gopacket.Packet) int {
	depth := 0

	for _, layer := range packet.Layers() {
		if isTunnelLayerType(layer.LayerType()) {
			depth++
		}
	}

	return depth
}

// innerLayers returns the layers that follow the innermost tunnel layer of the packet.
// It returns every layer of a packet that carries no tunnel. It allocates nothing,
// because it returns one slice of the list the packet already holds.
func innerLayers(packet gopacket.Packet) []gopacket.Layer {
	all := packet.Layers()
	start := 0

	for index, layer := range all {
		if isTunnelLayerType(layer.LayerType()) {
			start = index + 1
		}
	}

	return all[start:]
}

// CheckTunnel returns a non-fatal error when the parser reads no inner packet from a
// tunnel. It returns nil for a packet that carries no tunnel.
//
// It returns ErrTunnelDepthExceeded when the packet nests more than MaxTunnelDepth tunnel
// layers. It returns ErrTunnelPayloadUnread when it reads neither an IPv4 layer nor an
// IPv6 layer inside the innermost tunnel layer.
func CheckTunnel(packet gopacket.Packet) error {
	depth := TunnelDepth(packet)
	if depth == 0 {
		return nil
	}

	if depth > MaxTunnelDepth {
		return ErrTunnelDepthExceeded
	}

	for _, layer := range innerLayers(packet) {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
			return nil
		}
	}

	return ErrTunnelPayloadUnread
}

// GetUDPLayer extracts the UDP layer of the innermost packet, or nil if not present.
//
// A tunnel carries its own transport layer, and that layer names the tunnel and not the
// connection. The search therefore starts after the innermost tunnel layer. A VXLAN
// packet on UDP port 4789 that carries TCP inside returns nil.
func GetUDPLayer(packet gopacket.Packet) *layers.UDP {
	for _, layer := range innerLayers(packet) {
		if udp, held := layer.(*layers.UDP); held {
			return udp
		}
	}

	return nil
}

// GetTCPLayer extracts the TCP layer of the innermost packet, or nil if not present.
//
// A tunnel carries its own transport layer, and that layer names the tunnel and not the
// connection. The search therefore starts after the innermost tunnel layer.
func GetTCPLayer(packet gopacket.Packet) *layers.TCP {
	for _, layer := range innerLayers(packet) {
		if tcp, held := layer.(*layers.TCP); held {
			return tcp
		}
	}

	return nil
}

// GetTCPPayload extracts the TCP payload bytes from a packet.
func GetTCPPayload(packet gopacket.Packet) []byte {
	tcp := GetTCPLayer(packet)
	if tcp == nil {
		return nil
	}
	payload := tcp.Payload
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// GetIPInfo extracts source/destination IP addresses and TTL from a packet.
// Supports both IPv4 and IPv6. For IPv6, ttl is the HopLimit field.
//
// It reads the outermost address layer, which is the layer a `FingerprintResult` reports
// and the layer the time-to-live comes from. Use GetGroupingIPInfo for the address pair
// that collects packets into one connection. `docs/specs/spec.md` `## Changelog` records
// the ruling of 2026-08-11 that separates the two.
func GetIPInfo(packet gopacket.Packet) (srcIP, dstIP string, ttl uint8, ok bool) {
	// A caller that supplies a custom decoder can register another concrete type under an
	// IP layer type. The caller reads `ok` as false for such a packet, and no assertion
	// panics.
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip, held := ipLayer.(*layers.IPv4); held {
			return ip.SrcIP.String(), ip.DstIP.String(), ip.TTL, true
		}
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		if ip, held := ipLayer.(*layers.IPv6); held {
			return ip.SrcIP.String(), ip.DstIP.String(), ip.HopLimit, true
		}
	}
	return "", "", 0, false
}

// GetGroupingIPInfo returns the address pair that collects packets into one connection.
// It reads the innermost address layer. It reports false when the packet carries no
// address layer the parser reads.
//
// The grouping pair reads the inner layer, because a mirror sends both directions of one
// session from one outer address pair. The outer pair separates no direction there, and
// one connection then holds two measurement points that belong to two endpoints.
//
// It returns no time-to-live, because the time-to-live reads the outer layer that
// GetIPInfo returns.
func GetGroupingIPInfo(packet gopacket.Packet) (srcIP, dstIP string, ok bool) {
	for _, layer := range innerLayers(packet) {
		switch ip := layer.(type) {
		case *layers.IPv4:
			return ip.SrcIP.String(), ip.DstIP.String(), true
		case *layers.IPv6:
			return ip.SrcIP.String(), ip.DstIP.String(), true
		}
	}

	return "", "", false
}

// GetPacketTimestamp returns the packet's capture timestamp.
func GetPacketTimestamp(packet gopacket.Packet) time.Time {
	if md := packet.Metadata(); md != nil {
		return md.Timestamp
	}
	return time.Time{}
}
