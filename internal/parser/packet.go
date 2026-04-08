package parser

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GetUDPLayer extracts the UDP layer from a packet, or nil if not present.
func GetUDPLayer(packet gopacket.Packet) *layers.UDP {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		return udpLayer.(*layers.UDP)
	}
	return nil
}

// GetTCPLayer extracts the TCP layer from a packet, or nil if not present.
func GetTCPLayer(packet gopacket.Packet) *layers.TCP {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		return tcpLayer.(*layers.TCP)
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
func GetIPInfo(packet gopacket.Packet) (srcIP, dstIP string, ttl uint8, ok bool) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String(), ip.TTL, true
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String(), ip.HopLimit, true
	}
	return "", "", 0, false
}

// GetPacketTimestamp returns the packet's capture timestamp.
func GetPacketTimestamp(packet gopacket.Packet) time.Time {
	if md := packet.Metadata(); md != nil {
		return md.Timestamp
	}
	return time.Time{}
}
