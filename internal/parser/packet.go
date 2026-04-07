package parser

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

// GetIPInfo extracts source/destination IP addresses from a packet (IPv4 only).
func GetIPInfo(packet gopacket.Packet) (srcIP, dstIP string, ok bool) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String(), true
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
