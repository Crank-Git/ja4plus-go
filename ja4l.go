package ja4plus

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type connState struct {
	timestamps map[string]time.Time // "A" (SYN), "B" (SYN-ACK), "C" (ACK)
	ttls       map[string]uint8    // "client", "server"
	direction  string              // "forward" or "reverse"
	connKey    string
}

// JA4LFingerprinter generates JA4L latency fingerprints from TCP handshake timing.
type JA4LFingerprinter struct {
	connections map[string]*connState
	results     []FingerprintResult
}

// NewJA4L creates a new JA4L latency fingerprinter.
func NewJA4L() *JA4LFingerprinter {
	return &JA4LFingerprinter{
		connections: make(map[string]*connState),
	}
}

// ProcessPacket processes a packet and returns JA4L fingerprints if a handshake
// timing measurement can be computed.
func (f *JA4LFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	tcp := GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil
	}
	ip := ipLayer.(*layers.IPv4)

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	ttl := ip.TTL

	// Normalize connection key: always put the lexicographically smaller IP
	// (or lower port when IPs match) first so both directions map to the same key.
	var connKey, direction string
	ip1, port1, ip2, port2 := srcIP, srcPort, dstIP, dstPort
	forward := ip1 < ip2 || (ip1 == ip2 && port1 < port2)
	if !forward {
		ip1, port1, ip2, port2 = dstIP, dstPort, srcIP, srcPort
	}
	connKey = fmt.Sprintf("tcp_%s:%d_%s:%d", ip1, port1, ip2, port2)
	if forward {
		direction = "forward"
	} else {
		direction = "reverse"
	}

	conn, exists := f.connections[connKey]
	if !exists {
		conn = &connState{
			timestamps: make(map[string]time.Time),
			ttls:       make(map[string]uint8),
			direction:  direction,
			connKey:    connKey,
		}
		f.connections[connKey] = conn
	}

	ts := GetPacketTimestamp(packet)

	// SYN packet (not SYN-ACK).
	if tcp.SYN && !tcp.ACK {
		conn.timestamps["A"] = ts
		conn.ttls["client"] = ttl
		return nil, nil
	}

	// SYN-ACK packet.
	if tcp.SYN && tcp.ACK {
		conn.timestamps["B"] = ts
		conn.ttls["server"] = ttl

		if synTime, ok := conn.timestamps["A"]; ok {
			diff := ts.Sub(synTime)
			latencyUS := int(diff.Microseconds())
			if latencyUS < 1 {
				latencyUS = 1
			}
			fingerprint := fmt.Sprintf("JA4L-S=%d_%d", latencyUS, ttl)
			result := FingerprintResult{
				Fingerprint: fingerprint,
				Type:        "ja4l",
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Timestamp:   ts,
			}
			f.results = append(f.results, result)
			return []FingerprintResult{result}, nil
		}
		return nil, nil
	}

	// ACK packet (completing handshake) -- ACK set, SYN not set.
	if tcp.ACK && !tcp.SYN {
		if synAckTime, ok := conn.timestamps["B"]; ok {
			// Only process the first ACK after SYN-ACK (handshake completion).
			if _, already := conn.timestamps["C"]; already {
				return nil, nil
			}
			conn.timestamps["C"] = ts

			diff := ts.Sub(synAckTime)
			latencyUS := int(diff.Microseconds())
			if latencyUS < 1 {
				latencyUS = 1
			}
			fingerprint := fmt.Sprintf("JA4L-C=%d_%d", latencyUS, ttl)
			result := FingerprintResult{
				Fingerprint: fingerprint,
				Type:        "ja4l",
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Timestamp:   ts,
			}
			f.results = append(f.results, result)
			return []FingerprintResult{result}, nil
		}
	}

	return nil, nil
}

// Reset clears all connection state and results.
func (f *JA4LFingerprinter) Reset() {
	f.connections = make(map[string]*connState)
	f.results = nil
}
