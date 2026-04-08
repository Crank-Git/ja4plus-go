package ja4plus

import (
	"fmt"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

type connState struct {
	timestamps map[string]time.Time // "A", "B", "C", "D" (for QUIC 4-point)
	ttls       map[string]uint8    // "client", "server"
	direction  string              // "forward" or "reverse"
	connKey    string
	proto      string // "tcp" or "udp"
}

// JA4LFingerprinter generates JA4L latency fingerprints from TCP handshake
// timing or QUIC/UDP exchange timing.
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
// timing measurement can be computed. Supports both TCP and UDP/QUIC.
func (f *JA4LFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	// Try TCP first
	if parser.GetTCPLayer(packet) != nil {
		return f.processTCP(packet)
	}

	// Try UDP/QUIC
	if parser.GetUDPLayer(packet) != nil {
		return f.processUDP(packet)
	}

	return nil, nil
}

func (f *JA4LFingerprinter) processTCP(packet gopacket.Packet) ([]FingerprintResult, error) {
	tcpLayer := parser.GetTCPLayer(packet)
	if tcpLayer == nil {
		return nil, nil
	}

	srcIP, dstIP, ttl, ok := parser.GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	srcPort := uint16(tcpLayer.SrcPort)
	dstPort := uint16(tcpLayer.DstPort)

	connKey, direction := f.normalizeKey("tcp", srcIP, srcPort, dstIP, dstPort)

	conn := f.getOrCreateConn(connKey, direction, "tcp")
	ts := parser.GetPacketTimestamp(packet)

	// SYN packet (not SYN-ACK).
	if tcpLayer.SYN && !tcpLayer.ACK {
		conn.timestamps["A"] = ts
		conn.ttls["client"] = ttl
		return nil, nil
	}

	// SYN-ACK packet.
	if tcpLayer.SYN && tcpLayer.ACK {
		conn.timestamps["B"] = ts
		conn.ttls["server"] = ttl

		if synTime, ok := conn.timestamps["A"]; ok {
			return f.emitResult("JA4L-S", ts.Sub(synTime), ttl, srcIP, dstIP, srcPort, dstPort, ts), nil
		}
		return nil, nil
	}

	// ACK packet (completing handshake).
	if tcpLayer.ACK && !tcpLayer.SYN {
		if synAckTime, ok := conn.timestamps["B"]; ok {
			if _, already := conn.timestamps["C"]; already {
				return nil, nil
			}
			conn.timestamps["C"] = ts
			return f.emitResult("JA4L-C", ts.Sub(synAckTime), ttl, srcIP, dstIP, srcPort, dstPort, ts), nil
		}
	}

	return nil, nil
}

func (f *JA4LFingerprinter) processUDP(packet gopacket.Packet) ([]FingerprintResult, error) {
	udp := parser.GetUDPLayer(packet)
	if udp == nil {
		return nil, nil
	}

	srcIP, dstIP, ttl, ok := parser.GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	connKey, direction := f.normalizeKey("udp", srcIP, srcPort, dstIP, dstPort)

	conn := f.getOrCreateConn(connKey, direction, "udp")
	ts := parser.GetPacketTimestamp(packet)

	isClient := f.srcIsClient(srcIP, conn)

	// 4-point QUIC timing: A (client) -> B (server) -> C (client) -> D (server)
	if _, ok := conn.timestamps["A"]; !ok && isClient {
		conn.timestamps["A"] = ts
		conn.ttls["client"] = ttl
		return nil, nil
	}

	if _, ok := conn.timestamps["A"]; ok {
		if _, ok := conn.timestamps["B"]; !ok && !isClient {
			conn.timestamps["B"] = ts
			conn.ttls["server"] = ttl
			return f.emitResult("JA4L-S", ts.Sub(conn.timestamps["A"]), ttl, srcIP, dstIP, srcPort, dstPort, ts), nil
		}
	}

	if _, ok := conn.timestamps["B"]; ok {
		if _, ok := conn.timestamps["C"]; !ok && isClient {
			conn.timestamps["C"] = ts
			return nil, nil
		}
	}

	if _, ok := conn.timestamps["C"]; ok {
		if _, ok := conn.timestamps["D"]; !ok && !isClient {
			conn.timestamps["D"] = ts
			clientTTL := conn.ttls["client"]
			return f.emitResult("JA4L-C", ts.Sub(conn.timestamps["C"]), clientTTL, srcIP, dstIP, srcPort, dstPort, ts), nil
		}
	}

	return nil, nil
}

func (f *JA4LFingerprinter) normalizeKey(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) (string, string) {
	ip1, port1, ip2, port2 := srcIP, srcPort, dstIP, dstPort
	forward := ip1 < ip2 || (ip1 == ip2 && port1 < port2)
	if !forward {
		ip1, port1, ip2, port2 = dstIP, dstPort, srcIP, srcPort
	}
	connKey := fmt.Sprintf("%s_%s:%d_%s:%d", proto, ip1, port1, ip2, port2)
	direction := "forward"
	if !forward {
		direction = "reverse"
	}
	return connKey, direction
}

func (f *JA4LFingerprinter) getOrCreateConn(connKey, direction, proto string) *connState {
	conn, exists := f.connections[connKey]
	if !exists {
		conn = &connState{
			timestamps: make(map[string]time.Time),
			ttls:       make(map[string]uint8),
			direction:  direction,
			connKey:    connKey,
			proto:      proto,
		}
		f.connections[connKey] = conn
	}
	return conn
}

// srcIsClient determines if the source IP is the client side of this connection.
func (f *JA4LFingerprinter) srcIsClient(srcIP string, conn *connState) bool {
	if conn.direction == "forward" {
		// In a "forward" connection, the first IP in the key is the client
		// Parse client IP from connKey: "proto_ip1:port1_ip2:port2"
		parts := splitConnKey(conn.connKey)
		if len(parts) >= 2 {
			return srcIP == parts[0]
		}
	}
	return false
}

// splitConnKey extracts IPs from a connection key like "udp_1.2.3.4:5_6.7.8.9:10"
func splitConnKey(key string) []string {
	// Skip protocol prefix
	for i, c := range key {
		if c == '_' {
			key = key[i+1:]
			break
		}
	}
	// Split on underscore to get "ip:port" parts
	var ips []string
	for _, part := range splitOn(key, '_') {
		if idx := lastIndexByte(part, ':'); idx >= 0 {
			ips = append(ips, part[:idx])
		}
	}
	return ips
}

func splitOn(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func (f *JA4LFingerprinter) emitResult(label string, diff time.Duration, ttl uint8, srcIP, dstIP string, srcPort, dstPort uint16, ts time.Time) []FingerprintResult {
	latencyUS := int(diff.Microseconds())
	if latencyUS < 1 {
		latencyUS = 1
	}
	fingerprint := fmt.Sprintf("%s=%d_%d", label, latencyUS, ttl)
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
	return []FingerprintResult{result}
}

// Reset clears all connection state and results.
func (f *JA4LFingerprinter) Reset() {
	f.connections = make(map[string]*connState)
	f.results = nil
}

// CleanupConnection removes internal state for the given connection.
// JA4L normalizes keys lexicographically by IP then port.
func (f *JA4LFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	connKey, _ := f.normalizeKey(proto, srcIP, srcPort, dstIP, dstPort)
	delete(f.connections, connKey)
}

// CalculateDistance estimates physical distance in miles from one-way latency.
// Uses speed of light in fiber optic cable (0.128 miles/us).
// propagationFactor accounts for non-direct routing (default 1.6).
func CalculateDistance(latencyUS int, propagationFactor float64) float64 {
	if propagationFactor <= 0 {
		propagationFactor = 1.6
	}
	return (float64(latencyUS) * 0.128) / propagationFactor
}

// CalculateDistanceKm estimates physical distance in kilometers from one-way latency.
// Uses speed of light in fiber optic cable (0.206 km/us).
func CalculateDistanceKm(latencyUS int, propagationFactor float64) float64 {
	if propagationFactor <= 0 {
		propagationFactor = 1.6
	}
	return (float64(latencyUS) * 0.206) / propagationFactor
}

// EstimateOS estimates the operating system based on observed TTL value.
func EstimateOS(ttl uint8) string {
	if ttl <= 64 {
		return "Mac, Linux, Phone, or IoT device (initial TTL: 64)"
	} else if ttl <= 128 {
		return "Windows (initial TTL: 128)"
	}
	return "Cisco, F5, or Networking Device (initial TTL: 255)"
}

// EstimateHopCount estimates the number of network hops based on observed TTL.
func EstimateHopCount(ttl uint8) int {
	if ttl <= 64 {
		return 64 - int(ttl)
	} else if ttl <= 128 {
		return 128 - int(ttl)
	}
	return 255 - int(ttl)
}
