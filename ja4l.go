package ja4plus

import (
	"fmt"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// quicPort is the UDP port that names the server of a QUIC flow.
// The reference reads the direction of every QUIC packet from this one number.
// `ja4plus/fingerprinters/ja4l.py:55` holds the same value.
const quicPort uint16 = 443

// latencyDivisor turns a measured time into the one-way latency that JA4L reports.
// One measurement covers a round trip. `docs/specs/foxio/JA4L.md` R6 states the rule.
const latencyDivisor = 2

type connState struct {
	timestamps map[string]time.Time // "A", "B", "C", "D" (for QUIC 4-point)
	ttls       map[string]uint8     // "client", "server"
	direction  string               // "forward" or "reverse"
	connKey    string
	proto      string // "tcp" or "udp"
	// The four fields below hold the endpoints that every result of this connection
	// reports. The first packet fixes them, because a mirror sends both directions from
	// one outer address pair and a later packet would otherwise pair that one address with
	// the opposite port. `docs/specs/spec.md` `## Changelog` records the ruling.
	reportedSrcIP   string
	reportedDstIP   string
	reportedSrcPort uint16
	reportedDstPort uint16
}

// JA4LFingerprinter generates JA4L latency fingerprints from TCP handshake
// timing or QUIC/UDP exchange timing.
//
// One JA4LFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4LFingerprinter struct {
	connections map[string]*connState
}

// NewJA4L creates a new JA4L latency fingerprinter.
func NewJA4L() *JA4LFingerprinter {
	return &JA4LFingerprinter{
		connections: make(map[string]*connState),
	}
}

// ensure fills the state map that the constructor fills.
// A caller who writes `var f JA4LFingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4LFingerprinter) ensure() {
	if f.connections == nil {
		f.connections = make(map[string]*connState)
	}
}

// ProcessPacket processes a packet and returns JA4L fingerprints if a handshake
// timing measurement can be computed. Supports both TCP and UDP/QUIC.
func (f *JA4LFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

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

	groupSrcIP, groupDstIP, grouped := parser.GetGroupingIPInfo(packet)
	if !grouped {
		return nil, nil
	}

	srcPort := uint16(tcpLayer.SrcPort)
	dstPort := uint16(tcpLayer.DstPort)

	connKey, direction := f.normalizeKey("tcp", groupSrcIP, srcPort, groupDstIP, dstPort)

	conn := f.getOrCreateConn(connKey, direction, "tcp")
	conn.report(srcIP, srcPort, dstIP, dstPort)
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
			return f.emitResult("JA4L-S", ts.Sub(synTime), ttl, conn, ts), nil
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
			return f.emitResult("JA4L-C", ts.Sub(synAckTime), ttl, conn, ts), nil
		}
	}

	return nil, nil
}

func (f *JA4LFingerprinter) processUDP(packet gopacket.Packet) ([]FingerprintResult, error) {
	udp := parser.GetUDPLayer(packet)
	if udp == nil {
		return nil, nil
	}

	// JA4L reads a UDP flow only when the flow carries QUIC. An NTP flow reaches this
	// method, and the reference produces no value for it.
	// `ja4plus/fingerprinters/ja4l.py:554-558` states the rule, and issue #173 holds the
	// reading.
	if !parser.HasQUICLongHeader(udp.Payload) {
		return nil, nil
	}

	srcIP, dstIP, ttl, ok := parser.GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	groupSrcIP, groupDstIP, grouped := parser.GetGroupingIPInfo(packet)
	if !grouped {
		return nil, nil
	}

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// The reference reads the direction of a QUIC flow from the UDP port alone.
	// A flow whose two ports are the QUIC port names no server. The direction of such a
	// packet is unknown, and every value it gives is a guess.
	// `ja4plus/fingerprinters/ja4l.py:561-566` states the rule.
	toServer := dstPort == quicPort
	fromServer := srcPort == quicPort
	if toServer == fromServer {
		return nil, nil
	}
	isClient := toServer

	connKey, direction := f.normalizeKey("udp", groupSrcIP, srcPort, groupDstIP, dstPort)

	conn := f.getOrCreateConn(connKey, direction, "udp")
	conn.report(srcIP, srcPort, dstIP, dstPort)
	ts := parser.GetPacketTimestamp(packet)

	// 4-point QUIC timing: A (client) -> B (server) -> C (server) -> D (client)
	// `ja4plus/fingerprinters/ja4l.py:589-599` fills the two client points in that order.
	// Issue #186 holds the reading.
	if _, ok := conn.timestamps["A"]; !ok && isClient {
		conn.timestamps["A"] = ts
		conn.ttls["client"] = ttl
		return nil, nil
	}

	if _, ok := conn.timestamps["A"]; ok {
		if _, ok := conn.timestamps["B"]; !ok && !isClient {
			conn.timestamps["B"] = ts
			conn.ttls["server"] = ttl
			return f.emitResult("JA4L-S", ts.Sub(conn.timestamps["A"]), ttl, conn, ts), nil
		}
	}

	// The two client points read a Handshake packet only, and every other long-header type
	// fills neither of them.
	// `ja4plus/fingerprinters/ja4l.py:580-581` states the rule.
	if !parser.IsQUICHandshakePacket(udp.Payload) {
		return nil, nil
	}

	// The server sends one to five Handshake packets. The client measurement starts at the
	// last of them, so every server packet moves point C until point D fills.
	if _, ok := conn.timestamps["B"]; ok {
		if _, ok := conn.timestamps["D"]; !ok && !isClient {
			conn.timestamps["C"] = ts
			return nil, nil
		}
	}

	if _, ok := conn.timestamps["C"]; ok {
		if _, ok := conn.timestamps["D"]; !ok && isClient {
			conn.timestamps["D"] = ts
			clientTTL := conn.ttls["client"]
			return f.emitResult("JA4L-C", ts.Sub(conn.timestamps["C"]), clientTTL, conn, ts), nil
		}
	}

	return nil, nil
}

func (f *JA4LFingerprinter) normalizeKey(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) (string, string) {
	// The key holds the protocol token, and a caller of CleanupConnection chooses the
	// spelling of it. One case for every token keeps the write and the removal in step.
	proto = strings.ToLower(proto)

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

// report fixes the endpoints that every result of this connection carries.
// The first packet of the connection sets them, and a later packet does not move them.
func (c *connState) report(srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
	if c.reportedSrcIP != "" {
		return
	}

	c.reportedSrcIP = srcIP
	c.reportedDstIP = dstIP
	c.reportedSrcPort = srcPort
	c.reportedDstPort = dstPort
}

func (f *JA4LFingerprinter) emitResult(label string, diff time.Duration, ttl uint8, conn *connState, ts time.Time) []FingerprintResult {
	// JA4L reports one-way latency, so the value is half the time between the two
	// measurement points.
	// `docs/specs/foxio/JA4L.md` R6 states the rule. R6 cites four FoxIO reference
	// implementations that each divide by 2.
	// The two integer references truncate the half toward zero. Go integer division
	// truncates the same way. Issue #166 holds the reading.
	latencyUS := int(diff.Microseconds()) / latencyDivisor
	if latencyUS < 1 {
		latencyUS = 1
	}
	fingerprint := fmt.Sprintf("%s=%d_%d", label, latencyUS, ttl)
	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4l",
		SrcIP:       conn.reportedSrcIP,
		DstIP:       conn.reportedDstIP,
		SrcPort:     conn.reportedSrcPort,
		DstPort:     conn.reportedDstPort,
		Timestamp:   ts,
	}
	return []FingerprintResult{result}
}

// Reset clears the connection table.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4LFingerprinter) Reset() {
	f.ensure()

	f.connections = make(map[string]*connState)
}

// CleanupConnection removes internal state for the given connection.
// JA4L normalizes keys lexicographically by IP then port.
func (f *JA4LFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

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
