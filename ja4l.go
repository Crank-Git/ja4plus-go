package ja4plus

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// quicPort is the UDP port that names the server of a QUIC flow.
// The reference reads the direction of every QUIC packet from this one number.
// `ja4plus/fingerprinters/ja4l.py:55` holds the same value.
const quicPort uint16 = 443

// quicMarker names the protocol of a QUIC connection in the third part of a JA4L value.
// A TCP connection carries two parts, and a QUIC connection carries three.
// `ja4plus/fingerprinters/ja4l.py:62` defines `QUIC_MARKER = "quic"`, and the port writes
// three parts at `:549` and at `:602`. Issue #197 holds the ruling, and port issue #225
// holds the other half.
const quicMarker = "quic"

// latencyDivisor turns a measured time into the one-way latency that JA4L reports.
// One measurement covers a round trip. `docs/specs/foxio/JA4L.md` R6 states the rule.
const latencyDivisor = 2

type connState struct {
	timestamps map[string]time.Time // "A", "B", "C", "D" (for QUIC 4-point)
	ttls       map[string]uint8     // "client", "server"
	// isns holds the initial sequence number of each endpoint, keyed by the endpoint.
	// The client measurement point reads a relative sequence number, and a relative number
	// needs the initial sequence number that the SYN of the endpoint carries.
	isns      map[string]uint32
	direction string // "forward" or "reverse"
	connKey   string
	proto     string // "tcp" or "udp"
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
	// groupingKeys reads the grouping key of a connection from the reported key.
	// A caller of CleanupConnection holds the address pair that a FingerprintResult
	// carries, and a tunneled connection groups under the inner pair. Without this map the
	// caller names a key that `connections` never holds.
	// `ja4plus/fingerprinters/ja4l.py:100-104` holds the same map.
	groupingKeys map[string]string
}

// NewJA4L creates a new JA4L latency fingerprinter.
func NewJA4L() *JA4LFingerprinter {
	return &JA4LFingerprinter{
		connections:  make(map[string]*connState),
		groupingKeys: make(map[string]string),
	}
}

// ensure fills the state map that the constructor fills.
// A caller who writes `var f JA4LFingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4LFingerprinter) ensure() {
	if f.connections == nil {
		f.connections = make(map[string]*connState)
	}

	if f.groupingKeys == nil {
		f.groupingKeys = make(map[string]string)
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
	if conn.report(srcIP, srcPort, dstIP, dstPort) {
		f.indexReported(conn)
	}
	ts := parser.GetPacketTimestamp(packet)

	// The SYN of each endpoint carries the initial sequence number that every relative
	// number of that endpoint counts from.
	//
	// The two endpoint names read the grouping address pair, and never the reported pair. A
	// mirror sends both directions of one session from one outer address to one other outer
	// address, so the reported pair names the sender of every packet alike. The initial
	// sequence number of the server would then reach a name that no client packet reads, and
	// `gre-erspan-vxlan.pcap` stream 0 would reach no client value.
	source := tcpEndpoint(groupSrcIP, srcPort)

	// Point A and point B never move. `python/common.py:101` names `A` and `B` among the
	// fields that the reference declines to update, so a repeated SYN or a repeated SYN-ACK
	// keeps the first timestamp and the first TTL. A second server value would repeat the
	// first, and the reference publishes one server value for one connection.
	// `ja4plus/fingerprinters/ja4l.py:456-461` holds the same rule, and the port measured the
	// repeat on `ssh2.pcapng` stream 15 in its issue #272.

	// SYN packet (not SYN-ACK).
	if tcpLayer.SYN && !tcpLayer.ACK {
		// A SYN that carries another initial sequence number opens another connection on the
		// same endpoints, and the reference counts the two separately.
		// `ja4plus/fingerprinters/ja4l.py:433-437` holds the test, and
		// `ja4plus/fingerprinters/ja4l.py:406-417` clears the state. Issue #211 holds the
		// reading.
		if conn.opensASecondConnection(source, tcpLayer.Seq) {
			conn.restart()
		}

		conn.isns[source] = tcpLayer.Seq

		if _, held := conn.timestamps["A"]; held {
			return nil, nil
		}

		conn.timestamps["A"] = ts
		conn.ttls["client"] = ttl

		return nil, nil
	}

	// SYN-ACK packet.
	if tcpLayer.SYN && tcpLayer.ACK {
		conn.isns[source] = tcpLayer.Seq

		if _, held := conn.timestamps["B"]; held {
			return nil, nil
		}

		conn.timestamps["B"] = ts
		conn.ttls["server"] = ttl

		if synTime, ok := conn.timestamps["A"]; ok {
			return f.emitResult("JA4L-S", ts.Sub(synTime), ttl, conn, ts), nil
		}

		return nil, nil
	}

	// ACK packet that carries no SYN.
	if tcpLayer.ACK && !tcpLayer.SYN {
		return f.clientPoint(conn, tcpLayer, source, tcpEndpoint(groupDstIP, dstPort), ts), nil
	}

	return nil, nil
}

// tcpEndpoint names one endpoint of a TCP connection.
// The caller supplies the grouping address of the endpoint, which separates the two
// directions of a mirrored session. `docs/specs/spec.md` `## Changelog` round 12 states the
// two keys of a tunneled connection.
func tcpEndpoint(ip string, port uint16) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// relativeNumbers returns the relative sequence number and the relative acknowledgement
// number of one TCP packet.
//
// It returns false when the capture holds no SYN for one of the two endpoints, because a
// relative number counts from the initial sequence number that the SYN carries.
// `python/ja4.py:570` reads the two numbers that the dissector counts. A sequence number
// wraps at 32 bits, and unsigned subtraction wraps the same way.
func (c *connState) relativeNumbers(source, target string, seq, acknowledgement uint32) (uint32, uint32, bool) {
	sourceISN, held := c.isns[source]
	if !held {
		return 0, 0, false
	}

	targetISN, held := c.isns[target]
	if !held {
		return 0, 0, false
	}

	return seq - sourceISN, acknowledgement - targetISN, true
}

// opensASecondConnection reports whether one SYN opens a second connection on the endpoints of
// a connection that this state already times.
//
// The endpoint that sends a retransmitted SYN holds the initial sequence number of that SYN
// already, so a retransmission opens no second connection.
// `ja4plus/fingerprinters/ja4l.py:435` reads the initial sequence number of the endpoint with
// `dict.get`, which matches no value when the connection holds none for that endpoint.
func (c *connState) opensASecondConnection(source string, sequence uint32) bool {
	if _, held := c.timestamps["A"]; !held {
		return false
	}

	isn, held := c.isns[source]

	return !held || isn != sequence
}

// restart drops every measurement point of one connection.
//
// A second connection that reuses the endpoints of a closed one reads the points of the first
// one without this call, and its client value grows with the age of the state.
// `ja4plus/fingerprinters/ja4l.py:406-417` clears the same three maps. The port also drops the
// index of the client value it reported, and this library holds no such index, because
// ProcessPacket returns every result to the caller. Issue #25 removed the results slice.
//
// The endpoints that every result reports stay, because the first packet of the address pair
// fixes them. `docs/specs/spec.md` `## Changelog` holds that ruling.
func (c *connState) restart() {
	c.timestamps = make(map[string]time.Time)
	c.ttls = make(map[string]uint8)
	c.isns = make(map[string]uint32)
}

// holdsACompleteHTTPRequest reports whether the payload holds an HTTP request with its whole
// header block.
//
// The reference keeps the timestamps of a packet under the protocol that its dissector
// reports, and `python/common.py:77-83` gives a packet of the `http` protocol a separate
// cache. That cache holds no measurement point of the connection, so a packet that carries a
// whole request moves the client point of no connection. A packet that carries the first part
// of a request reaches the same cache as any other TCP packet, and it does move the point.
//
// `latest.pcapng` stream 6 and `http-empty-useragent.pcap` prove the two halves.
func holdsACompleteHTTPRequest(payload []byte) bool {
	if !parser.IsHTTPRequest(payload) {
		return false
	}

	return bytes.Contains(payload, []byte("\r\n\r\n")) || bytes.Contains(payload, []byte("\n\n"))
}

// clientPoint moves the client measurement point to this packet, and it returns the JA4L-C
// value that the packet gives.
//
// The reference records the point on every packet that carries `ACK`, carries no `SYN`, and
// holds the relative sequence number `1` and the relative acknowledgement number `1`. That is
// the bare ACK of the handshake first, and then the first packet of the application
// handshake. `python/ja4.py:570` states the rule.
//
// The point moves. `python/common.py:101` omits `C` from the fields
// that it declines to update, so a later packet replaces the point and the value.
//
// The point moves in either direction, and the value reads the client TTL for a packet of
// either direction. `python/ja4.py:159` reads `client_ttl`.
//
// Issue #196 holds the reading.
func (f *JA4LFingerprinter) clientPoint(
	conn *connState,
	tcpLayer *layers.TCP,
	source, target string,
	ts time.Time,
) []FingerprintResult {
	synAckTime, held := conn.timestamps["B"]
	if !held {
		return nil
	}

	clientTTL, held := conn.ttls["client"]
	if !held {
		return nil
	}

	sequence, acknowledgement, read := conn.relativeNumbers(source, target, tcpLayer.Seq, tcpLayer.Ack)
	if !read || sequence != 1 || acknowledgement != 1 {
		return nil
	}

	if holdsACompleteHTTPRequest(tcpLayer.Payload) {
		return nil
	}

	conn.timestamps["C"] = ts

	return f.emitResult("JA4L-C", ts.Sub(synAckTime), clientTTL, conn, ts)
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
	if conn.report(srcIP, srcPort, dstIP, dstPort) {
		f.indexReported(conn)
	}
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
			isns:       make(map[string]uint32),
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
// It returns true when it set them, so that the caller indexes the reported key once.
func (c *connState) report(srcIP string, srcPort uint16, dstIP string, dstPort uint16) bool {
	if c.reportedSrcIP != "" {
		return false
	}

	c.reportedSrcIP = srcIP
	c.reportedDstIP = dstIP
	c.reportedSrcPort = srcPort
	c.reportedDstPort = dstPort

	return true
}

// indexReported records the reported key of the connection, so that CleanupConnection
// reaches the grouping key from the address pair a FingerprintResult carries.
// The two keys hold one value for a connection that no tunnel carries.
// FR-gaps-14c states the rule.
func (f *JA4LFingerprinter) indexReported(conn *connState) {
	reportedKey, _ := f.normalizeKey(conn.proto,
		conn.reportedSrcIP, conn.reportedSrcPort, conn.reportedDstIP, conn.reportedDstPort)
	f.groupingKeys[reportedKey] = conn.connKey
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

	// A QUIC connection reaches this method only through processUDP, which admits a UDP
	// flow that carries a QUIC long header alone. The protocol token therefore names QUIC.
	if conn.proto == "udp" {
		fingerprint = fmt.Sprintf("%s_%s", fingerprint, quicMarker)
	}

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
	f.groupingKeys = make(map[string]string)
}

// CleanupConnection removes internal state for the given connection.
// The caller names the address pair that a FingerprintResult carries, which is the
// reported key. A tunneled connection groups under the inner address pair, so this method
// reads the grouping key from the reported key first.
// JA4L normalizes keys lexicographically by IP then port.
func (f *JA4LFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	reportedKey, _ := f.normalizeKey(proto, srcIP, srcPort, dstIP, dstPort)

	// A caller that names the grouping key reaches no index entry, and the key it gave
	// removes the connection directly. `ja4plus/fingerprinters/ja4l.py:216` falls back the
	// same way.
	connKey, indexed := f.groupingKeys[reportedKey]
	if !indexed {
		connKey = reportedKey
	}

	// A caller that names the grouping key removes no index entry above, because the index
	// holds the reported key alone. The connection carries the reported pair, so the method
	// reads that pair and removes the entry the caller cannot name. Without this removal one
	// entry leaks for every tunneled connection, and a long-running monitor never reclaims
	// it.
	if conn, held := f.connections[connKey]; held {
		indexedKey, _ := f.normalizeKey(conn.proto,
			conn.reportedSrcIP, conn.reportedSrcPort, conn.reportedDstIP, conn.reportedDstPort)
		delete(f.groupingKeys, indexedKey)
	}

	delete(f.groupingKeys, reportedKey)
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
