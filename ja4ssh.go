package ja4plus

import (
	"container/list"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
)

const defaultSSHWindow = 200

// The maximum count of connections the state table holds. The insert that reaches this count
// removes the connection that received no packet for the longest time.
// Issue #221 opens one connection for each completed TCP handshake to port 22. A port scan of
// that port therefore fills the table with connections that carry no SSH.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface where this
// project shipped nothing, and no FoxIO source addresses a state table.
// `ja4plus/utils/state_table.py:52` sets `DEFAULT_MAX_CONNECTIONS = 10000`.
const maxSSHConnections = 10000

// The maximum age of one connection of the state table.
// `ja4plus/utils/state_table.py:58` sets `DEFAULT_MAX_CONNECTION_AGE = 600`. The same file
// records the longest gap of the shared vector set at 320.714503 seconds, in `ssh-r.pcap`.
const maxSSHConnectionAge = 600 * time.Second

// The count of packets between two age passes. One pass reads every connection, so a pass on
// each packet costs the connection count on each packet.
// `ja4plus/utils/state_table.py:62` sets `DEFAULT_EVICTION_INTERVAL = 1000`.
const sshEvictionInterval = 1000

// The maximum count of entries the handshake table holds.
// A SYN on a non-standard port carries no SSH data, so it opens no connection and the state
// table bound above reaches no such packet. The handshake table therefore holds a bound of its
// own. `ja4plus/fingerprinters/ja4ssh.py:53` sets `MAX_HANDSHAKE_CONNECTIONS = 1000`.
const maxSSHHandshakes = 1000

// sshHandshakeClient names the client endpoint that the TCP handshake of one connection states.
// The SYN sender is the client, and the SYN+ACK sender is the server.
type sshHandshakeClient struct {
	ip   string
	port uint16
	// lastSeen holds the timestamp of the last handshake packet of the pair. The age pass
	// reads it, and the pass reads the packet clock rather than the wall clock.
	lastSeen time.Time
	// element names the position of the entry in the handshake order list. A Go map states no
	// order, so the entry bound reads the list to name the least recent entry.
	element *list.Element
}

// sshConnState tracks SSH packet statistics for a single connection.
type sshConnState struct {
	clientSizes  []int
	serverSizes  []int
	clientACKs   int
	serverACKs   int
	hassh        string
	hasshServer  string
	clientBanner string
	serverBanner string
	// clientIP, serverIP, clientPort and serverPort name the two endpoints.
	// CloseOpenWindows reads no packet, so the result reads the endpoints from here.
	clientIP   string
	serverIP   string
	clientPort uint16
	serverPort uint16
	// lastSeen holds the timestamp of the last packet of the connection. An open window
	// carries it, because no packet triggers that emission.
	lastSeen time.Time
	// element names the position of the connection in the order list of the fingerprinter.
	// The eviction reads that list, because a Go map states no order of its own.
	element *list.Element
	// arrival holds the count of connections the fingerprinter opened before this one.
	// A range over a Go map orders nothing, and CloseOpenWindows publishes in capture
	// order, so two runs of one capture agree.
	arrival int
	// clientMessages and serverMessages follow the SSH message boundary of the two
	// directions. FoxIO counts the segment that completes an SSH message, and it counts no
	// segment that holds part of one. Issue #200 records the 42 comparisons that a count of
	// the TCP segment cost.
	clientMessages parser.SSHMessageTracker
	serverMessages parser.SSHMessageTracker
}

// HASSHResult holds a HASSH fingerprint and associated metadata.
type HASSHResult struct {
	// Fingerprint holds the HASSH value.
	Fingerprint string
	// Banner holds the SSH identification string of the side.
	Banner string
	// Type is `client` or `server`.
	Type string
	// ConnKey names the connection that produced the value.
	ConnKey string
}

// JA4SSHFingerprinter generates JA4SSH fingerprints from SSH traffic patterns.
// It tracks per-connection packet sizes and ACK counts in a rolling window.
//
// Format: c{client_mode}s{server_mode}_c{client_pkts}s{server_pkts}_c{client_acks}s{server_acks}
//
// One JA4SSHFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4SSHFingerprinter struct {
	connections map[string]*sshConnState
	packetCount int
	// arrivals counts the connections the fingerprinter opened. Each connection stores
	// the value it read at its own start, and CloseOpenWindows publishes in that order.
	arrivals int
	// order holds the key of each connection of the state table. The connection that received
	// no packet for the longest time stands at the front, and the entry bound removes that
	// one. A Go map states no order of its own.
	// The state table and this list name one set of connections. openConnection is the one
	// method that adds a connection, and removeConnection is the one method that removes
	// one, so the two cannot disagree.
	order *list.List
	// packets counts the packets the fingerprinter reads. The age pass runs on the eviction
	// interval, so the eviction cost stays proportional to the traffic.
	packets int
	// handshakes holds the client endpoint that the TCP handshake of one endpoint pair states.
	// Step 2 of the client direction reads it, and #413 builds that step.
	// The key encodes no direction, so a caller that holds four endpoint values and no packet
	// reaches the entry the packet path wrote.
	handshakes map[string]*sshHandshakeClient
	// handshakeOrder holds the key of each entry of the handshake table. The entry that
	// received no packet for the longest time stands at the front, and the entry bound removes
	// that one.
	// recordHandshake is the one method that adds an entry. removeHandshake is the one method
	// that removes one, so the table and this list cannot disagree.
	handshakeOrder *list.List
}

// NewJA4SSH creates a new JA4SSH fingerprinter.
// If packetCount is 0, the default window of 200 packets is used.
func NewJA4SSH(packetCount int) *JA4SSHFingerprinter {
	if packetCount <= 0 {
		packetCount = defaultSSHWindow
	}
	return &JA4SSHFingerprinter{
		connections:    make(map[string]*sshConnState),
		packetCount:    packetCount,
		order:          list.New(),
		handshakes:     make(map[string]*sshHandshakeClient),
		handshakeOrder: list.New(),
	}
}

// ensure fills the state map and the window size that the constructor fills.
// A caller who writes `var f JA4SSHFingerprinter` reaches a nil map and a window of 0.
// A write to a nil map panics, and a window of 0 fills on every packet.
// Every entry point calls this method first.
func (f *JA4SSHFingerprinter) ensure() {
	if f.connections == nil {
		f.connections = make(map[string]*sshConnState)
	}

	if f.order == nil {
		f.order = list.New()
	}

	if f.handshakes == nil {
		f.handshakes = make(map[string]*sshHandshakeClient)
	}

	if f.handshakeOrder == nil {
		f.handshakeOrder = list.New()
	}

	if f.packetCount <= 0 {
		f.packetCount = defaultSSHWindow
	}
}

// ProcessPacket processes a packet and returns JA4SSH fingerprints when a window fills.
// It returns the open window of the connection on a packet that carries the FIN flag and the
// ACK flag. Such a packet closes the connection. Issue #222 holds the readings.
func (f *JA4SSHFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}

	// Need IP layer for connection tracking
	srcIP, dstIP, _, ok := parser.GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	// The age pass reads every connection, so it runs on the eviction interval.
	// The port announces each packet to its state table at
	// `ja4plus/fingerprinters/ja4ssh.py:122`, and it runs the pass on the same schedule.
	// The pass precedes the connection of this packet, so it can remove the connection that
	// this packet continues. The packet then opens that connection again, and the new window
	// counts from zero. The port holds the same order, and it counts such a connection as a
	// returned connection at `ja4plus/utils/state_table.py:95`.
	f.packets++
	if f.packets%sshEvictionInterval == 0 {
		f.evictAgedConnections(parser.GetPacketTimestamp(packet))
	}

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	payload := tcp.Payload

	// Check if this is an SSH data packet
	hasSSHData := len(payload) > 0 && parser.IsSSHPacket(payload)

	// The TCP handshake names the two endpoints, and it arrives before any SSH data. The
	// record precedes the admission guard below, because a SYN on a non-standard port carries
	// no SSH data and opens no connection. The guard would otherwise discard the one packet
	// that states the direction. The port holds the same order at
	// `ja4plus/fingerprinters/ja4ssh.py:152`, and its guard sits at
	// `ja4plus/fingerprinters/ja4ssh.py:179`.
	//
	// A packet that carries the RST flag opens no connection and accepts none.
	// `ja4plus/utils/packet_utils.py:40-42` denies the same packet.
	opensConnection := tcp.SYN && !tcp.ACK && !tcp.RST
	acceptsConnection := tcp.SYN && tcp.ACK && !tcp.RST

	f.recordHandshake(
		opensConnection, acceptsConnection,
		srcIP, srcPort, dstIP, dstPort, parser.GetPacketTimestamp(packet))

	clientIP, clientPort, serverIP, serverPort := f.decideEndpoints(srcIP, srcPort, dstIP, dstPort)
	isClientToServer := clientIP == srcIP && clientPort == srcPort

	connKey := fmt.Sprintf("%s:%d-%s:%d", clientIP, clientPort, serverIP, serverPort)

	// The entry bound of the handshake table can remove the entry of a connection that lives.
	// A later packet of that pair then reaches step 3, which names the other endpoint as the
	// client. The connection splits into a second entry. The connection keeps the endpoints it
	// started with. The port holds the same guard at
	// `ja4plus/fingerprinters/ja4ssh.py:159-165`.
	reversedKey := fmt.Sprintf("%s:%d-%s:%d", serverIP, serverPort, clientIP, clientPort)
	if _, held := f.connections[connKey]; !held {
		if _, reversed := f.connections[reversedKey]; reversed {
			connKey = reversedKey
			clientIP, clientPort, serverIP, serverPort = serverIP, serverPort, clientIP, clientPort
			isClientToServer = !isClientToServer
		}
	}

	conn, exists := f.connections[connKey]

	// A bare ACK carries the ACK flag alone and no payload. FoxIO PR #281 counts one only
	// where the TCP flags equal 0x0010, which denies a SYN-ACK, a FIN-ACK and a RST-ACK.
	isBareACK := len(payload) == 0 &&
		tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG

	// The third packet of the TCP handshake is a bare ACK. It arrives before the first SSH
	// packet, and the reference counts it. The state table therefore needs the connection
	// before any SSH data reaches it. `wireshark/source/packet-ja4.c:1302` reads no SSH state
	// first, and `python/ja4ssh.py:112` counts the same packet.
	// The TCP port picks the connection this test opens. A bare ACK on every TCP connection
	// would fill the state table with traffic that carries no SSH. The port holds the same test
	// at `ja4plus/fingerprinters/ja4ssh.py:176`.
	opensOnSSHPort := isBareACK && (srcPort == 22 || dstPort == 22)

	// A packet that carries the FIN flag and the ACK flag closes the connection. The
	// reference emits the window the connection holds open on it.
	// `wireshark/source/packet-ja4.c:1400` tests the flags and
	// `wireshark/source/packet-ja4.c:1402` writes the value. `python/ja4.py:555` tests the two
	// flags and `python/ja4.py:556` calls `finalize_ja4ssh`. The port holds the rule at
	// `ja4plus/fingerprinters/ja4ssh.py:268`.
	// The test reads the two flags alone, and it reads no other flag, so a FIN+PSH+ACK packet
	// reaches the emission. `wireshark/source/packet-ja4.c:1400` tests `tcp_flags == 0x011`
	// instead, and issue #222 follows the port.
	closesConnection := tcp.FIN && tcp.ACK

	// A cipher hides the length field of every SSH record after the key exchange, so the
	// byte test denies a record the reference counts. A payload on a connection the library
	// already reads still carries SSH. Issue #200 records the 42 comparisons that a stricter
	// guard cost.
	//
	// This guard also carries divergence D2 of the port, which the maintainer ruled on
	// 2026-08-11 UTC in the second comment of #129. A payload that carries SSH opens a
	// connection on any port, and the port holds the same admission at
	// `ja4plus/fingerprinters/ja4ssh.py:135`. The FoxIO Python and the Wireshark dissector
	// each require port 22 instead. The maintainer ruled D2 beside the three-step client
	// direction that `decideEndpoints` holds. The endpoint rule without the port rule
	// answers differently on a connection that uses no port 22. #129 is the reversal path,
	// and a reversal changes the port as well.
	if !hasSSHData && !opensOnSSHPort && !exists {
		return nil, nil
	}

	// Initialize connection if needed
	if !exists {
		conn = f.openConnection(connKey, clientIP, serverIP, clientPort, serverPort)
	}

	// A packet that carries no payload reaches the bare ACK counter, and it advances no
	// window.
	if len(payload) == 0 {
		if !isBareACK && !closesConnection {
			return nil, nil
		}

		if isBareACK {
			// The count reads no SSH state, because the handshake ACK precedes every SSH packet
			// of the connection. `ja4plus/fingerprinters/ja4ssh.py:250` counts the same way.

			// Count ACK for this direction
			if isClientToServer {
				conn.clientACKs++
			} else {
				conn.serverACKs++
			}
			f.touchConnection(conn, parser.GetPacketTimestamp(packet))
		}

		return f.checkWindow(conn, packet, srcIP, dstIP, srcPort, dstPort, closesConnection)
	}

	f.touchConnection(conn, parser.GetPacketTimestamp(packet))

	// The tracker reads every payload segment of the direction, and not the segments the
	// window counts alone. It reads the sequence number too, because a retransmission
	// repeats bytes the tracker already read, and a segment that arrives out of order
	// arrives before the segment it follows.
	tracker := &conn.serverMessages
	if isClientToServer {
		tracker = &conn.clientMessages
	}

	completed := tracker.AddSegment(payload, tcp.Seq)

	// Extract SSH banners and HASSH from KEXINIT
	if len(payload) >= 4 && payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-' {
		banner := string(payload)
		if idx := len(banner); idx > 0 {
			// Trim trailing CR/LF
			for len(banner) > 0 && (banner[len(banner)-1] == '\r' || banner[len(banner)-1] == '\n') {
				banner = banner[:len(banner)-1]
			}
		}
		if isClientToServer {
			conn.clientBanner = banner
		} else {
			conn.serverBanner = banner
		}
	}

	// Check for KEXINIT and extract HASSH
	kexInfo := parser.ParseKEXINITFromPacket(payload)
	if kexInfo != nil {
		if isClientToServer {
			conn.hassh = parser.ComputeHASSH(kexInfo, false)
		} else {
			conn.hasshServer = parser.ComputeHASSH(kexInfo, true)
		}
	}

	// Count the SSH packets that FoxIO counts. The reference reads the label that the
	// `tshark` SSH dissector writes. That dissector labels the segment that completes an SSH
	// message. It labels no segment that holds part of one.
	// `wireshark/source/packet-ja4.c:1469` counts one packet for each `ssh.direction` field,
	// and `python/ja4ssh.py:94` counts the packet whose protocol list holds `ssh`. The port
	// holds the same rule at `ja4plus/fingerprinters/ja4ssh.py:247`.
	// The version line of either direction identifies the connection, so an opaque record
	// counts from that point on.
	if len(completed) > 0 && (hasSSHData || conn.clientBanner != "" || conn.serverBanner != "") {
		if isClientToServer {
			conn.clientSizes = append(conn.clientSizes, completed...)
		} else {
			conn.serverSizes = append(conn.serverSizes, completed...)
		}
	}

	return f.checkWindow(conn, packet, srcIP, dstIP, srcPort, dstPort, closesConnection)
}

// openConnection returns a new connection of the state table, and it holds the entry bound.
// The bound removes the connection that received no packet for the longest time, until the
// state table holds space for this connection. The port applies the same bound at the insert,
// at `ja4plus/utils/state_table.py:509`.
// A removed connection that receives a later packet reaches this method again, and its window
// then counts from zero.
func (f *JA4SSHFingerprinter) openConnection(
	connKey string, clientIP string, serverIP string, clientPort uint16, serverPort uint16,
) *sshConnState {
	for len(f.connections) >= maxSSHConnections {
		front := f.order.Front()
		if front == nil {
			break
		}

		oldestKey, held := front.Value.(string)
		if !held {
			f.order.Remove(front)
			continue
		}

		f.removeConnection(oldestKey)
	}

	conn := &sshConnState{
		clientIP:   clientIP,
		serverIP:   serverIP,
		clientPort: clientPort,
		serverPort: serverPort,
		arrival:    f.arrivals,
	}

	f.connections[connKey] = conn
	conn.element = f.order.PushBack(connKey)
	f.arrivals++

	return conn
}

// touchConnection records the timestamp of the packet on the connection, and it moves the
// connection to the back of the order list.
// The two bounds read one measure of recency, because the entry bound removes the front
// connection and the age pass reads the same timestamp.
func (f *JA4SSHFingerprinter) touchConnection(conn *sshConnState, timestamp time.Time) {
	conn.lastSeen = timestamp

	if conn.element != nil {
		f.order.MoveToBack(conn.element)
	}
}

// removeConnection removes one connection from the state table and from the order list.
// One method serves every removal path, because a state table and an order list that disagree
// remove the wrong connection at the entry bound.
func (f *JA4SSHFingerprinter) removeConnection(connKey string) {
	conn, held := f.connections[connKey]
	if !held {
		return
	}

	delete(f.connections, connKey)

	if conn.element != nil {
		f.order.Remove(conn.element)
		conn.element = nil
	}
}

// evictAgedConnections removes each connection and each handshake entry that received no
// packet for the maximum age.
//
// The clock reads the packet timestamp, and never the wall clock. A capture replays faster
// than the wall clock, so a wall clock removes state that the capture still needs. The port
// reads the packet timestamp at `ja4plus/fingerprinters/ja4ssh.py:122`.
//
// The pass reads every connection. A capture states a timestamp of its own, so two packets can
// arrive out of order. The order list then does not follow the age.
//
// The packet carries that timestamp, so a crafted capture controls it, and one timestamp
// decides the age of every connection.
//
// The forged timestamp reaches two cases, and this comment states both.
//
//   - The key of the sender. A packet dated far in the future gives every later packet of
//     that connection a negative age, so this pass removes that entry never.
//   - Every other key. The packet that carries the future timestamp ages the whole table at
//     once, so this pass removes every other connection and every handshake entry.
//
// **The maintainer ruled the second case on 2026-08-14, and the library accepts it.** Issue
// #577 holds the ruling and the reversal path. `state_bound.go`, `ja4ts.go` and `ja4h.go` hold the same clock, and
// the port holds it at `ja4plus/utils/state_table.py:414` of tag `v1.1.0`.
// `age_clock_ruling_test.go` builds the separating packet.
//
// The entry bound holds the memory whatever the timestamp states, because it reads the
// recency order and no timestamp. So the loss of the second case is the tracked state, and
// never the memory.
func (f *JA4SSHFingerprinter) evictAgedConnections(now time.Time) {
	for element := f.order.Front(); element != nil; {
		next := element.Next()

		connKey, held := element.Value.(string)
		if held {
			if conn, present := f.connections[connKey]; present &&
				now.Sub(conn.lastSeen) > maxSSHConnectionAge {
				f.removeConnection(connKey)
			}
		}

		element = next
	}

	// The handshake table reads the same age, because one age serves the two tables and the
	// port reads one class for both.
	for element := f.handshakeOrder.Front(); element != nil; {
		next := element.Next()

		key, held := element.Value.(string)
		if held {
			if entry, present := f.handshakes[key]; present &&
				now.Sub(entry.lastSeen) > maxSSHConnectionAge {
				f.removeHandshake(key)
			}
		}

		element = next
	}
}

// checkWindow emits the window when the count of SSH packets reaches the threshold, and it
// emits the open window when the packet closes the connection.
//
// The window counts the SSH packets of the two directions, and a bare ACK does not advance
// it. `technical_details/JA4SSH.png` lists the SSH packet counts and the bare ACK counts as
// separate fields, and `ja4plus/fingerprinters/ja4ssh.py:259` counts the SSH packets alone.
// The threshold holds no upper cap, so the default window of 200 emits at 200 packets. The
// port's issue #28 rules the threshold, and its issue #97 declines an empty window.
//
// `closing` reports a packet that carries the FIN flag and the ACK flag. One packet reaches
// one emission, because the reference reads one window boundary for it. The port holds the
// same order at `ja4plus/fingerprinters/ja4ssh.py:261` and
// `ja4plus/fingerprinters/ja4ssh.py:268`. Issue #222 records the reading.
func (f *JA4SSHFingerprinter) checkWindow(conn *sshConnState, packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, closing bool) ([]FingerprintResult, error) {
	if len(conn.clientSizes)+len(conn.serverSizes) < f.packetCount && !closing {
		return nil, nil
	}

	result, held := emitSSHWindow(conn, srcIP, dstIP, srcPort, dstPort, parser.GetPacketTimestamp(packet))
	if !held {
		return nil, nil
	}

	return []FingerprintResult{result}, nil
}

// emitSSHWindow returns the value of the open window of the connection, and it starts a new
// window.
// It reports false when the window holds no SSH packet, because a value of an empty window
// describes no traffic. The port's issue #97 declines the same value, and
// `ja4plus/fingerprinters/ja4ssh.py:423` holds the guard.
// The mode field reads the packet lengths of the window alone, because the emission clears
// the two length lists.
func emitSSHWindow(conn *sshConnState, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time) (FingerprintResult, bool) {
	if len(conn.clientSizes) == 0 && len(conn.serverSizes) == 0 {
		return FingerprintResult{}, false
	}

	fingerprint := fmt.Sprintf("c%ds%d_c%ds%d_c%ds%d",
		mode(conn.clientSizes), mode(conn.serverSizes),
		len(conn.clientSizes), len(conn.serverSizes),
		conn.clientACKs, conn.serverACKs,
	)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4ssh",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Timestamp:   timestamp,
	}

	// Start the next window. The mode field of the next value reads that window alone.
	conn.clientSizes = nil
	conn.serverSizes = nil
	conn.clientACKs = 0
	conn.serverACKs = 0

	return result, true
}

// CloseOpenWindows returns the value of the window that each connection holds open, and it
// starts a new window on each one.
//
// The caller calls the method when the packet source ends. A connection whose last window
// never reaches the threshold holds that window open, and this method is the one rule that
// emits it.
// ProcessPacket emits the open window on a packet that carries the FIN flag and the ACK flag.
// A connection that sends such a packet therefore holds no window open.
// `rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164` both emit that window, and
// the port's issues #105, #199 and #214 hold the ruling.
//
// It returns the values in the order the packet source opened the connections.
// It returns an empty slice for a window that holds no SSH packet, so a second call returns
// an empty slice.
// Each result names the client of the connection as the source and the server as the
// destination. No packet triggers this emission, so the result reads the endpoints of the
// connection. A result that ProcessPacket returns names the sender of the packet that filled
// the window, which is the direction that every other method of this library reports.
// The method is opt-in. A caller who never calls it loses the open window, and the library
// forces no flush.
func (f *JA4SSHFingerprinter) CloseOpenWindows() []FingerprintResult {
	f.ensure()

	order := make([]*sshConnState, 0, len(f.connections))
	for _, conn := range f.connections {
		order = append(order, conn)
	}

	sort.Slice(order, func(first, second int) bool {
		return order[first].arrival < order[second].arrival
	})

	var results []FingerprintResult

	for _, conn := range order {
		result, held := emitSSHWindow(
			conn, conn.clientIP, conn.serverIP, conn.clientPort, conn.serverPort, conn.lastSeen)
		if held {
			results = append(results, result)
		}
	}

	return results
}

// GetHASSHFingerprints returns all collected HASSH fingerprints across tracked connections.
func (f *JA4SSHFingerprinter) GetHASSHFingerprints() []HASSHResult {
	f.ensure()

	var results []HASSHResult
	for connKey, conn := range f.connections {
		if conn.hassh != "" {
			results = append(results, HASSHResult{
				Fingerprint: conn.hassh,
				Banner:      conn.clientBanner,
				Type:        "client",
				ConnKey:     connKey,
			})
		}
		if conn.hasshServer != "" {
			results = append(results, HASSHResult{
				Fingerprint: conn.hasshServer,
				Banner:      conn.serverBanner,
				Type:        "server",
				ConnKey:     connKey,
			})
		}
	}
	return results
}

// Reset clears the connection table.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
// It keeps the arrival counter. The counter orders the connections that CloseOpenWindows
// publishes, and a counter that returns to zero would order a new connection against a
// stale number.
// It empties the order list too, because the state table and that list name one set of
// connections. It keeps the packet counter, which schedules the age pass alone.
// It empties the handshake table and the handshake order list, which step 2 of the client
// direction reads. `.claude/rules/concurrency.md` states that a new state map reaches
// CleanupConnection and Reset.
func (f *JA4SSHFingerprinter) Reset() {
	f.ensure()

	f.connections = make(map[string]*sshConnState)
	f.order.Init()
	f.handshakes = make(map[string]*sshHandshakeClient)
	f.handshakeOrder.Init()
}

// decideEndpoints returns the client endpoint and the server endpoint of one packet.
//
// The maintainer ruled a three-step order for the client direction on 2026-08-11, in the
// second comment of #129. Three steps decide, in this order.
//
//  1. An endpoint on port 22 is the server.
//  2. The TCP handshake names the client, because the SYN sender opens the connection.
//  3. The lower port is the server. That answer is a guess, because two ephemeral ports carry
//     no meaning of their own.
//
// The project manager ruled #346 on 2026-08-13, under the widened delegation that
// `.claude/rules/rulings.md` holds. That ruling is provisional, and the maintainer confirms it
// or reverses it. A reversal deletes step 2 and records the decline, in this repository and in
// the port together.
//
// One method serves the packet path and sshConnKeyOfEndpoints. A second copy of the three
// steps answers differently after a later change to one copy. The two answers then name two
// keys for one connection.
// The port holds the same three steps at `ja4plus/fingerprinters/ja4ssh.py:321-365`.
func (f *JA4SSHFingerprinter) decideEndpoints(
	srcIP string, srcPort uint16, dstIP string, dstPort uint16,
) (clientIP string, clientPort uint16, serverIP string, serverPort uint16) {
	if dstPort == 22 {
		return srcIP, srcPort, dstIP, dstPort
	}

	if srcPort == 22 {
		return dstIP, dstPort, srcIP, srcPort
	}

	if client, held := f.handshakes[sshHandshakeKey(srcIP, srcPort, dstIP, dstPort)]; held {
		if client.ip == srcIP && client.port == srcPort {
			return srcIP, srcPort, dstIP, dstPort
		}

		if client.ip == dstIP && client.port == dstPort {
			return dstIP, dstPort, srcIP, srcPort
		}
	}

	if srcPort > dstPort {
		return srcIP, srcPort, dstIP, dstPort
	}

	return dstIP, dstPort, srcIP, srcPort
}

// sshHandshakeKey returns the key of one endpoint pair, in either order.
//
// The key encodes no direction. The state-table key names the client first, and step 2 decides
// which endpoint that is. A key of that shape therefore misses the entry that decides it. The
// port holds the same rule at `ja4plus/fingerprinters/ja4ssh.py:281-287`.
func sshHandshakeKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, srcPort, dstIP, dstPort = dstIP, dstPort, srcIP, srcPort
	}

	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// recordHandshake records the client endpoint that the TCP handshake of one pair names.
//
// The SYN sender is the client. The SYN+ACK sender is the server, so the destination of that
// packet is the client. A capture that starts after the SYN still holds the SYN+ACK.
//
// It records nothing when one endpoint holds port 22, because step 1 decides that connection
// and the entry would hold state that nothing reads. Every SSH capture of the corpus holds
// port 22 on one side. The port returns on the same test at
// `ja4plus/fingerprinters/ja4ssh.py:308-309`.
//
// The entry bound removes the entry that received no packet for the longest time, until the
// table holds space for this entry.
func (f *JA4SSHFingerprinter) recordHandshake(
	opens bool, accepts bool,
	srcIP string, srcPort uint16, dstIP string, dstPort uint16, timestamp time.Time,
) {
	if srcPort == 22 || dstPort == 22 {
		return
	}

	var clientIP string
	var clientPort uint16

	switch {
	case opens:
		clientIP, clientPort = srcIP, srcPort
	case accepts:
		clientIP, clientPort = dstIP, dstPort
	default:
		return
	}

	key := sshHandshakeKey(srcIP, srcPort, dstIP, dstPort)

	if entry, held := f.handshakes[key]; held {
		entry.ip = clientIP
		entry.port = clientPort
		entry.lastSeen = timestamp
		f.handshakeOrder.MoveToBack(entry.element)

		return
	}

	for len(f.handshakes) >= maxSSHHandshakes {
		front := f.handshakeOrder.Front()
		if front == nil {
			break
		}

		oldestKey, held := front.Value.(string)
		if !held {
			f.handshakeOrder.Remove(front)
			continue
		}

		f.removeHandshake(oldestKey)
	}

	entry := &sshHandshakeClient{ip: clientIP, port: clientPort, lastSeen: timestamp}
	f.handshakes[key] = entry
	entry.element = f.handshakeOrder.PushBack(key)
}

// removeHandshake removes one entry from the handshake table and from the handshake order
// list.
// One method serves every removal path, because a table and an order list that disagree remove
// the wrong entry at the entry bound.
func (f *JA4SSHFingerprinter) removeHandshake(key string) {
	entry, held := f.handshakes[key]
	if !held {
		return
	}

	delete(f.handshakes, key)

	if entry.element != nil {
		f.handshakeOrder.Remove(entry.element)
		entry.element = nil
	}
}

// sshConnKeyOfEndpoints returns the state-table key of the connection the two endpoints
// name, in either order.
// JA4SSH normalizes the key by the three steps of decideEndpoints, so a caller names the two
// endpoints in either order and reaches one key.
// CleanupConnection and CloseConnectionWindow both read it. Neither one holds a packet, and
// step 2 reads the handshake table rather than the packet. Both therefore reach the answer
// that the packet path reached.
func (f *JA4SSHFingerprinter) sshConnKeyOfEndpoints(
	srcIP string, srcPort uint16, dstIP string, dstPort uint16,
) string {
	clientIP, clientPort, serverIP, serverPort := f.decideEndpoints(srcIP, srcPort, dstIP, dstPort)

	return fmt.Sprintf("%s:%d-%s:%d", clientIP, clientPort, serverIP, serverPort)
}

// CleanupConnection removes internal state for the given connection.
// JA4SSH normalizes keys by the three steps of decideEndpoints.
// It removes the handshake entry of the pair too. That entry would otherwise outlive the
// connection, because the caller states that the connection ended. The port removes the same
// entry at `ja4plus/fingerprinters/ja4ssh.py:541-544`.
// It emits no fingerprint. A caller that wants the open window of the connection calls
// CloseConnectionWindow instead, and issue #216 records that ruling.
func (f *JA4SSHFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	f.removeConnection(f.sshConnKeyOfEndpoints(srcIP, srcPort, dstIP, dstPort))
	f.removeHandshake(sshHandshakeKey(srcIP, srcPort, dstIP, dstPort))
}

// CloseConnectionWindow returns the value of the window that one connection holds open, and
// it then removes the connection.
//
// The caller calls the method when it evicts one connection, which is the moment the
// reference publishes the final window. `rust/ja4/src/ssh.rs:45-55` and
// `zeek/ja4ssh/main.zeek:160-164` both emit at teardown, and CloseOpenWindows reaches every
// connection at once, which is the wrong instrument for one connection that just ended.
// The maintainer ruled the method on 2026-08-12, and issue #216 records the ruling.
//
// It names the connection by the same key CleanupConnection accepts, so the caller names the
// two endpoints in either order.
// It returns an empty slice for a connection the state table does not hold, and an empty
// slice for a window that holds no SSH packet. It removes the connection in both cases, so a
// second call returns an empty slice.
// The result names the client of the connection as the source and the server as the
// destination. CloseOpenWindows names the two endpoints the same way. No packet triggers
// this emission, so the result reads the endpoints of the connection.
// The method is opt-in. CleanupConnection still emits nothing, so a caller that only reclaims
// memory receives no fingerprint it did not ask for.
func (f *JA4SSHFingerprinter) CloseConnectionWindow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) []FingerprintResult {
	f.ensure()

	connKey := f.sshConnKeyOfEndpoints(srcIP, srcPort, dstIP, dstPort)

	// The caller states that the connection ended, so the handshake entry of the pair goes with
	// it. The removal precedes the two returns below, because a connection the state table does
	// not hold still carries an entry that a SYN wrote.
	f.removeHandshake(sshHandshakeKey(srcIP, srcPort, dstIP, dstPort))

	conn, exists := f.connections[connKey]
	if !exists {
		return nil
	}

	result, held := emitSSHWindow(
		conn, conn.clientIP, conn.serverIP, conn.clientPort, conn.serverPort, conn.lastSeen)

	// The eviction follows the emission, which is the order the ruling of issue #216 states.
	// A window that holds no SSH packet reaches this line too, because CleanupConnection
	// evicts such a connection and this method must not leave it behind.
	f.removeConnection(connKey)

	if !held {
		return nil
	}

	return []FingerprintResult{result}
}

// mode returns the most common value in a slice. Returns 0 if the slice is empty.
// On ties, the LOWEST value wins (FoxIO PR #281 deterministic tiebreak).
func mode(values []int) int {
	if len(values) == 0 {
		return 0
	}
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}
	var bestVal int
	var bestCount int
	first := true
	for v, c := range freq {
		if first || c > bestCount || (c == bestCount && v < bestVal) {
			bestVal = v
			bestCount = c
			first = false
		}
	}
	return bestVal
}

// hasshKnownNames is a built-in lookup table of common HASSH fingerprints.
// Ported verbatim from the Python ja4plus reference implementation.
var hasshKnownNames = map[string]string{
	"8a8ae540028bf433cd68356c1b9e8d5b": "CyberDuck Version 6.7.1",
	"b5752e36ba6c5979a575e43178908adf": "Paramiko 2.4.1 (Metasploit)",
	"16f898dd8ed8279e1055350b4e20666c": "Dropbear 2012.55 (IoT)",
	"06046964c022c6407d15a27b12a6a4fb": "OpenSSH 7.6",
	"de30354b88bae4c2810426614e1b6976": "Renci.SshNet.SshClient (PowerShell/Empire)",
	"fafc45381bfde997b6305c4e1600f1bf": "Ruby/Net::SSH 5.0.2 (Metasploit)",
	"c1c596caaeb93c566b8ecf3cae9b5a9e": "Dropbear 2016.74 (Server)",
	"d93f46d063c4382b6232a4d77db532b2": "Dropbear 2016.72 (Server)",
	"2dd9a9b3dbebfaeec8b8aabd689e75d2": "AWSCodeCommit (Server)",
	"696e7f84ac571fdf8fa5073e64ee2dc8": "SSH-2.0-FTP (Server)",
}

// LookupHASSH returns a human-readable name for a known HASSH fingerprint,
// or "" if the fingerprint is not in the built-in lookup table.
func LookupHASSH(hassh string) string {
	return hasshKnownNames[hassh]
}

// SSHSessionInfo holds the interpretation of a JA4SSH fingerprint.
type SSHSessionInfo struct {
	// SessionType names the class of the session.
	SessionType string
	// Description states the reading in one sentence.
	Description string
	// ClientMode is the mode of the client payload size.
	ClientMode int
	// ServerMode is the mode of the server payload size.
	ServerMode int
	// ClientSSH is the count of SSH packets the client sent.
	ClientSSH int
	// ServerSSH is the count of SSH packets the server sent.
	ServerSSH int
	// ClientACK is the count of bare ACKs the client sent.
	ClientACK int
	// ServerACK is the count of bare ACKs the server sent.
	ServerACK int
}

// InterpretJA4SSH parses a JA4SSH fingerprint and classifies the session type.
// Returns nil if the fingerprint format is invalid.
func InterpretJA4SSH(fingerprint string) *SSHSessionInfo {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return nil
	}

	info := &SSHSessionInfo{}

	// Parse c{val}s{val} format from each part
	if n, _ := fmt.Sscanf(parts[0], "c%ds%d", &info.ClientMode, &info.ServerMode); n != 2 {
		return nil
	}
	if n, _ := fmt.Sscanf(parts[1], "c%ds%d", &info.ClientSSH, &info.ServerSSH); n != 2 {
		return nil
	}
	if n, _ := fmt.Sscanf(parts[2], "c%ds%d", &info.ClientACK, &info.ServerACK); n != 2 {
		return nil
	}

	// Classify session type
	if info.ClientMode == 36 && info.ServerMode == 36 && info.ClientACK > 60 {
		info.SessionType = "Interactive SSH Session"
		info.Description = "Normal interactive terminal session, client typing commands"
	} else if info.ClientMode > 70 && info.ServerMode > 70 && info.ServerACK > 60 {
		info.SessionType = "Reverse SSH Session"
		info.Description = "Double-padded SSH tunnel, server side typing commands"
	} else if info.ServerMode > 1000 && info.ClientSSH < 20 && info.ServerSSH > 80 {
		info.SessionType = "SSH File Transfer"
		info.Description = "Server sending large packets to client (download)"
	} else if info.ClientMode > 1000 && info.ClientSSH > 80 && info.ServerSSH < 20 {
		info.SessionType = "SSH File Transfer (Upload)"
		info.Description = "Client sending large packets to server (upload)"
	} else {
		info.SessionType = "Unknown"
	}

	return info
}
