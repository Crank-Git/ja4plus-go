package ja4plus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

const defaultSSHWindow = 200

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
	Fingerprint string
	Banner      string
	Type        string // "client" or "server"
	ConnKey     string
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
}

// NewJA4SSH creates a new JA4SSH fingerprinter.
// If packetCount is 0, the default window of 200 packets is used.
func NewJA4SSH(packetCount int) *JA4SSHFingerprinter {
	if packetCount <= 0 {
		packetCount = defaultSSHWindow
	}
	return &JA4SSHFingerprinter{
		connections: make(map[string]*sshConnState),
		packetCount: packetCount,
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

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	payload := tcp.Payload

	// Check if this is an SSH data packet
	hasSSHData := len(payload) > 0 && parser.IsSSHPacket(payload)

	// Determine client/server direction
	var clientIP, serverIP string
	var clientPort, serverPort uint16
	var isClientToServer bool

	if dstPort == 22 {
		clientIP, serverIP = srcIP, dstIP
		clientPort, serverPort = srcPort, dstPort
		isClientToServer = true
	} else if srcPort == 22 {
		clientIP, serverIP = dstIP, srcIP
		clientPort, serverPort = dstPort, srcPort
		isClientToServer = false
	} else {
		// Non-standard port: higher port is client, lower port is server
		// (fixed from Python where this was reversed)
		if srcPort > dstPort {
			clientIP, serverIP = srcIP, dstIP
			clientPort, serverPort = srcPort, dstPort
			isClientToServer = true
		} else {
			clientIP, serverIP = dstIP, srcIP
			clientPort, serverPort = dstPort, srcPort
			isClientToServer = false
		}
	}

	connKey := fmt.Sprintf("%s:%d-%s:%d", clientIP, clientPort, serverIP, serverPort)

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
	if !hasSSHData && !opensOnSSHPort && !exists {
		return nil, nil
	}

	// Initialize connection if needed
	if !exists {
		conn = &sshConnState{
			clientIP:   clientIP,
			serverIP:   serverIP,
			clientPort: clientPort,
			serverPort: serverPort,
			arrival:    f.arrivals,
		}
		f.connections[connKey] = conn
		f.arrivals++
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
			conn.lastSeen = parser.GetPacketTimestamp(packet)
		}

		return f.checkWindow(conn, packet, srcIP, dstIP, srcPort, dstPort, closesConnection)
	}

	conn.lastSeen = parser.GetPacketTimestamp(packet)

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
func (f *JA4SSHFingerprinter) Reset() {
	f.ensure()

	f.connections = make(map[string]*sshConnState)
}

// sshConnKeyOfEndpoints returns the state-table key of the connection the two endpoints
// name, in either order.
// JA4SSH normalizes the key by port 22 or by the higher-port direction, so a caller names
// the two endpoints in either order and reaches one key.
// CleanupConnection and CloseConnectionWindow both read it. One rule serves the two, because
// a second copy of the rule would answer differently after a later change to one copy.
func sshConnKeyOfEndpoints(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	var clientIP, serverIP string
	var clientPort, serverPort uint16

	if dstPort == 22 {
		clientIP, serverIP = srcIP, dstIP
		clientPort, serverPort = srcPort, dstPort
	} else if srcPort == 22 {
		clientIP, serverIP = dstIP, srcIP
		clientPort, serverPort = dstPort, srcPort
	} else if srcPort > dstPort {
		clientIP, serverIP = srcIP, dstIP
		clientPort, serverPort = srcPort, dstPort
	} else {
		clientIP, serverIP = dstIP, srcIP
		clientPort, serverPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%d-%s:%d", clientIP, clientPort, serverIP, serverPort)
}

// CleanupConnection removes internal state for the given connection.
// JA4SSH normalizes keys by port 22 or higher-port direction.
// It emits no fingerprint. A caller that wants the open window of the connection calls
// CloseConnectionWindow instead, and issue #216 records that ruling.
func (f *JA4SSHFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	delete(f.connections, sshConnKeyOfEndpoints(srcIP, srcPort, dstIP, dstPort))
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
// destination, as a result of CloseOpenWindows does. No packet triggers this emission, so the
// result reads the endpoints of the connection.
// The method is opt-in. CleanupConnection still emits nothing, so a caller that only reclaims
// memory receives no fingerprint it did not ask for.
func (f *JA4SSHFingerprinter) CloseConnectionWindow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) []FingerprintResult {
	f.ensure()

	connKey := sshConnKeyOfEndpoints(srcIP, srcPort, dstIP, dstPort)

	conn, exists := f.connections[connKey]
	if !exists {
		return nil
	}

	delete(f.connections, connKey)

	result, held := emitSSHWindow(
		conn, conn.clientIP, conn.serverIP, conn.clientPort, conn.serverPort, conn.lastSeen)
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
	SessionType string
	Description string
	ClientMode  int
	ServerMode  int
	ClientSSH   int
	ServerSSH   int
	ClientACK   int
	ServerACK   int
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
