package ja4plus

import (
	"fmt"
	"strings"

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
	hasSSH       bool // whether we've seen SSH data on this connection
	hassh        string
	hasshServer  string
	clientBanner string
	serverBanner string
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
type JA4SSHFingerprinter struct {
	connections map[string]*sshConnState
	packetCount int
	results     []FingerprintResult
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

// ProcessPacket processes a packet and returns JA4SSH fingerprints when a window fills.
func (f *JA4SSHFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
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

	// If no SSH data detected, check if this is an ACK for an existing SSH connection
	if !hasSSHData {
		// Pure ACK: ACK flag set, no payload
		isACK := tcp.ACK && len(payload) == 0
		if !isACK {
			return nil, nil
		}
		conn, exists := f.connections[connKey]
		if !exists || (!conn.hasSSH && conn.clientBanner == "" && conn.serverBanner == "") {
			return nil, nil
		}
		// Count ACK for this direction
		if isClientToServer {
			conn.clientACKs++
		} else {
			conn.serverACKs++
		}
		return f.checkWindow(connKey, conn, packet, srcIP, dstIP, srcPort, dstPort)
	}

	// Initialize connection if needed
	conn, exists := f.connections[connKey]
	if !exists {
		conn = &sshConnState{}
		f.connections[connKey] = conn
	}
	conn.hasSSH = true

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

	// Track SSH data packet size
	packetSize := len(payload)
	if isClientToServer {
		conn.clientSizes = append(conn.clientSizes, packetSize)
	} else {
		conn.serverSizes = append(conn.serverSizes, packetSize)
	}

	return f.checkWindow(connKey, conn, packet, srcIP, dstIP, srcPort, dstPort)
}

// checkWindow checks if the window threshold is met and emits a fingerprint if so.
func (f *JA4SSHFingerprinter) checkWindow(connKey string, conn *sshConnState, packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16) ([]FingerprintResult, error) {
	totalPackets := len(conn.clientSizes) + len(conn.serverSizes) + conn.clientACKs + conn.serverACKs

	// Early trigger at min(packetCount, 10), OR when both HASSH are available
	// and there's at least 1 packet (matching Python behavior).
	threshold := f.packetCount
	if threshold > 10 {
		threshold = 10
	}

	hasshReady := totalPackets > 0 && conn.hassh != "" && conn.hasshServer != ""
	if totalPackets < threshold && !hasshReady {
		return nil, nil
	}

	// Calculate mode (most common packet size) per direction
	clientMode := mode(conn.clientSizes)
	serverMode := mode(conn.serverSizes)

	clientSSHCount := len(conn.clientSizes)
	serverSSHCount := len(conn.serverSizes)

	fingerprint := fmt.Sprintf("c%ds%d_c%ds%d_c%ds%d",
		clientMode, serverMode,
		clientSSHCount, serverSSHCount,
		conn.clientACKs, conn.serverACKs,
	)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4ssh",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Timestamp:   parser.GetPacketTimestamp(packet),
	}

	f.results = append(f.results, result)

	// Reset counters for next window
	conn.clientSizes = nil
	conn.serverSizes = nil
	conn.clientACKs = 0
	conn.serverACKs = 0

	return []FingerprintResult{result}, nil
}

// GetHASSHFingerprints returns all collected HASSH fingerprints across tracked connections.
func (f *JA4SSHFingerprinter) GetHASSHFingerprints() []HASSHResult {
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

// Reset clears all connection state and results.
func (f *JA4SSHFingerprinter) Reset() {
	f.connections = make(map[string]*sshConnState)
	f.results = nil
}

// mode returns the most common value in a slice. Returns 0 if the slice is empty.
// On ties, the first-encountered value wins (matching Python's Counter.most_common behavior).
func mode(values []int) int {
	if len(values) == 0 {
		return 0
	}
	freq := make(map[int]int)
	var order []int
	seen := make(map[int]bool)
	for _, v := range values {
		freq[v]++
		if !seen[v] {
			order = append(order, v)
			seen[v] = true
		}
	}
	bestVal := order[0]
	bestCount := freq[bestVal]
	for _, v := range order[1:] {
		if freq[v] > bestCount {
			bestVal = v
			bestCount = freq[v]
		}
	}
	return bestVal
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
