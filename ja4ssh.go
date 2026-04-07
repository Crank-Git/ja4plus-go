package ja4plus

import (
	"fmt"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

const defaultSSHWindow = 200

// sshConnState tracks SSH packet statistics for a single connection.
type sshConnState struct {
	clientSizes []int
	serverSizes []int
	clientACKs  int
	serverACKs  int
	hasSSH      bool // whether we've seen SSH data on this connection
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
	srcIP, dstIP, ok := parser.GetIPInfo(packet)
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
		if !exists || !conn.hasSSH {
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

	// Early trigger at min(packetCount, 10)
	threshold := f.packetCount
	if threshold > 10 {
		threshold = 10
	}

	if totalPackets < threshold {
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

// Reset clears all connection state and results.
func (f *JA4SSHFingerprinter) Reset() {
	f.connections = make(map[string]*sshConnState)
	f.results = nil
}

// mode returns the most common value in a slice. Returns 0 if the slice is empty.
func mode(values []int) int {
	if len(values) == 0 {
		return 0
	}
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}
	bestVal := 0
	bestCount := 0
	for v, c := range freq {
		if c > bestCount || (c == bestCount && v < bestVal) {
			bestVal = v
			bestCount = c
		}
	}
	return bestVal
}
