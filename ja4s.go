package ja4plus

import (
	"fmt"
	"sort"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// JA4SFingerprinter computes JA4S TLS Server Hello fingerprints.
type JA4SFingerprinter struct {
	results []FingerprintResult
}

// NewJA4S creates a new JA4SFingerprinter.
func NewJA4S() *JA4SFingerprinter {
	return &JA4SFingerprinter{}
}

// ProcessPacket processes a packet and returns JA4S fingerprint results.
func (f *JA4SFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return nil, nil
	}

	if !parser.IsTLSHandshake(payload) || payload[5] != parser.TLSHandshakeServerHello {
		return nil, nil
	}

	sh, err := parser.ParseServerHello(payload)
	if err != nil {
		return nil, err
	}
	if sh == nil {
		return nil, nil
	}

	fingerprint := computeJA4SFromServerHello(sh)
	if fingerprint == "" {
		return nil, nil
	}

	srcIP, dstIP, _ := parser.GetIPInfo(packet)
	tcp := parser.GetTCPLayer(packet)
	var srcPort, dstPort uint16
	if tcp != nil {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	}

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "JA4S",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Timestamp:   parser.GetPacketTimestamp(packet),
	}

	f.results = append(f.results, result)
	return []FingerprintResult{result}, nil
}

// Reset clears all stored results.
func (f *JA4SFingerprinter) Reset() {
	f.results = nil
}

// ComputeJA4S is a convenience function that extracts a JA4S fingerprint from a packet.
// Returns an empty string if the packet is not a TLS ServerHello.
func ComputeJA4S(packet gopacket.Packet) string {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return ""
	}
	if !parser.IsTLSHandshake(payload) || payload[5] != parser.TLSHandshakeServerHello {
		return ""
	}
	sh, err := parser.ParseServerHello(payload)
	if err != nil || sh == nil {
		return ""
	}
	return computeJA4SFromServerHello(sh)
}

// computeJA4SFromServerHello generates a JA4S fingerprint from a parsed ServerHello.
func computeJA4SFromServerHello(sh *parser.ServerHello) string {
	// Protocol: always TCP for now (QUIC/DTLS not tracked in ServerHello struct)
	proto := "t"

	// Version: use supported_versions (non-GREASE) if present, else handshake version.
	// ParseServerHello already updates sh.Version from supported_versions,
	// but we replicate the logic here for clarity.
	version := sh.Version

	verStr := parser.TLSVersionString(version)

	// Extension count: INCLUDES GREASE (unlike JA4), capped at 99
	extCount := len(sh.Extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN
	var alpn string
	if sh.ALPNProtocol != "" {
		alpn = parser.ALPNValue([]string{sh.ALPNProtocol})
	} else {
		alpn = "00"
	}

	partA := fmt.Sprintf("%s%s%02d%s", proto, verStr, extCount, alpn)

	// Cipher: 4-char lowercase hex
	cipherStr := fmt.Sprintf("%04x", sh.CipherSuite)

	// Extension hash: sorted numerically, INCLUDING GREASE, no SNI/ALPN removal
	var extHash string
	if len(sh.Extensions) == 0 {
		extHash = parser.EmptyHash
	} else {
		sorted := make([]uint16, len(sh.Extensions))
		copy(sorted, sh.Extensions)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		extHash = parser.TruncatedHash(formatHexList(sorted))
	}

	return fmt.Sprintf("%s_%s_%s", partA, cipherStr, extHash)
}
