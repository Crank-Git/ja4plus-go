package ja4plus

import (
	"fmt"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// JA4SFingerprinter computes JA4S TLS Server Hello fingerprints.
type JA4SFingerprinter struct {
	results   []FingerprintResult
	quicDCIDs map[string][]byte // tracks client DCIDs for QUIC server decryption
}

// NewJA4S creates a new JA4SFingerprinter.
func NewJA4S() *JA4SFingerprinter {
	return &JA4SFingerprinter{
		quicDCIDs: make(map[string][]byte),
	}
}

// ProcessPacket processes a packet and returns JA4S fingerprint results.
func (f *JA4SFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	var sh *parser.ServerHello
	var srcPort, dstPort uint16

	// Try TCP/TLS first
	if payload := parser.GetTCPPayload(packet); payload != nil {
		if parser.IsTLSHandshake(payload) && payload[5] == parser.TLSHandshakeServerHello {
			var err error
			sh, err = parser.ParseServerHello(payload)
			if err != nil {
				return nil, err
			}
		}
		if tcp := parser.GetTCPLayer(packet); tcp != nil {
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	}

	// Try QUIC in UDP packets
	if sh == nil {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if len(udp.Payload) > 0 {
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)

				// Build connection key for DCID tracking
				srcIP, dstIP, _, _ := parser.GetIPInfo(packet)
				connKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
				reverseKey := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)

				// Check if this is a client Initial (to capture DCID)
				ch, _ := parser.ParseQUICInitial(udp.Payload)
				if ch != nil {
					// Extract DCID from the packet for later server decryption
					if len(udp.Payload) > 5 {
						dcidLen := int(udp.Payload[5])
						if 6+dcidLen <= len(udp.Payload) {
							dcid := make([]byte, dcidLen)
							copy(dcid, udp.Payload[6:6+dcidLen])
							f.quicDCIDs[connKey] = dcid
						}
					}
					return nil, nil
				}

				// Try as server Initial using stored DCID
				if dcid, ok := f.quicDCIDs[reverseKey]; ok {
					var err error
					sh, err = parser.ParseQUICServerInitial(udp.Payload, dcid)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	if sh == nil {
		return nil, nil
	}

	fingerprint := computeJA4SFromServerHello(sh)
	if fingerprint == "" {
		return nil, nil
	}

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4s",
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
	f.quicDCIDs = make(map[string][]byte)
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
	proto := "t"
	if sh.IsQUIC {
		proto = "q"
	} else if sh.IsDTLS {
		proto = "d"
	}

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

	// Extension hash: ORIGINAL WIRE ORDER, INCLUDING GREASE, no SNI/ALPN removal
	var extHash string
	if len(sh.Extensions) == 0 {
		extHash = parser.EmptyHash
	} else {
		extHash = parser.TruncatedHash(formatHexList(sh.Extensions))
	}

	return fmt.Sprintf("%s_%s_%s", partA, cipherStr, extHash)
}
