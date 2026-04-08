package ja4plus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// JA4Fingerprinter computes JA4 TLS Client Hello fingerprints.
type JA4Fingerprinter struct {
	results       []FingerprintResult
	quicFragments map[string][]parser.CryptoFragment // DCID hex -> accumulated fragments
	dcidToTuple   map[string]string                  // DCID hex -> 5-tuple key for cleanup
}

// NewJA4 creates a new JA4Fingerprinter.
func NewJA4() *JA4Fingerprinter {
	return &JA4Fingerprinter{
		quicFragments: make(map[string][]parser.CryptoFragment),
		dcidToTuple:   make(map[string]string),
	}
}

// ProcessPacket processes a packet and returns JA4 fingerprint results.
func (f *JA4Fingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	var ch *parser.ClientHello
	var srcPort, dstPort uint16

	// Try TCP/TLS first
	if payload := parser.GetTCPPayload(packet); payload != nil {
		var err error
		ch, err = parser.ParseClientHello(payload)
		if err != nil {
			return nil, err
		}
		if tcp := parser.GetTCPLayer(packet); tcp != nil {
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	}

	// Try QUIC in UDP packets with multi-packet CRYPTO frame accumulation
	if ch == nil {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if len(udp.Payload) > 0 {
				frags, dcid, err := parser.DecryptQUICInitialCrypto(udp.Payload)
				if err != nil {
					return nil, err
				}
				if len(frags) > 0 && len(dcid) > 0 {
					dcidKey := fmt.Sprintf("%x", dcid)
					f.quicFragments[dcidKey] = append(f.quicFragments[dcidKey], frags...)

					// Record DCID-to-tuple mapping for cleanup and shard routing
					srcIP, dstIP, _, _ := parser.GetIPInfo(packet)
					tupleKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort))
					f.dcidToTuple[dcidKey] = tupleKey

					// Try to parse ClientHello from accumulated fragments
					ch, err = parser.ClientHelloFromCryptoFragments(f.quicFragments[dcidKey])
					if err != nil {
						return nil, err
					}
					if ch != nil {
						delete(f.quicFragments, dcidKey)
						delete(f.dcidToTuple, dcidKey)
					}
				}
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			}
		}
	}

	if ch == nil {
		return nil, nil
	}

	fingerprint := computeJA4FromClientHello(ch)
	if fingerprint == "" {
		return nil, nil
	}

	raw := computeJA4RawFromClientHello(ch)
	rawOO := computeJA4RawOriginalOrder(ch)

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	result := FingerprintResult{
		Fingerprint:      fingerprint,
		Raw:              raw,
		RawOriginalOrder: rawOO,
		Type:             "ja4",
		SrcIP:            srcIP,
		DstIP:            dstIP,
		SrcPort:          srcPort,
		DstPort:          dstPort,
		Timestamp:        parser.GetPacketTimestamp(packet),
	}

	f.results = append(f.results, result)
	return []FingerprintResult{result}, nil
}

// Reset clears all stored results.
func (f *JA4Fingerprinter) Reset() {
	f.results = nil
	f.quicFragments = make(map[string][]parser.CryptoFragment)
	f.dcidToTuple = make(map[string]string)
}

// CleanupConnection removes internal state for the given connection.
// JA4 QUIC state is keyed by DCID hex. This method looks up the DCID
// via the dcidToTuple reverse map and cleans the corresponding fragments.
func (f *JA4Fingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	tupleKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	for dcid, tuple := range f.dcidToTuple {
		if tuple == tupleKey {
			delete(f.quicFragments, dcid)
			delete(f.dcidToTuple, dcid)
		}
	}
}

// ComputeJA4 is a convenience function that extracts a JA4 fingerprint from a packet.
// Returns an empty string if the packet is not a TLS ClientHello.
func ComputeJA4(packet gopacket.Packet) string {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return ""
	}
	ch, err := parser.ParseClientHello(payload)
	if err != nil || ch == nil {
		return ""
	}
	return computeJA4FromClientHello(ch)
}

// computeJA4FromClientHello generates a JA4 fingerprint string from a parsed ClientHello.
func computeJA4FromClientHello(ch *parser.ClientHello) string {
	partA := ja4PartA(ch)
	cipherHash := ja4CipherHash(ch)
	extHash := ja4ExtensionHash(ch)
	return fmt.Sprintf("%s_%s_%s", partA, cipherHash, extHash)
}

// computeJA4RawFromClientHello generates the raw (unhashed) JA4 fingerprint.
func computeJA4RawFromClientHello(ch *parser.ClientHello) string {
	partA := ja4PartA(ch)

	// Cipher list: sorted, GREASE filtered
	ciphers := parser.FilterGreaseValues(ch.CipherSuites)
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherList := formatHexList(sortedCiphers)

	// Extension list: GREASE filtered, SNI/ALPN removed, sorted
	extensions := parser.FilterGreaseValues(ch.Extensions)
	var filtered []uint16
	for _, e := range extensions {
		if e != parser.ExtSNI && e != parser.ExtALPN {
			filtered = append(filtered, e)
		}
	}
	sortedExts := make([]uint16, len(filtered))
	copy(sortedExts, filtered)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	extList := formatHexList(sortedExts)

	// Signature algorithms in original order
	if len(ch.SignatureAlgorithms) > 0 {
		sigAlgList := formatHexList(ch.SignatureAlgorithms)
		return fmt.Sprintf("%s_%s_%s_%s", partA, cipherList, extList, sigAlgList)
	}
	return fmt.Sprintf("%s_%s_%s", partA, cipherList, extList)
}

// ja4PartA builds the first section of the JA4 fingerprint.
func ja4PartA(ch *parser.ClientHello) string {
	// Protocol
	proto := "t"
	if ch.IsQUIC {
		proto = "q"
	} else if ch.IsDTLS {
		proto = "d"
	}

	// Version: prefer max non-GREASE supported_version
	version := ch.Version
	sv := parser.FilterGreaseValues(ch.SupportedVersions)
	if len(sv) > 0 {
		maxV := sv[0]
		for _, v := range sv[1:] {
			if v > maxV {
				maxV = v
			}
		}
		version = maxV
	}
	verStr := parser.TLSVersionString(version)

	// SNI
	sniChar := "i"
	if ch.HasSNI {
		sniChar = "d"
	}

	// Cipher count (excluding GREASE, capped at 99)
	cipherCount := len(parser.FilterGreaseValues(ch.CipherSuites))
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (excluding GREASE, capped at 99)
	extCount := len(parser.FilterGreaseValues(ch.Extensions))
	if extCount > 99 {
		extCount = 99
	}

	// ALPN
	alpn := parser.ALPNValue(ch.ALPNProtocols)

	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, verStr, sniChar, cipherCount, extCount, alpn)
}

// ja4CipherHash generates the cipher hash section.
func ja4CipherHash(ch *parser.ClientHello) string {
	ciphers := parser.FilterGreaseValues(ch.CipherSuites)
	if len(ciphers) == 0 {
		return parser.EmptyHash
	}
	sorted := make([]uint16, len(ciphers))
	copy(sorted, ciphers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return parser.TruncatedHash(formatHexList(sorted))
}

// ja4ExtensionHash generates the extension hash section.
func ja4ExtensionHash(ch *parser.ClientHello) string {
	extensions := parser.FilterGreaseValues(ch.Extensions)

	// Remove SNI and ALPN
	var filtered []uint16
	for _, e := range extensions {
		if e != parser.ExtSNI && e != parser.ExtALPN {
			filtered = append(filtered, e)
		}
	}

	// Sort
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })

	extStr := formatHexList(filtered)

	// Append signature algorithms in original order
	if len(ch.SignatureAlgorithms) > 0 {
		sigAlgStr := formatHexList(ch.SignatureAlgorithms)
		extStr = extStr + "_" + sigAlgStr
	}

	return parser.TruncatedHash(extStr)
}

// computeJA4RawOriginalOrder generates the original wire-order raw JA4 fingerprint.
// Unlike the sorted raw variant, this preserves wire order and keeps SNI/ALPN in extensions.
func computeJA4RawOriginalOrder(ch *parser.ClientHello) string {
	partA := ja4PartA(ch)

	// Cipher list: GREASE filtered, original wire order (no sorting)
	ciphers := parser.FilterGreaseValues(ch.CipherSuites)
	cipherList := formatHexList(ciphers)

	// Extension list: GREASE filtered, original wire order, SNI/ALPN PRESERVED
	extensions := parser.FilterGreaseValues(ch.Extensions)
	extList := formatHexList(extensions)

	// Signature algorithms in original order
	if len(ch.SignatureAlgorithms) > 0 {
		sigAlgList := formatHexList(ch.SignatureAlgorithms)
		return fmt.Sprintf("%s_%s_%s_%s", partA, cipherList, extList, sigAlgList)
	}
	return fmt.Sprintf("%s_%s_%s", partA, cipherList, extList)
}

// formatHexList formats a slice of uint16 as comma-separated 4-char lowercase hex.
func formatHexList(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}
