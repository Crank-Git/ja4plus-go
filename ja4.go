package ja4plus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/gopacket"
)

// JA4Fingerprinter computes JA4 TLS Client Hello fingerprints.
type JA4Fingerprinter struct {
	results []FingerprintResult
}

// NewJA4 creates a new JA4Fingerprinter.
func NewJA4() *JA4Fingerprinter {
	return &JA4Fingerprinter{}
}

// ProcessPacket processes a packet and returns JA4 fingerprint results.
func (f *JA4Fingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	payload := GetTCPPayload(packet)
	if payload == nil {
		return nil, nil
	}

	ch, err := ParseClientHello(payload)
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return nil, nil
	}

	fingerprint := computeJA4FromClientHello(ch)
	if fingerprint == "" {
		return nil, nil
	}

	raw := computeJA4RawFromClientHello(ch)

	srcIP, dstIP, _ := GetIPInfo(packet)
	tcp := GetTCPLayer(packet)
	var srcPort, dstPort uint16
	if tcp != nil {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	}

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Raw:         raw,
		Type:        "JA4",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Timestamp:   GetPacketTimestamp(packet),
	}

	f.results = append(f.results, result)
	return []FingerprintResult{result}, nil
}

// Reset clears all stored results.
func (f *JA4Fingerprinter) Reset() {
	f.results = nil
}

// ComputeJA4 is a convenience function that extracts a JA4 fingerprint from a packet.
// Returns an empty string if the packet is not a TLS ClientHello.
func ComputeJA4(packet gopacket.Packet) string {
	payload := GetTCPPayload(packet)
	if payload == nil {
		return ""
	}
	ch, err := ParseClientHello(payload)
	if err != nil || ch == nil {
		return ""
	}
	return computeJA4FromClientHello(ch)
}

// computeJA4FromClientHello generates a JA4 fingerprint string from a parsed ClientHello.
func computeJA4FromClientHello(ch *ClientHello) string {
	partA := ja4PartA(ch)
	cipherHash := ja4CipherHash(ch)
	extHash := ja4ExtensionHash(ch)
	return fmt.Sprintf("%s_%s_%s", partA, cipherHash, extHash)
}

// computeJA4RawFromClientHello generates the raw (unhashed) JA4 fingerprint.
func computeJA4RawFromClientHello(ch *ClientHello) string {
	partA := ja4PartA(ch)

	// Cipher list: sorted, GREASE filtered
	ciphers := FilterGreaseValues(ch.CipherSuites)
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherList := formatHexList(sortedCiphers)

	// Extension list: GREASE filtered, SNI/ALPN removed, sorted
	extensions := FilterGreaseValues(ch.Extensions)
	var filtered []uint16
	for _, e := range extensions {
		if e != extSNI && e != extALPN {
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
func ja4PartA(ch *ClientHello) string {
	// Protocol
	proto := "t"
	if ch.IsQUIC {
		proto = "q"
	} else if ch.IsDTLS {
		proto = "d"
	}

	// Version: prefer max non-GREASE supported_version
	version := ch.Version
	sv := FilterGreaseValues(ch.SupportedVersions)
	if len(sv) > 0 {
		maxV := sv[0]
		for _, v := range sv[1:] {
			if v > maxV {
				maxV = v
			}
		}
		version = maxV
	}
	verStr := tlsVersionString(version)

	// SNI
	sniChar := "i"
	if ch.HasSNI {
		sniChar = "d"
	}

	// Cipher count (excluding GREASE, capped at 99)
	cipherCount := len(FilterGreaseValues(ch.CipherSuites))
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (excluding GREASE, capped at 99)
	extCount := len(FilterGreaseValues(ch.Extensions))
	if extCount > 99 {
		extCount = 99
	}

	// ALPN
	alpn := alpnValue(ch.ALPNProtocols)

	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, verStr, sniChar, cipherCount, extCount, alpn)
}

// ja4CipherHash generates the cipher hash section.
func ja4CipherHash(ch *ClientHello) string {
	ciphers := FilterGreaseValues(ch.CipherSuites)
	if len(ciphers) == 0 {
		return emptyHash
	}
	sorted := make([]uint16, len(ciphers))
	copy(sorted, ciphers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return TruncatedHash(formatHexList(sorted))
}

// ja4ExtensionHash generates the extension hash section.
func ja4ExtensionHash(ch *ClientHello) string {
	extensions := FilterGreaseValues(ch.Extensions)

	// Remove SNI and ALPN
	var filtered []uint16
	for _, e := range extensions {
		if e != extSNI && e != extALPN {
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

	return TruncatedHash(extStr)
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
