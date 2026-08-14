package ja4plus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// JA4Fingerprinter computes JA4 TLS Client Hello fingerprints.
//
// One JA4Fingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4Fingerprinter struct {
	quicFragments map[string][]parser.CryptoFragment // DCID hex -> accumulated fragments
	dcidToTuple   map[string]string                  // DCID hex -> grouping key for cleanup
	// dcidToReported reads the reported key of a connection from the same DCID hex.
	// A caller of CleanupConnection holds the address pair that a FingerprintResult carries,
	// and a tunneled connection groups under the inner pair. Without this map the caller
	// names a key that `dcidToTuple` never holds. FR-gaps-14d states the rule.
	// This map runs from the DCID hex to the reported key, and the `groupingKeys` map of
	// `ja4l.go` runs from the reported key to the grouping key. The two directions differ
	// because CleanupConnection reads every entry of `dcidToTuple` already.
	dcidToReported map[string]string
}

// NewJA4 creates a new JA4Fingerprinter.
func NewJA4() *JA4Fingerprinter {
	return &JA4Fingerprinter{
		quicFragments:  make(map[string][]parser.CryptoFragment),
		dcidToTuple:    make(map[string]string),
		dcidToReported: make(map[string]string),
	}
}

// ensure fills the state maps that the constructor fills.
// A caller who writes `var f JA4Fingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4Fingerprinter) ensure() {
	if f.quicFragments == nil {
		f.quicFragments = make(map[string][]parser.CryptoFragment)
	}

	if f.dcidToTuple == nil {
		f.dcidToTuple = make(map[string]string)
	}

	if f.dcidToReported == nil {
		f.dcidToReported = make(map[string]string)
	}
}

// ProcessPacket processes a packet and returns JA4 fingerprint results.
func (f *JA4Fingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

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
		// The helper reads the UDP layer of the innermost packet. A tunnel carries its own
		// UDP header, and that header names the tunnel and not the connection.
		udp := parser.GetUDPLayer(packet)
		if udp == nil {
			return nil, foreignUDPLayerError(packet)
		}

		if len(udp.Payload) > 0 {
			// DecryptQUICInitialCrypto returns the fragments it read beside a truncation
			// error. The fingerprinter keeps them, because a whole client hello can sit
			// in front of the truncated frame.
			frags, dcid, err := parser.DecryptQUICInitialCrypto(udp.Payload)
			if len(frags) == 0 && err != nil {
				return nil, err
			}
			if len(frags) > 0 && len(dcid) > 0 {
				dcidKey := fmt.Sprintf("%x", dcid)

				// The entry holds the grouping key, so it reads the inner address pair.
				// GetShardKey reads the same pair, and a tunneled connection would
				// otherwise reach one shard under two names.
				groupSrcIP, groupDstIP, _ := parser.GetGroupingIPInfo(packet)
				tupleKey := fmt.Sprintf("%s:%d-%s:%d", groupSrcIP, uint16(udp.SrcPort), groupDstIP, uint16(udp.DstPort))
				f.dcidToTuple[dcidKey] = tupleKey

				// The index reads the outer address pair with the inner port pair, which is the
				// pair every result of this connection reports. CleanupConnection reaches the
				// entry from it. Issue #193 records the leak that the absent index caused.
				if reportedSrcIP, reportedDstIP, _, held := parser.GetIPInfo(packet); held {
					f.dcidToReported[dcidKey] = fmt.Sprintf("%s:%d-%s:%d",
						reportedSrcIP, uint16(udp.SrcPort), reportedDstIP, uint16(udp.DstPort))
				}

				// A sender that never completes a client hello reaches the fragment
				// buffer bound. The fingerprinter then drops the connection state,
				// because an unbounded buffer is a memory-exhaustion path.
				collected, err := parser.CollectCryptoFragments(f.quicFragments[dcidKey], frags)
				if err != nil {
					f.dropConnection(dcidKey)

					return nil, err
				}

				f.quicFragments[dcidKey] = collected

				// Try to parse ClientHello from accumulated fragments
				ch, err = parser.ClientHelloFromCryptoFragments(collected)
				if err != nil {
					// ClientHelloFromCryptoFragments returns nil and no error while a fragment is
					// missing. So an error names a handshake message that holds every byte its
					// length field counts. No later packet repairs that message. The entries then
					// leak in a monitor that calls no CleanupConnection. Issue #533 records the leak.
					f.dropConnection(dcidKey)

					return nil, err
				}
				if ch != nil {
					f.dropConnection(dcidKey)
				}
			}
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
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
	originalOrder := computeJA4OriginalOrder(ch)

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	result := FingerprintResult{
		Fingerprint:      fingerprint,
		Raw:              raw,
		OriginalOrder:    originalOrder,
		RawOriginalOrder: rawOO,
		Type:             "ja4",
		SrcIP:            srcIP,
		DstIP:            dstIP,
		SrcPort:          srcPort,
		DstPort:          dstPort,
		Timestamp:        parser.GetPacketTimestamp(packet),
	}

	return []FingerprintResult{result}, nil
}

// Reset clears the QUIC fragment table and the connection identifier table.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4Fingerprinter) Reset() {
	f.ensure()

	f.quicFragments = make(map[string][]parser.CryptoFragment)
	f.dcidToTuple = make(map[string]string)
	f.dcidToReported = make(map[string]string)
}

// dropConnection removes every table entry that one connection identifier holds.
// One removal path keeps the three tables in step, because a table this method skips leaks
// in a long-running monitor.
func (f *JA4Fingerprinter) dropConnection(dcidKey string) {
	delete(f.quicFragments, dcidKey)
	delete(f.dcidToTuple, dcidKey)
	delete(f.dcidToReported, dcidKey)
}

// CleanupConnection removes internal state for the given connection.
// JA4 QUIC state is keyed by DCID hex. This method looks up the DCID
// via the dcidToTuple reverse map and cleans the corresponding fragments.
// The caller names the two endpoints in either order, because the reverse map holds the
// order of the datagram that carried the client hello.
// The caller names the address pair that a FingerprintResult carries, which is the
// reported key. JA4L holds the same contract.
// A tunneled connection groups under the inner address pair, so this method reads the
// reported key of each connection as well as the grouping key. It falls back to the
// grouping key, because a caller of GetShardKey holds that key instead.
// FR-gaps-14e states the fallback, and `ja4plus/fingerprinters/ja4l.py:216` holds it too.
// Issue #193 records the leak that the absent index caused.
func (f *JA4Fingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	forward := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	reverse := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)

	for dcid, tuple := range f.dcidToTuple {
		reported := f.dcidToReported[dcid]
		if tuple == forward || tuple == reverse || reported == forward || reported == reverse {
			f.dropConnection(dcid)
		}
	}
}

// ComputeJA4 is a one-shot function that extracts a JA4 fingerprint from a packet.
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

	// Signature algorithms in original order.
	// `docs/specs/foxio/JA4.md` R31 states that the list skips a GREASE value.
	sigAlgs := parser.FilterGreaseValues(ch.SignatureAlgorithms)
	if len(sigAlgs) > 0 {
		sigAlgList := formatHexList(sigAlgs)
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

// ja4SortedExtensionString returns the sorted extension string that `JA4` part c hashes.
//
// `JA4_o` reads the same string, because
// `testdata/foxio/reference/python/ja4.py:248` tests it for the zero sentinel of the
// wire-order part. One builder therefore serves the two values, and a second builder would
// let the two rules drift apart.
func ja4SortedExtensionString(ch *parser.ClientHello) string {
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

	// Append signature algorithms in original order.
	// `docs/specs/foxio/JA4.md` R31 states that the list skips a GREASE value.
	sigAlgs := parser.FilterGreaseValues(ch.SignatureAlgorithms)
	if len(sigAlgs) > 0 {
		sigAlgStr := formatHexList(sigAlgs)
		extStr = extStr + "_" + sigAlgStr
	}

	return extStr
}

// ja4ExtensionHash generates the extension hash section.
func ja4ExtensionHash(ch *parser.ClientHello) string {
	return parser.TruncatedHash(ja4SortedExtensionString(ch))
}

// ja4OriginalOrderLists returns the wire-order cipher list and the wire-order extension
// list of a client hello.
//
// `JA4_o` hashes each of the two lists, and `JA4_ro` writes each one unhashed, so one
// function builds both. Two builders drift apart, and a reader then cannot tell which of
// the two values is wrong.
//
// The extension list keeps SNI and ALPN, because
// `testdata/foxio/reference/python/common.py:144` removes the two only when it sorts. It
// carries the signature algorithms after a `_` separator, which
// `testdata/foxio/reference/python/ja4.py:246` appends before it hashes.
func ja4OriginalOrderLists(ch *parser.ClientHello) (string, string) {
	cipherList := formatHexList(parser.FilterGreaseValues(ch.CipherSuites))
	extList := formatHexList(parser.FilterGreaseValues(ch.Extensions))

	// `docs/specs/foxio/JA4.md` R31 states that the list skips a GREASE value.
	sigAlgs := parser.FilterGreaseValues(ch.SignatureAlgorithms)
	if len(sigAlgs) > 0 {
		extList = extList + "_" + formatHexList(sigAlgs)
	}

	return cipherList, extList
}

// computeJA4RawOriginalOrder generates the original wire-order raw JA4 fingerprint.
// Unlike the sorted raw variant, this preserves wire order and keeps SNI/ALPN in extensions.
func computeJA4RawOriginalOrder(ch *parser.ClientHello) string {
	cipherList, extList := ja4OriginalOrderLists(ch)

	return fmt.Sprintf("%s_%s_%s", ja4PartA(ch), cipherList, extList)
}

// computeJA4OriginalOrder generates the FoxIO `JA4_o` value of a client hello.
//
// The value carries the part a of `JA4`, a hash of the wire-order cipher list and a hash of
// the wire-order extension list. `testdata/foxio/reference/python/ja4.py:291` states the
// form. An empty list reaches `parser.EmptyHash`.
//
// The extension part reads the sorted extension string for that sentinel, and never the
// wire-order string. `testdata/foxio/reference/python/ja4.py:248` tests the sorted string,
// and `testdata/foxio/reference/python/ja4.py:253` writes `000000000000` into the
// wire-order part from that test. The Rust reference hashes the wire-order string on its
// own at `testdata/foxio/reference/rust/ja4/src/tls.rs:363`, so the two references answer a
// client hello whose sorted list is empty differently. The maintainer ruled the split on
// 2026-08-12 in issue #287, and this library follows the Python reference.
func computeJA4OriginalOrder(ch *parser.ClientHello) string {
	cipherList, extList := ja4OriginalOrderLists(ch)

	extHash := parser.TruncatedHash(extList)
	if ja4SortedExtensionString(ch) == "" {
		extHash = parser.EmptyHash
	}

	return fmt.Sprintf("%s_%s_%s", ja4PartA(ch),
		parser.TruncatedHash(cipherList), extHash)
}

// foreignUDPLayerError returns a non-fatal error when the packet holds a UDP layer type
// that carries another concrete type. It returns nil for every other packet.
// JA4 and JA4S both call it.
//
// A caller that supplies a custom decoder registers such a type, and parser.GetUDPLayer
// returns nil for it. Finding F-24-1 requires the error, because a silent skip tells the
// caller nothing about the layer the fingerprinter declined to read.
//
// It reads the outermost UDP layer type. A foreign type inside a tunnel therefore reaches
// no error, because the tunnel carries a genuine UDP header that matches first.
func foreignUDPLayerError(packet gopacket.Packet) error {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	if _, held := udpLayer.(*layers.UDP); held {
		return nil
	}

	return fmt.Errorf("the UDP layer carries the type %T", udpLayer)
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
