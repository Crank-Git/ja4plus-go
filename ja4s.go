package ja4plus

import (
	"fmt"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// JA4SFingerprinter computes JA4S TLS Server Hello fingerprints.
//
// One JA4SFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4SFingerprinter struct {
	quicDCIDs map[string][]byte // tracks client DCIDs for QUIC server decryption
	// groupingKeys reads the grouping key of a connection from the reported key.
	// A caller of CleanupConnection holds the address pair that a FingerprintResult carries,
	// and a tunneled connection groups under the inner pair. Without this map the caller
	// names a key that `quicDCIDs` never holds. FR-gaps-14d states the rule, and `ja4l.go`
	// holds the same map under the same name.
	groupingKeys map[string]string
	// reportedKeys reads the reported key of a connection from the grouping key.
	// A caller that names the grouping key cannot name the reported key. The removal reads this
	// map to reach the index entry of the connection. `ja4l.go` reads the reported key of the
	// connection state for the same reason.
	reportedKeys map[string]string
}

// NewJA4S creates a new JA4SFingerprinter.
func NewJA4S() *JA4SFingerprinter {
	return &JA4SFingerprinter{
		quicDCIDs:    make(map[string][]byte),
		groupingKeys: make(map[string]string),
		reportedKeys: make(map[string]string),
	}
}

// ensure fills the state map that the constructor fills.
// A caller who writes `var f JA4SFingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4SFingerprinter) ensure() {
	if f.quicDCIDs == nil {
		f.quicDCIDs = make(map[string][]byte)
	}

	if f.groupingKeys == nil {
		f.groupingKeys = make(map[string]string)
	}

	if f.reportedKeys == nil {
		f.reportedKeys = make(map[string]string)
	}
}

// ProcessPacket processes a packet and returns JA4S fingerprint results.
func (f *JA4SFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

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
		// The helper reads the UDP layer of the innermost packet. A tunnel carries its own
		// UDP header, and that header names the tunnel and not the connection.
		udp := parser.GetUDPLayer(packet)
		if udp == nil {
			return nil, foreignUDPLayerError(packet)
		}

		if len(udp.Payload) > 0 {
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)

			// The key holds the grouping key, so it reads the inner address pair.
			// GetShardKey reads the same pair, and a tunneled connection would
			// otherwise reach one shard under two names.
			groupSrcIP, groupDstIP, _ := parser.GetGroupingIPInfo(packet)
			connKey := fmt.Sprintf("%s:%d-%s:%d", groupSrcIP, srcPort, groupDstIP, dstPort)
			reverseKey := fmt.Sprintf("%s:%d-%s:%d", groupDstIP, dstPort, groupSrcIP, srcPort)

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
						f.indexReported(packet, connKey, srcPort, dstPort)
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

	return []FingerprintResult{result}, nil
}

// indexReported records the reported key of the connection, so that CleanupConnection
// reaches the grouping key from the address pair a FingerprintResult carries.
// The reported key holds the outer address pair with the inner port pair. The two keys hold
// one value for a connection that no tunnel carries.
// It records nothing when the packet carries no address layer that the parser reads. A caller
// then removes the connection by the grouping key alone.
func (f *JA4SFingerprinter) indexReported(packet gopacket.Packet, connKey string, srcPort, dstPort uint16) {
	reportedSrcIP, reportedDstIP, _, held := parser.GetIPInfo(packet)
	if !held {
		return
	}

	// Two tunnel endpoints of one path send one connection from two outer addresses, so a
	// second packet can move the reported key. The entry of the previous reported key would
	// then stay for the life of the process.
	// `ja4plus/fingerprinters/ja4l.py:170` removes the previous entry the same way.
	if previous, held := f.reportedKeys[connKey]; held {
		delete(f.groupingKeys, previous)
	}

	reportedKey := fmt.Sprintf("%s:%d-%s:%d", reportedSrcIP, srcPort, reportedDstIP, dstPort)
	f.groupingKeys[reportedKey] = connKey
	f.reportedKeys[connKey] = reportedKey
}

// Reset clears the QUIC connection identifier table and the two index tables.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4SFingerprinter) Reset() {
	f.ensure()

	f.quicDCIDs = make(map[string][]byte)
	f.groupingKeys = make(map[string]string)
	f.reportedKeys = make(map[string]string)
}

// dropConnection removes every table entry that one grouping key holds.
// A caller that names the grouping key cannot name the reported key, so this method reads the
// reported key from the connection. Without that removal one index entry leaks for every
// tunneled connection, and a long-running monitor never reclaims it.
func (f *JA4SFingerprinter) dropConnection(groupingKey string) {
	if reportedKey, held := f.reportedKeys[groupingKey]; held {
		delete(f.groupingKeys, reportedKey)
	}

	delete(f.reportedKeys, groupingKey)
	delete(f.quicDCIDs, groupingKey)
}

// CleanupConnection removes internal state for the given connection.
// JA4S QUIC state is keyed by directional tuple: srcIP:srcPort-dstIP:dstPort.
// The caller names the address pair that a FingerprintResult carries, which is the
// reported key. JA4L holds the same contract.
// The caller names the two endpoints in either order, so this method reads both orders.
// A tunneled connection groups under the inner address pair, so this method reads the
// grouping key from the index first. It falls back to the key the caller gave, because a
// caller of GetShardKey holds the grouping key instead.
// FR-gaps-14e states the fallback, and `ja4plus/fingerprinters/ja4l.py:216` holds it too.
// Issue #193 records the leak that the absent index caused.
func (f *JA4SFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	fwd := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	rev := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)

	for _, key := range []string{fwd, rev} {
		if groupingKey, indexed := f.groupingKeys[key]; indexed {
			f.dropConnection(groupingKey)
		}

		f.dropConnection(key)
	}
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
