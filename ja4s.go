package ja4plus

import (
	"fmt"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
)

// maxJA4SConnections bounds the connection identifier table and the two indexes that name it.
// Every packet is untrusted input. One QUIC client Initial opens one entry, so a sender fills
// the three maps at the cost of one datagram for each connection.
// No FoxIO source addresses a state table. `.claude/rules/parity.md` rule 2 gives the port the
// interface this project shipped without one.
// `ja4plus/fingerprinters/ja4s.py:58` of tag `v1.1.0` builds a `BoundedStateTable` with no
// argument, so the table holds the default that `ja4plus/utils/state_table.py:52` states.
const maxJA4SConnections = 10000

// ja4sConnectionAge drops a connection that received no packet for 600 seconds.
// The connection identifier outlives the fragments, because a server answers a client Initial
// after a round trip. The comment above `ja4plus/fingerprinters/ja4s.py:58` of tag `v1.1.0`
// states that reason, and `ja4plus/utils/state_table.py:58` states the value.
const ja4sConnectionAge = 600 * time.Second

// ja4sEvictionInterval is the count of packets between two age passes.
// One pass reads every connection, so a pass on each packet costs the connection count on each
// packet. `ja4plus/utils/state_table.py:62` of tag `v1.1.0` states the value.
const ja4sEvictionInterval = 1000

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
	// keys holds the recency order of the connection identifier table, and it names the
	// connection that the entry bound and the age bound remove.
	keys boundedKeys
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
						f.openConnection(connKey, parser.GetPacketTimestamp(packet))
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

	fingerprint, raw := computeJA4SPair(sh)
	if fingerprint == "" {
		return nil, nil
	}

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	// RawOriginalOrder stays empty, because FoxIO publishes `JA4S_r` and publishes no
	// `JA4S_ro`. The raw form already holds the wire order, so a second field would emit a
	// key that no vector holds. Issue #275 records the rule.
	result := FingerprintResult{
		Fingerprint: fingerprint,
		Raw:         raw,
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
	f.keys.reset()
}

// openConnection records one packet of the connection, and it holds the two bounds.
// The removal path of this fingerprinter reaches all three maps, so an eviction removes every
// entry the connection holds.
func (f *JA4SFingerprinter) openConnection(connKey string, now time.Time) {
	f.keys.admit(connKey, now,
		maxJA4SConnections, ja4sConnectionAge, ja4sEvictionInterval, f.dropConnection)
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
	f.keys.remove(groupingKey)
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

// ComputeJA4S is a one-shot function that extracts a JA4S fingerprint from a packet.
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
	fingerprint, _ := computeJA4SPair(sh)
	return fingerprint
}

// computeJA4SPair returns the JA4S fingerprint and the JA4S_r raw form of the ServerHello.
//
// The two values hold one prefix, and they differ on the last part alone. One function
// builds both, so the raw form cannot drift from the fingerprint.
//
// The raw form holds the extensions in the wire order, and it sorts no list.
// `rust/ja4/src/tls.rs:467` and `wireshark/source/packet-ja4.c:547` each build the raw
// form from the string the fingerprint hashes. The raw form is that hash preimage with the
// prefix in front of it. `ja4plus/fingerprinters/ja4s.py:179` states the same rule for the
// Python port.
//
// FoxIO publishes `JA4S_r` and publishes no `JA4S_ro`. The `_r` suffix therefore names the
// wire order here, and not the sorted order that JA4 gives it. Issue #275 records the
// measurement.
func computeJA4SPair(sh *parser.ServerHello) (fingerprint, raw string) {
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

	// Extension list: ORIGINAL WIRE ORDER, INCLUDING GREASE, no SNI/ALPN removal
	extList := formatHexList(sh.Extensions)

	var extHash string
	if len(sh.Extensions) == 0 {
		extHash = parser.EmptyHash
	} else {
		extHash = parser.TruncatedHash(extList)
	}

	prefix := fmt.Sprintf("%s_%s", partA, cipherStr)

	return prefix + "_" + extHash, prefix + "_" + extList
}
