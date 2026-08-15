package ja4plus

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// maxJA4TSDelays bounds part e at ten delays.
// The deleted FoxIO file `technical_details/JA4T.md` states the bound: "The max is 10
// retransmissions counted and the timeout is 2 minutes after the last SYNACK."
// `docs/specs/foxio/JA4T.md` R18 records it, and the port holds `MAX_SYN_ACK_DELAYS` at
// `ja4plus/fingerprinters/ja4ts.py:24` of tag `v1.1.0`.
const maxJA4TSDelays = 10

// ja4tsSynAckTimeout drops a connection that receives no SYN-ACK for two minutes.
// The same deleted FoxIO sentence states it, `docs/specs/foxio/JA4T.md` R22 records the
// Zeek test at `zeek/ja4t/main.zeek:162`, and the port holds `SYN_ACK_TIMEOUT_SECONDS` at
// `ja4plus/fingerprinters/ja4ts.py:25` of tag `v1.1.0`.
const ja4tsSynAckTimeout = 120 * time.Second

// maxJA4TSConnections bounds the state table.
// FoxIO bounds the delay list and states no bound on the connection count. A monitor reads
// a SYN-ACK for every connection on the wire, so this table needs one of its own. The port
// holds `MAX_TRACKED_CONNECTIONS` at `ja4plus/fingerprinters/ja4ts.py:31` of tag `v1.1.0`.
const maxJA4TSConnections = 1000

// ja4tsConnState holds what a later packet of one connection needs to write a JA4TS value.
type ja4tsConnState struct {
	// times holds the capture timestamp of each SYN-ACK of the connection, in arrival
	// order. Part e reads the interval between two of them.
	times []time.Time
	// prefix holds part a through part d of the first SYN-ACK. A RST packet carries no
	// window size and no option, so the RST value reads this field instead of the packet.
	prefix string
	// arrival counts the connections the fingerprinter opened before this one. A range
	// over a Go map orders nothing, so the count bound reads this field to find the
	// oldest entry.
	arrival int
}

// JA4TSFingerprinter fingerprints TCP SYN-ACK packets (server-side).
//
// A connection the server answered twice or more carries part e, which holds the delay of
// each SYN-ACK after the first. A RST that the server sends on such a connection appends
// `-R` and its own delay.
//
// One JA4TSFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4TSFingerprinter struct {
	// connections holds one entry for each connection that sent a SYN-ACK. The key names
	// four fields of that packet: the source address, the source port, the destination
	// address and the destination port. Every SYN-ACK travels from the server, so the key
	// names the server first. A client packet reverses it.
	connections map[string]*ja4tsConnState
	// arrivals counts the connections the fingerprinter opened. Each entry stores the
	// value it read at its own start.
	arrivals int
}

// NewJA4TS creates a new JA4TS fingerprinter.
func NewJA4TS() *JA4TSFingerprinter {
	return &JA4TSFingerprinter{connections: map[string]*ja4tsConnState{}}
}

// ensure fills the state table that the constructor fills.
// A caller who writes `var f JA4TSFingerprinter` reaches a nil map, and a write to a nil
// map panics. F-24-4 through F-24-9 record the same defect on six other types, and every
// entry point of this type calls this method first.
func (f *JA4TSFingerprinter) ensure() {
	if f.connections == nil {
		f.connections = make(map[string]*ja4tsConnState)
	}
}

// ProcessPacket processes a packet and returns JA4TS fingerprint results for SYN-ACK packets.
// It returns one result for a RST packet of a connection that already sent a SYN-ACK. It
// returns no result for any other packet.
func (f *JA4TSFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}

	now := parser.GetPacketTimestamp(packet)

	// The RST branch comes first, because a RST packet ends the connection and
	// `zeek/ja4t/main.zeek:167` reads the RST bit before it reads the SYN-ACK flags.
	if tcp.RST {
		return f.resetResults(packet, tcp, now), nil
	}

	if !tcp.SYN || !tcp.ACK {
		return nil, nil
	}

	fp := generateTCPFingerprint(packet, tcp, "ja4ts")

	delays := f.recordSynAck(ja4tsConnKey(fp.SrcIP, fp.SrcPort, fp.DstIP, fp.DstPort), now, fp.Fingerprint)
	if len(delays) > 0 {
		fp.Fingerprint += "_" + ja4tsJoinDelays(delays)
	}

	return []FingerprintResult{*fp}, nil
}

// Reset clears the state of the fingerprinter.
// It drops every connection, so a second capture reads none of the SYN-ACK times of the
// first one.
func (f *JA4TSFingerprinter) Reset() {
	f.connections = map[string]*ja4tsConnState{}
	f.arrivals = 0
}

// CleanupConnection removes the stored SYN-ACK times and stored parts of the connection.
// The key names the server first, because every SYN-ACK travels from the server. The
// caller names either direction, so this method drops both orderings.
func (f *JA4TSFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	delete(f.connections, ja4tsConnKey(srcIP, srcPort, dstIP, dstPort))
	delete(f.connections, ja4tsConnKey(dstIP, dstPort, srcIP, srcPort))
}

// ja4tsConnKey returns the connection key of one SYN-ACK packet or one RST packet.
// The packet order names the connection without a normalization, because every SYN-ACK of
// one connection travels from the server to the client. A RST that the server sends
// produces the same key, and a client RST reverses it and finds no connection.
func ja4tsConnKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// ja4tsDelaySeconds returns the delay between two capture timestamps, in whole seconds.
//
// It rounds to the nearest second, half away from zero, which is the Wireshark reading of
// the reference split that `docs/specs/foxio/JA4T.md` R24 records. Wireshark calls the C
// `round` at `wireshark/source/packet-ja4.c:277`, and Zeek truncates at
// `zeek/ja4t/main.zeek:180`. R24 names issue #18, which recorded the split. **Issue #56
// holds the reading this library follows**, and the maintainer read the port's shipped
// rule on 2026-08-13. The port holds `_delay_seconds` at
// `ja4plus/fingerprinters/ja4ts.py:43` of tag `v1.1.0`.
//
// A capture that holds a SYN-ACK out of order produces a negative delay, so this function
// reads the sign apart from the magnitude.
func ja4tsDelaySeconds(later, earlier time.Time) int {
	delay := later.Sub(earlier).Seconds()
	if delay < 0 {
		return -int(math.Floor(-delay + 0.5))
	}

	return int(math.Floor(delay + 0.5))
}

// ja4tsDelayList returns the delay between each stored SYN-ACK, in whole seconds.
// The list is empty for a connection the server answered once.
func ja4tsDelayList(times []time.Time) []int {
	delays := make([]int, 0, len(times))
	for index := 1; index < len(times); index++ {
		delays = append(delays, ja4tsDelaySeconds(times[index], times[index-1]))
	}

	return delays
}

// ja4tsJoinDelays returns the delay list as part e writes it, joined by `-`.
// `docs/specs/foxio/JA4T.md` R14 states the separator.
func ja4tsJoinDelays(delays []int) string {
	parts := make([]string, 0, len(delays))
	for _, delay := range delays {
		parts = append(parts, strconv.Itoa(delay))
	}

	return strings.Join(parts, "-")
}

// recordSynAck stores one SYN-ACK and returns the delay list that part e writes.
// The list is empty for the first SYN-ACK of a connection.
func (f *JA4TSFingerprinter) recordSynAck(key string, now time.Time, prefix string) []int {
	f.evictAgedConnections(now)

	conn, held := f.connections[key]
	if !held {
		f.evictOldestConnection()

		conn = &ja4tsConnState{prefix: prefix, arrival: f.arrivals}
		f.arrivals++
		f.connections[key] = conn
	}

	// FoxIO counts ten retransmissions and no more, so the eleventh timestamp is the last
	// one this entry stores. A later SYN-ACK changes no fingerprint, and it renews the
	// entry not at all, so the entry ages from the tenth retransmission. The port holds
	// the same guard at `ja4plus/fingerprinters/ja4ts.py:161` of tag `v1.1.0`.
	//
	// The maintainer ruled this question on 2026-08-13, under #369 question 2. This
	// library reads the eleventh timestamp for the reset delay, and the ruling keeps that
	// behavior. The port reads the eleventh timestamp too, under the port's issue #246.
	//
	// Three implementations hold three readings. Wireshark stores no time after the tenth
	// at `wireshark/source/packet-ja4.c:1290-1291`, and it reads the frozen tenth time at
	// `wireshark/source/packet-ja4.c:694`. This library reads the eleventh time instead.
	// Zeek assigns `last_ts` on every SYN-ACK at `zeek/ja4t/main.zeek:183`. Zeek stops
	// setting the next packet threshold at `zeek/ja4t/main.zeek:185-189`, so it observes
	// no RST of such a connection and writes no reset value.
	//
	// No capture of the FoxIO corpus reaches an eleventh SYN-ACK, so
	// `TestJA4TS_ReadsTheEleventhSynAckForTheResetDelayPastTheCap` is the one record of
	// the ruling. #369 states the reversal path.
	if len(conn.times) <= maxJA4TSDelays {
		conn.times = append(conn.times, now)
	}

	return ja4tsDelayList(conn.times)
}

// resetResults returns the results that one RST packet produces.
// It returns no result when the fingerprinter holds no state for the connection.
//
// Both FoxIO implementations write the reset letter inside the delay branch.
// `wireshark/source/packet-ja4.c:684` opens that branch on `syn_ack_count > 1`, and
// `wireshark/source/packet-ja4.c:693` reads `rst_time` inside it.
// `zeek/ja4t/main.zeek:229` opens that branch on a delay list that holds a value, and
// `zeek/ja4t/main.zeek:232` reads `rst_ts` inside it.
//
// Neither branch reaches the four-part value, and each implementation writes that value
// above the branch. So a connection with one SYN-ACK still reaches a JA4TS value.
// The maintainer ruled that question on 2026-08-14, at #484, and #484 is the reversal
// path. `wireshark/source/packet-ja4.c:1599-1608` writes the four-part value for the RST
// packet, and `TestJA4TS_PublishesTheStoredFourPartValueOnAResetOfAOneSynAckConnection`
// holds the rule. The port half is `Crank-Git/ja4plus#609`.
//
// A RST packet carries no window size and no option, so part a through part d read the
// stored prefix of the first SYN-ACK. `wireshark/source/packet-ja4.c:1604-1606` appends
// the stored option list to the option list of the RST packet, so the dissector reads
// both lists. This library reads the stored prefix alone, which FR-parity-41 states, and
// the port reads the stored prefix alone at `ja4plus/fingerprinters/ja4ts.py:157` of tag
// `v1.1.0`. No capture of the FoxIO corpus carries a RST packet that holds a TCP option,
// so no comparison separates the two readings.
func (f *JA4TSFingerprinter) resetResults(packet gopacket.Packet, tcp *layers.TCP, now time.Time) []FingerprintResult {
	f.evictAgedConnections(now)

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	conn, held := f.connections[ja4tsConnKey(srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort))]
	if !held {
		return nil
	}

	// A connection the server answered once holds no delay, so the value stops at part d.
	// `wireshark/source/packet-ja4.c:684` guards the delay list and the reset letter alone.
	fingerprint := conn.prefix
	if len(conn.times) >= 2 {
		fingerprint = fmt.Sprintf("%s_%s-R%d", conn.prefix, ja4tsJoinDelays(ja4tsDelayList(conn.times)),
			ja4tsDelaySeconds(now, conn.times[len(conn.times)-1]))
	}

	return []FingerprintResult{{
		Fingerprint: fingerprint,
		Type:        "ja4ts",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     uint16(tcp.SrcPort),
		DstPort:     uint16(tcp.DstPort),
		Timestamp:   now,
	}}
}

// evictAgedConnections removes each connection that received no SYN-ACK for the timeout.
// The pass reads the capture timestamp of the packet that arrives, and never the wall
// clock, because a capture replays faster than real time.
//
// The packet carries that timestamp, so a crafted capture controls it, and one timestamp
// decides the age of every connection.
//
// The forged timestamp reaches two cases, and this comment states both.
//
//   - The key of the sender. A SYN-ACK dated far in the future gives every later packet a
//     negative age, so this pass removes that entry never.
//   - Every other key. The packet that carries the future timestamp ages the whole table at
//     once, so this pass removes every other connection.
//
// **The maintainer ruled the second case on 2026-08-14, and the library accepts it.** Issue
// #577 holds the ruling and the reversal path. `state_bound.go`, `ja4ssh.go` and `ja4h.go` hold the same clock, and
// the port holds it at `ja4plus/utils/state_table.py:414` of tag `v1.1.0`.
// `age_clock_ruling_test.go` builds the separating packet.
//
// `evictOldestConnection` is the bound that holds the memory, because it reads the arrival
// order and no timestamp. This pass reclaims a stale entry early, and it is no memory bound
// of its own. So the loss of the second case is the tracked state, and never the memory.
func (f *JA4TSFingerprinter) evictAgedConnections(now time.Time) {
	for key, conn := range f.connections {
		if len(conn.times) == 0 {
			continue
		}

		if now.Sub(conn.times[len(conn.times)-1]) > ja4tsSynAckTimeout {
			delete(f.connections, key)
		}
	}
}

// evictOldestConnection removes the connection that opened first, when the table is full.
// The caller runs it before it adds an entry, so the table never passes its bound.
func (f *JA4TSFingerprinter) evictOldestConnection() {
	if len(f.connections) < maxJA4TSConnections {
		return
	}

	oldestKey := ""
	oldestArrival := 0

	for key, conn := range f.connections {
		if oldestKey == "" || conn.arrival < oldestArrival {
			oldestKey = key
			oldestArrival = conn.arrival
		}
	}

	delete(f.connections, oldestKey)
}

// ComputeJA4TS is a one-shot function that computes the JA4TS fingerprint for a single packet.
//
// It reads one packet through a new fingerprinter, so that packet is always the first
// SYN-ACK of its connection. The value therefore carries no part e. A caller that needs
// part e keeps one JA4TSFingerprinter across the packets of the connection.
func ComputeJA4TS(packet gopacket.Packet) string {
	fp := NewJA4TS()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
