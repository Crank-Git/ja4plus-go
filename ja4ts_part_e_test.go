package ja4plus

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// This file holds part e of JA4TS and the JA4TS value that a RST produces. Issue #56 of
// Epic 8b builds both, and `docs/specs/features/08-python-parity.md` states FR-parity-37
// through FR-parity-46.

// The two endpoints of every connection this file builds. A fixed address keeps each
// connection key readable in a failure message.
var (
	ja4tsServerIP = net.IP{10, 0, 0, 1}
	ja4tsClientIP = net.IP{10, 0, 0, 2}
)

const (
	ja4tsServerPort = 443
	ja4tsClientPort = 50000
)

// ja4tsOptions holds the TCP options of the third example of the deleted FoxIO file
// `technical_details/JA4T.md`. They produce part b `2-1-3-1-1-4`, part c `65495` and part
// d `8`. The option region reaches 12 bytes, which is three whole words, so `gopacket`
// adds no pad byte and part b carries no End-of-Option-List entry.
var ja4tsOptions = []layers.TCPOption{
	{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(65495)},
	{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
	{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
	{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
	{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
}

// ja4tsPrefix holds part a through part d that `ja4tsOptions` produces.
const ja4tsPrefix = "65535_2-1-3-1-1-4_65495_8"

// ja4tsBaseTime anchors every capture timestamp of this file. The deleted FoxIO file
// states each time as an offset inside one capture, so the anchor value changes no delay.
var ja4tsBaseTime = time.Unix(1700000000, 0)

// ja4tsAt returns the capture timestamp that sits the named count of seconds after the
// anchor.
func ja4tsAt(seconds float64) time.Time {
	return ja4tsBaseTime.Add(time.Duration(seconds * float64(time.Second)))
}

// buildTCPPacketWithFlagsAtTime returns one TCP packet that carries the named flags and
// the named capture timestamp.
//
// `buildTCPPacket` sets no RST flag and no capture timestamp, and part e reads both.
// `parser.GetPacketTimestamp` reads `md.Timestamp`, so this builder writes that field.
func buildTCPPacketWithFlagsAtTime(t testing.TB, srcIP, dstIP net.IP, srcPort, dstPort uint16,
	syn, ack, rst bool, window uint16, options []layers.TCPOption, when time.Time,
) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		RST:     rst,
		Window:  window,
		Options: options,
	}

	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = when

	return packet
}

// ja4tsSynAck returns one server SYN-ACK packet of the standard connection.
func ja4tsSynAck(t testing.TB, when time.Time) gopacket.Packet {
	t.Helper()

	return buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
		ja4tsServerPort, ja4tsClientPort, true, true, false, 65535, ja4tsOptions, when)
}

// ja4tsServerReset returns one server RST packet of the standard connection.
// A RST packet carries no window size and no option, so this builder sets neither.
func ja4tsServerReset(t testing.TB, when time.Time) gopacket.Packet {
	t.Helper()

	return buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
		ja4tsServerPort, ja4tsClientPort, false, false, true, 0, nil, when)
}

// ja4tsValue returns the one JA4TS value the packet produces, or the empty string.
func ja4tsValue(t testing.TB, fingerprinter *JA4TSFingerprinter, packet gopacket.Packet) string {
	t.Helper()

	results, err := fingerprinter.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(results) == 0 {
		return ""
	}

	if len(results) != 1 {
		t.Fatalf("the packet produced %d results, want 1", len(results))
	}

	return results[0].Fingerprint
}

// FR-parity-39. A connection the server answered once omits part e.
// `docs/specs/foxio/JA4T.md` R17 states the rule, and the deleted FoxIO file states it as
// "If no retransmissions are seen, as there shouldn't be in normal network communications,
// the fingerprint will omit section e." The port's issue #226 holds the other half.
func TestJA4TS_OmitsPartEWhenTheServerAnswersOnce(t *testing.T) {
	fingerprinter := NewJA4TS()

	if got := ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0))); got != ja4tsPrefix {
		t.Errorf("the first SYN-ACK produces %q, want %q", got, ja4tsPrefix)
	}
}

// FR-parity-37 and FR-parity-38. A JA4TS value carries part e when the server sent two
// SYN-ACK packets, and part e holds the delay in whole seconds.
// The port's issue #226 holds the other half.
func TestJA4TS_WritesOnePartEDelayWhenTheServerAnswersTwice(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))

	got := ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(1)))
	want := ja4tsPrefix + "_1"

	if got != want {
		t.Errorf("the second SYN-ACK produces %q, want %q", got, want)
	}
}

// The server sends three SYN-ACK packets, so part e holds two delays, joined by `-`.
// `docs/specs/features/08-python-parity.md` holds the row as an edge case, and
// `docs/specs/foxio/JA4T.md` R14 states the separator. The port's issue #226 holds the
// other half.
func TestJA4TS_WritesTwoPartEDelaysWhenTheServerAnswersThreeTimes(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))
	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(1)))

	got := ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(3)))
	want := ja4tsPrefix + "_1-2"

	if got != want {
		t.Errorf("the third SYN-ACK produces %q, want %q", got, want)
	}
}

// Each part e delay rounds to the nearest second, half away from zero.
//
// `docs/specs/foxio/JA4T.md` R24 records a reference split. Zeek truncates each delay at
// `zeek/ja4t/main.zeek:180`, and Wireshark rounds each delay at
// `wireshark/source/packet-ja4.c:277`. R24 names issue #18, which recorded the split.
// Issue #56 holds the reading this library follows, and the maintainer read the port's
// shipped rule on 2026-08-13. The port holds `_delay_seconds` at
// `ja4plus/fingerprinters/ja4ts.py:43` of tag `v1.1.0`. The register row
// `Part e of JA4TS, the time since the last SYN-ACK` carries the port half, in the
// `## Parity with ja4plus-go` section of `docs/specs/spec.md` in `Crank-Git/ja4plus` at
// tag `v1.1.0`. The port issue is `Crank-Git/ja4plus#226`, and a reversal changes both
// repositories.
func TestJA4TS_RoundsAPartEDelayToTheNearestSecond(t *testing.T) {
	cases := []struct {
		name    string
		seconds float64
		want    string
	}{
		{"a delay of 1.6 seconds rounds up", 1.6, "2"},
		{"a delay of 1.4 seconds rounds down", 1.4, "1"},
		{"a delay of 0.5 seconds rounds away from zero", 0.5, "1"},
		// A capture that holds a SYN-ACK out of order produces a negative delay, and every
		// packet is untrusted input. A half away from zero reads the sign.
		{"a delay of -1.5 seconds rounds away from zero", -1.5, "-2"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := NewJA4TS()

			_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(10)))

			got := ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(10+testCase.seconds)))
			want := ja4tsPrefix + "_" + testCase.want

			if got != want {
				t.Errorf("the second SYN-ACK produces %q, want %q", got, want)
			}
		})
	}
}

// Part e holds at most ten delays. `docs/specs/foxio/JA4T.md` R18 states the count of each
// implementation, and the two counts differ.
//
// Zeek writes at most ten delays. `zeek/ja4t/main.zeek:185` reads
// `if (|c$fp$ja4t$synack_delays| == 10) {` and returns.
//
// Wireshark writes at most nine delays. `wireshark/source/packet-ja4.c:1290` stores a
// timestamp only while `conn->syn_ack_count < MAX_SYN_ACK_TIMES`, so the array holds ten
// timestamps at most. `wireshark/source/packet-ja4.c:686` then reads
// `for (int i = 1; i < conn->syn_ack_count; i++)`, and ten timestamps give nine delays.
//
// This library writes ten delays. The port holds `MAX_SYN_ACK_DELAYS` at
// `ja4plus/fingerprinters/ja4ts.py:24` of tag `v1.1.0`, under its issue #226.
func TestJA4TS_HoldsTenPartEDelaysAtMost(t *testing.T) {
	fingerprinter := NewJA4TS()

	last := ""
	for index := 0; index < 14; index++ {
		last = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(float64(index))))
	}

	want := ja4tsPrefix + "_1-1-1-1-1-1-1-1-1-1"

	if last != want {
		t.Errorf("the fourteenth SYN-ACK produces %q, want %q", last, want)
	}
}

// The state table of #56 is a map, and a write to a nil map panics. A caller who
// writes `var f JA4TSFingerprinter` reaches that nil map, so `ensure` fills it on the first
// call. F-24-4 through F-24-9 of `docs/audit/findings.md` record the same defect on six
// other types, and `audit_panic_test.go` holds the six.
func TestJA4TS_AZeroValueFingerprinterReadsItsFirstPacketWithNoPanic(t *testing.T) {
	var fingerprinter JA4TSFingerprinter

	if got := ja4tsValue(t, &fingerprinter, ja4tsSynAck(t, ja4tsAt(0))); got != ja4tsPrefix {
		t.Errorf("the zero value produces %q, want %q", got, ja4tsPrefix)
	}

	var cleaner JA4TSFingerprinter

	cleaner.CleanupConnection(ja4tsServerIP.String(), ja4tsServerPort,
		ja4tsClientIP.String(), ja4tsClientPort, "tcp")
}

// The reset delay of a connection that passed the ten-delay cap reads the eleventh
// SYN-ACK, and never a later one.
//
// **The maintainer ruled this question on 2026-08-13, under #369 question 2.** This library
// reads the eleventh timestamp, and the ruling keeps that behavior. Three implementations
// hold three readings. Wireshark stores no time after the tenth at
// `wireshark/source/packet-ja4.c:1290-1291`, and it reads the frozen tenth time at
// `wireshark/source/packet-ja4.c:694`. Zeek stops setting the next packet threshold at
// `zeek/ja4t/main.zeek:185-189`, so it observes no RST of such a connection and writes no
// reset value. The port also reads the eleventh timestamp, at
// `ja4plus/fingerprinters/ja4ts.py:161` of tag `v1.1.0`, under its issue #246.
//
// No capture of the FoxIO corpus reaches an eleventh SYN-ACK, so this test is the one
// record of the ruling. It fails when a later change reverses the ruling, and #369 states
// the reversal path.
func TestJA4TS_ReadsTheEleventhSynAckForTheResetDelayPastTheCap(t *testing.T) {
	fingerprinter := NewJA4TS()

	// Eleven SYN-ACK packets, one second apart, fill the ten-delay cap.
	for index := 0; index < 11; index++ {
		_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(float64(index))))
	}

	// A twelfth SYN-ACK stores no time, so it moves the reset delay not at all.
	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(15)))

	// The RST sits 7 seconds after the eleventh SYN-ACK, and 2 seconds after the twelfth.
	got := ja4tsValue(t, fingerprinter, ja4tsServerReset(t, ja4tsAt(17)))
	want := ja4tsPrefix + "_1-1-1-1-1-1-1-1-1-1-R7"

	if got != want {
		t.Errorf("the RST packet produces %q, want %q", got, want)
	}
}

// FR-parity-45. `CleanupConnection` clears one entry of the state table.
// The caller names either direction, so both orderings drop the connection.
// The port's issue #246 holds the other half, at `SynAckTracker.drop`.
func TestJA4TS_CleanupConnectionRemovesTheNamedConnection(t *testing.T) {
	cases := []struct {
		name    string
		cleanup func(fingerprinter *JA4TSFingerprinter)
	}{
		{"the caller names the server endpoint first", func(fingerprinter *JA4TSFingerprinter) {
			fingerprinter.CleanupConnection(ja4tsServerIP.String(), ja4tsServerPort,
				ja4tsClientIP.String(), ja4tsClientPort, "tcp")
		}},
		{"the caller names the client endpoint first", func(fingerprinter *JA4TSFingerprinter) {
			fingerprinter.CleanupConnection(ja4tsClientIP.String(), ja4tsClientPort,
				ja4tsServerIP.String(), ja4tsServerPort, "tcp")
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := NewJA4TS()

			_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))

			if length := len(fingerprinter.connections); length != 1 {
				t.Fatalf("the SYN-ACK left %d connections, want 1", length)
			}

			testCase.cleanup(fingerprinter)

			if got := len(fingerprinter.connections); got != 0 {
				t.Errorf("CleanupConnection leaves %d connections, want 0", got)
			}
		})
	}
}

// A connection that receives no SYN-ACK for 120 seconds leaves the table.
// The deleted FoxIO file states the bound as "the timeout is 2 minutes after the last
// SYNACK", and `docs/specs/foxio/JA4T.md` R22 records the Zeek test at
// `zeek/ja4t/main.zeek:162`. The port holds `SYN_ACK_TIMEOUT_SECONDS` at
// `ja4plus/fingerprinters/ja4ts.py:25` of tag `v1.1.0`.
//
// The pass reads the capture timestamp and never the wall clock, because a capture
// replays faster than real time.
func TestJA4TS_DropsAConnectionThatReceivesNoSynAckForTheTimeout(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))

	// The second SYN-ACK arrives after the timeout, so the pass drops the first entry and
	// this packet opens a connection that carries no delay.
	got := ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(121)))

	if got != ja4tsPrefix {
		t.Errorf("the SYN-ACK after the timeout produces %q, want %q", got, ja4tsPrefix)
	}

	if length := len(fingerprinter.connections); length != 1 {
		t.Errorf("the table holds %d connections, want 1", length)
	}
}

// The state table holds at most `maxJA4TSConnections` connections.
// FoxIO bounds the delay list and states no bound on the connection count, and a monitor
// reads a SYN-ACK for every connection on the wire. The port holds
// `MAX_TRACKED_CONNECTIONS` at `ja4plus/fingerprinters/ja4ts.py:31` of tag `v1.1.0`.
// Batch #184 leaked one map entry for each tunneled connection, so every new map of this
// package carries a bound.
func TestJA4TS_BoundsTheTrackedConnectionCount(t *testing.T) {
	fingerprinter := NewJA4TS()

	for index := 0; index < maxJA4TSConnections+200; index++ {
		packet := buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
			ja4tsServerPort, uint16(20000+index), true, true, false, 65535, ja4tsOptions,
			ja4tsAt(0))
		_ = ja4tsValue(t, fingerprinter, packet)
	}

	if got := len(fingerprinter.connections); got > maxJA4TSConnections {
		t.Errorf("the table holds %d connections, want %d at most", got, maxJA4TSConnections)
	}
}

// FR-parity-40 and FR-parity-41. A RST on a connection that already holds a delay appends
// `-R` and the delay of the RST to part e, and the value reads part a through part d from
// the first SYN-ACK of the connection.
//
// The deleted FoxIO file states both rules: "the final TCP packet, a RST packet, should be
// appended to the last JA4TS denoted with “R” and its delay" and "Note that RST packets do
// not contain TCP options or window sizes, as such the program will need to be aware of
// the previous JA4TS." The port's issue #246 holds the other half.
func TestJA4TS_AppendsTheResetDelayToPartE(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))
	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(1)))

	got := ja4tsValue(t, fingerprinter, ja4tsServerReset(t, ja4tsAt(4)))
	want := ja4tsPrefix + "_1-R3"

	if got != want {
		t.Errorf("the RST packet produces %q, want %q", got, want)
	}
}

// FR-parity-42. The RST test reads the RST bit of the flag byte, so a RST that also carries
// ACK reaches the rule.
//
// `docs/specs/foxio/JA4T.md` R30 records a reference split. Zeek tests
// `rph$tcp$flags & TH_RST != 0` at `zeek/ja4t/main.zeek:167`, and Wireshark tests
// `tcp_flags == 0x004` for equality at `wireshark/source/packet-ja4.c:1296`. The maintainer
// read the port's shipped rule on 2026-08-13, at issue #126, and this library follows Zeek.
// The register row `The JA4TS value that a RST produces` carries the port half, in the
// `## Parity with ja4plus-go` section of `docs/specs/spec.md` in `Crank-Git/ja4plus` at
// tag `v1.1.0`. The port issue is `Crank-Git/ja4plus#246`, and a reversal changes both
// repositories.
func TestJA4TS_ReadsARSTThatAlsoCarriesACK(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))
	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(1)))

	reset := buildTCPPacketWithFlagsAtTime(t, ja4tsServerIP, ja4tsClientIP,
		ja4tsServerPort, ja4tsClientPort, false, true, true, 0, nil, ja4tsAt(4))

	got := ja4tsValue(t, fingerprinter, reset)
	want := ja4tsPrefix + "_1-R3"

	if got != want {
		t.Errorf("the RST packet that carries ACK produces %q, want %q", got, want)
	}
}

// A RST that arrives before any SYN-ACK produces no value.
// The connection key reaches no entry, so the fingerprinter holds no part a through part d
// to publish. The port returns None on the same input at
// `ja4plus/fingerprinters/ja4ts.py:183-184` of tag `v1.1.0`, under the port's issue #246.
//
// This test held a second case until #495, and the maintainer ruled that case on 2026-08-14.
// `TestJA4TS_PublishesTheStoredFourPartValueOnAResetOfAOneSynAckConnection` now holds it.
func TestJA4TS_ProducesNoValueForARSTBeforeAnySynAck(t *testing.T) {
	fingerprinter := NewJA4TS()

	if got := ja4tsValue(t, fingerprinter, ja4tsServerReset(t, ja4tsAt(4))); got != "" {
		t.Errorf("the RST packet produces %q, want the empty string", got)
	}
}

// A RST of a connection that holds one SYN-ACK produces the stored four-part value.
//
// The maintainer ruled split T2 on 2026-08-14, at #484, and #484 states the reversal path.
// The dissector writes the four-part value outside the delay guard.
// `wireshark/source/packet-ja4.c:1599-1608` reads the window size, the maximum segment
// size, the window scale and the option list from the stored connection state.
// `wireshark/source/packet-ja4.c:684` guards the delay list and the reset letter alone, on
// `conn->syn_ack_count > 1`.
//
// Six per-packet comparisons of the FoxIO corpus name a reset frame of a one-SYN-ACK
// connection. #495 measured that 3 of them close. The other 3 are client resets of
// `https3-301-get.pcap`, which FR-parity-44 declines, and #502 holds that question.
// `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`
// `## Cause 2 — the library returns no JA4TS value on a reset of a connection that holds one SYN-ACK`
// names each frame, and it states 6.
//
// The port returns None on this input at `ja4plus/fingerprinters/ja4ts.py:183-184` of tag
// `v1.1.0`, and `Crank-Git/ja4plus#609` holds the port half.
func TestJA4TS_PublishesTheStoredFourPartValueOnAResetOfAOneSynAckConnection(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))

	// The value carries no part e, because one SYN-ACK reaches no delay and no reset letter.
	if got := ja4tsValue(t, fingerprinter, ja4tsServerReset(t, ja4tsAt(4))); got != ja4tsPrefix {
		t.Errorf("the RST packet produces %q, want %q", got, ja4tsPrefix)
	}
}

// FR-parity-44. A RST that the client sent produces no value.
// Every SYN-ACK travels from the server, and the connection key names the server first, so
// a client RST reverses the key and finds no connection. The port's issue #246 holds the
// other half.
func TestJA4TS_ProducesNoValueForAClientRST(t *testing.T) {
	fingerprinter := NewJA4TS()

	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(0)))
	_ = ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(1)))

	reset := buildTCPPacketWithFlagsAtTime(t, ja4tsClientIP, ja4tsServerIP,
		ja4tsClientPort, ja4tsServerPort, false, false, true, 0, nil, ja4tsAt(4))

	if got := ja4tsValue(t, fingerprinter, reset); got != "" {
		t.Errorf("the client RST produces %q, want the empty string", got)
	}
}

// FR-parity-46 and acceptance criterion 8. The capture that the deleted
// `technical_details/JA4T.md` describes reaches the value
// `65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6`.
//
// No capture of the FoxIO corpus reaches the rule, so this test builds the packet list. The
// deleted file states the six capture times, and it states the six values they produce. The
// port builds the same capture at `tests/build_ja4ts_rst.py` of tag `v1.1.0`, under its
// issue #246.
func TestJA4TS_ProducesTheValueOfTheDeletedFoxIOSpecification(t *testing.T) {
	// The five SYN-ACK times and the RST time of the third example of the deleted file.
	synAckTimes := []float64{16.681435, 17.683799, 19.691548, 23.703045, 31.714762}
	resetTime := 37.723966

	// The six values the deleted file lists, in order.
	want := []string{
		"65535_2-1-3-1-1-4_65495_8",
		"65535_2-1-3-1-1-4_65495_8_1",
		"65535_2-1-3-1-1-4_65495_8_1-2",
		"65535_2-1-3-1-1-4_65495_8_1-2-4",
		"65535_2-1-3-1-1-4_65495_8_1-2-4-8",
		"65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6",
	}

	fingerprinter := NewJA4TS()

	got := make([]string, 0, len(want))
	for _, when := range synAckTimes {
		got = append(got, ja4tsValue(t, fingerprinter, ja4tsSynAck(t, ja4tsAt(when))))
	}

	got = append(got, ja4tsValue(t, fingerprinter, ja4tsServerReset(t, ja4tsAt(resetTime))))

	for index := range want {
		if got[index] != want[index] {
			t.Errorf("packet %d produces %q, want %q", index+1, got[index], want[index])
		}
	}
}
