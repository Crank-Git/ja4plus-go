package ja4plus

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// JA4TFingerprinter fingerprints TCP SYN packets (client-side).
//
// One JA4TFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4TFingerprinter struct {
}

// NewJA4T creates a new JA4T fingerprinter.
func NewJA4T() *JA4TFingerprinter {
	return &JA4TFingerprinter{}
}

// ProcessPacket processes a packet and returns JA4T fingerprint results for SYN packets.
func (f *JA4TFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}
	// The line below tests two bits, and it reads no other flag. The maintainer ruled that
	// selection on 2026-08-13, under #126, so a SYN that carries the ECN flags reaches a
	// value. `rust/ja4/src/tcp.rs:146` tests the same two bits, and
	// `zeek/ja4t/main.zeek:126` and `wireshark/source/packet-ja4.c:1266` each test the whole
	// flag byte against `0x02`. The port holds the bit test at
	// `ja4plus/fingerprinters/ja4t.py:159`. `Crank-Git/ja4plus#603` is open, and it adds the
	// row of the `## Parity with ja4plus` section on the port side.
	// `ja4t_syn_selection_test.go` holds the ruling, and a reversal changes both
	// repositories.
	if !tcp.SYN || tcp.ACK {
		return nil, nil
	}
	fp := generateTCPFingerprint(packet, tcp, "ja4t")
	return []FingerprintResult{*fp}, nil
}

// Reset clears the state of the fingerprinter.
// JA4T holds no state, so this method changes nothing. It keeps the Fingerprinter
// interface whole. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4TFingerprinter) Reset() {
}

// CleanupConnection is a no-op for JA4T (stateless per-packet fingerprinter).
func (f *JA4TFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
}

// tcpOptionEntries returns the JA4T part b entries, the maximum segment size and the
// window scale that a raw TCP option region holds.
//
// It reads the raw bytes, because `gopacket` reports the first End-of-Option-List byte and
// drops every byte after it. `layers/tcp.go:279-282` appends one option for that byte,
// assigns the rest of the header to `tcp.Padding`, and breaks the option loop. The
// maintainer ruled on 2026-08-12 that part b holds one entry for each option byte, and
// #297 records the ruling.
//
// A packet carries the option bytes, so an attacker controls them. The read stops at the
// first length the region does not hold, and it slices no byte past the end.
func tcpOptionEntries(region []byte) (entries []string, mss uint16, wscale uint8) {
	for i := 0; i < len(region); {
		kind := layers.TCPOptionKind(region[i])
		length := 1
		var data []byte
		if kind != layers.TCPOptionKindEndList && kind != layers.TCPOptionKindNop {
			if i+1 >= len(region) {
				break
			}
			length = int(region[i+1])
			// A length below 2 advances the read by nothing, and the loop never ends.
			if length < 2 || i+length > len(region) {
				break
			}
			data = region[i+2 : i+length]
		}
		switch kind {
		case layers.TCPOptionKindEndList:
			entries = append(entries, "0")
		case layers.TCPOptionKindNop:
			entries = append(entries, "1")
		case layers.TCPOptionKindMSS:
			entries = append(entries, "2")
			if len(data) >= 2 {
				mss = binary.BigEndian.Uint16(data[:2])
			}
		case layers.TCPOptionKindWindowScale:
			entries = append(entries, "3")
			if len(data) >= 1 {
				wscale = data[0]
			}
		case layers.TCPOptionKindSACKPermitted:
			entries = append(entries, "4")
		case layers.TCPOptionKindTimestamps:
			entries = append(entries, "8")
		}
		i += length
	}
	return entries, mss, wscale
}

// tcpOptionRegion returns the raw TCP option bytes of the header.
//
// `gopacket` assigns `tcp.Contents` the whole header at `layers/tcp.go:270`, so the slice
// after the first 20 bytes holds every option byte. It returns nil for a header that
// carries no option.
//
// The data offset states the header length, and a crafted segment states a length the
// segment does not hold. `layers/tcp.go:264-268` assigns `tcp.Contents = data` for such a
// segment, and that slice holds the payload as well as the header. `layers/tcp.go:319`
// adds the layer before it reads the error, so a fingerprinter reads that segment. The
// bound below returns nil for it, which is what `tcp.Options` reported before #297.
func tcpOptionRegion(tcp *layers.TCP) []byte {
	const tcpHeaderLength = 20
	headerLength := int(tcp.DataOffset) * 4
	if headerLength <= tcpHeaderLength || headerLength > len(tcp.Contents) {
		return nil
	}
	return tcp.Contents[tcpHeaderLength:headerLength]
}

// generateTCPFingerprint returns the four-part value of a TCP header.
// JA4T reads a SYN packet, and JA4TS reads a SYN-ACK packet. Both methods call it.
// Format: {window_size}_{options}_{mss}_{wscale}
//
// It returns a non-nil result for every packet, and no input makes it fail. Each read of
// the header writes a default rather than an error, so the value holds four parts on every
// input. A zero-valued header reaches `0_00_00_00`.
//
// A caller therefore needs no nil test. Issue #508 deleted the dead nil test of both
// callers: `ProcessPacket` of `ja4t.go` and `ProcessPacket` of `ja4ts.go`.
// `TestGenerateTCPFingerprintReturnsANonNilResultForEveryPacket` and
// `TestGenerateTCPFingerprintHoldsOneReturnOfACompositeLiteralAddress` hold the contract,
// and each one fails when a later change makes the function fallible.
func generateTCPFingerprint(packet gopacket.Packet, tcp *layers.TCP, fpType string) *FingerprintResult {
	windowSize := tcp.Window

	// The two-digit form keys on the value, and never on the presence of the option. An
	// absent option and an option that carries zero therefore write the same part.
	// Ruling #125 states the form, and `wireshark/source/packet-ja4.c:668` and
	// `zeek/ja4t/main.zeek:206` each test the value.
	optionParts, mss, wscale := tcpOptionEntries(tcpOptionRegion(tcp))

	optionsStr := "00"
	if len(optionParts) > 0 {
		optionsStr = strings.Join(optionParts, "-")
	}

	// Part c and part d take different forms above zero. Zeek writes part c as
	// `fmt("%02d", ...)` at `zeek/ja4t/main.zeek:204`, so a segment size below 10 carries
	// a leading zero. Zeek writes part d as `"%d"` above zero at
	// `zeek/ja4t/main.zeek:209`, so a window scale carries none.
	// `wireshark/source/packet-ja4.c:664-676` writes the same two forms.
	wscaleStr := "00"
	if wscale != 0 {
		wscaleStr = strconv.Itoa(int(wscale))
	}

	fingerprint := fmt.Sprintf("%d_%s_%02d_%s", windowSize, optionsStr, mss, wscaleStr)
	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	return &FingerprintResult{
		Fingerprint: fingerprint,
		Type:        fpType,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     uint16(tcp.SrcPort),
		DstPort:     uint16(tcp.DstPort),
		Timestamp:   parser.GetPacketTimestamp(packet),
	}
}

// ComputeJA4T is a one-shot function that computes the JA4T fingerprint for a single packet.
func ComputeJA4T(packet gopacket.Packet) string {
	fp := NewJA4T()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
