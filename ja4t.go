package ja4plus

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	if !tcp.SYN || tcp.ACK {
		return nil, nil
	}
	fp := generateTCPFingerprint(packet, tcp, "ja4t")
	if fp == nil {
		return nil, nil
	}
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

// generateTCPFingerprint builds the fingerprint string from TCP header fields.
// Shared between JA4T (SYN) and JA4TS (SYN-ACK).
// Format: {window_size}_{options}_{mss}_{wscale}
func generateTCPFingerprint(packet gopacket.Packet, tcp *layers.TCP, fpType string) *FingerprintResult {
	windowSize := tcp.Window

	var optionParts []string

	// The two-digit form keys on the value, and never on the presence of the option. An
	// absent option and an option that carries zero therefore write the same part.
	// Ruling #125 states the form, and `wireshark/source/packet-ja4.c:668` and
	// `zeek/ja4t/main.zeek:206` each test the value.
	var mss uint16
	var wscale uint8

	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindEndList:
			optionParts = append(optionParts, "0")
		case layers.TCPOptionKindNop:
			optionParts = append(optionParts, "1")
		case layers.TCPOptionKindMSS:
			optionParts = append(optionParts, "2")
			if len(opt.OptionData) >= 2 {
				mss = binary.BigEndian.Uint16(opt.OptionData[:2])
			}
		case layers.TCPOptionKindWindowScale:
			optionParts = append(optionParts, "3")
			if len(opt.OptionData) >= 1 {
				wscale = opt.OptionData[0]
			}
		case layers.TCPOptionKindSACKPermitted:
			optionParts = append(optionParts, "4")
		case layers.TCPOptionKindTimestamps:
			optionParts = append(optionParts, "8")
		}
	}

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

// ComputeJA4T is a convenience function that computes the JA4T fingerprint for a single packet.
func ComputeJA4T(packet gopacket.Packet) string {
	fp := NewJA4T()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
