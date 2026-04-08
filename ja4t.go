package ja4plus

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// JA4TFingerprinter fingerprints TCP SYN packets (client-side).
type JA4TFingerprinter struct {
	results []FingerprintResult
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
	f.results = append(f.results, *fp)
	return []FingerprintResult{*fp}, nil
}

// Reset clears accumulated results.
func (f *JA4TFingerprinter) Reset() {
	f.results = nil
}

// generateTCPFingerprint builds the fingerprint string from TCP header fields.
// Shared between JA4T (SYN) and JA4TS (SYN-ACK).
// Format: {window_size}_{options}_{mss}_{wscale}
func generateTCPFingerprint(packet gopacket.Packet, tcp *layers.TCP, fpType string) *FingerprintResult {
	windowSize := tcp.Window

	var optionParts []string
	mss := "0"
	wscale := "0"

	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindEndList:
			optionParts = append(optionParts, "0")
		case layers.TCPOptionKindNop:
			optionParts = append(optionParts, "1")
		case layers.TCPOptionKindMSS:
			optionParts = append(optionParts, "2")
			if len(opt.OptionData) >= 2 {
				mss = fmt.Sprintf("%d", binary.BigEndian.Uint16(opt.OptionData[:2]))
			}
		case layers.TCPOptionKindWindowScale:
			optionParts = append(optionParts, "3")
			if len(opt.OptionData) >= 1 {
				wscale = fmt.Sprintf("%d", opt.OptionData[0])
			}
		case layers.TCPOptionKindSACKPermitted:
			optionParts = append(optionParts, "4")
		case layers.TCPOptionKindTimestamps:
			optionParts = append(optionParts, "8")
		}
	}

	optionsStr := "0"
	if len(optionParts) > 0 {
		optionsStr = strings.Join(optionParts, "-")
	}

	fingerprint := fmt.Sprintf("%d_%s_%s_%s", windowSize, optionsStr, mss, wscale)
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
