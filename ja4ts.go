package ja4plus

import "github.com/google/gopacket"

// JA4TSFingerprinter fingerprints TCP SYN-ACK packets (server-side).
type JA4TSFingerprinter struct {
	results []FingerprintResult
}

// NewJA4TS creates a new JA4TS fingerprinter.
func NewJA4TS() *JA4TSFingerprinter {
	return &JA4TSFingerprinter{}
}

// ProcessPacket processes a packet and returns JA4TS fingerprint results for SYN-ACK packets.
func (f *JA4TSFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	tcp := GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}
	if !tcp.SYN || !tcp.ACK {
		return nil, nil
	}
	fp := generateTCPFingerprint(packet, tcp, "ja4ts")
	if fp == nil {
		return nil, nil
	}
	f.results = append(f.results, *fp)
	return []FingerprintResult{*fp}, nil
}

// Reset clears accumulated results.
func (f *JA4TSFingerprinter) Reset() {
	f.results = nil
}

// ComputeJA4TS is a convenience function that computes the JA4TS fingerprint for a single packet.
func ComputeJA4TS(packet gopacket.Packet) string {
	fp := NewJA4TS()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
