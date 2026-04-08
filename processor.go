package ja4plus

import (
	"fmt"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// Processor runs all JA4+ fingerprinters on each packet and aggregates results.
// Errors from individual fingerprinters are non-fatal; they are collected and
// returned alongside any successful results.
type Processor struct {
	ja4    *JA4Fingerprinter
	ja4s   *JA4SFingerprinter
	ja4h   *JA4HFingerprinter
	ja4t   *JA4TFingerprinter
	ja4ts  *JA4TSFingerprinter
	ja4l   *JA4LFingerprinter
	ja4x   *JA4XFingerprinter
	ja4ssh *JA4SSHFingerprinter
}

// NewProcessor creates a Processor with all fingerprinters initialized.
func NewProcessor() *Processor {
	return &Processor{
		ja4:    NewJA4(),
		ja4s:   NewJA4S(),
		ja4h:   NewJA4H(),
		ja4t:   NewJA4T(),
		ja4ts:  NewJA4TS(),
		ja4l:   NewJA4L(),
		ja4x:   NewJA4X(),
		ja4ssh: NewJA4SSH(0),
	}
}

// ProcessPacket runs all fingerprinters on the given packet.
// It returns all fingerprint results and any non-fatal errors encountered.
func (p *Processor) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, []error) {
	var allResults []FingerprintResult
	var allErrors []error

	fingerprinters := []Fingerprinter{
		p.ja4,
		p.ja4s,
		p.ja4h,
		p.ja4t,
		p.ja4ts,
		p.ja4l,
		p.ja4x,
		p.ja4ssh,
	}

	for _, fp := range fingerprinters {
		results, err := fp.ProcessPacket(packet)
		if err != nil {
			allErrors = append(allErrors, err)
			continue
		}
		if len(results) > 0 {
			allResults = append(allResults, results...)
		}
	}

	return allResults, allErrors
}

// Reset clears all fingerprinter state.
func (p *Processor) Reset() {
	p.ja4.Reset()
	p.ja4s.Reset()
	p.ja4h.Reset()
	p.ja4t.Reset()
	p.ja4ts.Reset()
	p.ja4l.Reset()
	p.ja4x.Reset()
	p.ja4ssh.Reset()
}

// CleanupConnection removes internal state for the given connection across all
// fingerprinters. Each fingerprinter normalizes the 5-tuple to its own internal
// key format. Call this when a connection is evicted from the monitor's tracker
// to prevent state leaks in long-running processes.
func (p *Processor) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	p.ja4.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4s.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4h.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4t.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4ts.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4l.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4x.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4ssh.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
}

// GetShardKey returns a stable key for routing packets to processor shards.
// For TCP/UDP packets, this is the sorted 5-tuple. For QUIC packets with
// known DCID-to-tuple mappings, this returns the original connection tuple
// to ensure all packets for the same QUIC connection go to the same shard.
func (p *Processor) GetShardKey(packet gopacket.Packet) string {
	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)
	if srcIP == "" {
		return ""
	}

	var srcPort, dstPort uint16
	var proto string

	if tcp := parser.GetTCPLayer(packet); tcp != nil {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "tcp"
	} else if udp := parser.GetUDPLayer(packet); udp != nil {
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "udp"
	} else {
		return ""
	}

	// Sort to ensure both directions of the same connection go to the same shard
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%s:%d->%s:%d", proto, srcIP, srcPort, dstIP, dstPort)
}
