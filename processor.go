package ja4plus

import (
	"fmt"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// Processor runs all JA4+ fingerprinters on each packet and aggregates results.
// Errors from individual fingerprinters are non-fatal; they are collected and
// returned alongside any successful results.
//
// One Processor serves one goroutine. Every fingerprinter holds state that no lock
// guards. Two goroutines that share one Processor write a data race. The race detector
// reports the race. The library does not detect it at run time.
//
// A caller who wants more than one goroutine takes one of two patterns.
//
//   - Route each packet with GetShardKey, and give each goroutine its own Processor.
//     GetShardKey returns one key for both directions of one connection.
//   - Share one SyncProcessor, which serializes every call with one mutex.
//
// The first pattern gives higher throughput, because the per-packet path acquires no
// lock. The second pattern costs one mutex acquisition for each packet.
type Processor struct {
	ja4    *JA4Fingerprinter
	ja4s   *JA4SFingerprinter
	ja4h   *JA4HFingerprinter
	ja4t   *JA4TFingerprinter
	ja4ts  *JA4TSFingerprinter
	ja4l   *JA4LFingerprinter
	ja4x   *JA4XFingerprinter
	ja4ssh *JA4SSHFingerprinter
	ja4d   *JA4DFingerprinter
	ja4d6  *JA4D6Fingerprinter
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
		ja4d:   NewJA4D(),
		ja4d6:  NewJA4D6(),
	}
}

// ensure fills each fingerprinter that the constructor fills.
// A caller who writes `var p Processor` reaches a nil pointer, and a method call on it
// dereferences that pointer. Every entry point calls this method first.
func (p *Processor) ensure() {
	if p.ja4 == nil {
		p.ja4 = NewJA4()
	}

	if p.ja4s == nil {
		p.ja4s = NewJA4S()
	}

	if p.ja4h == nil {
		p.ja4h = NewJA4H()
	}

	if p.ja4t == nil {
		p.ja4t = NewJA4T()
	}

	if p.ja4ts == nil {
		p.ja4ts = NewJA4TS()
	}

	if p.ja4l == nil {
		p.ja4l = NewJA4L()
	}

	if p.ja4x == nil {
		p.ja4x = NewJA4X()
	}

	if p.ja4ssh == nil {
		p.ja4ssh = NewJA4SSH(0)
	}

	if p.ja4d == nil {
		p.ja4d = NewJA4D()
	}

	if p.ja4d6 == nil {
		p.ja4d6 = NewJA4D6()
	}
}

// ProcessPacket runs all fingerprinters on the given packet.
// It returns all fingerprint results and any non-fatal errors encountered.
func (p *Processor) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, []error) {
	p.ensure()

	// FR-gaps-12 produces no fingerprint past the depth limit, and the edge-case table of
	// `docs/specs/features/05-conformance-gaps.md` produces none from a tunnel whose inner
	// packet the parser does not read. The check runs before every fingerprinter, because
	// a fingerprinter that reads such a packet reports the tunnel and not the connection.
	if err := parser.CheckTunnel(packet); err != nil {
		return nil, []error{err}
	}

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
		p.ja4d,
		p.ja4d6,
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
	p.ensure()

	p.ja4.Reset()
	p.ja4s.Reset()
	p.ja4h.Reset()
	p.ja4t.Reset()
	p.ja4ts.Reset()
	p.ja4l.Reset()
	p.ja4x.Reset()
	p.ja4ssh.Reset()
	p.ja4d.Reset()
	p.ja4d6.Reset()
}

// CleanupConnection removes internal state for the given connection across all
// fingerprinters. Each fingerprinter normalizes the 5-tuple to its own internal
// key format. Call this when a connection is evicted from the monitor's tracker
// to prevent state leaks in long-running processes.
func (p *Processor) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	p.ensure()

	p.ja4.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4s.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4h.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4t.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4ts.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4l.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4x.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4ssh.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4d.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
	p.ja4d6.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
}

// GetShardKey returns a stable key that routes one packet to one Processor shard.
// The key is the sorted five-tuple, so a packet and its reply return one key.
// The key reads no QUIC connection identifier, so every packet of one QUIC
// connection returns one key after the identifier changes.
// It returns an empty string for a packet that carries neither TCP nor UDP.
// The caller decides what to do with an empty key.
// GetShardKey acquires no lock and holds no state.
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
