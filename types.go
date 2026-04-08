package ja4plus

import (
	"time"

	"github.com/google/gopacket"
)

// Fingerprinter is the interface that all JA4+ fingerprinters implement.
type Fingerprinter interface {
	ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error)
	Reset()
	// CleanupConnection removes internal state associated with a connection
	// identified by the given 5-tuple. Each fingerprinter normalizes the tuple
	// to its own internal key format. This prevents state leaks in long-running
	// monitors. For QUIC-keyed fingerprinters (JA4, JA4S), this also cleans up
	// any DCID-to-tuple mappings.
	CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string)
}

// FingerprintResult holds a single fingerprint and its metadata.
type FingerprintResult struct {
	Fingerprint      string
	Raw              string
	RawOriginalOrder string // JA4_ro: wire-order, no sorting, SNI/ALPN preserved
	Type             string
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	Timestamp        time.Time
}
