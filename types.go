package ja4plus

import (
	"time"

	"github.com/google/gopacket"
)

// Fingerprinter is the interface that all JA4+ fingerprinters implement.
type Fingerprinter interface {
	ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error)
	Reset()
}

// FingerprintResult holds a single fingerprint and its metadata.
type FingerprintResult struct {
	Fingerprint string
	Raw         string
	Type        string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Timestamp   time.Time
}
