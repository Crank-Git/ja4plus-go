package ja4plus

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// Stream tracking constants.
const (
	ja4xMaxStreamBytes    = 1048576 // 1MB per stream
	ja4xMaxSearchBytes    = 200000  // 200KB search limit
	ja4xMaxStreams        = 50
	ja4xMaxProcessedCerts = 1000
	ja4xPrunedCerts       = 500
	ja4xCleanupInterval   = 30 * time.Second
)

// TLS handshake type for Certificate message.
const tlsHandshakeCertificate = 0x0b

// JA4XFingerprinter computes JA4X X.509 certificate fingerprints.
// It is stateful: it tracks TCP streams to reassemble TLS Certificate
// messages that may span multiple TCP segments.
//
// One JA4XFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4XFingerprinter struct {
	streams        map[string][]byte
	processedCerts map[string]struct{}
	// certsByStream names the certificate hashes that each stream produced. It is the
	// removal path of processedCerts, whose key is the certificate hash alone. Without
	// this index CleanupConnection leaves every hash for the life of the process.
	certsByStream map[string]map[string]struct{}
	lastCleanup   time.Time
}

// NewJA4X creates a new JA4XFingerprinter.
func NewJA4X() *JA4XFingerprinter {
	return &JA4XFingerprinter{
		streams:        make(map[string][]byte),
		processedCerts: make(map[string]struct{}),
		certsByStream:  make(map[string]map[string]struct{}),
		lastCleanup:    time.Now(),
	}
}

// ensure fills the state maps that the constructor fills.
// A caller who writes `var f JA4XFingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4XFingerprinter) ensure() {
	if f.streams == nil {
		f.streams = make(map[string][]byte)
	}

	if f.processedCerts == nil {
		f.processedCerts = make(map[string]struct{})
	}

	if f.certsByStream == nil {
		f.certsByStream = make(map[string]map[string]struct{})
	}

	if f.lastCleanup.IsZero() {
		f.lastCleanup = time.Now()
	}
}

// ProcessPacket processes a packet and returns JA4X fingerprint results.
func (f *JA4XFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return nil, nil
	}

	srcIP, dstIP, _, ok := parser.GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	streamID := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)

	// Append payload to stream buffer.
	stream := f.streams[streamID]
	stream = append(stream, payload...)

	// Enforce max stream size.
	if len(stream) > ja4xMaxStreamBytes {
		stream = stream[len(stream)-ja4xMaxStreamBytes:]
	}
	f.streams[streamID] = stream

	// Search for certificates in the accumulated stream data.
	results := f.findCertificatesInStream(streamID, stream, packet, srcIP, dstIP, srcPort, dstPort)

	// Periodic cleanup.
	now := time.Now()
	if now.Sub(f.lastCleanup) > ja4xCleanupInterval {
		f.cleanup()
		f.lastCleanup = now
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// Reset clears the stream table and the certificate set.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4XFingerprinter) Reset() {
	f.ensure()

	f.streams = make(map[string][]byte)
	f.processedCerts = make(map[string]struct{})
	f.certsByStream = make(map[string]map[string]struct{})
	f.lastCleanup = time.Now()
}

// CleanupConnection removes internal state for the given connection.
// JA4X uses directional keys: srcIP:srcPort-dstIP:dstPort.
// Both directions are cleaned since the certificate may arrive from either side.
func (f *JA4XFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	fwd := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	rev := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
	delete(f.streams, fwd)
	delete(f.streams, rev)

	// certsByStream is the reverse lookup that processedCerts needs. The key of
	// processedCerts is the certificate hash, so that set names no connection.
	for _, stream := range []string{fwd, rev} {
		for certHash := range f.certsByStream[stream] {
			delete(f.processedCerts, certHash)
		}

		delete(f.certsByStream, stream)
	}
}

// cleanup prunes streams and processed certs to prevent unbounded growth.
func (f *JA4XFingerprinter) cleanup() {
	// Trim to max streams (keep most recent by deleting oldest).
	if len(f.streams) > ja4xMaxStreams {
		// Simple approach: clear all streams since we have no ordering info.
		f.streams = make(map[string][]byte)
	}

	// Prune processed certs.
	// certsByStream indexes the processedCerts set, so the reset of one resets the other.
	// A stale index grows without a bound. It also removes a hash the set no longer holds.
	if len(f.processedCerts) > ja4xMaxProcessedCerts {
		f.processedCerts = make(map[string]struct{}, ja4xPrunedCerts)
		f.certsByStream = make(map[string]map[string]struct{})
	}
}

// findCertificatesInStream scans accumulated stream data for TLS Certificate messages.
func (f *JA4XFingerprinter) findCertificatesInStream(
	streamID string,
	data []byte,
	packet gopacket.Packet,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
) []FingerprintResult {
	var results []FingerprintResult

	if len(data) == 0 {
		return nil
	}

	maxSearch := len(data)
	if maxSearch > ja4xMaxSearchBytes {
		maxSearch = ja4xMaxSearchBytes
	}

	i := 0
	for i < maxSearch-10 {
		// Look for TLS Handshake record type.
		if data[i] != parser.TLSRecordTypeHandshake {
			i++
			continue
		}

		// Need at least 5 bytes for TLS record header.
		if i+5 >= len(data) {
			break
		}

		recordLength := int(data[i+3])<<8 | int(data[i+4])

		// Sanity check record length.
		if recordLength < 4 || recordLength > 65535 {
			i++
			continue
		}

		// Check if we have the complete record.
		if i+5+recordLength > len(data) {
			break // Incomplete record, wait for more data.
		}

		// Check if this is a Certificate message (handshake type 0x0b).
		if data[i+5] == tlsHandshakeCertificate {
			certs := extractCertificates(data[i : i+5+recordLength])
			for _, certDER := range certs {
				// Dedup by SHA-256 of DER bytes.
				h := sha256.Sum256(certDER)
				certHash := hex.EncodeToString(h[:])

				if _, seen := f.processedCerts[certHash]; seen {
					continue
				}

				fp, raw := computeJA4XWithRaw(certDER)
				if fp != "" {
					result := FingerprintResult{
						Fingerprint: fp,
						Raw:         raw,
						Type:        "ja4x",
						SrcIP:       srcIP,
						DstIP:       dstIP,
						SrcPort:     srcPort,
						DstPort:     dstPort,
						Timestamp:   parser.GetPacketTimestamp(packet),
					}
					results = append(results, result)
					f.processedCerts[certHash] = struct{}{}

					if f.certsByStream[streamID] == nil {
						f.certsByStream[streamID] = make(map[string]struct{})
					}
					f.certsByStream[streamID][certHash] = struct{}{}
				}
			}
		}

		// Move past this TLS record.
		i += 5 + recordLength
	}

	// Trim consumed data from the stream.
	if i > 1000 {
		f.streams[streamID] = data[i:]
	}

	return results
}

// extractCertificates extracts individual DER-encoded certificates from a
// TLS Certificate handshake message (including the 5-byte TLS record header).
func extractCertificates(data []byte) [][]byte {
	// Skip TLS record header (5 bytes) + handshake header (4 bytes).
	pos := 9
	if len(data) < pos+3 {
		return nil
	}

	// Certificate list length (3 bytes).
	certsLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
	pos += 3

	if certsLen <= 0 || certsLen > len(data)-pos {
		return nil
	}

	var certs [][]byte
	endPos := pos + certsLen

	for pos < endPos-2 {
		if pos+3 > len(data) {
			break
		}

		// Individual certificate length (3 bytes).
		certLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if certLen <= 0 || certLen > 200000 {
			break
		}
		if pos+certLen > len(data) {
			break
		}

		cert := make([]byte, certLen)
		copy(cert, data[pos:pos+certLen])
		certs = append(certs, cert)
		pos += certLen
	}

	return certs
}

// ja4xParts returns the three unhashed object identifier lists of the certificate.
// The order is the issuer list, the subject list and the extension list. The second
// return value is false when the certificate cannot be read.
//
// Each list holds the hexadecimal form of an identifier, and a comma separates each pair.
// R8, R9 and R10 of `docs/specs/foxio/JA4X.md` state the three rules, and no sort applies.
func ja4xParts(certDER []byte) ([3]string, bool) {
	var parts [3]string

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return parts, false
	}

	// Extract issuer RDN OIDs.
	var issuerOIDs []string
	for _, attr := range cert.Issuer.Names {
		issuerOIDs = append(issuerOIDs, parser.OIDToHex(attr.Type.String()))
	}

	// Extract subject RDN OIDs.
	var subjectOIDs []string
	for _, attr := range cert.Subject.Names {
		subjectOIDs = append(subjectOIDs, parser.OIDToHex(attr.Type.String()))
	}

	// Extract extension OIDs.
	var extOIDs []string
	for _, ext := range cert.Extensions {
		extOIDs = append(extOIDs, parser.OIDToHex(ext.Id.String()))
	}

	parts[0] = strings.Join(issuerOIDs, ",")
	parts[1] = strings.Join(subjectOIDs, ",")
	parts[2] = strings.Join(extOIDs, ",")

	return parts, true
}

// computeJA4XWithRaw returns the JA4X fingerprint and the JA4X_r raw form of the
// certificate. It returns two empty strings when the certificate cannot be read.
//
// Both values read the same three lists, so the raw form is the exact preimage of the
// fingerprint. `testdata/foxio/reference/rust/ja4x/src/lib.rs:49` hashes each part into
// the fingerprint, and `:50` writes the raw form as
// `let ja4x_r = with_raw.then(|| parts.join("_"));`.
//
// R12 of `docs/specs/foxio/JA4X.md` states the zero sentinel `000000000000`, and
// `parser.TruncatedHash` returns it for an empty list. The raw form hashes nothing, so an
// empty list reaches the raw form as an empty part and never as the sentinel.
func computeJA4XWithRaw(certDER []byte) (string, string) {
	parts, ok := ja4xParts(certDER)
	if !ok {
		return "", ""
	}

	fingerprint := fmt.Sprintf("%s_%s_%s",
		parser.TruncatedHash(parts[0]),
		parser.TruncatedHash(parts[1]),
		parser.TruncatedHash(parts[2]),
	)

	return fingerprint, strings.Join(parts[:], "_")
}

// ComputeJA4XFromDER computes a JA4X fingerprint from DER-encoded certificate bytes.
// Returns an empty string if the certificate cannot be parsed.
//
// Format: {issuer_hash}_{subject_hash}_{extension_hash}
func ComputeJA4XFromDER(certDER []byte) string {
	fingerprint, _ := computeJA4XWithRaw(certDER)
	return fingerprint
}

// ComputeJA4XFromPEM computes a JA4X fingerprint from PEM-encoded certificate bytes.
// Returns an empty string if the certificate cannot be parsed.
func ComputeJA4XFromPEM(pemData []byte) string {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return ""
	}
	return ComputeJA4XFromDER(block.Bytes)
}

// ComputeJA4XFromPacket is a convenience function that extracts JA4X fingerprints
// from a single packet. It creates a temporary fingerprinter, so it does not
// support stream reassembly. For multi-packet streams, use JA4XFingerprinter.
func ComputeJA4XFromPacket(packet gopacket.Packet) string {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return ""
	}

	// Look for a TLS Certificate message directly in this packet.
	for i := 0; i < len(payload)-10; i++ {
		if payload[i] != parser.TLSRecordTypeHandshake {
			continue
		}
		if i+5 >= len(payload) {
			break
		}

		recordLength := int(payload[i+3])<<8 | int(payload[i+4])
		if recordLength < 4 || recordLength > 65535 {
			continue
		}
		if i+5+recordLength > len(payload) {
			break
		}

		if payload[i+5] == tlsHandshakeCertificate {
			certs := extractCertificates(payload[i : i+5+recordLength])
			if len(certs) > 0 {
				fp := ComputeJA4XFromDER(certs[0])
				if fp != "" {
					return fp
				}
			}
		}
		i += 5 + recordLength - 1 // -1 because loop increments
	}

	return ""
}
