package ja4plus

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// Stream tracking constants.
const (
	ja4xMaxStreamBytes  = 1048576 // 1MB per stream
	ja4xMaxSearchBytes  = 200000  // 200KB search limit
	ja4xMaxStreams       = 50
	ja4xMaxProcessedCerts = 1000
	ja4xPrunedCerts     = 500
	ja4xCleanupInterval = 30 * time.Second
)

// TLS handshake type for Certificate message.
const tlsHandshakeCertificate = 0x0b

// JA4XFingerprinter computes JA4X X.509 certificate fingerprints.
// It is stateful: it tracks TCP streams to reassemble TLS Certificate
// messages that may span multiple TCP segments.
type JA4XFingerprinter struct {
	mu             sync.Mutex
	streams        map[string][]byte
	processedCerts map[string]struct{}
	results        []FingerprintResult
	lastCleanup    time.Time
}

// NewJA4X creates a new JA4XFingerprinter.
func NewJA4X() *JA4XFingerprinter {
	return &JA4XFingerprinter{
		streams:        make(map[string][]byte),
		processedCerts: make(map[string]struct{}),
		lastCleanup:    time.Now(),
	}
}

// ProcessPacket processes a packet and returns JA4X fingerprint results.
func (f *JA4XFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	payload := GetTCPPayload(packet)
	if payload == nil {
		return nil, nil
	}

	srcIP, dstIP, ok := GetIPInfo(packet)
	if !ok {
		return nil, nil
	}

	tcp := GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	streamID := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)

	f.mu.Lock()
	defer f.mu.Unlock()

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

// Reset clears all stored state.
func (f *JA4XFingerprinter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streams = make(map[string][]byte)
	f.processedCerts = make(map[string]struct{})
	f.results = nil
	f.lastCleanup = time.Now()
}

// cleanup prunes streams and processed certs to prevent unbounded growth.
// Must be called with f.mu held.
func (f *JA4XFingerprinter) cleanup() {
	// Trim to max streams (keep most recent by deleting oldest).
	if len(f.streams) > ja4xMaxStreams {
		// Simple approach: clear all streams since we have no ordering info.
		f.streams = make(map[string][]byte)
	}

	// Prune processed certs.
	if len(f.processedCerts) > ja4xMaxProcessedCerts {
		f.processedCerts = make(map[string]struct{}, ja4xPrunedCerts)
	}
}

// findCertificatesInStream scans accumulated stream data for TLS Certificate messages.
// Must be called with f.mu held.
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
		if data[i] != tlsRecordTypeHandshake {
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

				fp := ComputeJA4XFromDER(certDER)
				if fp != "" {
					result := FingerprintResult{
						Fingerprint: fp,
						Type:        "JA4X",
						SrcIP:       srcIP,
						DstIP:       dstIP,
						SrcPort:     srcPort,
						DstPort:     dstPort,
						Timestamp:   GetPacketTimestamp(packet),
					}
					results = append(results, result)
					f.results = append(f.results, result)
					f.processedCerts[certHash] = struct{}{}
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

// ComputeJA4XFromDER computes a JA4X fingerprint from DER-encoded certificate bytes.
// Returns an empty string if the certificate cannot be parsed.
//
// Format: {issuer_hash}_{subject_hash}_{extension_hash}
func ComputeJA4XFromDER(certDER []byte) string {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ""
	}

	// Extract issuer RDN OIDs.
	var issuerOIDs []string
	for _, attr := range cert.Issuer.Names {
		issuerOIDs = append(issuerOIDs, OIDToHex(attr.Type.String()))
	}

	// Extract subject RDN OIDs.
	var subjectOIDs []string
	for _, attr := range cert.Subject.Names {
		subjectOIDs = append(subjectOIDs, OIDToHex(attr.Type.String()))
	}

	// Extract extension OIDs.
	var extOIDs []string
	for _, ext := range cert.Extensions {
		extOIDs = append(extOIDs, OIDToHex(ext.Id.String()))
	}

	issuerHash := TruncatedHash(strings.Join(issuerOIDs, ","))
	subjectHash := TruncatedHash(strings.Join(subjectOIDs, ","))
	extHash := TruncatedHash(strings.Join(extOIDs, ","))

	return fmt.Sprintf("%s_%s_%s", issuerHash, subjectHash, extHash)
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
	payload := GetTCPPayload(packet)
	if payload == nil {
		return ""
	}

	// Look for a TLS Certificate message directly in this packet.
	for i := 0; i < len(payload)-10; i++ {
		if payload[i] != tlsRecordTypeHandshake {
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
