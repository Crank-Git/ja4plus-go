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
	"github.com/gopacket/gopacket"
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
	// reassembler orders the segments of one stream by sequence number.
	//
	// A capture stores the segments of a stream in the order the reader saw them, and that
	// order is not the sequence order. `testdata/foxio/pcap/socks4-https.pcap` holds one
	// 40-byte segment before the 1360-byte segment that precedes it, so a reader that
	// concatenates in arrival order reads a TLS record header at the wrong offset and finds
	// no certificate. `parser.TCPStreamReassembler` is the mechanism `ja4h.go:18` already
	// uses, so JA4X reads one reassembler and never a second mechanism.
	reassembler *parser.TCPStreamReassembler
	// processedCerts names the certificate of one stream that the reader already read. Its
	// key is ja4xCertSetKey, which names the certificate hash and the stream together.
	//
	// The key held the certificate hash alone until #489, so a certificate that two live
	// streams carried reached one value. Three FoxIO implementations write one value for
	// each certificate of each stream, and none of them holds a certificate cache.
	// `docs/audit/ja4x-deviation-cluster.md` `## Cause 1 — the certificate set names no
	// stream` measured 36 deviations of that shape.
	processedCerts map[string]struct{}
	// certsByStream names the certificate hashes that each stream produced. It is the
	// removal path of processedCerts, because a caller of CleanupConnection names a
	// connection and never a certificate. Without this index CleanupConnection reads every
	// key of the set to find the keys of one stream.
	certsByStream map[string]map[string]struct{}
	// streamBytes counts the payload bytes that each stream offered the reassembler.
	//
	// It bounds no memory. Issue #567 gave that duty to `parser.TCPStreamReassembler`, which
	// now bounds the bytes one stream stores against the MaxBytes this file passes. So the
	// two names bound two quantities, and never the same bytes twice.
	//
	// This counter bounds the payload that the reader searches for a certificate on one
	// stream, and it removes the stream at the bound. A server sends the certificate chain in
	// the first few kilobytes, so a stream above the bound carries application data and no
	// certificate. The removal also releases a stream that the byte bound holds full, and
	// the next segment of that connection opens a stream that stores bytes again.
	//
	// The two counts differ. The reassembler counts the bytes it stores. This counter counts
	// every byte the stream offered, which includes a duplicate and a byte the byte bound
	// refused.
	streamBytes map[string]int
	lastCleanup time.Time
}

// NewJA4X creates a new JA4XFingerprinter.
func NewJA4X() *JA4XFingerprinter {
	return &JA4XFingerprinter{
		reassembler:    parser.NewTCPStreamReassembler(ja4xMaxStreams, ja4xMaxStreamBytes),
		processedCerts: make(map[string]struct{}),
		certsByStream:  make(map[string]map[string]struct{}),
		streamBytes:    make(map[string]int),
		lastCleanup:    time.Now(),
	}
}

// ensure fills the state maps that the constructor fills.
// A caller who writes `var f JA4XFingerprinter` reaches a nil map, and a write to a nil
// map panics. Every entry point calls this method first.
func (f *JA4XFingerprinter) ensure() {
	if f.reassembler == nil {
		f.reassembler = parser.NewTCPStreamReassembler(ja4xMaxStreams, ja4xMaxStreamBytes)
	}

	if f.processedCerts == nil {
		f.processedCerts = make(map[string]struct{})
	}

	if f.certsByStream == nil {
		f.certsByStream = make(map[string]map[string]struct{})
	}

	if f.streamBytes == nil {
		f.streamBytes = make(map[string]int)
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

	// The reassembler orders the segments by sequence number and returns the contiguous
	// run that starts at the lowest one.
	f.reassembler.AddSegment(streamID, tcp.Seq, payload)
	f.streamBytes[streamID] += len(payload)
	stream := f.reassembler.GetStream(streamID)

	// Search for certificates in the accumulated stream data.
	results := f.findCertificatesInStream(streamID, stream, packet, srcIP, dstIP, srcPort, dstPort)

	// A server sends the certificate chain in the first few kilobytes of the session, so a
	// stream above the bound carries application data and no certificate. The removal ends
	// the search of this stream, and `parser.TCPStreamReassembler` bounds its memory.
	if f.streamBytes[streamID] > ja4xMaxStreamBytes {
		f.reassembler.RemoveStream(streamID)
		delete(f.streamBytes, streamID)
	}

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

	f.reassembler = parser.NewTCPStreamReassembler(ja4xMaxStreams, ja4xMaxStreamBytes)
	f.processedCerts = make(map[string]struct{})
	f.certsByStream = make(map[string]map[string]struct{})
	f.streamBytes = make(map[string]int)
	f.lastCleanup = time.Now()
}

// CleanupConnection removes internal state for the given connection.
// JA4X uses directional keys: srcIP:srcPort-dstIP:dstPort.
// Both directions are cleaned since the certificate may arrive from either side.
func (f *JA4XFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	fwd := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	rev := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
	f.reassembler.RemoveStream(fwd)
	f.reassembler.RemoveStream(rev)
	delete(f.streamBytes, fwd)
	delete(f.streamBytes, rev)

	// certsByStream is the reverse lookup that processedCerts needs. The key of
	// processedCerts names one certificate of one stream, so a caller who names a
	// connection reaches no key of the set without this index.
	for _, stream := range []string{fwd, rev} {
		for certHash := range f.certsByStream[stream] {
			delete(f.processedCerts, ja4xCertSetKey(stream, certHash))
		}

		delete(f.certsByStream, stream)
	}
}

// cleanup prunes the certificate set and the byte counter to prevent unbounded growth.
//
// The reassembler bounds the count of its stream table, because it evicts the least recent
// stream when the table reaches ja4xMaxStreams. It also bounds the bytes of one stream,
// because #567 made `AddSegment` refuse a segment that a full stream offers. So this method
// bounds no memory of the reassembler, and it prunes the two maps of this file alone.
func (f *JA4XFingerprinter) cleanup() {
	// Prune processed certs.
	// certsByStream indexes the processedCerts set, so the reset of one resets the other.
	// A stale index grows without a bound. It also removes a hash the set no longer holds.
	if len(f.processedCerts) > ja4xMaxProcessedCerts {
		f.processedCerts = make(map[string]struct{}, ja4xPrunedCerts)
		f.certsByStream = make(map[string]map[string]struct{})
	}

	// The reassembler evicts the least recent stream on its own, and it names no evicted
	// key. The byte counter therefore keeps an entry for a stream the reassembler dropped,
	// and that entry leaks in a long-running monitor.
	if len(f.streamBytes) > ja4xMaxStreams {
		f.streamBytes = make(map[string]int)
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

		// One TLS record carries several handshake messages, so the reader walks every
		// message of the record. A server that coalesces ServerHello and Certificate into
		// one record puts the Certificate message second, and a reader of the first
		// message alone finds no certificate.
		// `testdata/foxio/pcap/socks4-https.pcap` holds such a record.
		{
			certs := ja4xCertificatesInRecord(data[i+5 : i+5+recordLength])
			for _, certDER := range certs {
				// The key names the SHA-256 hash of the DER bytes and the stream.
				h := sha256.Sum256(certDER)
				certHash := hex.EncodeToString(h[:])
				setKey := ja4xCertSetKey(streamID, certHash)

				// The reassembler keeps every segment until a removal, so this reader reads
				// the same certificate again at each later packet of the stream.
				if _, seen := f.processedCerts[setKey]; seen {
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
					f.processedCerts[setKey] = struct{}{}

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

	// The reassembler holds the segments, and it drops one only at RemoveStream or at an
	// eviction. A trim of the returned run would therefore reappear at the next packet, so
	// this reader trims nothing and the certificate set removes the repeat instead.

	return results
}

// ja4xCertSetKey returns the processedCerts key of one certificate on one stream.
//
// The hexadecimal hash is always 64 characters, so the concatenation needs no separator and
// two pairs reach one key only when the pairs are equal. A separator would need an escape,
// because a stream name of an IPv6 connection holds a colon.
func ja4xCertSetKey(streamID, certHash string) string {
	return certHash + streamID
}

// extractCertificates extracts individual DER-encoded certificates from a
// TLS Certificate handshake message (including the 5-byte TLS record header).
func extractCertificates(data []byte) [][]byte {
	// Skip TLS record header (5 bytes) + handshake header (4 bytes).
	if len(data) < 9 {
		return nil
	}
	return ja4xCertificatesInMessage(data[9:])
}

// ja4xCertificatesInRecord returns the certificates of every Certificate message that the
// body of one TLS handshake record holds. The body starts after the 5-byte record header.
//
// RFC 8446 section 5.1 lets one record carry several handshake messages, so the walk reads
// every message and never the first alone.
func ja4xCertificatesInRecord(body []byte) [][]byte {
	var certs [][]byte
	for offset := 0; offset+4 <= len(body); {
		// Every packet is untrusted input, so the length field is bounds-checked before
		// the slice below reads it.
		messageLength := int(body[offset+1])<<16 | int(body[offset+2])<<8 | int(body[offset+3])
		if messageLength < 0 || offset+4+messageLength > len(body) {
			break
		}
		if body[offset] == tlsHandshakeCertificate {
			certs = append(certs, ja4xCertificatesInMessage(body[offset+4:offset+4+messageLength])...)
		}
		offset += 4 + messageLength
	}
	return certs
}

// ja4xCertificatesInMessage returns the DER-encoded certificates that the body of one
// Certificate handshake message holds. The body starts after the 4-byte message header.
func ja4xCertificatesInMessage(message []byte) [][]byte {
	if len(message) < 3 {
		return nil
	}

	// Certificate list length (3 bytes).
	certsLen := int(message[0])<<16 | int(message[1])<<8 | int(message[2])
	pos := 3

	if certsLen <= 0 || certsLen > len(message)-pos {
		return nil
	}

	var certs [][]byte
	endPos := pos + certsLen

	for pos < endPos-2 {
		if pos+3 > len(message) {
			break
		}

		// Individual certificate length (3 bytes).
		certLen := int(message[pos])<<16 | int(message[pos+1])<<8 | int(message[pos+2])
		pos += 3

		if certLen <= 0 || certLen > 200000 {
			break
		}
		if pos+certLen > len(message) {
			break
		}

		cert := make([]byte, certLen)
		copy(cert, message[pos:pos+certLen])
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
		// `crypto/x509` fails the whole certificate parse for a public key it declines, and
		// JA4X reads no public key. `parser.ReadX509Identifiers` reads the three identifier
		// lists from the ASN.1 structure, so a certificate that names explicit elliptic
		// curve parameters still reaches a value. Issue #490 records the measurement, and
		// `docs/audit/ja4x-deviation-cluster.md`
		// `## Cause 3 — the Go certificate parser refuses explicit elliptic curve parameters`
		// holds the evidence.
		identifiers, ok := parser.ReadX509Identifiers(certDER)
		if !ok {
			return parts, false
		}

		parts[0] = strings.Join(identifiers.Issuer, ",")
		parts[1] = strings.Join(identifiers.Subject, ",")
		parts[2] = strings.Join(identifiers.Extensions, ",")

		return parts, true
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

// ComputeJA4XFromPacket is a one-shot function that extracts JA4X fingerprints
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
