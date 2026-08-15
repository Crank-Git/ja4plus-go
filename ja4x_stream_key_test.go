package ja4plus

import (
	"net"
	"testing"
)

// The certificate set of JA4X names the stream, and issue #489 made it do so.
//
// Three FoxIO implementations write one JA4X value for each certificate of each
// Certificate message, and none of them holds a certificate cache.
// `testdata/foxio/reference/python/ja4x.py:14` states
// `# JA4X does not use any caching from common.py`.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1628` writes one value for each
// certificate of the message. `testdata/foxio/reference/rust/ja4/src/tls.rs:93` pushes one
// record for each certificate. So the reference is unanimous, and
// `.claude/rules/parity.md` `## Where a difference comes from` row 1 names a change to this
// code and no register entry.
//
// The port holds the same key. `ja4plus/fingerprinters/ja4x.py:341` at the tag `v1.1.0`
// reads `key = (stream_id, hashlib.sha256(cert_bytes).hexdigest())`.

// TestJA4XProducesOneValueForEachStreamThatCarriesOneCertificate builds the separating case
// of issue #489: two live streams that carry the same certificate.
//
// The set was keyed by the certificate hash alone, so the second stream produced no value.
// `docs/audit/ja4x-deviation-cluster.md` `## Cause 1 — the certificate set names no stream`
// measured 36 deviations of that shape.
func TestJA4XProducesOneValueForEachStreamThatCarriesOneCertificate(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}
	record := buildCertificateRecordPayload(generateSelfSignedCertDER(t))

	fingerprinter := NewJA4X()

	first, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 41001, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("the first stream produced %d values, want 1", len(first))
	}

	second, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 41002, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("the second stream produced %d values, want 1", len(second))
	}

	if first[0].Fingerprint != second[0].Fingerprint {
		t.Errorf("the two streams produced %q and %q, and one certificate reaches one value",
			first[0].Fingerprint, second[0].Fingerprint)
	}
	if second[0].DstPort != 41002 {
		t.Errorf("the second value names the port %d, want 41002", second[0].DstPort)
	}
}

// TestJA4XProducesOneValueWhenOneStreamRepeatsOneCertificate holds the deduplication that
// one stream still needs.
//
// The reassembler keeps every segment until a removal, so `findCertificatesInStream` reads
// the same certificate again at each later packet of the stream. The stream key must not
// defeat that deduplication.
func TestJA4XProducesOneValueWhenOneStreamRepeatsOneCertificate(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}
	record := buildCertificateRecordPayload(generateSelfSignedCertDER(t))

	fingerprinter := NewJA4X()

	var total int
	for _, sequence := range []uint32{1, 1 + uint32(len(record))} {
		results, err := fingerprinter.ProcessPacket(
			buildTCPPacketWithSeq(t, server, client, 443, 41003, sequence, record))
		if err != nil {
			t.Fatalf("ProcessPacket returned the error %v", err)
		}
		total += len(results)
	}

	if total != 1 {
		t.Errorf("one stream that carries the certificate twice produced %d values, want 1", total)
	}
}

// TestJA4XCleanupConnectionKeepsTheEntryOfASecondLiveStream states that the removal path
// reaches one stream alone.
//
// `.claude/rules/concurrency.md` requires a removal path for every state map, and a removal
// that reaches a second live stream returns the defect that issue #489 closed.
func TestJA4XCleanupConnectionKeepsTheEntryOfASecondLiveStream(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}
	record := buildCertificateRecordPayload(generateSelfSignedCertDER(t))

	fingerprinter := NewJA4X()

	for _, port := range []uint16{41004, 41005} {
		results, err := fingerprinter.ProcessPacket(
			buildTCPPacketWithSeq(t, server, client, 443, port, 1, record))
		if err != nil {
			t.Fatalf("ProcessPacket returned the error %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("the stream of port %d produced %d values, want 1", port, len(results))
		}
	}

	if got := len(fingerprinter.processedCerts); got != 2 {
		t.Fatalf("the certificate set holds %d entries, and two streams wrote two", got)
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 41004, auditStateServerIP, 443, "tcp")

	if got := len(fingerprinter.processedCerts); got != 1 {
		t.Errorf("the certificate set holds %d entries after one removal, want 1", got)
	}

	// The second stream stays live, so a later packet of it produces no second value.
	again, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 41005, 1+uint32(len(record)), record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(again) != 0 {
		t.Errorf("the live second stream produced %d more values, want 0", len(again))
	}
}
