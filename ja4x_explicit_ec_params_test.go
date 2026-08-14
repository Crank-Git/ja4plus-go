package ja4plus

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// This file holds the behavior of #490.
//
// `crypto/x509` refuses a certificate whose public key names explicit elliptic curve
// parameters, and JA4X reads no public key. `docs/audit/ja4x-deviation-cluster.md`
// `## Cause 3 — the Go certificate parser refuses explicit elliptic curve parameters`
// measured the cause, and it names certificate 2 of frame 7 of `badcurveball.pcap`.
//
// The corpus is fetched and never tracked, so each test below skips until `make corpus`
// runs. `.claude/rules/external-apis.md` `## Rules for this project` states that rule.

// badcurveballCapture holds the two certificates that this behavior separates.
const badcurveballCapture = "badcurveball.pcap"

// The expected values come from the FoxIO per-packet vector
// `testdata/foxio/wireshark/badcurveball.pcap.json`, at frame 7, for certificate 2.
// `.claude/rules/external-apis.md` bars a change to a vector, so these two values are
// verbatim.
const (
	badcurveballSecondCertJA4X    = "2e9214a636bc_2e9214a636bc_795797892f9c"
	badcurveballSecondCertJA4XRaw = "550406,550408,55040a,550403_550406,550408,55040a,550403_551d0e,551d23,551d13"
)

// badcurveballCertificates returns every certificate that the capture holds, in the order
// the capture presents them.
func badcurveballCertificates(t *testing.T) [][]byte {
	t.Helper()

	capture := filepath.Join(corpusCaptureDir, badcurveballCapture)
	if _, err := os.Stat(capture); err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", capture)
	}

	// The Certificate record of this capture spans frame 6 and frame 7, so the reader needs
	// the reassembler. Frame 7 carries no record header, and a walk of one payload therefore
	// finds no certificate in it.
	reassembler := parser.NewTCPStreamReassembler(ja4xMaxStreams, ja4xMaxStreamBytes)
	var streamOrder []string
	knownStream := make(map[string]bool)

	for _, packet := range loadPCAP(t, capture) {
		payload := parser.GetTCPPayload(packet)
		if len(payload) == 0 {
			continue
		}

		srcIP, dstIP, _, ok := parser.GetIPInfo(packet)
		if !ok {
			continue
		}

		tcp := parser.GetTCPLayer(packet)
		if tcp == nil {
			continue
		}

		streamID := fmt.Sprintf("%s:%d-%s:%d", srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort))
		reassembler.AddSegment(streamID, tcp.Seq, payload)
		if !knownStream[streamID] {
			knownStream[streamID] = true
			streamOrder = append(streamOrder, streamID)
		}
	}

	var certs [][]byte
	for _, streamID := range streamOrder {
		certs = append(certs, certificatesInStream(reassembler.GetStream(streamID))...)
	}
	return certs
}

// certificatesInStream returns the certificates of every complete TLS handshake record that
// one reassembled stream holds.
//
// The walk reads the records of the stream, and it calls no function that a sibling issue
// of this batch changes.
func certificatesInStream(payload []byte) [][]byte {
	var certs [][]byte
	for offset := 0; offset+5 <= len(payload); {
		if payload[offset] != parser.TLSRecordTypeHandshake {
			offset++
			continue
		}

		// Every packet is untrusted input, so the length field is bounds-checked before the
		// slice below reads it.
		recordLength := int(payload[offset+3])<<8 | int(payload[offset+4])
		if recordLength < 4 || offset+5+recordLength > len(payload) {
			break
		}

		certs = append(certs, ja4xCertificatesInRecord(payload[offset+5:offset+5+recordLength])...)
		offset += 5 + recordLength
	}
	return certs
}

// The capture holds two certificates, and `crypto/x509` refuses the second one. That
// refusal is the cause the fingerprint must survive.
func TestCryptoX509RefusesTheSecondCertificateOfBadcurveball(t *testing.T) {
	certs := badcurveballCertificates(t)
	if len(certs) != 2 {
		t.Fatalf("the capture holds %d certificates, and the measurement of #490 names 2",
			len(certs))
	}

	if _, err := x509.ParseCertificate(certs[0]); err != nil {
		t.Errorf("crypto/x509 refused certificate 1: %v", err)
	}

	if _, err := x509.ParseCertificate(certs[1]); err == nil {
		t.Error("crypto/x509 read certificate 2, so the fallback reader guards nothing")
	}
}

// A certificate whose public key names explicit elliptic curve parameters reaches a JA4X
// value and a JA4X_r value. That is the acceptance criterion of #490.
func TestComputeJA4XReadsACertificateThatNamesExplicitEllipticCurveParameters(t *testing.T) {
	certs := badcurveballCertificates(t)
	if len(certs) != 2 {
		t.Fatalf("the capture holds %d certificates, and the measurement of #490 names 2",
			len(certs))
	}

	fingerprint, raw := computeJA4XWithRaw(certs[1])
	if fingerprint != badcurveballSecondCertJA4X {
		t.Errorf("the JA4X value is %q, and the FoxIO vector holds %q",
			fingerprint, badcurveballSecondCertJA4X)
	}
	if raw != badcurveballSecondCertJA4XRaw {
		t.Errorf("the JA4X_r value is %q, and the FoxIO vector holds %q",
			raw, badcurveballSecondCertJA4XRaw)
	}
}

// The fallback reader must move no value that `crypto/x509` already reads, so certificate
// 1 keeps the value the FoxIO vector holds.
func TestComputeJA4XKeepsTheValueOfTheCertificateThatCryptoX509Accepts(t *testing.T) {
	certs := badcurveballCertificates(t)
	if len(certs) != 2 {
		t.Fatalf("the capture holds %d certificates, and the measurement of #490 names 2",
			len(certs))
	}

	const wantFingerprint = "2e9214a636bc_a373a9f83c6b_0e17604154c5"
	const wantRaw = "550406,550408,55040a,550403_550406,55040a,550403_551d13,551d11,551d0e,551d0f,551d25"

	fingerprint, raw := computeJA4XWithRaw(certs[0])
	if fingerprint != wantFingerprint {
		t.Errorf("the JA4X value is %q, and the FoxIO vector holds %q", fingerprint, wantFingerprint)
	}
	if raw != wantRaw {
		t.Errorf("the JA4X_r value is %q, and the FoxIO vector holds %q", raw, wantRaw)
	}
}

// A truncated certificate reaches two empty strings, because the fallback reader refuses a
// length field that overruns the input. Every packet is untrusted input.
func TestComputeJA4XReturnsNoValueForATruncatedCertificate(t *testing.T) {
	certs := badcurveballCertificates(t)
	if len(certs) != 2 {
		t.Fatalf("the capture holds %d certificates, and the measurement of #490 names 2",
			len(certs))
	}

	for _, certDER := range certs {
		for length := 0; length < len(certDER); length++ {
			fingerprint, raw := computeJA4XWithRaw(certDER[:length])
			if fingerprint != "" || raw != "" {
				t.Fatalf("the first %d bytes of %d reached the value %q and the raw form %q",
					length, len(certDER), fingerprint, raw)
			}
		}
	}
}

// The one-shot entry point reads the same certificate, so a caller that holds one packet
// reaches the value too.
func TestComputeJA4XFromDERReadsACertificateThatNamesExplicitEllipticCurveParameters(t *testing.T) {
	certs := badcurveballCertificates(t)
	if len(certs) != 2 {
		t.Fatalf("the capture holds %d certificates, and the measurement of #490 names 2",
			len(certs))
	}

	if got := ComputeJA4XFromDER(certs[1]); got != badcurveballSecondCertJA4X {
		t.Errorf("the JA4X value is %q, and the FoxIO vector holds %q",
			got, badcurveballSecondCertJA4X)
	}
}
