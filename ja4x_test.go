package ja4plus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// generateSelfSignedCertDER creates a self-signed certificate in DER format
// for testing purposes.
func generateSelfSignedCertDER(t testing.TB) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		Issuer: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return certDER
}

func TestComputeJA4XFromDER_Format(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	fp := ComputeJA4XFromDER(certDER)
	if fp == "" {
		t.Fatal("ComputeJA4XFromDER returned empty string")
	}

	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts separated by '_', got %d: %q", len(parts), fp)
	}

	for i, part := range parts {
		if len(part) != 12 {
			t.Errorf("part %d has length %d, want 12: %q", i, len(part), part)
		}
		// Verify it's lowercase hex.
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("part %d contains non-lowercase-hex character %q: %q", i, string(c), part)
				break
			}
		}
	}
}

func TestComputeJA4XFromDER_NonEmptyHashes(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)
	fp := ComputeJA4XFromDER(certDER)
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("unexpected format: %q", fp)
	}

	// A self-signed cert with subject/issuer fields should not have empty hashes.
	if parts[0] == parser.EmptyHash {
		t.Error("issuer hash should not be empty for a cert with issuer fields")
	}
	if parts[1] == parser.EmptyHash {
		t.Error("subject hash should not be empty for a cert with subject fields")
	}
	// Extensions should also be present (BasicConstraints, KeyUsage, etc.).
	if parts[2] == parser.EmptyHash {
		t.Error("extension hash should not be empty for a cert with extensions")
	}
}

func TestComputeJA4XFromDER_SelfSignedIssuerEqualsSubject(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)
	fp := ComputeJA4XFromDER(certDER)
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("unexpected format: %q", fp)
	}

	// For a self-signed cert, issuer and subject should be identical.
	if parts[0] != parts[1] {
		t.Errorf("self-signed cert: issuer hash %q != subject hash %q", parts[0], parts[1])
	}
}

func TestComputeJA4XFromDER_InvalidDER(t *testing.T) {
	fp := ComputeJA4XFromDER([]byte("not a certificate"))
	if fp != "" {
		t.Errorf("expected empty string for invalid DER, got %q", fp)
	}
}

func TestComputeJA4XFromDER_Deterministic(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)
	fp1 := ComputeJA4XFromDER(certDER)
	fp2 := ComputeJA4XFromDER(certDER)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
}

func TestJA4XFingerprinter_Dedup(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	f := NewJA4X()

	// Same cert should produce same fingerprint.
	fp1 := ComputeJA4XFromDER(certDER)
	fp2 := ComputeJA4XFromDER(certDER)

	if fp1 == "" || fp2 == "" {
		t.Fatal("fingerprints should not be empty")
	}
	if fp1 != fp2 {
		t.Errorf("same cert should produce same fingerprint: %q != %q", fp1, fp2)
	}

	// Verify the fingerprinter itself is created properly.
	if f == nil {
		t.Fatal("NewJA4X returned nil")
	}
	if f.reassembler == nil {
		t.Error("new fingerprinter should hold a reassembler")
	}
	if got := f.reassembler.GetStream("test"); got != nil {
		t.Errorf("new fingerprinter should hold no stream, got %d bytes", len(got))
	}
}

func TestJA4XFingerprinter_Reset(t *testing.T) {
	f := NewJA4X()
	f.reassembler.AddSegment("test", 1, []byte{1, 2, 3})
	f.processedCerts["abc"] = struct{}{}

	f.Reset()

	if got := f.reassembler.GetStream("test"); got != nil {
		t.Errorf("Reset did not clear streams")
	}
	if len(f.processedCerts) != 0 {
		t.Errorf("Reset did not clear processed certs")
	}
}

func TestComputeJA4XFromPEM(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	// Convert DER to PEM.
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	fpPEM := ComputeJA4XFromPEM(pemData)
	fpDER := ComputeJA4XFromDER(certDER)

	if fpPEM == "" {
		t.Fatal("ComputeJA4XFromPEM returned empty string")
	}
	if fpPEM != fpDER {
		t.Errorf("PEM fingerprint %q != DER fingerprint %q", fpPEM, fpDER)
	}
}

// ja4xEmptyListHash is the first 12 characters of the SHA-256 hash of the empty string.
// The maintainer ruled on 2026-08-14 that an empty object identifier list writes this
// value, and R18 of `docs/specs/foxio/JA4H.md` is the deciding rule. Issue #582 is the
// reversal path of the JA4X half, and the port half lives in `Crank-Git/ja4plus#619`.
const ja4xEmptyListHash = "e3b0c44298fc"

// ja4xZeroSentinel is the value that R12 of `docs/specs/foxio/JA4X.md` transcribes as one
// half of a reference split. No part of JA4X writes it after the ruling of 2026-08-14.
const ja4xZeroSentinel = "000000000000"

// ja4xTemplateFingerprint is the value that `generateSelfSignedCertDER` produces.
//
// Part a and part b hash `550406,55040a,550403`, and part c hashes
// `551d0f,551d25,551d13`. Each list follows the template of `generateSelfSignedCertDER`,
// so the value is deterministic and the key of the certificate does not reach it.
//
// `ja4x_test.go` reads `a373a9f83c6b` from the FoxIO badcurveball vector for the same
// subject list, so the reference corroborates part b of this value.
const ja4xTemplateFingerprint = "a373a9f83c6b_a373a9f83c6b_b06bda150783"

// generateCertDERWithEmptyOIDList returns a self-signed certificate whose subject list or
// whose extension list is empty.
//
// `emptySubject` clears every relative distinguished name of the subject. A certificate
// that names its host in a subject alternative name alone holds such a subject.
// `x509.CreateCertificate` copies the subject of a self-signed certificate into the
// issuer, so an empty subject empties the issuer list too.
//
// `emptyExtensions` clears every field that `x509.CreateCertificate` encodes as an
// extension, which a version 1 certificate also reaches.
func generateCertDERWithEmptyOIDList(t testing.TB, emptySubject, emptyExtensions bool) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	name := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Test Org"},
		CommonName:   "test.example.com",
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               name,
		Issuer:                name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if emptySubject {
		template.Subject = pkix.Name{}
	}
	if emptyExtensions {
		template.KeyUsage = 0
		template.ExtKeyUsage = nil
		template.BasicConstraintsValid = false
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return certDER
}

// ja4xPartsOf returns the three parts of the JA4X value of the certificate.
func ja4xPartsOf(t testing.TB, certDER []byte) []string {
	t.Helper()

	fingerprint := ComputeJA4XFromDER(certDER)
	if fingerprint == "" {
		t.Fatal("ComputeJA4XFromDER produced no value")
	}

	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		t.Fatalf("ComputeJA4XFromDER = %q, and the value holds %d parts rather than 3",
			fingerprint, len(parts))
	}

	return parts
}

// TestJA4XHashesAnEmptyExtensionList holds the ruling of 2026-08-14 for part c.
//
// A version 1 certificate and a zero-length extension sequence each reach an empty list,
// and part c is the most common of the three. Issue #582 is the reversal path.
func TestJA4XHashesAnEmptyExtensionList(t *testing.T) {
	parts := ja4xPartsOf(t, generateCertDERWithEmptyOIDList(t, false, true))

	if parts[2] != ja4xEmptyListHash {
		t.Errorf("part c = %q, want %q", parts[2], ja4xEmptyListHash)
	}
}

// TestJA4XHashesAnEmptySubjectList holds the ruling of 2026-08-14 for part b.
//
// A leaf certificate that names its host in a subject alternative name alone holds an
// empty subject list. Issue #582 is the reversal path.
func TestJA4XHashesAnEmptySubjectList(t *testing.T) {
	parts := ja4xPartsOf(t, generateCertDERWithEmptyOIDList(t, true, false))

	if parts[1] != ja4xEmptyListHash {
		t.Errorf("part b = %q, want %q", parts[1], ja4xEmptyListHash)
	}
}

// TestJA4XHashesAnEmptyIssuerList holds the ruling of 2026-08-14 for part a.
//
// The certificate below carries an empty subject, and `x509.CreateCertificate` copies
// that subject into the issuer of a self-signed certificate. Issue #582 is the reversal
// path.
func TestJA4XHashesAnEmptyIssuerList(t *testing.T) {
	parts := ja4xPartsOf(t, generateCertDERWithEmptyOIDList(t, true, false))

	if parts[0] != ja4xEmptyListHash {
		t.Errorf("part a = %q, want %q", parts[0], ja4xEmptyListHash)
	}
}

// TestJA4XWritesTheZeroSentinelInNoPart holds the reach of the ruling of 2026-08-14.
//
// The three parts of JA4X follow one rule, so all three move together. A part that still
// writes the sentinel would answer two ways for one question.
func TestJA4XWritesTheZeroSentinelInNoPart(t *testing.T) {
	certificates := map[string][]byte{
		"an empty subject list":   generateCertDERWithEmptyOIDList(t, true, false),
		"an empty extension list": generateCertDERWithEmptyOIDList(t, false, true),
		"two empty lists":         generateCertDERWithEmptyOIDList(t, true, true),
	}

	for description, certDER := range certificates {
		for i, part := range ja4xPartsOf(t, certDER) {
			if part == ja4xZeroSentinel {
				t.Errorf("the certificate with %s writes the sentinel in part %d", description, i)
			}
		}
	}
}

// TestJA4XKeepsTheValueOfANonEmptyList guards the other side of the ruling.
//
// JA4H kept the sentinel in part c and in part d, and JA4X holds no such part. So the
// guard reads the value of a non-empty list instead: the ruling moves an empty list
// alone, and a change that moved a non-empty list would disagree with every FoxIO
// implementation.
func TestJA4XKeepsTheValueOfANonEmptyList(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	if got := ComputeJA4XFromDER(certDER); got != ja4xTemplateFingerprint {
		t.Errorf("ComputeJA4XFromDER = %q, want %q", got, ja4xTemplateFingerprint)
	}
}

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

// processOneCertificatePacket returns the one JA4X result of a TLS Certificate record.
// The helper fails the test when the fingerprinter reports no result, because every
// assertion below reads a field of that result.
func processOneCertificatePacket(t *testing.T) FingerprintResult {
	t.Helper()

	certDER := generateSelfSignedCertDER(t)
	packet := buildTCPPayloadPacket(t, buildCertificateRecordPayload(certDER))

	results, err := NewJA4X().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	return results[0]
}

func TestJA4XFillsTheRawFormBesideTheFingerprint(t *testing.T) {
	result := processOneCertificatePacket(t)

	if result.Raw == "" {
		t.Fatal("Raw is empty, so the harness reports no JA4X_r value")
	}

	rawParts := strings.Split(result.Raw, "_")
	if len(rawParts) != 3 {
		t.Fatalf("expected 3 raw parts separated by '_', got %d: %q", len(rawParts), result.Raw)
	}
}

func TestJA4XHashesEachRawPartIntoTheMatchingFingerprintPart(t *testing.T) {
	// R11 of `docs/specs/foxio/JA4X.md` states the hash rule, and
	// `testdata/foxio/reference/rust/ja4x/src/lib.rs:49` writes
	// `let ja4x = parts.iter().map(hash12).join("_");` over the same three parts that
	// `:50` joins into the raw form. The raw form is therefore the exact preimage of the
	// fingerprint, and a raw form that is not fails this test.
	result := processOneCertificatePacket(t)

	rawParts := strings.Split(result.Raw, "_")
	hashParts := strings.Split(result.Fingerprint, "_")

	if len(rawParts) != 3 || len(hashParts) != 3 {
		t.Fatalf("expected 3 parts each, got raw %q and fingerprint %q", result.Raw, result.Fingerprint)
	}

	for i := range hashParts {
		if want := parser.TruncatedHash(rawParts[i]); hashParts[i] != want {
			t.Errorf("part %d: fingerprint holds %q, the hash of the raw part is %q", i, hashParts[i], want)
		}
	}
}

func TestJA4XRawFormHoldsTheObjectIdentifierOfTheCommonName(t *testing.T) {
	// R9 of `docs/specs/foxio/JA4X.md` states that a list entry is the hexadecimal form
	// of the object identifier content octets. `550403` is that form of `2.5.4.3`, the
	// common name, and the test certificate carries one in the issuer and in the subject.
	result := processOneCertificatePacket(t)

	rawParts := strings.Split(result.Raw, "_")
	if len(rawParts) != 3 {
		t.Fatalf("expected 3 raw parts, got %q", result.Raw)
	}

	for i, name := range []string{"issuer", "subject"} {
		if !strings.Contains(rawParts[i], "550403") {
			t.Errorf("the %s raw part holds no common name identifier: %q", name, rawParts[i])
		}
	}
}

func TestJA4XLeavesTheRawOriginalOrderEmpty(t *testing.T) {
	// FoxIO publishes no `JA4X_ro` key. The per-packet vectors write `ja4.ja4x_r` and no
	// wire-order sibling, and `testdata/foxio/reference/rust/ja4x/src/lib.rs:19` declares
	// `ja4x_r` as the one raw field of the output record. R8 states that no sort applies
	// to a JA4X list, so a wire-order form would repeat the raw form.
	//
	// The conformance harness emits a `JA4X_ro` key for every value this field holds, and
	// the corpus holds no such key, so a filled field reports a deviation on every
	// certificate. Issue #276 holds the rule.
	result := processOneCertificatePacket(t)

	if result.RawOriginalOrder != "" {
		t.Errorf("RawOriginalOrder holds %q, and FoxIO publishes no JA4X_ro key", result.RawOriginalOrder)
	}
}

func TestJA4XRawFormReachesTheFoxIOVectorRelation(t *testing.T) {
	// The values come from `wireshark/test/testdata/badcurveball.pcap.json` at the commit
	// in `testdata/foxio.pin`, frame 7, first certificate. They are verbatim.
	const (
		vectorRaw         = "550406,550408,55040a,550403_550406,55040a,550403_551d13,551d11,551d0e,551d0f,551d25"
		vectorFingerprint = "2e9214a636bc_a373a9f83c6b_0e17604154c5"
	)

	// The test reads `parser.TruncatedHashNoSentinel`, because `computeJA4XWithRaw` calls
	// that function for every part after the ruling of 2026-08-14. The two functions agree
	// on a non-empty part, and they disagree on an empty one. Each part of this vector is
	// non-empty, so the ruling moves no value of this test. Issue #582 holds the ruling.
	rawParts := strings.Split(vectorRaw, "_")
	hashParts := strings.Split(vectorFingerprint, "_")

	for i := range hashParts {
		if got := parser.TruncatedHashNoSentinel(rawParts[i]); got != hashParts[i] {
			t.Errorf("part %d: the hash of %q is %q, the vector holds %q",
				i, rawParts[i], got, hashParts[i])
		}
	}
}

func TestJA4XFingerprintKeepsItsValueWhenTheRawFormIsFilled(t *testing.T) {
	// The raw form must add a field and move no fingerprint. `ComputeJA4XFromDER` is the
	// exported path that a caller compares against, so the two must agree.
	certDER := generateSelfSignedCertDER(t)
	packet := buildTCPPayloadPacket(t, buildCertificateRecordPayload(certDER))

	results, err := NewJA4X().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if want := ComputeJA4XFromDER(certDER); results[0].Fingerprint != want {
		t.Errorf("the fingerprinter reports %q, ComputeJA4XFromDER reports %q",
			results[0].Fingerprint, want)
	}
}

func TestJA4XReportsNoRawFormForACertificateItCannotRead(t *testing.T) {
	// A crafted packet reaches this path. The fingerprinter must report no result rather
	// than a result whose raw form describes nothing.
	packet := buildTCPPayloadPacket(t, buildCertificateRecordPayload([]byte("not a certificate")))

	results, err := NewJA4X().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected no result, got %d", len(results))
	}
}

// The certificate set of JA4X names the stream, and issue #489 made it do so.
//
// Three FoxIO implementations write one JA4X value for each certificate of each
// Certificate message, and none of them holds a certificate cache.
// `testdata/foxio/reference/python/ja4x.py:14` states
// `# JA4X does not use any caching from common.py`.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1628` writes one value for each
// certificate of the message. `testdata/foxio/reference/rust/ja4/src/tls.rs:99` pushes one
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

// The addresses and the ports of the synthetic TLS 1.3 connection of this file.
const (
	tls13TestClientIP   = "192.0.2.10"
	tls13TestServerIP   = "192.0.2.20"
	tls13TestClientPort = 51000
	tls13TestServerPort = 443
)

// tls13TestKeys returns the write key and the write initialization vector of one traffic
// secret.
//
// The test derives them through the parser, because the parser holds the one derivation of
// RFC 8446 section 7.3 and a second copy would drift from it.
func tls13TestKeys(t *testing.T, secret []byte) *parser.TLS13RecordKeys {
	t.Helper()

	keys, err := parser.DeriveTLS13RecordKeys(secret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	return keys
}

// tls13TestProtectRecord returns one protected TLS 1.3 record that carries the content.
// RFC 8446 section 5.2 states the record, and section 5.3 states the nonce.
func tls13TestProtectRecord(
	t *testing.T,
	keys *parser.TLS13RecordKeys,
	content []byte,
	innerType byte,
	sequence uint64,
) []byte {
	t.Helper()

	plaintext := append(append([]byte{}, content...), innerType)

	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		t.Fatalf("aes.NewCipher returned %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM returned %v", err)
	}

	length := len(plaintext) + aead.Overhead()
	header := []byte{
		parser.TLSRecordTypeApplicationData,
		0x03, 0x03,
		byte(length >> 8), byte(length),
	}

	nonce := make([]byte, len(keys.IV))
	copy(nonce, keys.IV)

	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}

	return aead.Seal(header, nonce, plaintext, header)
}

// tls13TestCertificateMessage returns one TLS 1.3 Certificate handshake message that
// carries the certificates.
//
// RFC 8446 section 4.4.2 states the body: `opaque certificate_request_context<0..2^8-1>;`
// then `CertificateEntry certificate_list<0..2^24-1>;`. One entry holds
// `opaque cert_data<1..2^24-1>` and `Extension extensions<0..2^16-1>`.
func tls13TestCertificateMessage(certs ...[]byte) []byte {
	var list []byte

	for _, cert := range certs {
		list = append(list, byte(len(cert)>>16), byte(len(cert)>>8), byte(len(cert)))
		list = append(list, cert...)
		list = append(list, 0x00, 0x00)
	}

	body := []byte{0x00}
	body = append(body, byte(len(list)>>16), byte(len(list)>>8), byte(len(list)))
	body = append(body, list...)

	message := []byte{
		tlsHandshakeCertificate,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
	}

	return append(message, body...)
}

// tls13TestClientHelloRecord returns one TLS 1.3 ClientHello record that carries the
// random.
func tls13TestClientHelloRecord(random []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, 0x00, 0x00)

	message := []byte{parser.TLSHandshakeClientHello, 0x00, byte(len(body) >> 8), byte(len(body))}
	message = append(message, body...)

	record := []byte{parser.TLSRecordTypeHandshake, 0x03, 0x01, byte(len(message) >> 8), byte(len(message))}

	return append(record, message...)
}

// tls13TestPacket returns one TCP packet that carries the payload.
func tls13TestPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		PSH:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers returned %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()

	return packet
}

// tls13TestCertificate returns one self-signed certificate in DER form.
func tls13TestCertificate(t *testing.T, name string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"ja4plus"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate returned %v", err)
	}

	return der
}

// tls13TestKeyLog returns the KeyLog that names one secret of one connection.
func tls13TestKeyLog(t *testing.T, label string, random, secret []byte) *KeyLog {
	t.Helper()

	line := label + " " + hex.EncodeToString(random) + " " + hex.EncodeToString(secret) + "\n"

	keyLog, err := ParseKeyLog(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	return keyLog
}

// tls13TestFingerprints returns the JA4X fingerprint of each result.
func tls13TestFingerprints(results []FingerprintResult) []string {
	var values []string

	for _, result := range results {
		if result.Type == "ja4x" {
			values = append(values, result.Fingerprint)
		}
	}

	return values
}

// TestTheProcessorReadsTheCertificateOfAProtectedTLS13Record holds the acceptance criterion
// of #492: the library reads the Certificate message of a protected TLS 1.3 record on TCP
// where the key log holds the secret.
//
// A TLS 1.3 server writes the Certificate message under the outer content type
// TLSRecordTypeApplicationData, which RFC 8446 section 5.2 states. So the plaintext reader
// of `findCertificatesInStream` walks past it.
func TestTheProcessorReadsTheCertificateOfAProtectedTLS13Record(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")

	want := ComputeJA4XFromDER(certDER)
	if want == "" {
		t.Fatal("ComputeJA4XFromDER read no certificate, and the test built one")
	}

	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	// The client sends the ClientHello, which names the connection in the key log.
	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	// The server sends one unprotected ServerHello record, one ChangeCipherSpec record and
	// then the protected records. The first protected record is sequence number 0.
	server := []byte{parser.TLSRecordTypeHandshake, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}
	server = append(server, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	server = append(server, tls13TestProtectRecord(t, keys, []byte{0x08, 0x00, 0x00, 0x00}, parser.TLSRecordTypeHandshake, 0)...)
	server = append(server, tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 1)...)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	values := tls13TestFingerprints(results)
	if len(values) != 1 || values[0] != want {
		t.Fatalf("the processor returned %v, and the record carries %s", values, want)
	}
}

// TestTheProcessorReadsTheCertificateOfEveryProtectedRecordOfAChain holds a chain that one
// Certificate message carries, and a message that spans two records.
func TestTheProcessorReadsTheCertificateOfEveryProtectedRecordOfAChain(t *testing.T) {
	random := bytes.Repeat([]byte{0x2e}, 32)
	secret := bytes.Repeat([]byte{0x77}, 32)

	leaf := tls13TestCertificate(t, "leaf.example")
	issuer := tls13TestCertificate(t, "issuer.example")

	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	// One Certificate message spans two records, because the message is larger than the
	// record the sender writes. RFC 8446 section 5.1 permits that split.
	message := tls13TestCertificateMessage(leaf, issuer)
	half := len(message) / 2

	server := tls13TestProtectRecord(t, keys, message[:half], parser.TLSRecordTypeHandshake, 0)
	server = append(server, tls13TestProtectRecord(t, keys, message[half:], parser.TLSRecordTypeHandshake, 1)...)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	values := tls13TestFingerprints(results)
	want := []string{ComputeJA4XFromDER(leaf), ComputeJA4XFromDER(issuer)}

	if len(values) != len(want) {
		t.Fatalf("the processor returned %v, and the chain carries %v", values, want)
	}

	for i, value := range values {
		if value != want[i] {
			t.Errorf("the processor returned %s at position %d, and the chain carries %s", value, i, want[i])
		}
	}
}

// TestTheProcessorReadsNoProtectedCertificateWithoutAKeyLog holds FR-gaps-18: the library
// produces no fingerprint from a secret when the caller supplies none.
func TestTheProcessorReadsNoProtectedCertificateWithoutAKeyLog(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)

	processor := NewProcessor()

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	server := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	if values := tls13TestFingerprints(results); len(values) != 0 {
		t.Fatalf("the processor returned %v, and the caller supplied no key log", values)
	}
}

// TestTheProcessorReadsNoProtectedCertificateOfATruncatedRecord holds the bound of every
// length field. Every packet is untrusted input, and a fingerprinter never panics.
func TestTheProcessorReadsNoProtectedCertificateOfATruncatedRecord(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	record := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	for _, length := range []int{1, 4, 5, 6, len(record) / 2, len(record) - 1} {
		processor := NewProcessor(WithKeyLog(keyLog))

		client := tls13TestPacket(t,
			tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
			1, tls13TestClientHelloRecord(random))
		if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v", errs)
		}

		results, errs := processor.ProcessPacket(tls13TestPacket(t,
			tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
			1, record[:length]))
		if len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v at %d bytes", errs, length)
		}

		if values := tls13TestFingerprints(results); len(values) != 0 {
			t.Errorf("the processor returned %v from a record of %d bytes", values, length)
		}
	}
}

// TestCleanupConnectionRemovesTheProtectedStream holds the removal path of the state that
// the protected reader uses. The reader reads the reverse stream of the reassembler, and
// `CleanupConnection` removes both directions.
func TestCleanupConnectionRemovesTheProtectedStream(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	processor.CleanupConnection(tls13TestClientIP, tls13TestClientPort, tls13TestServerIP, tls13TestServerPort, "tcp")

	server := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	if values := tls13TestFingerprints(results); len(values) != 0 {
		t.Fatalf("the processor returned %v after CleanupConnection removed the client stream", values)
	}
}

// TestTheProcessorReadsTheProtectedCertificatesOfTheHTTP2Capture holds the yield that #492
// buys on the corpus.
//
// `http2-with-cookies.pcapng` carries a TLS 1.3 connection and the Decryption Secrets
// Blocks of that connection. Frame 10 holds three certificates behind the record
// protection, and `docs/audit/ja4x-deviation-cluster.md`
// `## Cause 2 — the library reads no encrypted TLS 1.3 handshake record` measured the 9
// deviations that the three values close.
//
// The three expected values are the FoxIO vector values, and the register held each one
// under ruling #492 until this issue removed the entry.
func TestTheProcessorReadsTheProtectedCertificatesOfTheHTTP2Capture(t *testing.T) {
	path := filepath.Join(corpusCaptureDir, "http2-with-cookies.pcapng")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", path)
	}

	keyLog, err := ReadKeyLogFromCapture(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadKeyLogFromCapture returned %v", err)
	}

	if keyLog.Len() == 0 {
		t.Fatal("the capture holds no Decryption Secrets Block, and the vector set needs one")
	}

	processor := NewProcessor(WithKeyLog(keyLog))

	var values []string

	for _, packet := range loadPCAP(t, path) {
		results, _ := processor.ProcessPacket(packet)
		values = append(values, tls13TestFingerprints(results)...)
	}

	want := []string{
		"a373a9f83c6b_7022c563de38_2e3757343cb0",
		"a373a9f83c6b_a373a9f83c6b_5d71497f7704",
		"7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b",
	}

	if !slices.Equal(values, want) {
		t.Fatalf("the processor returned %v, and the FoxIO vector holds %v", values, want)
	}
}

// The port's register row `JA4X on a stream that a proxy tunnel carries` holds this
// reading, and the port decided it at its issue #138 on 2026-08-07. JA4X reads the TLS
// record layer without regard to the tunnel protocol that carries it, so a SOCKS4 tunnel
// on port 9901 produces the certificates of the tunneled session. No FoxIO implementation
// publishes a JA4X key for `socks4-https.pcap`, and the maintainer decided that the three
// values stay. The maintainer ruled on 2026-08-13 that a row the port's register already
// holds lands in this repository as a reading.
//
// FR-parity-49 and FR-parity-50 of `docs/specs/features/08-python-parity.md` state the
// rule. The register half of FR-parity-50 is sequenced behind #361, which builds the
// uncovered-value machinery. An entry written before that machinery is an orphan, and
// `conformanceCheckOrphans` fails the run for one.

// ja4xSOCKS4Values holds the three JA4X values that the SOCKS4 tunnel of
// `socks4-https.pcap` produces, in the order the certificate list carries them.
var ja4xSOCKS4Values = []string{
	"14f85a9f494d_3f8190b6b671_80ea7ef3b044",
	"14f85a9f494d_14f85a9f494d_be007da94c85",
	"e7bc7ebc3d9e_14f85a9f494d_9c8ed4a87d4b",
}

// TestJA4XReadsTheTLSRecordLayerOfASOCKS4Tunnel holds FR-parity-49 and the test half of
// FR-parity-50.
//
// The stream carries two conditions that no other capture of the corpus carries together.
// The reader stores the segments out of sequence order, and the server coalesces
// ServerHello and Certificate into one TLS record. #57 repaired both, and this test fails
// when either repair is reversed.
func TestJA4XReadsTheTLSRecordLayerOfASOCKS4Tunnel(t *testing.T) {
	pcapPath := "testdata/foxio/pcap/socks4-https.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("the fixture %s is not present, so this test reads no capture", pcapPath)
	}

	packets := loadPCAP(t, pcapPath)

	fingerprinter := NewJA4X()
	var got []string
	for _, packet := range packets {
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned the error %v", err)
		}
		for _, result := range results {
			// The tunnel carries the session on port 9901, and no port test gates the read.
			if result.SrcPort != 9901 {
				t.Errorf("a JA4X value reached the port %d, want 9901", result.SrcPort)
			}
			got = append(got, result.Fingerprint)
		}
	}

	if len(got) != len(ja4xSOCKS4Values) {
		t.Fatalf("the SOCKS4 tunnel produced %d JA4X values, want %d; the values are %v",
			len(got), len(ja4xSOCKS4Values), got)
	}
	for index, want := range ja4xSOCKS4Values {
		if got[index] != want {
			t.Errorf("JA4X value %d is %q, want %q", index, got[index], want)
		}
	}
}

// TestJA4XDropsAStreamAboveTheByteBound holds the memory bound of the reader.
//
// The buffer that `parser.TCPStreamReassembler` replaced kept the last ja4xMaxStreamBytes
// bytes of one stream. The reassembler bounds the run that GetStream returns, and it
// bounds no stored segment, so the reader counts the bytes it adds and drops a stream
// above the bound. A server sends the certificate chain in the first few kilobytes of the
// session, so a stream above one megabyte carries application data and no certificate.
func TestJA4XDropsAStreamAboveTheByteBound(t *testing.T) {
	client := net.IP{192, 168, 1, 20}
	server := net.IP{10, 0, 0, 20}

	fingerprinter := NewJA4X()
	segment := make([]byte, 1400)
	var sequence uint32 = 1
	for sent := 0; sent <= ja4xMaxStreamBytes; sent += len(segment) {
		packet := buildTCPPacketWithSeq(t, server, client, 443, 40020, sequence, segment)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("ProcessPacket returned the error %v", err)
		}
		sequence += uint32(len(segment))
	}

	streams := auditStateFieldLengths("JA4XFingerprinter", fingerprinter)["JA4XFingerprinter.reassembler.streams"]
	if streams != 0 {
		t.Errorf("the reassembler holds %d streams above the bound, want 0", streams)
	}
	if len(fingerprinter.streamBytes) != 0 {
		t.Errorf("the byte counter holds %d streams above the bound, want 0", len(fingerprinter.streamBytes))
	}
}
