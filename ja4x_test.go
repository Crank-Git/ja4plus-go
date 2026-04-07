package ja4plus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateSelfSignedCertDER creates a self-signed certificate in DER format
// for testing purposes.
func generateSelfSignedCertDER(t *testing.T) []byte {
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
	if parts[0] == emptyHash {
		t.Error("issuer hash should not be empty for a cert with issuer fields")
	}
	if parts[1] == emptyHash {
		t.Error("subject hash should not be empty for a cert with subject fields")
	}
	// Extensions should also be present (BasicConstraints, KeyUsage, etc.).
	if parts[2] == emptyHash {
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
	if len(f.streams) != 0 {
		t.Errorf("new fingerprinter should have empty streams, got %d", len(f.streams))
	}
}

func TestJA4XFingerprinter_Reset(t *testing.T) {
	f := NewJA4X()
	f.streams["test"] = []byte{1, 2, 3}
	f.processedCerts["abc"] = struct{}{}

	f.Reset()

	if len(f.streams) != 0 {
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
