package ja4plus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

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
// `ja4x_raw_test.go` reads `a373a9f83c6b` from the FoxIO badcurveball vector for the same
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
