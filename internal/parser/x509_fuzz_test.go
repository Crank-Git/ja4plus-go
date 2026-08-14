package parser

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// fuzzCertificateDER returns the DER bytes of one self-signed certificate.
//
// The key comes from a fixed seed, and Ed25519 signs without randomness, so the bytes
// never change between two runs. A seed that changes on each run writes a new corpus
// entry on each run.
//
// `testCertificateDER` in `x509_identifiers_test.go` builds a similar certificate, and it
// takes a `*testing.T`. A fuzz target adds its seeds from a `*testing.F`, so this helper
// takes a `testing.TB`.
func fuzzCertificateDER(tb testing.TB) []byte {
	tb.Helper()

	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	template := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Example"},
			OrganizationalUnit: []string{"Example Unit"},
			CommonName:         "example.com",
		},
		NotBefore:             time.Unix(1579219200, 0),
		NotAfter:              time.Unix(1610841600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, private.Public(), private)
	if err != nil {
		tb.Fatalf("the helper created no certificate: %v", err)
	}

	return der
}

// FuzzReadX509IdentifiersReadsAnyCertificate proves that ReadX509Identifiers returns for
// any DER input. FR-fuzz-8 states the requirement.
func FuzzReadX509IdentifiersReadsAnyCertificate(f *testing.F) {
	certificate := fuzzCertificateDER(f)

	// The reader accepts this seed.
	f.Add(certificate)

	// The reader rejects each seed below. The first holds no byte. The second is a prefix
	// of the certificate, so every length field runs past the input. The third states a
	// SEQUENCE length that the input does not hold.
	f.Add([]byte{})
	f.Add(certificate[:len(certificate)/2])
	f.Add([]byte{0x30, 0x82, 0xff, 0xff, 0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		input := fuzzprop.ExactInput(der)

		fuzzprop.Check(t, len(input), func() any {
			identifiers, ok := ReadX509Identifiers(input)

			return []any{identifiers, ok}
		})
	})
}
