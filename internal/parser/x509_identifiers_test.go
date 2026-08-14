package parser

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

// testCertificateDER returns the DER bytes of one self-signed certificate.
//
// `crypto/x509` accepts this certificate, so a test compares the reader of this package
// against `x509.ParseCertificate` on the same bytes. The certificate names a named curve,
// because `crypto/x509` writes no explicit curve parameter.
func testCertificateDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("the test generated no key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			Country:            []string{"HR"},
			Province:           []string{"Zagreb"},
			Organization:       []string{"INFIGO IS"},
			OrganizationalUnit: []string{"INFIGO"},
			CommonName:         "INFIGO",
		},
		NotBefore:             time.Unix(1579219200, 0),
		NotAfter:              time.Unix(1610841600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"bad.curveballtest.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("the test created no certificate: %v", err)
	}
	return der
}

// crypto/x509 states the identifier lists of a certificate it accepts, so the reader of
// this package must state the same three lists on the same bytes.
func TestReadX509IdentifiersAgreesWithCryptoX509OnACertificateThatCryptoX509Accepts(t *testing.T) {
	der := testCertificateDER(t)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("crypto/x509 read no certificate: %v", err)
	}

	identifiers, ok := ReadX509Identifiers(der)
	if !ok {
		t.Fatal("the reader read no certificate")
	}

	var wantIssuer, wantSubject, wantExtensions []string
	for _, attribute := range cert.Issuer.Names {
		wantIssuer = append(wantIssuer, OIDToHex(attribute.Type.String()))
	}
	for _, attribute := range cert.Subject.Names {
		wantSubject = append(wantSubject, OIDToHex(attribute.Type.String()))
	}
	for _, extension := range cert.Extensions {
		wantExtensions = append(wantExtensions, OIDToHex(extension.Id.String()))
	}

	for _, comparison := range []struct {
		name string
		got  []string
		want []string
	}{
		{"issuer", identifiers.Issuer, wantIssuer},
		{"subject", identifiers.Subject, wantSubject},
		{"extension", identifiers.Extensions, wantExtensions},
	} {
		gotJoined := strings.Join(comparison.got, ",")
		wantJoined := strings.Join(comparison.want, ",")
		if gotJoined != wantJoined {
			t.Errorf("the %s list is %q, and crypto/x509 states %q",
				comparison.name, gotJoined, wantJoined)
		}
	}

	if len(identifiers.Subject) != 5 {
		t.Errorf("the subject list holds %d identifiers, and the certificate names 5",
			len(identifiers.Subject))
	}
}

// Every packet is untrusted input, so a truncated certificate must reach a refusal and
// never a panic. `CLAUDE.md` `## Conventions` states the rule.
func TestReadX509IdentifiersRefusesEveryTruncatedPrefixOfACertificate(t *testing.T) {
	der := testCertificateDER(t)

	for length := 0; length < len(der); length++ {
		if _, ok := ReadX509Identifiers(der[:length]); ok {
			t.Fatalf("the reader read a certificate from the first %d bytes of %d",
				length, len(der))
		}
	}
}

// A byte that no certificate holds must reach a refusal, so each case below states one
// malformed input and the reader answers false for every one.
func TestReadX509IdentifiersRefusesAMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"an empty input":             {},
		"one tag byte":               {0x30},
		"a length that overruns":     {0x30, 0x7f, 0x02, 0x01, 0x07},
		"an indefinite length":       {0x30, 0x80, 0x00, 0x00},
		"a five-byte length":         {0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05},
		"an integer and no sequence": {0x02, 0x01, 0x07},
		"an empty outer sequence":    {0x30, 0x00},
		"an empty tbs certificate":   {0x30, 0x02, 0x30, 0x00},
	}

	for name, der := range cases {
		if _, ok := ReadX509Identifiers(der); ok {
			t.Errorf("the reader read a certificate from %s", name)
		}
	}
}

// derBuild returns one DER element that carries the tag and the content.
//
// The builder writes the short length form below 128 bytes and the one-octet long form
// above it, so every element it builds stays under 256 bytes.
func derBuild(tag byte, content []byte) []byte {
	if len(content) < 0x80 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	return append([]byte{tag, 0x81, byte(len(content))}, content...)
}

// derBuildName returns one RDNSequence that holds one attribute with the identifier.
func derBuildName(oid []byte) []byte {
	attribute := derBuild(0x30, append(derBuild(0x06, oid), derBuild(0x13, []byte("x"))...))
	return derBuild(0x30, derBuild(0x31, attribute))
}

// A certificate that carries a unique identifier field puts that field between the public
// key and the extensions, so the reader must skip it and still find the extensions.
//
// `crypto/x509` writes no unique identifier field, so the test builds the certificate. RFC
// 5280 section 4.1 states that issuerUniqueID and subjectUniqueID are each optional.
func TestReadX509IdentifiersSkipsTheUniqueIdentifierFieldsAndReadsTheExtensions(t *testing.T) {
	var tbs []byte
	tbs = append(tbs, derBuild(0xa0, derBuild(0x02, []byte{0x02}))...)    // version v3
	tbs = append(tbs, derBuild(0x02, []byte{0x07})...)                    // serialNumber
	tbs = append(tbs, derBuild(0x30, derBuild(0x06, []byte{0x2a}))...)    // signature
	tbs = append(tbs, derBuildName([]byte{0x55, 0x04, 0x06})...)          // issuer C
	tbs = append(tbs, derBuild(0x30, nil)...)                             // validity
	tbs = append(tbs, derBuildName([]byte{0x55, 0x04, 0x03})...)          // subject CN
	tbs = append(tbs, derBuild(0x30, derBuild(0x06, []byte{0x2a}))...)    // publicKey
	tbs = append(tbs, derBuild(0x81, []byte{0x00, 0x01})...)              // issuerUniqueID
	tbs = append(tbs, derBuild(0x82, []byte{0x00, 0x02})...)              // subjectUniqueID
	extension := derBuild(0x30, derBuild(0x06, []byte{0x55, 0x1d, 0x0e})) // subjectKeyIdentifier
	tbs = append(tbs, derBuild(0xa3, derBuild(0x30, extension))...)       // extensions
	certificate := derBuild(0x30, append(derBuild(0x30, tbs), derBuild(0x03, []byte{0x00})...))

	identifiers, ok := ReadX509Identifiers(certificate)
	if !ok {
		t.Fatal("the reader read no certificate")
	}
	if got := strings.Join(identifiers.Issuer, ","); got != "550406" {
		t.Errorf("the issuer list is %q, and the certificate names one country", got)
	}
	if got := strings.Join(identifiers.Subject, ","); got != "550403" {
		t.Errorf("the subject list is %q, and the certificate names one common name", got)
	}
	if got := strings.Join(identifiers.Extensions, ","); got != "551d0e" {
		t.Errorf("the extension list is %q, and the certificate names one extension", got)
	}
}

// A certificate that holds no extension reaches an empty extension list, because the
// extensions field of TBSCertificate is optional. RFC 5280 section 4.1 states that.
func TestReadX509IdentifiersReadsAnEmptyExtensionListWhenTheCertificateHoldsNoExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("the test generated no key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "no extension"},
		NotBefore:    time.Unix(1579219200, 0),
		NotAfter:     time.Unix(1610841600, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("the test created no certificate: %v", err)
	}

	identifiers, ok := ReadX509Identifiers(der)
	if !ok {
		t.Fatal("the reader read no certificate")
	}
	if len(identifiers.Extensions) != 0 {
		t.Errorf("the extension list holds %d identifiers, and the certificate names none",
			len(identifiers.Extensions))
	}
	if strings.Join(identifiers.Subject, ",") != "550403" {
		t.Errorf("the subject list is %q, and the certificate names one common name",
			strings.Join(identifiers.Subject, ","))
	}
}
