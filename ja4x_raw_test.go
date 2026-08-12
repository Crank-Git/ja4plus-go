package ja4plus

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

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

	rawParts := strings.Split(vectorRaw, "_")
	hashParts := strings.Split(vectorFingerprint, "_")

	for i := range hashParts {
		if got := parser.TruncatedHash(rawParts[i]); got != hashParts[i] {
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
