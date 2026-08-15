package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The three tests of this file hold FR-parity-13, FR-parity-14 and FR-parity-15 of
// `docs/specs/features/08-python-parity.md`.
//
// The register row at `docs/specs/spec.md:395` states the ruling: the library holds no
// plausibility guard, so a structurally valid client hello produces a fingerprint whatever
// its body holds. The port ruled the question first, and the port's issue #338 holds the
// measurement while the port's issue #343 re-measured it. The port holds its own half at
// `tests/fuzz/test_structural_validity.py`.
//
// The port measured 5000 random client hello bodies. All 5000 produced a well-formed
// fingerprint. 4998 carried the version token `00`, and 720 carried neither a cipher suite
// nor an extension. The same measurement read 168 client hellos of the committed captures,
// and 0 of the 168 carried either condition. A guard on the two conditions therefore moves
// no vector, and it costs a permanent difference from every FoxIO implementation.
//
// Each test asserts the whole fingerprint value. A test that asserts the absence of an
// error alone passes when the value is wrong.

// ja4PlausibilityPacket builds one TCP packet that carries the named client hello.
//
// The packet reaches ProcessPacket, so the assertion covers the parser and the
// fingerprinter together. A plausibility guard could sit in either one.
func ja4PlausibilityPacket(t *testing.T, version uint16, ciphers []uint16, exts []parser.TLSExtension) gopacket.Packet {
	t.Helper()

	tlsPayload := parser.BuildClientHello(version, ciphers, exts)

	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 443,
		ACK:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(tlsPayload)); err != nil {
		t.Fatalf("the test does not serialize the packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

// ja4PlausibilityResult returns the one JA4 result of the named client hello.
// It fails the test when the fingerprinter returns no result, because a guard that rejects
// the body reaches exactly that state.
func ja4PlausibilityResult(t *testing.T, version uint16, ciphers []uint16, exts []parser.TLSExtension) FingerprintResult {
	t.Helper()

	packet := ja4PlausibilityPacket(t, version, ciphers, exts)

	results, err := NewJA4().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v, and the library holds no plausibility guard", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returns %d results, and a structurally valid client hello gives 1",
			len(results))
	}

	return results[0]
}

// assertWellFormedJA4 checks the shape of a JA4 value.
//
// The FoxIO form holds three parts. Part a holds 10 characters, and each of the two hashes
// holds 12. A guard that returns an empty value fails the part count first.
func assertWellFormedJA4(t *testing.T, value string) {
	t.Helper()

	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		t.Fatalf("the JA4 value is %q, and the FoxIO form holds 3 parts", value)
	}
	if len(parts[0]) != 10 {
		t.Errorf("part a is %q, and the FoxIO form holds 10 characters", parts[0])
	}
	if len(parts[1]) != 12 {
		t.Errorf("the cipher hash is %q, and the FoxIO form holds 12 characters", parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("the extension hash is %q, and the FoxIO form holds 12 characters", parts[2])
	}
}

// TestJA4FingerprintsAClientHelloWithNoCipherSuiteAndNoExtension holds FR-parity-14.
//
// The client hello carries the version `0x0303`, no cipher suite and no extension. The
// cipher count and the extension count each read `00`, and each hash reaches the zero
// sentinel that `internal/parser/hash.go:15` returns for an empty list.
//
// The port holds the same case at `tests/fuzz/test_structural_validity.py`, and the port's
// issue #343 records the ruling. A reader who reverses the ruling reverses both halves.
func TestJA4FingerprintsAClientHelloWithNoCipherSuiteAndNoExtension(t *testing.T) {
	result := ja4PlausibilityResult(t, 0x0303, nil, nil)

	assertWellFormedJA4(t, result.Fingerprint)

	if result.Fingerprint != "t12i000000_000000000000_000000000000" {
		t.Errorf("JA4 is %q, and a client hello with no cipher suite and no extension gives %q",
			result.Fingerprint, "t12i000000_000000000000_000000000000")
	}
	if result.Raw != "t12i000000__" {
		t.Errorf("JA4_r is %q, and the two empty lists give %q", result.Raw, "t12i000000__")
	}
}

// TestJA4FingerprintsAClientHelloWithTheVersionToken00 holds FR-parity-15.
//
// The client hello carries the version `0x0000`, which
// `internal/parser/tls.go:342-343` maps to the version token `00`. The body also carries two
// cipher suites and two extensions, so the two hashes read a real list and the assertion
// separates the version token from an empty body.
//
// The port holds the same case at `tests/fuzz/test_structural_validity.py`, and the port's
// issue #343 records the ruling. A reader who reverses the ruling reverses both halves.
func TestJA4FingerprintsAClientHelloWithTheVersionToken00(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302}
	exts := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),
		{Typ: 0x0017}, // extended_master_secret, which the sorted list keeps
	}

	result := ja4PlausibilityResult(t, 0x0000, ciphers, exts)

	assertWellFormedJA4(t, result.Fingerprint)

	if result.Fingerprint != "t00d020200_62ed6f6ca7ad_1ca028f07214" {
		t.Errorf("JA4 is %q, and the version token `00` gives %q",
			result.Fingerprint, "t00d020200_62ed6f6ca7ad_1ca028f07214")
	}
	if result.Raw != "t00d020200_1301,1302_0017" {
		t.Errorf("JA4_r is %q, and the version token `00` gives %q",
			result.Raw, "t00d020200_1301,1302_0017")
	}
}

// TestTheLibraryHoldsNoPlausibilityGuardOnTheClientHelloBody holds FR-parity-13.
//
// The client hello carries the version `0x0000`, no cipher suite and no extension. It meets
// both separating conditions of the measurement at once, so it is the input that a guard on
// those conditions rejects. **This test fails when a guard is ever added.**
//
// The register row at `docs/specs/spec.md:395` states the ruling, and the port's issue #343
// holds the other half. A guard costs a permanent difference from every FoxIO
// implementation on the same bytes, and comparison is the one thing a fingerprint is for.
func TestTheLibraryHoldsNoPlausibilityGuardOnTheClientHelloBody(t *testing.T) {
	result := ja4PlausibilityResult(t, 0x0000, nil, nil)

	assertWellFormedJA4(t, result.Fingerprint)

	if result.Fingerprint != "t00i000000_000000000000_000000000000" {
		t.Errorf("JA4 is %q, and the two separating conditions together give %q",
			result.Fingerprint, "t00i000000_000000000000_000000000000")
	}

	// ComputeJA4 reads the same client hello through the one-shot function. A guard in
	// either entry point therefore fails this test.
	direct := ComputeJA4(ja4PlausibilityPacket(t, 0x0000, nil, nil))
	if direct != result.Fingerprint {
		t.Errorf("ComputeJA4 returns %q, and ProcessPacket returns %q", direct, result.Fingerprint)
	}
}
