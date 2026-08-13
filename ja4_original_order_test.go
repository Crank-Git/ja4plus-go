package ja4plus

import (
	"net"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ja4OriginalOrderPacket builds one TCP packet that carries a TLS client hello.
//
// The cipher list holds the wire order `1303,1301,1302`, which no sort produces, so the
// sorted form and the wire-order form differ. The extension list holds SNI and ALPN, which
// the sorted form removes and the wire-order form keeps.
func ja4OriginalOrderPacket(t *testing.T) gopacket.Packet {
	t.Helper()

	ciphers := []uint16{0x1303, 0x1301, 0x1302}
	exts := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),
		parser.MakeALPNExtension("h2", "http/1.1"),
		parser.MakeSupportedVersionsClientExtension(0x0304, 0x0303),
		parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804),
		{Typ: 0x0017, Data: []byte{}},
	}
	tlsPayload := parser.BuildClientHello(0x0303, ciphers, exts)

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

// TestJA4OriginalOrderHoldsTheHashedWireOrderForm asserts the `JA4_o` value of one client
// hello.
//
// `testdata/foxio/reference/python/ja4.py:291` builds `JA4_o` from the same part a as
// `JA4`, from a hash of the wire-order cipher list, and from a hash of the wire-order
// extension list. `testdata/foxio/reference/python/common.py:144` keeps SNI and ALPN in
// that list, because it removes the two only when it sorts.
// `testdata/foxio/reference/python/ja4.py:246` appends the signature algorithms to the
// hashed string. Issue #277 records the field that carries the value.
func TestJA4OriginalOrderHoldsTheHashedWireOrderForm(t *testing.T) {
	results, err := NewJA4().ProcessPacket(ja4OriginalOrderPacket(t))
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) == 0 {
		t.Fatal("ProcessPacket returns no result for a client hello")
	}

	// The test computes the two hashes from the strings that the reference hashes:
	// `1303,1301,1302` and `0000,0010,002b,000d,0017_0403,0804`.
	const expected = "t13d0305h2_d0bf4380f24c_06e54ac24ee4"

	if results[0].OriginalOrder != expected {
		t.Errorf("OriginalOrder is %q, and the FoxIO rule gives %q",
			results[0].OriginalOrder, expected)
	}
}

// TestJA4OriginalOrderHashesEachPartOfTheRawWireOrderForm proves that the hashed form and
// the raw form read one input.
//
// `testdata/foxio/reference/python/ja4.py:291` and
// `testdata/foxio/reference/python/ja4.py:293` build `JA4_o` and `JA4_ro` from the same two
// strings, so the part count of the two values differs. `JA4_ro` carries the signature
// algorithms as a fourth part, and `JA4_o` hashes them into the third part.
func TestJA4OriginalOrderHashesEachPartOfTheRawWireOrderForm(t *testing.T) {
	results, err := NewJA4().ProcessPacket(ja4OriginalOrderPacket(t))
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) == 0 {
		t.Fatal("ProcessPacket returns no result for a client hello")
	}

	result := results[0]

	const expectedRaw = "t13d0305h2_1303,1301,1302_0000,0010,002b,000d,0017_0403,0804"
	if result.RawOriginalOrder != expectedRaw {
		t.Fatalf("RawOriginalOrder is %q, and the FoxIO rule gives %q",
			result.RawOriginalOrder, expectedRaw)
	}

	partA, cipherList, extList := "t13d0305h2", "1303,1301,1302", "0000,0010,002b,000d,0017_0403,0804"
	want := partA + "_" + parser.TruncatedHash(cipherList) + "_" + parser.TruncatedHash(extList)

	if result.OriginalOrder != want {
		t.Errorf("OriginalOrder is %q, and the hash of each part of RawOriginalOrder gives %q",
			result.OriginalOrder, want)
	}
}

// TestJA4OriginalOrderDiffersFromTheSortedFingerprint proves that the new field carries a
// second value, and never a copy of `Fingerprint`.
//
// The wire order of this client hello is no sorted order, so the two values differ. A field
// that copied `Fingerprint` would close every `JA4_o` comparison with a wrong value.
func TestJA4OriginalOrderDiffersFromTheSortedFingerprint(t *testing.T) {
	results, err := NewJA4().ProcessPacket(ja4OriginalOrderPacket(t))
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) == 0 {
		t.Fatal("ProcessPacket returns no result for a client hello")
	}

	result := results[0]

	if result.OriginalOrder == result.Fingerprint {
		t.Errorf("OriginalOrder and Fingerprint each hold %q, and the two forms differ",
			result.OriginalOrder)
	}
	if result.Fingerprint != "t13d0305h2_55b375c5d22e_f9b7c94aa166" {
		t.Errorf("Fingerprint is %q, and the change moves no JA4 value", result.Fingerprint)
	}
}

// TestTheJA4SResultLeavesTheOriginalOrderEmpty holds the rule that one fingerprinter fills
// the new field.
//
// FoxIO publishes `JA4_o` and publishes no `JA4S_o`.
// `testdata/foxio/reference/python/ja4.py:291` writes the one key, and `conformance_adapters_test.go`
// builds the key from the method name, so a value in this field emits a key the vector
// never holds. Issue #277 records the rule.
func TestTheJA4SResultLeavesTheOriginalOrderEmpty(t *testing.T) {
	payload := buildServerHelloPayload(0xc02b, []uint16{0x0000, 0xff01, 0x000b}, "")

	results, err := NewJA4S().ProcessPacket(buildTCPPayloadPacket(t, payload))
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returns %d results, and the test expects 1", len(results))
	}

	if results[0].OriginalOrder != "" {
		t.Errorf("OriginalOrder holds %q, and FoxIO publishes no JA4S_o key",
			results[0].OriginalOrder)
	}
}
