package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ja4EmptySortedExtensionPacket builds one TCP packet that separates the two references.
//
// The extension list holds SNI alone, and the client hello carries no signature algorithm.
// The sorted form removes SNI, so the sorted extension string is empty and the wire-order
// extension string is `0000`. `testdata/foxio/python/https3-301-get.pcap.json` holds that
// shape, and issue #287 records the split it reaches.
func ja4EmptySortedExtensionPacket(t *testing.T) gopacket.Packet {
	t.Helper()

	ciphers := []uint16{0x1301, 0x1302}
	exts := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),
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

// ja4EmptySortedExtensionResult returns the one result of the separating client hello.
func ja4EmptySortedExtensionResult(t *testing.T) FingerprintResult {
	t.Helper()

	results, err := NewJA4().ProcessPacket(ja4EmptySortedExtensionPacket(t))
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) == 0 {
		t.Fatal("ProcessPacket returns no result for a client hello")
	}

	return results[0]
}

// TestJA4OriginalOrderWritesTheZeroSentinelWhenTheSortedExtensionListIsEmpty holds the
// maintainer's ruling of 2026-08-12 on issue #287.
//
// The ruling follows the Python reference. `testdata/foxio/reference/python/ja4.py:248`
// tests the sorted extension string, and `testdata/foxio/reference/python/ja4.py:253`
// writes `000000000000` into the wire-order part from that test. The Rust reference hashes
// the wire-order string on its own at `testdata/foxio/reference/rust/ja4/src/tls.rs:363`.
// The Wireshark dissector emits no `JA4_o` key and the Zeek scripts emit none, so the
// split reaches the two references alone.
//
// The port needs no change, because `ja4plus/fingerprinters/ja4.py:228` writes the
// sentinel already.
func TestJA4OriginalOrderWritesTheZeroSentinelWhenTheSortedExtensionListIsEmpty(t *testing.T) {
	result := ja4EmptySortedExtensionResult(t)

	parts := strings.Split(result.OriginalOrder, "_")
	if len(parts) != 3 {
		t.Fatalf("OriginalOrder is %q, and the FoxIO form holds 3 parts", result.OriginalOrder)
	}

	if parts[2] != parser.EmptyHash {
		t.Errorf("the extension part of OriginalOrder is %q, and the ruling of #287 gives %q",
			parts[2], parser.EmptyHash)
	}
}

// TestTheSeparatingClientHelloHoldsAnEmptySortedListAndAWireOrderList proves that the
// input separates the two references.
//
// A ruling needs an input that the two rules answer differently. The wire-order extension
// string is `0000` here, so the Rust rule hashes a non-empty string and the Python rule
// writes the sentinel. An input whose wire-order string were empty would reach
// `000000000000` under each rule, and it would prove nothing.
func TestTheSeparatingClientHelloHoldsAnEmptySortedListAndAWireOrderList(t *testing.T) {
	result := ja4EmptySortedExtensionResult(t)

	rawParts := strings.Split(result.RawOriginalOrder, "_")
	if len(rawParts) != 3 {
		t.Fatalf("RawOriginalOrder is %q, and the FoxIO form holds 3 parts", result.RawOriginalOrder)
	}
	if rawParts[2] != "0000" {
		t.Fatalf("the wire-order extension list is %q, and the separating input gives %q",
			rawParts[2], "0000")
	}

	sortedParts := strings.Split(result.Raw, "_")
	if len(sortedParts) != 3 {
		t.Fatalf("Raw is %q, and the FoxIO form holds 3 parts", result.Raw)
	}
	if sortedParts[2] != "" {
		t.Fatalf("the sorted extension list is %q, and the separating input gives an empty string",
			sortedParts[2])
	}
}

// TestTheZeroSentinelRulingMovesNoOtherJA4Value guards the one-rule scope of issue #287.
//
// The ruling changes the extension part of `JA4_o` alone. `JA4`, `JA4_r` and `JA4_ro` each
// match the FoxIO vector before the change, so a move in any of the three reports a wrong
// change rather than a closed comparison.
func TestTheZeroSentinelRulingMovesNoOtherJA4Value(t *testing.T) {
	result := ja4EmptySortedExtensionResult(t)

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"JA4", result.Fingerprint, "t12d020100_62ed6f6ca7ad_000000000000"},
		{"JA4_r", result.Raw, "t12d020100_1301,1302_"},
		{"JA4_ro", result.RawOriginalOrder, "t12d020100_1301,1302_0000"},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s is %q, and the ruling of #287 moves no %s value", c.name, c.got, c.name)
		}
	}
}
