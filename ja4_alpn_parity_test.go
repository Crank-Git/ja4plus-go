package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// These tests hold FR-parity-8, FR-parity-9 and FR-parity-10 of
// `docs/specs/features/08-python-parity.md`. Issue #50 builds them.
//
// The port rules this value, and `Crank-Git/ja4plus#127`, `Crank-Git/ja4plus#141` and
// `Crank-Git/ja4plus#162` hold the three halves of that ruling. A reader who reverses a
// value below reverses it in `Crank-Git/ja4plus` as well.
//
//   - `Crank-Git/ja4plus#127` settled the value from the FoxIO vector. The vector
//     `python/test/testdata/tls-non-ascii-alpn.pcapng.json` holds the first ALPN value
//     `0xba 0xad` and the ALPN characters `99`.
//   - `Crank-Git/ja4plus#141` settled the condition by measurement. It ran both FoxIO
//     implementations at the commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, which is
//     the commit `testdata/foxio.pin` holds. The measurement shows that both
//     implementations pass a printable ASCII byte through, so the condition is the range
//     `0x20-0x7E` and not the alphanumeric test the FoxIO prose states.
//   - `Crank-Git/ja4plus#162` records the maintainer ruling of 2026-08-07. Every value
//     that the two FoxIO implementations dispute stays as the port wrote it.
//
// `docs/specs/foxio/JA4.md` R18 and R19 record the reference split, and Reading 5 records
// the tshark text form that causes it.

// alpnParityJA4PartA returns part a of the JA4 fingerprint of a ClientHello that carries
// one ALPN value. It builds the packet, so each case below reads a value the library
// produces from bytes on the wire.
func alpnParityJA4PartA(t *testing.T, alpn string) string {
	t.Helper()

	extensions := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),
		parser.MakeALPNExtension(alpn),
		parser.MakeSupportedVersionsClientExtension(0x0304),
	}
	payload := parser.BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, extensions)

	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{SrcPort: 54321, DstPort: 443, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returned %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, options, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers returned %v", err)
	}
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	results, err := NewJA4().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned %v", err)
	}
	if len(results) == 0 {
		t.Fatal("ProcessPacket returned no result")
	}

	return strings.Split(results[0].Fingerprint, "_")[0]
}

// alpnParityCharacters returns the two ALPN characters of part a. Part a ends with them,
// and `docs/specs/foxio/JA4.md` R16 states that.
func alpnParityCharacters(t *testing.T, partA string) string {
	t.Helper()

	if len(partA) < 2 {
		t.Fatalf("part a is %q, and it holds fewer than two characters", partA)
	}
	return partA[len(partA)-2:]
}

func TestTheALPNFieldWrites99WhenTheFirstByteFallsOutsideThePrintableASCIIRange(t *testing.T) {
	// FR-parity-8. `0xba 0xad` is the first ALPN value of the FoxIO vector
	// `tls-non-ascii-alpn.pcapng`, and the vector holds `99`. The three FoxIO sources
	// agree on that input: `python/ja4.py:279` writes `99` because the first byte is above
	// 127, `wireshark/source/packet-ja4.c:1027` writes `99` because the first byte is not
	// alphanumeric, and `rust/ja4/src/tls.rs:616` writes `9` for each of the two non-ASCII
	// characters.
	cases := []struct {
		name string
		alpn string
	}{
		{"the FoxIO vector value 0xba 0xad", "\xba\xad"},
		{"0xab 0xcd", "\xab\xcd"},
		{"a control byte before two alphanumeric bytes", "\x00h2"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != "99" {
				t.Errorf("the ALPN characters of %q are %q, and FR-parity-8 states %q",
					testCase.alpn, got, "99")
			}
		})
	}
}

func TestTheALPNFieldWrites99WhenTheLastByteFallsOutsideThePrintableASCIIRange(t *testing.T) {
	// FR-parity-9. The two FoxIO implementations dispute this input, and neither value
	// reads a byte the packet holds. `python/ja4.py:277` reduces `0x30 0xab` to two
	// characters and then tests the first byte alone, so it writes `0` and the tshark
	// replacement character. `rust/ja4/src/tls.rs:616` writes `09`.
	// `Crank-Git/ja4plus#162` holds `99` for the case.
	cases := []struct {
		name string
		alpn string
	}{
		{"a non-ASCII last byte", "\x30\xab"},
		{"two non-ASCII bytes at the end", "\x30\x31\xab\xcd"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != "99" {
				t.Errorf("the ALPN characters of %q are %q, and FR-parity-9 states %q",
					testCase.alpn, got, "99")
			}
		})
	}
}

func TestTheALPNFieldReadsNoByteBetweenTheFirstByteAndTheLastByte(t *testing.T) {
	// FR-parity-9 states the position rule, and this test states its limit. The rule reads
	// the first byte and the last byte alone, so a byte outside `0x20-0x7E` in a middle
	// position reaches no character of the field.
	//
	// The FoxIO measurement of `Crank-Git/ja4plus#141` records `01` for this input, in both
	// FoxIO implementations. FR-parity-9 reads as `99` for it, and issue #50 asks the
	// maintainer to reword the requirement.
	const alpn = "\x30\xab\xcd\x31"

	got := alpnParityCharacters(t, alpnParityJA4PartA(t, alpn))
	if got != "01" {
		t.Errorf("the ALPN characters of %q are %q, and the port measurement states %q",
			alpn, got, "01")
	}
}

func TestTheALPNFieldRepeatsTheByteWhenTheFirstALPNValueHoldsOneAlphanumericByte(t *testing.T) {
	// FR-parity-10. `docs/specs/foxio/JA4.md` R18 records a reference split of three
	// results, and two FoxIO sources repeat the byte. `technical_details/JA4.md:93` states
	// that the one character serves as both characters, and `zeek/ja4/main.zeek:86`
	// produces the same two characters because `[0]` and `[-1]` reach it.
	// `rust/ja4/src/tls.rs:334` writes `0` for the absent last character, and
	// `python/ja4.py:276` writes one character, which cannot fill a two-character field.
	cases := []struct {
		name string
		alpn string
		want string
	}{
		{"the letter h", "h", "hh"},
		{"the digit 3", "3", "33"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != testCase.want {
				t.Errorf("the ALPN characters of %q are %q, and FR-parity-10 states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}

func TestTheALPNFieldWrites99WhenAOneByteFirstALPNValueIsNotAlphanumeric(t *testing.T) {
	// FR-parity-10 repeats an alphanumeric byte, and this test states what a one-byte value
	// outside the alphanumeric ranges writes. The one-byte case is the one case that tests
	// the alphanumeric ranges rather than `0x20-0x7E`.
	//
	// `Crank-Git/ja4plus#141` records the reason. The two FoxIO implementations dispute
	// every one-byte value, so the port holds the value it wrote before the measurement.
	// `python/ja4.py:276` writes one character for `\x20`, and `rust/ja4/src/tls.rs:334`
	// writes ` 0`.
	cases := []struct {
		name string
		alpn string
	}{
		{"one byte that is printable and not alphanumeric", "\x20"},
		{"one byte outside the printable range", "\xab"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != "99" {
				t.Errorf("the ALPN characters of %q are %q, and the port writes %q",
					testCase.alpn, got, "99")
			}
		})
	}
}

func TestTheALPNFieldPassesAPrintableByteThroughWithoutAChange(t *testing.T) {
	// The measurement of `Crank-Git/ja4plus#141` settles the condition, and this test
	// holds it. Both FoxIO implementations pass a printable ASCII byte through, so a
	// printable byte that is not alphanumeric reaches the field without a change. The port
	// measured `h\x20` as `h ` and `\x20h` as ` h` in both implementations.
	//
	// FR-parity-8 states the alphanumeric test that the FoxIO prose states, and this
	// measurement contradicts that test. Issue #50 asks the maintainer to reword the
	// requirement, and this test holds the measured rule until the maintainer answers.
	cases := []struct {
		name string
		alpn string
		want string
	}{
		{"a leading space and one letter", "\x20\x61", "\x20a"},
		{"one letter and a trailing space", "\x61\x20", "a\x20"},
		{"the two alphanumeric ends of http/1.1", "http/1.1", "h1"},
		{"the two bytes of h2", "h2", "h2"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != testCase.want {
				t.Errorf("the ALPN characters of %q are %q, and the port measurement states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}
