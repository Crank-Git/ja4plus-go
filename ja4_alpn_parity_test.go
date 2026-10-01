package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

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
//     implementations at the commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, which was
//     the FoxIO pin of this repository until #797. The measurement shows that both
//     implementations pass a printable ASCII byte through, so the condition is the range
//     `0x20-0x7E` and not the alphanumeric test the FoxIO prose states.
//   - `Crank-Git/ja4plus#162` records the maintainer ruling of 2026-08-07. Every value
//     that the two FoxIO implementations dispute stays as the port wrote it.
//
// The maintainer ruling of 2026-10-01 UTC reverses part of those rulings. Issue #801 holds
// it, and `Crank-Git/ja4plus#789` holds the port half. A non-ASCII end byte writes `9`, and
// a one-byte printable value writes its byte twice. `ja4_alpn_ruling_test.go` holds the
// separating packets of that ruling, and the cases below follow it.
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
	// `tls-non-ascii-alpn.pcapng`, and the vector holds `99`. Three FoxIO sources agree on
	// that input, and each one reaches `99` by its own rule.
	//
	//   - `python/ja4.py:156-157` writes `9` for each of the two non-ASCII characters.
	//   - `wireshark/source/packet-ja4.c:1027-1028` writes `99`, because the first byte is
	//     not alphanumeric.
	//   - `rust/ja4/src/tls.rs:636-645` writes `9` for each of the two non-ASCII characters.
	//
	// The control byte `0x00` keeps the `99` of `Crank-Git/ja4plus#162`. The maintainer
	// confirmed that case on 2026-10-01 UTC, under #801.
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

func TestTheALPNFieldWrites9ForALastByteOf0x80OrHigher(t *testing.T) {
	// FR-parity-9, as the ruling of #801 on 2026-10-01 UTC amends it. `python/ja4.py:157`
	// and `rust/ja4/src/tls.rs:636-645` each write `9` for a non-ASCII last character, so
	// both write `09` for `0x30 0xab`. `Crank-Git/ja4plus#162` held `99` for the case until
	// that ruling, and `Crank-Git/ja4plus#789` carries the port half.
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
			if got != "09" {
				t.Errorf("the ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, "09")
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
	// FR-parity-10. `docs/specs/foxio/JA4.md` R18 records the reference split. Four FoxIO
	// sources repeat the byte. `technical_details/JA4.md:93` states that the one character
	// serves as both characters, and `python/ja4.py:149-158` and `zeek/src/ja4.cc:76-81`
	// each produce the same two characters. `wireshark/source/packet-ja4.c:552-554` repeats
	// the byte as well, and that code renders JA4S through the shared ALPN store.
	// `rust/ja4/src/tls.rs:352-353` writes `0` for the absent last character.
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

func TestTheALPNFieldWritesAOneByteValueByTheRulingOf801(t *testing.T) {
	// FR-parity-10 repeats an alphanumeric byte, and this test states what a one-byte value
	// outside the alphanumeric ranges writes. The ruling of #801 on 2026-10-01 UTC settles
	// it, and `Crank-Git/ja4plus#789` carries the port half.
	//
	//   - A printable byte writes itself twice. `python/ja4.py:149-158` and
	//     `zeek/src/ja4.cc:76-81` each write `\x20\x20`, and `rust/ja4/src/tls.rs:352-353`
	//     writes ` 0`.
	//   - A byte of 0x80 or higher writes `9` for each end, so it writes `99`.
	cases := []struct {
		name string
		alpn string
		want string
	}{
		{"one byte that is printable and not alphanumeric", "\x20", "\x20\x20"},
		{"one byte of 0x80 or higher", "\xab", "99"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != testCase.want {
				t.Errorf("the ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, testCase.want)
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
