package ja4plus

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// These tests hold the parser findings of issue #22. `docs/audit/findings.md` records each
// one, and the identifier in each test name points at the row.
//
// Every test below asserts the value the library produces today, which is the wrong value.
// The audit changes no code, so a test that asserts the right value would fail on this
// branch and hide every other finding. Issue #25 owns the repair under FR-audit-25, and it
// inverts each assertion in the same commit that closes the finding.
//
// `.claude/rules/rulings.md` asks for a test that builds the separating packet where no
// FoxIO vector reaches the value. F-22-2, F-22-3, F-22-6, F-22-7, F-22-8, F-22-11,
// F-22-12 and F-22-13 are those findings, and the tests below build their input.

// auditParserGreaseSigAlg is the GREASE signature algorithm that F-22-11, F-22-12 and
// F-22-13 use. RFC 8701 reserves it, and `docs/specs/foxio/JA4.md` R31 states that the
// signature algorithm list skips it.
const auditParserGreaseSigAlg = 0x0a0a

// auditParserClientHello builds a ClientHello that carries the extensions the caller
// names. It exists so that no test below reaches a helper of another audit file.
func auditParserClientHello(t *testing.T, extensions []parser.TLSExtension) []byte {
	t.Helper()

	return parser.BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, extensions)
}

func TestF22_1_ALPNValueHexEncodesTheWholeValueAndDisagreesWithTheFoxioVector(t *testing.T) {
	// The FoxIO vector for `tls-non-ascii-alpn.pcapng` stream 0 holds
	// `t13d151699_8daaf6152771_e5627efa2ab1`, and the library produces
	// `t13d1516bd_8daaf6152771_e5627efa2ab1`. Only the two ALPN characters differ.
	// `docs/audit/conformance.md:410` records the pair.
	//
	// `docs/specs/foxio/JA4.md` R19 records a reference split of four results for a
	// non-alphanumeric ALPN value. `.claude/rules/parity.md` rule 1 settles it, because a
	// vector reaches the value, and the vector holds `99`.
	//
	// The two values below separate the reading. `python/ja4.py:279` and
	// `wireshark/source/packet-ja4.c:1027` both write `99`, and the library writes the
	// first and last character of the hexadecimal form of the whole value.
	cases := []struct {
		alpn    string
		library string
		foxio   string
	}{
		{"\xbd\x99", "b9", "99"},
		{"\x99", "99", "99"},
		{"\x00h2", "02", "99"},
	}

	for _, testCase := range cases {
		got := parser.ALPNValue([]string{testCase.alpn})
		if got != testCase.library {
			t.Errorf("ALPNValue(%q) = %q, and the finding F-22-1 records %q",
				testCase.alpn, got, testCase.library)
		}
	}
}

func TestF22_2_ParseClientHelloReadsPastTheRecordLengthIntoTheNextRecord(t *testing.T) {
	// `ParseClientHello` reads the record length at `internal/parser/tls.go:71` and then
	// bounds every later slice by the payload length. A payload that holds two TLS records
	// therefore lets the first record's extensions length reach into the second record.
	hello := auditParserClientHello(t, []parser.TLSExtension{parser.MakeSNIExtension("a.example")})
	second := parser.BuildServerHello(0x0303, 0x1302, []parser.TLSExtension{parser.MakeALPNExtension("h2")})

	payload := make([]byte, 0, len(hello)+len(second))
	payload = append(payload, hello...)
	payload = append(payload, second...)

	honest, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the honest payload: %v", err)
	}

	if len(honest.Extensions) != 1 || honest.Extensions[0] != parser.ExtSNI {
		t.Fatalf("the honest payload produces the extensions %v, and the ClientHello holds one",
			honest.Extensions)
	}

	// The extensions length field sits after the record header, the handshake header, the
	// version, the random, the session identifier, the cipher suite list and the
	// compression method list.
	const extensionsLengthOffset = 5 + 4 + 2 + 32 + 1 + 2 + 4 + 2

	crafted := make([]byte, len(payload))
	copy(crafted, payload)

	grown := int(crafted[extensionsLengthOffset])<<8 | int(crafted[extensionsLengthOffset+1])
	grown += len(second)
	crafted[extensionsLengthOffset] = byte(grown >> 8)
	crafted[extensionsLengthOffset+1] = byte(grown)

	got, err := parser.ParseClientHello(crafted)
	if err != nil {
		t.Fatalf("the crafted payload: %v", err)
	}

	if len(got.Extensions) <= len(honest.Extensions) {
		t.Errorf("the crafted payload produces the extensions %v, and the finding F-22-2 records a longer list",
			got.Extensions)
	}

	// 0x1603 is the content type and the first version byte of the second record. The
	// parser reads the two bytes as an extension type.
	if got.Extensions[len(got.Extensions)-1] != 0x1603 {
		t.Errorf("the crafted payload ends with the extension %#04x, and the finding F-22-2 records 0x1603",
			got.Extensions[len(got.Extensions)-1])
	}
}

func TestF22_3_ParseServerHelloReadsPastTheRecordLengthIntoTheNextRecord(t *testing.T) {
	// `ParseServerHello` holds the same shape at `internal/parser/tls.go:175` and
	// `internal/parser/tls.go:223`.
	hello := parser.BuildServerHello(0x0303, 0x1301, []parser.TLSExtension{
		parser.MakeSupportedVersionsServerExtension(0x0304),
	})
	second := auditParserClientHello(t, []parser.TLSExtension{parser.MakeALPNExtension("h2")})

	payload := make([]byte, 0, len(hello)+len(second))
	payload = append(payload, hello...)
	payload = append(payload, second...)

	honest, err := parser.ParseServerHello(payload)
	if err != nil {
		t.Fatalf("the honest payload: %v", err)
	}

	// The ServerHello holds no cipher suite list and no compression method list, so its
	// extensions length field sits closer to the start than the ClientHello's.
	const extensionsLengthOffset = 5 + 4 + 2 + 32 + 1 + 2 + 1

	crafted := make([]byte, len(payload))
	copy(crafted, payload)

	grown := int(crafted[extensionsLengthOffset])<<8 | int(crafted[extensionsLengthOffset+1])
	grown += len(second)
	crafted[extensionsLengthOffset] = byte(grown >> 8)
	crafted[extensionsLengthOffset+1] = byte(grown)

	got, err := parser.ParseServerHello(crafted)
	if err != nil {
		t.Fatalf("the crafted payload: %v", err)
	}

	if len(got.Extensions) <= len(honest.Extensions) {
		t.Errorf("the crafted payload produces the extensions %v, and the finding F-22-3 records a longer list",
			got.Extensions)
	}
}

func TestF22_4_IsSSHPacketDeclinesAPacketWhoseLengthLowByteIsBelowThePaddingLength(t *testing.T) {
	// `internal/parser/ssh.go:40` compares the padding length against `byte(packetLength)`.
	// The conversion keeps the low 8 bits of a 32-bit length, so every packet length whose
	// low byte is at or below the padding length fails the comparison.
	declined := []uint32{256, 260, 264, 512, 1024}
	accepted := []uint32{300, 1035}

	for _, length := range declined {
		if parser.IsSSHPacket(auditParserSSHPacket(length, 8, 20)) {
			t.Errorf("IsSSHPacket accepts the packet length %d, and the finding F-22-4 records a decline",
				length)
		}
	}

	for _, length := range accepted {
		if !parser.IsSSHPacket(auditParserSSHPacket(length, 8, 20)) {
			t.Errorf("IsSSHPacket declines the packet length %d, and the low byte is above the padding length",
				length)
		}
	}
}

func TestF22_5_ParseSSHPacketDeclinesAPacketWhoseLengthLowByteIsBelowThePaddingLength(t *testing.T) {
	// `internal/parser/ssh.go:79` holds the same comparison, so the KEXINIT of a connection
	// whose packet length ends in a low byte at or below the padding length reaches no
	// fingerprinter.
	if parser.ParseSSHPacket(auditParserSSHPacket(1024, 8, 20)) != nil {
		t.Errorf("ParseSSHPacket accepts the packet length 1024, and the finding F-22-5 records a decline")
	}

	info := parser.ParseSSHPacket(auditParserSSHPacket(1035, 8, 20))
	if info == nil || info.Type != "kexinit" {
		t.Errorf("ParseSSHPacket declines the packet length 1035, and the low byte is above the padding length")
	}
}

// auditParserSSHPacket builds an SSH binary packet header with the length, the padding
// length and the message type the caller names.
func auditParserSSHPacket(length uint32, padding byte, messageType byte) []byte {
	packet := make([]byte, 64)
	binary.BigEndian.PutUint32(packet[:4], length)
	packet[4] = padding
	packet[5] = messageType

	return packet
}

func TestF22_6_OIDToHexTruncatesTheFirstTwoArcsIntoOneByte(t *testing.T) {
	// `internal/parser/x509_utils.go:36` writes `byte(nums[0]*40 + nums[1])`. X.690 encodes
	// that sum as a variable-length quantity, so a sum at or above 128 needs more than one
	// byte. `encoding/asn1` of the standard library is the reference here, because it
	// encodes the same identifier.
	cases := []struct {
		text    string
		oid     asn1.ObjectIdentifier
		library string
	}{
		{"2.5.4.3", asn1.ObjectIdentifier{2, 5, 4, 3}, "550403"},
		{"2.100.3", asn1.ObjectIdentifier{2, 100, 3}, "b403"},
		{"2.999.1", asn1.ObjectIdentifier{2, 999, 1}, "3701"},
	}

	for _, testCase := range cases {
		der, err := asn1.Marshal(testCase.oid)
		if err != nil {
			t.Fatalf("asn1.Marshal(%v): %v", testCase.oid, err)
		}

		// The first two bytes hold the tag and the length of these short identifiers.
		wanted := hex.EncodeToString(der[2:])
		got := parser.OIDToHex(testCase.text)

		if got != testCase.library {
			t.Errorf("OIDToHex(%q) = %q, and the finding F-22-6 records %q",
				testCase.text, got, testCase.library)
		}

		if testCase.text == "2.5.4.3" && got != wanted {
			t.Errorf("OIDToHex(%q) = %q, and X.690 encodes it as %q", testCase.text, got, wanted)
		}
	}

	// The truncation makes two identifiers collide, so one certificate reaches the JA4X
	// value of another. X.690 encodes `2.999.1` as `883701` and `0.55.1` as `370101`.
	if parser.OIDToHex("2.999.1") != parser.OIDToHex("0.55")+"01" {
		t.Errorf("OIDToHex(%q) = %q and OIDToHex(%q) = %q, and the finding F-22-6 records a collision",
			"2.999.1", parser.OIDToHex("2.999.1"), "0.55", parser.OIDToHex("0.55"))
	}
}

func TestF22_7_AddSegmentPanicsWhenTheStreamLimitIsZero(t *testing.T) {
	// `internal/parser/tcp_stream.go:42` indexes `r.order[0]` after a comparison that a
	// limit of zero makes true on the first segment, and `r.order` holds nothing yet.
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Errorf("AddSegment reaches no panic, and the finding F-22-7 records one")
			return
		}

		if !strings.Contains(strings.ToLower(auditParserText(recovered)), "index out of range") {
			t.Errorf("AddSegment panics with %v, and the finding F-22-7 records an index out of range",
				recovered)
		}
	}()

	reassembler := parser.NewTCPStreamReassembler(0, 4096)
	reassembler.AddSegment("one", 1, []byte("hello"))
}

func TestF22_8_GetStreamPanicsWhenTheByteLimitIsBelowZero(t *testing.T) {
	// `internal/parser/tcp_stream.go:93` slices `result[:r.MaxBytes]` after a comparison
	// that a limit below zero makes true for every non-empty result.
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Errorf("GetStream reaches no panic, and the finding F-22-8 records one")
			return
		}

		if !strings.Contains(strings.ToLower(auditParserText(recovered)), "slice bounds out of range") {
			t.Errorf("GetStream panics with %v, and the finding F-22-8 records a slice bound out of range",
				recovered)
		}
	}()

	reassembler := parser.NewTCPStreamReassembler(10, -1)
	reassembler.AddSegment("one", 1, []byte("hello"))
	reassembler.GetStream("one")
}

// auditParserText returns the text of a recovered panic value.
func auditParserText(recovered any) string {
	if err, ok := recovered.(error); ok {
		return err.Error()
	}

	if text, ok := recovered.(string); ok {
		return text
	}

	return ""
}

func TestF22_9_ParseCryptoFramesReturnsTheFragmentsItHoldsWithTheTruncationError(t *testing.T) {
	// `internal/parser/quic.go:553` returns the collected fragments beside the error.
	// `internal/parser/quic.go:337` and `internal/parser/quic.go:803` then answer
	// `return nil, err`, so a complete client hello in an earlier frame reaches no
	// fingerprinter. Issue #42 owns the repair under FR-gaps-21.
	//
	// The frame below carries a one-byte CRYPTO frame at offset 0 and a second CRYPTO
	// frame whose length field names more bytes than the payload holds.
	payload := []byte{
		0x06, 0x00, 0x01, 0x01, // CRYPTO, offset 0, length 1, one byte of data
		0x06, 0x01, 0x08, 0x02, // CRYPTO, offset 1, length 8, one byte of data
	}

	fragments, err := parser.ParseCryptoFrames(payload)
	if err == nil {
		t.Fatalf("ParseCryptoFrames reaches no error, and the payload holds a truncated frame")
	}

	if len(fragments) != 1 {
		t.Fatalf("ParseCryptoFrames returns %d fragments, and the finding F-22-9 records one",
			len(fragments))
	}

	if fragments[0].Offset != 0 || len(fragments[0].Data) != 1 {
		t.Errorf("ParseCryptoFrames returns the fragment %+v, and the payload holds one byte at offset 0",
			fragments[0])
	}
}

func TestF22_11_TheRawJA4KeepsAGreaseSignatureAlgorithm(t *testing.T) {
	// `docs/specs/foxio/JA4.md` R31 states that the signature algorithm list skips a GREASE
	// value. `ja4.go:181` writes the list with no filter, so the raw JA4 holds it.
	hello := auditParserGreaseClientHello(t)

	raw := computeJA4RawFromClientHello(hello)
	if !strings.Contains(raw, "0a0a") {
		t.Errorf("the raw JA4 %q holds no GREASE signature algorithm, and the finding F-22-11 records one",
			raw)
	}
}

func TestF22_12_TheJA4ExtensionHashKeepsAGreaseSignatureAlgorithm(t *testing.T) {
	// `ja4.go:266` writes the same unfiltered list into the hashed string, so the third
	// part of the JA4 differs from the FoxIO value that R31 states.
	withGrease := ja4ExtensionHash(auditParserGreaseClientHello(t))
	withoutGrease := ja4ExtensionHash(auditParserPlainClientHello(t))

	if withGrease == withoutGrease {
		t.Errorf("the two hashes both read %q, and the finding F-22-12 records a difference",
			withGrease)
	}
}

func TestF22_13_TheWireOrderRawJA4KeepsAGreaseSignatureAlgorithm(t *testing.T) {
	// `ja4.go:288` writes the same unfiltered list into the wire-order raw JA4.
	raw := computeJA4RawOriginalOrder(auditParserGreaseClientHello(t))
	if !strings.Contains(raw, "0a0a") {
		t.Errorf("the wire-order raw JA4 %q holds no GREASE signature algorithm, and the finding F-22-13 records one",
			raw)
	}
}

// auditParserGreaseClientHello returns a ClientHello whose signature algorithm list opens
// with a GREASE value.
func auditParserGreaseClientHello(t *testing.T) *parser.ClientHello {
	t.Helper()

	payload := auditParserClientHello(t, []parser.TLSExtension{
		parser.MakeSignatureAlgorithmsExtension(auditParserGreaseSigAlg, 0x0403, 0x0804),
	})

	hello, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the GREASE ClientHello: %v", err)
	}

	if len(hello.SignatureAlgorithms) != 3 || hello.SignatureAlgorithms[0] != auditParserGreaseSigAlg {
		t.Fatalf("the GREASE ClientHello holds the signature algorithms %v", hello.SignatureAlgorithms)
	}

	return hello
}

// auditParserPlainClientHello returns the same ClientHello with no GREASE signature
// algorithm.
func auditParserPlainClientHello(t *testing.T) *parser.ClientHello {
	t.Helper()

	payload := auditParserClientHello(t, []parser.TLSExtension{
		parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804),
	})

	hello, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the plain ClientHello: %v", err)
	}

	return hello
}

func TestF22_14_TheQUICHeaderGuardsDeclineAnUnreadableDatagramWithNoError(t *testing.T) {
	// The thirteen `nilerr` sites of `internal/parser/quic.go` are correct as written, and
	// the report records them as `no change needed`. The port collapses "not QUIC" and
	// "QUIC but unreadable" onto one return, and this test holds that shape so that a
	// later change cannot move it without a failing test.
	//
	// The datagram below is a QUIC version 1 long header whose token length varint runs
	// past the end of the datagram.
	datagram := []byte{
		0xc0,                   // long header, Initial, version 1
		0x00, 0x00, 0x00, 0x01, // version 1
		0x00, // DCID length 0
		0x00, // SCID length 0
		0x7f, // token length varint, prefix 1, and the second byte is absent
	}

	hello, err := parser.ParseQUICInitial(datagram)
	if err != nil {
		t.Errorf("ParseQUICInitial returns the error %v, and the record holds a decline with no error", err)
	}

	if hello != nil {
		t.Errorf("ParseQUICInitial returns the ClientHello %+v, and the datagram holds none", hello)
	}
}
