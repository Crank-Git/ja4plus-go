package ja4plus

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestComputeJA4FromClientHello_TLS13(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c},
		Extensions: []uint16{
			parser.ExtSNI,                 // 0x0000
			parser.ExtALPN,                // 0x0010
			parser.ExtSupportedVersions,   // 0x002b
			parser.ExtSignatureAlgorithms, // 0x000d
			0x0017,                        // extended_master_secret
		},
		SNI:                 "example.com",
		HasSNI:              true,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}

	fp := computeJA4FromClientHello(ch)

	// Format: {proto}{ver}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}

	partA := parts[0]
	// proto=t, ver=13 (from supported_versions max), sni=d, ciphers=04, exts=05, alpn=h2
	if partA != "t13d0405h2" {
		t.Errorf("part_a = %q, want %q", partA, "t13d0405h2")
	}

	// Cipher hash and ext hash should be 12 hex chars
	if len(parts[1]) != 12 {
		t.Errorf("cipher hash length = %d, want 12", len(parts[1]))
	}
	if len(parts[2]) != 12 {
		t.Errorf("ext hash length = %d, want 12", len(parts[2]))
	}
}

func TestComputeJA4_GREASEFiltering(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x0A0A, 0x1301, 0x2A2A, 0x1302},
		Extensions: []uint16{
			0x3A3A,                      // GREASE
			parser.ExtSNI,               // 0x0000
			0x4A4A,                      // GREASE
			parser.ExtSupportedVersions, // 0x002b
		},
		HasSNI:            true,
		SNI:               "test.com",
		SupportedVersions: []uint16{0x7A7A, 0x0304, 0x0303}, // GREASE + real versions
	}

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	partA := parts[0]

	// proto=t, ver=13 (0x0304, ignoring GREASE 0x7A7A), sni=d
	// ciphers: 2 non-GREASE (0x1301, 0x1302)
	// extensions: 2 non-GREASE (0x0000, 0x002b)
	// alpn: "00" (no ALPN)
	if partA != "t13d020200" {
		t.Errorf("part_a = %q, want %q", partA, "t13d020200")
	}
}

func TestJA4_EmptyCiphers(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{},
		Extensions:   []uint16{parser.ExtSNI},
		HasSNI:       true,
		SNI:          "x.com",
	}

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	if parts[1] != "000000000000" {
		t.Errorf("cipher hash = %q, want %q", parts[1], "000000000000")
	}
}

// TestJA4WritesTheMeasuredValueForEachPR277Example holds the eight example inputs of FoxIO
// PR #277 at the unit level, and it asserts the measured value of each one.
//
// The prose of the pull request states the first and last character of the hexadecimal
// form of the whole first ALPN value. Issue #50 withdrew that rule, because no FoxIO
// implementation produces it and the FoxIO vector `tls-non-ascii-alpn.pcapng` contradicts
// it. `internal/parser/tls.go` states the rule the library follows, and
// `docs/specs/foxio/JA4.md` R18, R19 and Reading 5 record the evidence.
//
// `ja4_test.go` holds FR-parity-8, FR-parity-9 and FR-parity-10 at the packet
// level. This test reads `ALPNValue` directly, so it separates the rule from the parser.
func TestJA4WritesTheMeasuredValueForEachPR277Example(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		// Empty / single-alnum baselines.
		{"empty", []string{}, "00"},
		{"empty-string", []string{""}, "00"},
		{"single-alnum-byte", []string{"h"}, "hh"},
		{"two-alnum-bytes", []string{"h2"}, "h2"},
		{"http/1.1-alnum-ends", []string{"http/1.1"}, "h1"},

		// The eight FoxIO PR #277 examples. The prose value of the pull request follows each
		// row in a comment. The ruling of #801 on 2026-10-01 UTC moved three rows: `0x20`,
		// `0x30 0xAB` and `0x30 0x31 0xAB 0xCD`. The other rows hold the value the port measured.
		{"0xAB", []string{"\xab"}, "99"},                            // the prose states `ab`
		{"0x20", []string{"\x20"}, "\x20\x20"},                      // the prose states `20`
		{"0xAB 0xCD", []string{"\xab\xcd"}, "99"},                   // the prose states `ad`
		{"0x20 0x61", []string{"\x20\x61"}, "\x20a"},                // the prose states `21`
		{"0x30 0xAB", []string{"\x30\xab"}, "09"},                   // the prose states `3b`
		{"0x61 0x20", []string{"\x61\x20"}, "a\x20"},                // the prose states `60`
		{"0x30 0x31 0xAB 0xCD", []string{"\x30\x31\xab\xcd"}, "09"}, // the prose states `3d`
		{"0x30 0xAB 0xCD 0x31", []string{"\x30\xab\xcd\x31"}, "01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.ALPNValue(tt.in)
			if got != tt.want {
				t.Errorf("ALPNValue(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestJA4_EmptyExtensionHash verifies FoxIO PR #288 spec: when the post-GREASE
// extension list is empty (and there are no signature algorithms either), the
// extension-hash component is the literal "000000000000", not sha256("")[:12].
func TestJA4_EmptyExtensionHash(t *testing.T) {
	// All extensions are GREASE -> filtered list is empty.
	// SNI/ALPN exclusion would also remove them, but here we confirm the
	// empty-after-filter case.
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions: []uint16{
			0x0A0A, // GREASE
			0x1A1A, // GREASE
		},
	}

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}
	if parts[2] != "000000000000" {
		t.Errorf("extension hash = %q, want %q (empty list -> literal zeros)", parts[2], "000000000000")
	}
}

func TestJA4_NoALPN(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		HasSNI:       true,
		SNI:          "x.com",
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// ALPN should be "00"
	if !strings.HasSuffix(partA, "00") {
		t.Errorf("part_a = %q, should end with 00 for no ALPN", partA)
	}
}

func TestJA4_ALPNSingleChar(t *testing.T) {
	ch := &parser.ClientHello{
		Version:       0x0303,
		CipherSuites:  []uint16{0x002f},
		ALPNProtocols: []string{"x"},
		HasSNI:        true,
		SNI:           "d.com",
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// Single char "x" should be doubled to "xx"
	if !strings.HasSuffix(partA, "xx") {
		t.Errorf("part_a = %q, should end with xx for single-char ALPN", partA)
	}
}

func TestJA4_ExtensionHash_SNIAndALPNExcluded(t *testing.T) {
	// With sig algs, the ext hash string is: sorted_exts_sigalgs
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		Extensions: []uint16{
			parser.ExtSNI,                 // should be excluded from hash
			parser.ExtALPN,                // should be excluded from hash
			0x0017,                        // should be included
			parser.ExtSignatureAlgorithms, // should be included
		},
		HasSNI:              true,
		SNI:                 "x.com",
		ALPNProtocols:       []string{"h2"},
		SignatureAlgorithms: []uint16{0x0804, 0x0403}, // original order preserved
	}

	// Compute manually what the hash should be:
	// Filtered exts (no SNI, no ALPN): 0x0017, 0x000d
	// Sorted: 0x000d, 0x0017
	// Ext string: "000d,0017"
	// Sig algs in original order: "0804,0403"
	// Combined: "000d,0017_0804,0403"
	expectedInput := "000d,0017_0804,0403"
	expectedHash := parser.TruncatedHash(expectedInput)

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	if parts[2] != expectedHash {
		t.Errorf("ext hash = %q, want %q (from input %q)", parts[2], expectedHash, expectedInput)
	}
}

func TestJA4_VersionFromSupportedVersions(t *testing.T) {
	ch := &parser.ClientHello{
		Version:           0x0301, // TLS 1.0 in handshake
		CipherSuites:      []uint16{0x002f},
		SupportedVersions: []uint16{0x0303, 0x0304}, // TLS 1.2, TLS 1.3
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// Should use max supported version = 0x0304 = "13"
	if !strings.HasPrefix(partA, "t13") {
		t.Errorf("part_a = %q, should start with t13 (version from supported_versions)", partA)
	}
}

func TestJA4_RawFingerprint(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1302, 0x1301},
		Extensions: []uint16{
			parser.ExtSNI,
			parser.ExtALPN,
			0x0017,
			parser.ExtSignatureAlgorithms,
		},
		HasSNI:              true,
		SNI:                 "test.com",
		ALPNProtocols:       []string{"h2"},
		SignatureAlgorithms: []uint16{0x0403},
	}

	raw := computeJA4RawFromClientHello(ch)
	parts := strings.Split(raw, "_")
	// Should have 4 parts: partA, sorted ciphers, sorted exts (no SNI/ALPN), sig algs
	if len(parts) != 4 {
		t.Fatalf("raw parts = %d, want 4: %s", len(parts), raw)
	}

	// Ciphers sorted: 0x1301, 0x1302
	if parts[1] != "1301,1302" {
		t.Errorf("raw ciphers = %q, want %q", parts[1], "1301,1302")
	}

	// Extensions (no SNI/ALPN), sorted: 0x000d, 0x0017
	if parts[2] != "000d,0017" {
		t.Errorf("raw exts = %q, want %q", parts[2], "000d,0017")
	}

	// Sig algs in original order
	if parts[3] != "0403" {
		t.Errorf("raw sig algs = %q, want %q", parts[3], "0403")
	}
}

func TestAlpnValue(t *testing.T) {
	tests := []struct {
		name      string
		protocols []string
		want      string
	}{
		{"empty", nil, "00"},
		{"h2", []string{"h2"}, "h2"},
		{"http/1.1", []string{"http/1.1"}, "h1"},
		{"single char", []string{"x"}, "xx"},
		{"empty first", []string{""}, "00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.ALPNValue(tt.protocols)
			if got != tt.want {
				t.Errorf("ALPNValue(%v) = %q, want %q", tt.protocols, got, tt.want)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0200, "s2"},
		{0xfeff, "d1"},
		{0xfefd, "d2"},
		{0xfefc, "d3"},
		{0x0000, "00"},
		{0x1234, "00"},
	}
	for _, tt := range tests {
		got := parser.TLSVersionString(tt.version)
		if got != tt.want {
			t.Errorf("TLSVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestJA4_FullIntegration(t *testing.T) {
	// Build a real ClientHello packet as bytes and verify end-to-end
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	exts := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),
		parser.MakeALPNExtension("h2", "http/1.1"),
		parser.MakeSupportedVersionsClientExtension(0x0304, 0x0303),
		parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804, 0x0401),
	}
	payload := parser.BuildClientHello(0x0303, ciphers, exts)

	ch, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	fp := computeJA4FromClientHello(ch)

	// Verify format: proto(1) + ver(2) + sni(1) + ciphers(2) + exts(2) + alpn(2) = 10 chars
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("fingerprint parts = %d, want 3", len(parts))
	}
	if len(parts[0]) != 10 {
		t.Errorf("part_a length = %d, want 10: %q", len(parts[0]), parts[0])
	}

	// Expected part_a: t13d0304h2
	// proto=t, ver=13, sni=d, ciphers=03, exts=04, alpn=h2
	if parts[0] != "t13d0304h2" {
		t.Errorf("part_a = %q, want %q", parts[0], "t13d0304h2")
	}
}

func TestJA4_NoSNI(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// SNI char should be 'i'
	if partA[3] != 'i' {
		t.Errorf("SNI char = %c, want 'i'", partA[3])
	}
}

func TestJA4_HasSNIMalformed(t *testing.T) {
	ch := &parser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		HasSNI:       true,
		SNI:          "", // malformed but present
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// SNI char should be 'd' because HasSNI is true
	if partA[3] != 'd' {
		t.Errorf("SNI char = %c, want 'd' for HasSNI=true", partA[3])
	}
}

func TestJA4_RawOriginalOrder(t *testing.T) {
	// Build a TLS ClientHello with extensions in a specific wire order.
	// The ciphers are intentionally unsorted so Raw (sorted) differs from RawOriginalOrder.
	ciphers := []uint16{0x1303, 0x1301, 0x1302}
	exts := []parser.TLSExtension{
		parser.MakeSNIExtension("example.com"),                      // 0x0000
		parser.MakeALPNExtension("h2", "http/1.1"),                  // 0x0010
		parser.MakeSupportedVersionsClientExtension(0x0304, 0x0303), // 0x002b
		parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804),     // 0x000d
		{Typ: 0x0017, Data: []byte{}},                               // extended_master_secret
	}
	tlsPayload := parser.BuildClientHello(0x0303, ciphers, exts)

	// Build a gopacket with IPv4+TCP carrying the ClientHello payload.
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
		SYN:     false,
		ACK:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(tlsPayload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	fp := NewJA4()
	results, err := fp.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("ProcessPacket error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result from ProcessPacket")
	}

	result := results[0]

	if result.RawOriginalOrder == "" {
		t.Fatal("RawOriginalOrder is empty")
	}
	if result.Raw == "" {
		t.Fatal("Raw is empty")
	}
	if result.RawOriginalOrder == result.Raw {
		t.Errorf("RawOriginalOrder should differ from Raw (sorted vs wire order)\nRaw:              %s\nRawOriginalOrder: %s", result.Raw, result.RawOriginalOrder)
	}

	// RawOriginalOrder preserves SNI (0000) and ALPN (0010) in extension list
	if !strings.Contains(result.RawOriginalOrder, "0000") {
		t.Errorf("RawOriginalOrder should contain SNI extension code 0000: %s", result.RawOriginalOrder)
	}
	if !strings.Contains(result.RawOriginalOrder, "0010") {
		t.Errorf("RawOriginalOrder should contain ALPN extension code 0010: %s", result.RawOriginalOrder)
	}

	// Raw (sorted variant) excludes SNI and ALPN from extension hash section.
	// Raw format: partA_sortedCiphers_sortedExts[_sigAlgs]
	// The extension part (parts[2]) should NOT contain 0000 or 0010.
	rawParts := strings.Split(result.Raw, "_")
	if len(rawParts) < 3 {
		t.Fatalf("Raw has fewer than 3 parts: %s", result.Raw)
	}
	rawExtSection := rawParts[2]
	if strings.Contains(rawExtSection, "0000") {
		t.Errorf("Raw extension section should not contain SNI (0000): %s", rawExtSection)
	}
	if strings.Contains(rawExtSection, "0010") {
		t.Errorf("Raw extension section should not contain ALPN (0010): %s", rawExtSection)
	}
}

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
// a one-byte printable value writes its byte twice. `ja4_test.go` holds the
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

// These tests hold the maintainer ruling of 2026-10-01 UTC on the ALPN characters of JA4
// part a and JA4S part a. Issue #801 holds the ruling and is the reversal path, and
// `Crank-Git/ja4plus#789` holds the port half. A reader who reverses a value below reverses
// it in `Crank-Git/ja4plus` as well.
//
// The ruling follows FoxIO Python and Rust at `16b96d95`. `python/ja4.py:156-157` and
// `rust/ja4/src/tls.rs:635-647` each write `9` for a non-ASCII end. `python/ja4.py:149-158`
// and `zeek/src/ja4.cc:76-81` each write a one-character value twice. The ruling departs
// from Wireshark, which writes `99` at `wireshark/source/packet-ja4.c:1027-1028`, from Zeek,
// which writes the raw byte of a non-ASCII end, and from Rust, which writes `0` for an
// absent last character at `rust/ja4/src/tls.rs:352-353`.

// alpnRulingCases holds one case for each row of the phase 1 table of #801, the empty
// value, and the control-byte cases. The same cases reach JA4 and JA4S, because the ruling
// names both.
var alpnRulingCases = []struct {
	name string
	alpn string
	want string
}{
	{"one alphanumeric byte 68", "\x68", "hh"},
	{"one printable byte 2d that is not alphanumeric", "\x2d", "--"},
	{"a last byte ff of 0x80 or higher", "\x68\xff", "h9"},
	{"a first byte ff of 0x80 or higher", "\xff\x68", "9h"},
	{"the FoxIO vector value ba ad", "\xba\xad", "99"},
	{"an empty first ALPN value", "", "00"},
	// The maintainer confirmed the control-byte case on 2026-10-01 UTC, under #801. An end
	// byte below 0x20, or the byte 0x7F, makes the whole field `99`.
	{"a first byte 01 below 0x20", "\x01\x68", "99"},
	{"a last byte 1f below 0x20", "\x68\x1f", "99"},
	{"a last byte 7f", "\x68\x7f", "99"},
	{"one control byte 00", "\x00", "99"},
}

func TestTheJA4ALPNCharactersFollowTheRulingOf801(t *testing.T) {
	for _, testCase := range alpnRulingCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != testCase.want {
				t.Errorf("the JA4 ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}

func TestTheJA4SALPNCharactersFollowTheRulingOf801(t *testing.T) {
	for _, testCase := range alpnRulingCases {
		t.Run(testCase.name, func(t *testing.T) {
			extensions := []parser.TLSExtension{
				parser.MakeALPNExtension(testCase.alpn),
				parser.MakeSupportedVersionsServerExtension(0x0304),
			}
			payload := parser.BuildServerHello(0x0303, 0x1301, extensions)

			results, err := NewJA4S().ProcessPacket(buildTCPPayloadPacket(t, payload))
			if err != nil {
				t.Fatalf("ProcessPacket returned %v", err)
			}
			if len(results) == 0 {
				t.Fatal("ProcessPacket returned no result")
			}
			partA := strings.Split(results[0].Fingerprint, "_")[0]

			got := alpnParityCharacters(t, partA)
			if got != testCase.want {
				t.Errorf("the JA4S ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}

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
// `testdata/foxio/reference/python/ja4.py:282` builds `JA4_o` from the same part a as
// `JA4`, from a hash of the wire-order cipher list, and from a hash of the wire-order
// extension list. `testdata/foxio/reference/python/common.py:144` keeps SNI and ALPN in
// that list, because it removes the two only when it sorts.
// `testdata/foxio/reference/python/ja4.py:248` appends the signature algorithms to the
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
// `testdata/foxio/reference/python/ja4.py:282` and
// `testdata/foxio/reference/python/ja4.py:284` build `JA4_o` and `JA4_ro` from the same two
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
// `testdata/foxio/reference/python/ja4.py:282` writes the one key, and `conformance_test.go`
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

// The tests of this file hold #795: JA4 reads a TLS ClientHello that spans more than one
// TCP segment. Each case ports a case of `tests/test_ja4_tcp_client_hello_reassembly.py` of
// the port at tag `v1.3.0`. Crank-Git/ja4plus#772 records the defect in the port, and
// Crank-Git/ja4plus#784 holds the repair and the four bounds.

// The FoxIO values of `sigalg-grease.pcapng`, verbatim from
// `testdata/foxio/python/sigalg-grease.pcapng.json` at FoxIO commit `16b96d95`.
const (
	sigalgGreaseJA4   = "t13d1517h2_8daaf6152771_cb7bf5808d99"
	sigalgGreaseJA4o  = "t13d1517h2_acb858a92679_88bf22a3e888"
	sigalgGreaseJA4r  = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
	sigalgGreaseJA4ro = "t13d1517h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_fe0d,0010,0017,0033,44cd,ff01,000a,000d,0023,002b,000b,ca34,002d,0000,0005,001b,0012_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
)

var (
	tcpHelloClientIP = net.IP{192, 168, 0, 1}
	tcpHelloServerIP = net.IP{10, 10, 10, 1}
)

const (
	tcpHelloClientPort = 56544
	tcpHelloServerPort = 443
	tcpHelloFirstSeq   = 1230333283
)

// tcpHelloSegment holds the fields of one constructed TCP segment.
type tcpHelloSegment struct {
	payload  []byte
	seq      uint32
	srcPort  uint16
	fin      bool
	rst      bool
	ack      bool
	toClient bool
	at       time.Time
}

// build returns the segment as a packet. A zero port names the client port.
func (s tcpHelloSegment) build(t testing.TB) gopacket.Packet {
	t.Helper()

	clientPort := s.srcPort
	if clientPort == 0 {
		clientPort = tcpHelloClientPort
	}

	src, dst := tcpHelloClientIP, tcpHelloServerIP
	srcPort, dstPort := clientPort, uint16(tcpHelloServerPort)

	if s.toClient {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}

	ip := &layers.IPv4{SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP, Version: 4, TTL: 64}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     s.seq,
		ACK:     s.ack || (!s.fin && !s.rst),
		PSH:     len(s.payload) > 0,
		FIN:     s.fin,
		RST:     s.rst,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(s.payload)); err != nil {
		t.Fatalf("the segment does not serialize: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = s.at

	return packet
}

// tcpHelloLongClientHello returns one ClientHello record of more than 2000 bytes. A
// padding extension makes it long, as a post-quantum key share makes the hello of a
// current browser long.
func tcpHelloLongClientHello() []byte {
	return parser.BuildClientHello(0x0303, []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		[]parser.TLSExtension{
			parser.MakeSNIExtension("example.com"),
			parser.MakeALPNExtension("h2", "http/1.1"),
			parser.MakeSupportedVersionsClientExtension(0x0304, 0x0303),
			parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804, 0x0401),
			{Typ: 0x0015, Data: make([]byte, 1900)},
		})
}

// tcpHelloCut returns the segments that cut the bytes at each offset, in stream order.
func tcpHelloCut(data []byte, seq uint32, offsets ...int) []tcpHelloSegment {
	bounds := append(append([]int{0}, offsets...), len(data))

	segments := make([]tcpHelloSegment, 0, len(bounds)-1)
	for i := 0; i+1 < len(bounds); i++ {
		segments = append(segments, tcpHelloSegment{
			payload: data[bounds[i]:bounds[i+1]],
			seq:     seq + uint32(bounds[i]),
		})
	}

	return segments
}

// tcpHelloFeed returns the JA4 value of each segment, in the order the fingerprinter read
// them. An empty string names a segment that gave no value.
func tcpHelloFeed(t *testing.T, fingerprinter *JA4Fingerprinter, segments []tcpHelloSegment) []string {
	t.Helper()

	values := make([]string, 0, len(segments))

	for _, segment := range segments {
		results, _ := fingerprinter.ProcessPacket(segment.build(t))

		switch len(results) {
		case 0:
			values = append(values, "")
		case 1:
			values = append(values, results[0].Fingerprint)
		default:
			t.Fatalf("one segment gave %d results", len(results))
		}
	}

	return values
}

// tcpHelloWholeValue returns the JA4 value that one segment of the whole hello gives.
func tcpHelloWholeValue(t *testing.T, hello []byte) string {
	t.Helper()

	results, err := NewJA4().ProcessPacket(tcpHelloSegment{payload: hello, seq: tcpHelloFirstSeq}.build(t))
	if err != nil || len(results) != 1 || results[0].Fingerprint == "" {
		t.Fatalf("one segment of the whole hello gives (%v, %v), want one value", results, err)
	}

	return results[0].Fingerprint
}

func tcpHelloAssertValues(t *testing.T, got []string, want ...string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("the segments gave %q, want %q", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the segments gave %q, want %q", got, want)
		}
	}
}

func tcpHelloAssertHeld(t *testing.T, fingerprinter *JA4Fingerprinter, want int) {
	t.Helper()

	if got := len(fingerprinter.tcpHellos); got != want {
		t.Errorf("the fingerprinter holds %d partial hellos, want %d", got, want)
	}

	if got := fingerprinter.tcpHelloKeys.count(); got != want {
		t.Errorf("the recency order names %d partial hellos, want %d", got, want)
	}
}

// TestJA4ReadsTheClientHelloThatFrame4AndFrame5OfSigalgGreasePcapng holds the FoxIO
// vector, and it skips when the corpus is absent. The ClientHello record is 2034 bytes.
// Frame 4 carries 1400 bytes of it, and frame 5 carries 639 bytes.
func TestJA4ReadsTheClientHelloThatFrame4AndFrame5OfSigalgGreasePcapng(t *testing.T) {
	packets := loadPCAP(t, filepath.Join("testdata", "foxio", "pcap", "sigalg-grease.pcapng"))

	fingerprinter := NewJA4()

	var produced []FingerprintResult

	for _, packet := range packets {
		results, _ := fingerprinter.ProcessPacket(packet)
		produced = append(produced, results...)
	}

	if len(produced) != 1 {
		t.Fatalf("the capture gives %d JA4 values, want one", len(produced))
	}

	result := produced[0]
	if result.Fingerprint != sigalgGreaseJA4 || result.OriginalOrder != sigalgGreaseJA4o ||
		result.Raw != sigalgGreaseJA4r || result.RawOriginalOrder != sigalgGreaseJA4ro {
		t.Errorf("the capture gives %+v, want the four FoxIO forms", result)
	}

	if result.SrcIP != "192.168.0.1" || result.SrcPort != 56544 || result.DstIP != "10.10.10.1" || result.DstPort != 443 {
		t.Errorf("the value names %s:%d -> %s:%d, want the client connection",
			result.SrcIP, result.SrcPort, result.DstIP, result.DstPort)
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsTheValueOnTheSegmentThatCompletesTwoSegments(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	fingerprinter := NewJA4()

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, tcpHelloCut(hello, tcpHelloFirstSeq, 1400)), "", want)
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsTheSameFourFormsAsOneSegmentOfTheWholeHello(t *testing.T) {
	hello := tcpHelloLongClientHello()

	whole, err := NewJA4().ProcessPacket(tcpHelloSegment{payload: hello, seq: tcpHelloFirstSeq}.build(t))
	if err != nil || len(whole) != 1 {
		t.Fatalf("one segment of the whole hello gives (%v, %v)", whole, err)
	}

	fingerprinter := NewJA4()
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)

	if _, err := fingerprinter.ProcessPacket(segments[0].build(t)); err != nil {
		t.Fatalf("the segment that opens the hello returns the error %v", err)
	}

	cut, err := fingerprinter.ProcessPacket(segments[1].build(t))
	if err != nil || len(cut) != 1 {
		t.Fatalf("the segment that completes the hello gives (%v, %v)", cut, err)
	}

	if cut[0].Fingerprint != whole[0].Fingerprint || cut[0].Raw != whole[0].Raw ||
		cut[0].OriginalOrder != whole[0].OriginalOrder || cut[0].RawOriginalOrder != whole[0].RawOriginalOrder {
		t.Errorf("two segments give %+v, and one segment gives %+v", cut[0], whole[0])
	}

	if cut[0].SrcPort != tcpHelloClientPort || cut[0].DstPort != tcpHelloServerPort ||
		cut[0].SrcIP != tcpHelloClientIP.String() || cut[0].DstIP != tcpHelloServerIP.String() {
		t.Errorf("the value names %s:%d -> %s:%d, want the client connection",
			cut[0].SrcIP, cut[0].SrcPort, cut[0].DstIP, cut[0].DstPort)
	}
}

func TestJA4EmitsTheValueOnTheSegmentThatCompletesThreeSegments(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, tcpHelloFirstSeq, 600, 1300))
	tcpHelloAssertValues(t, got, "", "", want)
}

// Seven bytes hold the record header and two of the four handshake header bytes.
func TestJA4StartsAStreamOnASegmentThatCutsTheHandshakeHeader(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, tcpHelloFirstSeq, 7))
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4EmitsOneValueWhenTheFirstSegmentArrivesTwice(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], segments[0], segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4EmitsTheValueWhenTwoSegmentsOverlap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq},
		{payload: hello[1300:], seq: tcpHelloFirstSeq + 1300},
	})
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4EmitsTheValueAcrossAWrapOfTheSequenceNumber(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, 0xFFFFFFFF-700, 1400))
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4HoldsNoStreamForAHelloThatOneSegmentHolds(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: hello, seq: tcpHelloFirstSeq}})
	tcpHelloAssertValues(t, got, want)
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsNoValueWhileASegmentIsMissing(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 600, 1300)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], segments[2]})
	tcpHelloAssertValues(t, got, "", "")
	tcpHelloAssertHeld(t, fingerprinter, 1)
}

// A gap reads as zeros nowhere. The value comes from the segment that fills the gap, so
// it equals the value of the whole hello.
func TestJA4FillsTheGapFromTheSegmentThatArrivesAndNeverFromZeros(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 600, 1300)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], segments[2], segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4EmitsNoValueWhenTheLaterSegmentArrivesFirst(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[1], segments[0]})
	tcpHelloAssertValues(t, got, "", "")
}

// A byte before the first hello byte would move the start of the stream, and the stream
// would then open with no TLS record.
func TestJA4IgnoresASegmentThatStartsBeforeTheHello(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)
	earlier := tcpHelloSegment{payload: make([]byte, 100), seq: tcpHelloFirstSeq - 100}

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], earlier, segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4HoldsNoStreamForAHelloLongerThanTheByteCap(t *testing.T) {
	declared := maxJA4TCPHelloBytes
	record := []byte{0x16, 0x03, 0x01, byte((declared - 4) >> 8), byte(declared - 4)}
	handshake := []byte{0x01, byte((declared - 8) >> 16), byte((declared - 8) >> 8), byte(declared - 8)}
	payload := append(append(record, handshake...), 0x03, 0x03)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: payload, seq: 1}})
	tcpHelloAssertValues(t, got, "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// A sender of one-byte segments reaches the segment cap long before the byte cap.
func TestJA4ReleasesAStreamThatReachesTheSegmentCap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	segments := []tcpHelloSegment{{payload: hello[:9], seq: tcpHelloFirstSeq}}

	for offset := 9; offset < 9+maxJA4TCPHelloSegments+5; offset++ {
		segments = append(segments, tcpHelloSegment{
			payload: hello[offset : offset+1],
			seq:     tcpHelloFirstSeq + uint32(offset),
		})
	}

	fingerprinter := NewJA4()

	for _, value := range tcpHelloFeed(t, fingerprinter, segments) {
		if value != "" {
			t.Fatalf("a stream of one-byte segments gave the value %q", value)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4HoldsNoMoreStreamsThanTheEntryCap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	fingerprinter := NewJA4()

	for port := 1024; port < 1024+maxJA4TCPHelloStreams+10; port++ {
		segment := tcpHelloSegment{payload: hello[:1400], seq: tcpHelloFirstSeq, srcPort: uint16(port)}
		if _, err := fingerprinter.ProcessPacket(segment.build(t)); err != nil {
			t.Fatalf("the segment of port %d returns the error %v", port, err)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, maxJA4TCPHelloStreams)
}

func TestJA4EmitsNoValueAfterTheStreamPassesTheMaximumAge(t *testing.T) {
	hello := tcpHelloLongClientHello()
	start := time.Unix(1000, 0)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq, at: start},
		{payload: hello[1400:], seq: tcpHelloFirstSeq + 1400, at: start.Add(ja4TCPHelloAge + time.Second)},
	})
	tcpHelloAssertValues(t, got, "", "")
}

func TestJA4EmitsTheValueInsideTheMaximumAge(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	start := time.Unix(1000, 0)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq, at: start},
		{payload: hello[1400:], seq: tcpHelloFirstSeq + 1400, at: start.Add(ja4TCPHelloAge - time.Second)},
	})
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4ReleasesTheStreamOnAClosingClientSegment(t *testing.T) {
	cases := []struct {
		name  string
		close tcpHelloSegment
	}{
		{"FIN and ACK", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, fin: true, ack: true}},
		{"RST", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, rst: true}},
		{"RST and ACK", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, rst: true, ack: true}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
			fingerprinter := NewJA4()

			got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], testCase.close})
			tcpHelloAssertValues(t, got, "", "")
			tcpHelloAssertHeld(t, fingerprinter, 0)

			tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, segments[1:]), "")
		})
	}
}

func TestJA4ReleasesTheClientStreamOnAServerReset(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], {seq: 1, rst: true, toClient: true}})
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The caller names the server endpoint first, so the removal reads both directions.
func TestJA4CleanupConnectionReleasesThePartialHello(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, segments[:1])
	tcpHelloAssertHeld(t, fingerprinter, 1)

	fingerprinter.CleanupConnection(tcpHelloServerIP.String(), tcpHelloServerPort,
		tcpHelloClientIP.String(), tcpHelloClientPort, "tcp")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4ResetReleasesThePartialHello(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, segments[:1])
	tcpHelloAssertHeld(t, fingerprinter, 1)

	fingerprinter.Reset()
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForAPayloadThatIsNoTLSRecord(t *testing.T) {
	fingerprinter := NewJA4()
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: request, seq: 1}}), "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForAServerHelloRecord(t *testing.T) {
	fingerprinter := NewJA4()
	cutServerHello := []byte{0x16, 0x03, 0x03, 0x04, 0xba, 0x02, 0x00, 0x04, 0xb6, 0x03, 0x03}

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: cutServerHello, seq: 1, toClient: true}})
	tcpHelloAssertValues(t, got, "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The reassembled bytes reach the reader that one segment reaches, so the two paths agree.
// The reader of this library refuses a hello that stops after the version field.
func TestJA4GivesTheResultOfOneSegmentForAShortHelloThatTwoSegmentsCarry(t *testing.T) {
	short := append([]byte{0x16, 0x03, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x06},
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff)

	alone, aloneErr := NewJA4().ProcessPacket(tcpHelloSegment{payload: short, seq: 1}.build(t))

	fingerprinter := NewJA4()
	segments := tcpHelloCut(short, 1, 9)

	if _, err := fingerprinter.ProcessPacket(segments[0].build(t)); err != nil {
		t.Fatalf("the segment that opens the hello returns the error %v", err)
	}

	cut, cutErr := fingerprinter.ProcessPacket(segments[1].build(t))

	if len(alone) != len(cut) || (aloneErr == nil) != (cutErr == nil) {
		t.Errorf("one segment gives (%v, %v), and two segments give (%v, %v)", alone, aloneErr, cut, cutErr)
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The handshake header claims 1 byte, and the reader needs 2 for the version.
func TestJA4LeavesNothingForACompletedRecordThatHoldsNoClientHello(t *testing.T) {
	truncated := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}
	fingerprinter := NewJA4()

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, tcpHelloCut(truncated, 1, 9)), "", "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForASegmentAfterTheValue(t *testing.T) {
	hello := tcpHelloLongClientHello()
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, tcpHelloCut(hello, tcpHelloFirstSeq, 1400))

	after := tcpHelloSegment{
		payload: append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, make([]byte, 32)...),
		seq:     tcpHelloFirstSeq + uint32(len(hello)),
	}
	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{after}), "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// Every length of a hostile segment is attacker input. A record header that claims the
// largest length and a handshake header that claims the largest length open no stream,
// and no segment panics.
func TestJA4ReadsHostileSegmentsWithoutAPanicOrAStream(t *testing.T) {
	payloads := [][]byte{
		{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff},
		{0x14, 0x03, 0x03, 0xff, 0xff, 0x16, 0x03, 0x01, 0x00, 0x10, 0x01},
		{0x16, 0x03},
	}

	fingerprinter := NewJA4()

	for index, payload := range payloads {
		if results, _ := fingerprinter.ProcessPacket(tcpHelloSegment{payload: payload, seq: uint32(index)}.build(t)); len(results) != 0 {
			t.Errorf("the hostile payload %x gives %v", payload, results)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The age pass can remove the stream that a segment continues, and the segment then opens
// a new stream. A payload past the byte cap leaves that stream with no segment. The batch
// #805 cross-member review found the panic that the empty stream caused. `get_stream` of
// `ja4plus/utils/tcp_stream.py` of the port at tag `v1.3.0` returns no byte for an empty
// stream, and `_add_tcp_segment` of `ja4plus/fingerprinters/ja4.py` then removes it.
func TestJA4ReleasesTheStreamWhenAnAgedHelloMeetsASegmentPastTheByteCap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	start := time.Unix(1000, 0)
	fingerprinter := NewJA4()

	segments := []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq, at: start},
		{
			payload: make([]byte, maxJA4TCPHelloBytes+1),
			seq:     tcpHelloFirstSeq + 1400,
			at:      start.Add(ja4TCPHelloAge + time.Second),
		},
	}

	for index, segment := range segments {
		results, err := fingerprinter.ProcessPacket(segment.build(t))
		if err != nil || len(results) != 0 {
			t.Fatalf("segment %d gives (%v, %v), want no result and no error", index, results, err)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// A stream that holds no segment holds no first byte. The table removes such a stream on
// the segment that made it, so this case holds the two methods against a later caller.
func TestJA4AssemblesNoByteFromAStreamThatHoldsNoSegment(t *testing.T) {
	var stream ja4TCPHello

	if data := stream.assemble(); len(data) != 0 {
		t.Errorf("an empty stream assembles %x, want no byte", data)
	}

	if _, held := stream.base(); held {
		t.Error("an empty stream reports a first sequence number")
	}
}

// A retransmission of the first segment carries the same truncated record as the first
// transmission. Both are segments of a hello that the table follows, so neither one returns
// the truncation error. The port returns no value and raises no error for both.
func TestJA4ReturnsNoErrorForARetransmittedFirstSegment(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	for index, segment := range []tcpHelloSegment{segments[0], segments[0]} {
		results, err := fingerprinter.ProcessPacket(segment.build(t))
		if err != nil || len(results) != 0 {
			t.Fatalf("transmission %d of the first segment gives (%v, %v), want no result and no error",
				index, results, err)
		}
	}

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, segments[1:]), want)
}

// The fuzz input of `FuzzJA4ReadsAnySequenceOfTCPSegments` holds a list of segment records.
// Each record opens with a header of tcpHelloFuzzHeader bytes:
//   - Bytes 0 and 1 hold a signed sequence offset from tcpHelloFuzzBaseSeq, big-endian.
//   - Byte 2 holds the seconds that the capture clock moves before the segment.
//   - Byte 3 holds the flags of tcpHelloFuzzFlag.
//   - Bytes 4 and 5 hold the payload length, big-endian, below tcpHelloFuzzMaxPayload.
//   - Bytes 6 and 7 hold the count of literal payload bytes that follow the header.
//
// Zero bytes fill the payload past the literal bytes. So a short input reaches a payload past
// the byte cap of the partial ClientHello table, and the batch #805 panic needed one.
const (
	tcpHelloFuzzHeader     = 8
	tcpHelloFuzzMaxRecords = 16
	tcpHelloFuzzMaxPayload = 1 << 15
	// The base sits below the wrap of the sequence number, so an offset reaches the wrap.
	tcpHelloFuzzBaseSeq = 0xffffc000
)

// tcpHelloFuzzFlag names one bit of byte 3 of a record header.
const (
	tcpHelloFuzzFIN      = 1 << 0
	tcpHelloFuzzRST      = 1 << 1
	tcpHelloFuzzToClient = 1 << 2
	tcpHelloFuzzPortTwo  = 1 << 3
)

// tcpHelloFuzzSegments returns the segments that the input encodes. A record that the input
// cuts ends the list.
func tcpHelloFuzzSegments(input []byte) []tcpHelloSegment {
	var segments []tcpHelloSegment

	at := time.Unix(1000, 0)

	for len(input) >= tcpHelloFuzzHeader && len(segments) < tcpHelloFuzzMaxRecords {
		offset := int16(binary.BigEndian.Uint16(input[0:2]))
		at = at.Add(time.Duration(input[2]) * time.Second)
		flags := input[3]
		length := int(binary.BigEndian.Uint16(input[4:6])) % tcpHelloFuzzMaxPayload
		literal := min(int(binary.BigEndian.Uint16(input[6:8])), len(input)-tcpHelloFuzzHeader, length)

		payload := make([]byte, length)
		copy(payload, input[tcpHelloFuzzHeader:tcpHelloFuzzHeader+literal])
		input = input[tcpHelloFuzzHeader+literal:]

		segment := tcpHelloSegment{
			payload:  payload,
			seq:      uint32(tcpHelloFuzzBaseSeq + int64(offset)),
			fin:      flags&tcpHelloFuzzFIN != 0,
			rst:      flags&tcpHelloFuzzRST != 0,
			toClient: flags&tcpHelloFuzzToClient != 0,
			at:       at,
		}
		if flags&tcpHelloFuzzPortTwo != 0 {
			segment.srcPort = tcpHelloClientPort + 1
		}

		segments = append(segments, segment)
	}

	return segments
}

// tcpHelloFuzzRecord returns one record of the fuzz input. The payload holds the literal
// bytes, and zero bytes fill it to the length.
func tcpHelloFuzzRecord(offset int16, seconds byte, flags byte, length int, literal []byte) []byte {
	record := make([]byte, tcpHelloFuzzHeader, tcpHelloFuzzHeader+len(literal))
	binary.BigEndian.PutUint16(record[0:2], uint16(offset))
	record[2] = seconds
	record[3] = flags
	binary.BigEndian.PutUint16(record[4:6], uint16(length))
	binary.BigEndian.PutUint16(record[6:8], uint16(len(literal)))

	return append(record, literal...)
}

// tcpHelloFuzzCompletedSeed returns two segments that complete one hello. The second
// segment emits the value.
func tcpHelloFuzzCompletedSeed() []byte {
	hello := tcpHelloLongClientHello()

	return append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(1400, 1, 0, len(hello)-1400, hello[1400:])...)
}

// tcpHelloFuzzAgedSeed returns the sequence of the batch #805 panic. The stream ages, and
// the next segment passes the byte cap.
func tcpHelloFuzzAgedSeed() []byte {
	hello := tcpHelloLongClientHello()

	return append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(1400, byte(ja4TCPHelloAge/time.Second)+1, 0, maxJA4TCPHelloBytes+1, nil)...)
}

// FuzzJA4ReadsAnySequenceOfTCPSegments proves that `JA4Fingerprinter.ProcessPacket` returns
// for any sequence of TCP segments. The partial ClientHello table holds state across
// packets, so a target that reads one frame never reaches a defect that two segments make.
// The batch #805 cross-member review found such a defect: an aged stream and a segment past
// the byte cap made `assemble` read the first segment of an empty stream.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, as every target of this
// package does, so it carries FR-fuzz-14 through FR-fuzz-18.
func FuzzJA4ReadsAnySequenceOfTCPSegments(f *testing.F) {
	hello := tcpHelloLongClientHello()

	f.Add(tcpHelloFuzzCompletedSeed())
	f.Add(tcpHelloFuzzAgedSeed())

	// A duplicate, a segment before the hello and a server reset.
	f.Add(append(append(append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400])...),
		tcpHelloFuzzRecord(-10, 0, 0, 10, nil)...),
		tcpHelloFuzzRecord(0, 0, tcpHelloFuzzRST|tcpHelloFuzzToClient, 0, nil)...))

	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		input := fuzzprop.ExactInput(data)
		segments := tcpHelloFuzzSegments(input)

		// Each call builds one fingerprinter, because the table holds state across packets
		// and a shared value would make the second call read the state of the first.
		fuzzprop.Check(t, len(input), func() any {
			fingerprinter := NewJA4()
			outcomes := make([]any, 0, 2*len(segments)+2)

			for _, segment := range segments {
				results, err := fingerprinter.ProcessPacket(segment.build(t))
				outcomes = append(outcomes, results, err)
			}

			// The table holds its bounds after any sequence.
			if held := len(fingerprinter.tcpHellos); held > maxJA4TCPHelloStreams ||
				held != fingerprinter.tcpHelloKeys.count() {
				t.Fatalf("the table holds %d partial hellos and the recency order names %d",
					held, fingerprinter.tcpHelloKeys.count())
			}

			for key, stream := range fingerprinter.tcpHellos {
				if len(stream.segments) == 0 || len(stream.segments) > maxJA4TCPHelloSegments ||
					stream.bytes > maxJA4TCPHelloBytes {
					t.Fatalf("the partial hello %s holds %d segments and %d bytes",
						key, len(stream.segments), stream.bytes)
				}
			}

			return outcomes
		})
	})
}

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
// The ruling follows the Python reference. `testdata/foxio/reference/python/ja4.py:250`
// tests the sorted extension string, and `testdata/foxio/reference/python/ja4.py:255`
// writes `000000000000` into the wire-order part from that test. The Rust reference hashes
// the wire-order string on its own at `testdata/foxio/reference/rust/ja4/src/tls.rs:382`.
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
