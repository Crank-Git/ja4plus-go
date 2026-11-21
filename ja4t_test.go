package ja4plus

import (
	"encoding/binary"
	goast "go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"slices"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func buildTCPPacket(t testing.TB, srcPort, dstPort uint16, syn, ack bool, window uint16, options []layers.TCPOption) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  window,
		Options: options,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mssOptionData(val uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, val)
	return b
}

func TestJA4T_SYNWithFullOptions(t *testing.T) {
	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindEndList, OptionLength: 1},
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 29200, options)

	// The option list reaches 23 bytes, so gopacket adds one zero pad byte. The packet
	// therefore carries two End-of-Option-List bytes, and ruling #297 writes one entry for
	// each of them.
	result := ComputeJA4T(pkt)
	expected := "29200_2-1-3-1-1-8-4-0-0_1460_7"
	if result != expected {
		t.Errorf("JA4T full options: got %q, want %q", result, expected)
	}
}

func TestJA4T_NonSYNPacket(t *testing.T) {
	// ACK only, no SYN
	pkt := buildTCPPacket(t, 12345, 80, false, true, 65535, nil)
	result := ComputeJA4T(pkt)
	if result != "" {
		t.Errorf("JA4T ACK-only: expected empty, got %q", result)
	}
}

func TestJA4T_SYNACKPacket(t *testing.T) {
	// SYN-ACK should not match JA4T
	pkt := buildTCPPacket(t, 80, 12345, true, true, 29200, nil)
	result := ComputeJA4T(pkt)
	if result != "" {
		t.Errorf("JA4T SYN-ACK: expected empty, got %q", result)
	}
}

func TestJA4T_NoOptions(t *testing.T) {
	pkt := buildTCPPacket(t, 12345, 80, true, false, 65535, nil)
	result := ComputeJA4T(pkt)
	// Ruling #125 writes each zero part as two digits. `ja4t_test.go` holds the
	// evidence and the port issue.
	expected := "65535_00_00_00"
	if result != expected {
		t.Errorf("JA4T no options: got %q, want %q", result, expected)
	}
}

func TestJA4T_MSSOnly(t *testing.T) {
	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1400)},
	}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)
	result := ComputeJA4T(pkt)
	// Ruling #125 writes the absent window scale as two digits.
	expected := "8192_2_1400_00"
	if result != expected {
		t.Errorf("JA4T MSS only: got %q, want %q", result, expected)
	}
}

// ja4tHeaderThatStatesALengthItDoesNotHold returns a TCP header whose data offset states a
// header the contents do not hold. `tcpOptionRegion` returns nil for it, so
// `tcpOptionEntries` reads no option byte.
func ja4tHeaderThatStatesALengthItDoesNotHold() *layers.TCP {
	return &layers.TCP{BaseLayer: layers.BaseLayer{Contents: make([]byte, 20)}, DataOffset: 15}
}

// ja4tHeaderWithATruncatedOption returns a TCP header whose option region ends inside one
// option. `tcpOptionEntries` breaks on that length, so it reaches the empty entry list.
func ja4tHeaderWithATruncatedOption() *layers.TCP {
	contents := make([]byte, 24)
	contents[20] = byte(layers.TCPOptionKindMSS)
	contents[21] = 8
	return &layers.TCP{BaseLayer: layers.BaseLayer{Contents: contents}, DataOffset: 6}
}

// TestGenerateTCPFingerprintReturnsANonNilResultForEveryPacket holds the non-nil contract of
// generateTCPFingerprint. Issue #508 deleted the dead nil test of both callers, and this test
// fails when a later change makes the function return nil.
//
// It reads both call sites, because one function serves both and the type name is the one
// argument that separates them.
//
// No test reaches either deleted branch, because no input reaches one. This test therefore
// asserts the contract that made both branches dead.
func TestGenerateTCPFingerprintReturnsANonNilResultForEveryPacket(t *testing.T) {
	synPacket := buildTCPPacket(t, 12345, 80, true, false, 65535, nil)
	synHeader, held := synPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !held {
		t.Fatalf("the serialized SYN packet carries no TCP layer")
	}
	// A packet that carries no address layer reads no source address, so `GetIPInfo` reports
	// false and the function writes the empty string.
	emptyPacket := gopacket.NewPacket(nil, layers.LayerTypeEthernet, gopacket.Default)

	cases := []struct {
		name   string
		packet gopacket.Packet
		tcp    *layers.TCP
	}{
		{"a SYN packet that carries no option", synPacket, synHeader},
		{"a zero-valued header on a packet that carries no address layer", emptyPacket, &layers.TCP{}},
		{"a header that states a length it does not hold", emptyPacket, ja4tHeaderThatStatesALengthItDoesNotHold()},
		{"a header with a truncated option", emptyPacket, ja4tHeaderWithATruncatedOption()},
	}

	// The two names are the two call sites. `ProcessPacket` of `ja4t.go` passes `ja4t`, and
	// `ProcessPacket` of `ja4ts.go` passes `ja4ts`.
	for _, fpType := range []string{"ja4t", "ja4ts"} {
		for _, one := range cases {
			t.Run(fpType+"/"+one.name, func(t *testing.T) {
				fp := generateTCPFingerprint(one.packet, one.tcp, fpType)
				if fp == nil {
					t.Fatalf("generateTCPFingerprint of type %s returns nil for %s", fpType, one.name)
				}
				if fp.Type != fpType {
					t.Errorf("the result reports type %q, want %q", fp.Type, fpType)
				}
				if parts := strings.Split(fp.Fingerprint, "_"); len(parts) != 4 {
					t.Errorf("the value %q holds %d parts, want 4", fp.Fingerprint, len(parts))
				}
			})
		}
	}
}

// TestGenerateTCPFingerprintHoldsOneReturnOfACompositeLiteralAddress reads the source of
// generateTCPFingerprint, and it reads no packet. The Go specification states that the
// address of a composite literal allocates storage for a variable, so that address is never
// nil.
//
// Issue #508 deleted the dead nil test of both callers. This test fails when a later change
// adds a second return statement to the function, or when it returns anything other than the
// address of a composite literal.
func TestGenerateTCPFingerprintHoldsOneReturnOfACompositeLiteralAddress(t *testing.T) {
	file, err := goparser.ParseFile(gotoken.NewFileSet(), "ja4t.go", nil, 0)
	if err != nil {
		t.Fatalf("the parse of ja4t.go failed: %v", err)
	}

	var body *goast.BlockStmt
	for _, decl := range file.Decls {
		fn, held := decl.(*goast.FuncDecl)
		if held && fn.Name.Name == "generateTCPFingerprint" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatalf("ja4t.go holds no declaration of generateTCPFingerprint")
	}

	var returns []*goast.ReturnStmt
	goast.Inspect(body, func(node goast.Node) bool {
		if ret, held := node.(*goast.ReturnStmt); held {
			returns = append(returns, ret)
		}
		return true
	})

	if len(returns) != 1 {
		t.Fatalf("generateTCPFingerprint holds %d return statements, want 1", len(returns))
	}
	if len(returns[0].Results) != 1 {
		t.Fatalf("the return holds %d results, want 1", len(returns[0].Results))
	}
	address, held := returns[0].Results[0].(*goast.UnaryExpr)
	if !held || address.Op != gotoken.AND {
		t.Fatalf("the return does not take an address, and the contract needs one")
	}
	if _, held := address.X.(*goast.CompositeLit); !held {
		t.Errorf("the return takes the address of something other than a composite literal")
	}
}

func TestJA4T_Reset(t *testing.T) {
	// JA4T holds no state, so Reset changes no result. Issue #25 removed the results
	// slice, which grew without a bound and which no exported method read.
	fp := NewJA4T()
	pkt := buildTCPPacket(t, 12345, 80, true, false, 65535, nil)

	before, _ := fp.ProcessPacket(pkt)
	if len(before) != 1 {
		t.Fatalf("the SYN packet produced %d results, want 1", len(before))
	}

	fp.Reset()

	after, _ := fp.ProcessPacket(pkt)
	if len(after) != 1 || after[0].Fingerprint != before[0].Fingerprint {
		t.Errorf("the read after Reset produces %v, and the read before it produces %v", after, before)
	}
}

// The maintainer ruled split T1 on 2026-08-14, under #484, and the library reads the TCP
// header that an ICMP error message quotes. This file holds that ruling, and #484 is the
// reversal path. The port half is `Crank-Git/ja4plus#610`, and a reversal changes both
// repositories.
//
// The vector holds `64240_2-1-3-1-1-4_1460_8` on each of the 31 deviating frames of
// `ssh2.pcapng`, and `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md` records that value
// at `## Cause 1 — the library reads no TCP header that an ICMP error message quotes`.
// `wireshark/source/packet-ja4.c:1261` matches the field abbreviation `tcp.flags` anywhere
// in the protocol tree, `wireshark/source/packet-ja4.c:1266` sets `syn = 1` for the flag
// byte `0x02`, and `wireshark/source/packet-ja4.c:1583-1584` writes `hf_ja4t` for the frame.
//
// The test below builds the ICMP payload byte by byte. A serializer writes the option
// region that `gopacket` produces, and the ruling needs the exact option list of the
// capture.

// buildICMPQuotedSYNPacket returns one ICMP `Destination unreachable (3)` message of code
// 13 that quotes a TCP SYN header. Frame 19 of `ssh2.pcapng` carries that shape, and it
// quotes the SYN of frame 18.
func buildICMPQuotedSYNPacket(t *testing.T, flagByte byte) gopacket.Packet {
	t.Helper()

	options := []byte{
		2, 4, 0x05, 0xB4, // MSS 1460
		1,       // NOP
		3, 3, 8, // window scale 8
		1,    // NOP
		1,    // NOP
		4, 2, // SACK permitted
	}

	quotedTCP := make([]byte, 20+len(options))
	binary.BigEndian.PutUint16(quotedTCP[0:2], 55606)
	binary.BigEndian.PutUint16(quotedTCP[2:4], 22)
	quotedTCP[12] = byte(len(quotedTCP)/4) << 4
	quotedTCP[13] = flagByte
	binary.BigEndian.PutUint16(quotedTCP[14:16], 64240)
	copy(quotedTCP[20:], options)

	quotedIP := make([]byte, 20+len(quotedTCP))
	quotedIP[0] = 0x45
	binary.BigEndian.PutUint16(quotedIP[2:4], uint16(len(quotedIP)))
	quotedIP[8] = 64
	quotedIP[9] = byte(layers.IPProtocolTCP)
	copy(quotedIP[12:16], []byte{172, 16, 225, 48})
	copy(quotedIP[16:20], []byte{172, 16, 225, 46})
	copy(quotedIP[20:], quotedTCP)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 128, 128, 128},
		DstIP:    []byte{172, 16, 225, 48},
		Protocol: layers.IPProtocolICMPv4,
		Version:  4,
		TTL:      64,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 13),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(quotedIP)); err != nil {
		t.Fatalf("the serializer failed: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestJA4TReadsTheSYNThatAnICMPErrorMessageQuotes holds the ruling of split T1.
//
// The value reproduces the vector string of the 31 deviating frames of `ssh2.pcapng`.
func TestJA4TReadsTheSYNThatAnICMPErrorMessageQuotes(t *testing.T) {
	packet := buildICMPQuotedSYNPacket(t, 0x02)

	const expected = "64240_2-1-3-1-1-4_1460_8"
	if got := ComputeJA4T(packet); got != expected {
		t.Fatalf("the library produced %q, and the vector holds %q", got, expected)
	}
}

// TestJA4TReadsNoQuotedHeaderThatCarriesTheACKFlag applies the packet selection of ruling
// #126 to the quoted header. The selection reads the two SYN bits of the header it reads,
// and a quoted SYN-ACK reaches no JA4T value.
func TestJA4TReadsNoQuotedHeaderThatCarriesTheACKFlag(t *testing.T) {
	packet := buildICMPQuotedSYNPacket(t, 0x12)

	if got := ComputeJA4T(packet); got != "" {
		t.Fatalf("the library produced %q for a quoted SYN-ACK, and it produces no value", got)
	}
}

// TestJA4TReportsTheOuterAddressPairOfAnICMPErrorMessage records which address pair the
// result carries.
//
// No FoxIO source states a rule for the address pair of a quoted header. The dissector
// writes `hf_ja4t` as a field of the frame, and it attaches no address pair to that field.
// So this library keeps its own rule: `GetIPInfo` of `internal/parser/packet.go` reads the
// outermost address layer, and its doc comment states that a `FingerprintResult` reports
// that layer. The rule moves no fingerprint value, because the value reads the quoted
// header alone. #484 is the reversal path.
func TestJA4TReportsTheOuterAddressPairOfAnICMPErrorMessage(t *testing.T) {
	packet := buildICMPQuotedSYNPacket(t, 0x02)

	results, err := NewJA4T().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test needs 1", len(results))
	}

	if results[0].SrcIP != "10.128.128.128" {
		t.Fatalf("the result reports the source address %q, and the outer header holds 10.128.128.128", results[0].SrcIP)
	}
	if results[0].DstIP != "172.16.225.48" {
		t.Fatalf("the result reports the destination address %q, and the outer header holds 172.16.225.48", results[0].DstIP)
	}
	if results[0].SrcPort != 55606 {
		t.Fatalf("the result reports the source port %d, and the quoted header holds 55606", results[0].SrcPort)
	}
	if results[0].DstPort != 22 {
		t.Fatalf("the result reports the destination port %d, and the quoted header holds 22", results[0].DstPort)
	}
}

// Part b of JA4T and JA4TS holds one entry for each option byte the packet carries. The
// maintainer ruled that count on 2026-08-12, and #297 records the ruling.
//
// `github.com/google/gopacket@v1.1.19` at `layers/tcp.go:279-282` appends one option for
// the first End-of-Option-List byte, assigns the rest of the header to `tcp.Padding`, and
// runs `break OPTIONS`. A reader of `tcp.Options` therefore counts one entry, whatever the
// packet carries. The library reads `tcp.Contents` instead.
// #438 moved this project to `github.com/gopacket/gopacket@v1.6.1`, and that fork keeps
// this reading at `layers/tcp.go:338-344`. So the library still reads `tcp.Contents`.
//
// Four sources write one entry for each byte, and one source writes none.
// `wireshark/source/packet-ja4.c:1456` appends one entry for each `tcp.option_kind` field
// occurrence, and `rust/ja4/src/tcp.rs:70` reads that same field list. The port reads the
// raw option bytes in `ja4plus/utils/tcp_options.py`. The per-packet vectors hold two
// entries. `zeek/src/ja4t.cc:71-73` breaks the loop before the append, so Zeek writes
// none. `docs/specs/foxio/JA4T.md` R10 marks that break a reference split.
//
// Ruling #125 stays closed. It keys the part width on the value, and this ruling decides
// the entry count.
//
// The port half of this ruling is `Crank-Git/ja4plus#215`, and it is closed. The port needs
// no change, because it already writes one entry for each option byte. The docstring of
// `option_bytes` at `ja4plus/utils/tcp_options.py:51-56` states that it reads the option
// bytes the capture carries. Line 56 of that docstring writes
// `#215 records the reading as D2.`, and that bare number names the port's issue #215.

// tcpOptionEndList returns a TCP End-of-Option-List option.
func tcpOptionEndList() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindEndList, OptionLength: 1}
}

// tcpOptionSACKPermitted returns a TCP selective acknowledgment permitted option.
func tcpOptionSACKPermitted() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
}

// tcpOptionTimestamps returns a TCP timestamps option that carries the eight data bytes.
func tcpOptionTimestamps(data []byte) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindTimestamps,
		OptionLength: 10,
		OptionData:   data,
	}
}

// The option list below reaches twelve bytes, so gopacket adds no pad byte. The bytes are
// `02 04 05 b4 01 03 03 02 04 02 00 00`. The test builds them on a SYN, because JA4T and
// JA4TS share one builder. `TestJA4TSWritesOneEntryForEachEndOfOptionListByte` names the
// capture that carries the bytes.
func TestJA4TWritesOneEntryForEachEndOfOptionListByte(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-1-3-4-0-0_1460_2"
	if got != want {
		t.Errorf("JA4T for the two End-of-Option-List bytes: got %q, want %q", got, want)
	}
}

// A SYN-ACK reaches the same rule, because JA4T and JA4TS share one builder.
//
// `browsers-x509.pcapng` frame 31 is a SYN-ACK, and it carries the option bytes above. The
// per-packet vector for that frame holds `ja4.ja4ts` as `64240_2-1-3-4-0-0_1460_2`. Frame
// 30 is the SYN of the same connection, and its `ja4.ja4t` value is
// `64240_2-1-3-1-1-4_1460_8`.
func TestJA4TSWritesOneEntryForEachEndOfOptionListByte(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 64240, options)

	got := ComputeJA4TS(pkt)
	want := "64240_2-1-3-4-0-0_1460_2"
	if got != want {
		t.Errorf("JA4TS for the two End-of-Option-List bytes: got %q, want %q", got, want)
	}
}

// A timestamps option carries eight data bytes, and each one of them can hold zero. A read
// that counts a zero byte rather than an option writes eight surplus entries here.
//
// The option list below reaches twenty-four bytes, so gopacket adds no pad byte.
func TestJA4TCountsNoZeroByteInsideATimestampsOption(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(7),
		tcpOptionNop(),
		tcpOptionNop(),
		tcpOptionTimestamps(make([]byte, 8)),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 29200, options)

	got := ComputeJA4T(pkt)
	want := "29200_2-1-3-1-1-8-4-0-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the zero bytes of the timestamps option: got %q, want %q", got, want)
	}
}

// A maximum segment size option can also carry two zero data bytes, and a window scale
// option can carry one. The list below holds three such bytes and four End-of-Option-List
// bytes, so the two counts separate.
//
// The option list reaches twelve bytes, so gopacket adds no pad byte.
func TestJA4TCountsNoZeroByteInsideAMaximumSegmentSizeOption(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(0),
		tcpOptionNop(),
		tcpOptionWindowScale(0),
		tcpOptionEndList(),
		tcpOptionEndList(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 8192, options)

	got := ComputeJA4T(pkt)
	want := "8192_2-1-3-0-0-0-0_00_00"
	if got != want {
		t.Errorf("JA4T for the zero bytes of the segment size option: got %q, want %q", got, want)
	}
}

// The option bytes are attacker-controlled, and a fingerprinter never panics. Each input
// below states a length that the region does not hold.
func TestTCPOptionEntriesStopsAtAMalformedOptionLength(t *testing.T) {
	cases := []struct {
		name   string
		region []byte
		want   []string
	}{
		{"the region ends before the length byte", []byte{0x02}, nil},
		{"the length byte states zero", []byte{0x02, 0x00, 0x01, 0x01}, nil},
		{"the length byte states one", []byte{0x02, 0x01, 0x01, 0x01}, nil},
		{"the length exceeds the region", []byte{0x02, 0x0a, 0x05, 0xb4}, nil},
		{"the region holds no byte", []byte{}, nil},
		{"a valid option precedes the malformed one", []byte{0x01, 0x00, 0x02, 0xff}, []string{"1", "0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, _, _ := tcpOptionEntries(c.region)
			if len(entries) != len(c.want) {
				t.Fatalf("entries: got %v, want %v", entries, c.want)
			}
			for i := range entries {
				if entries[i] != c.want[i] {
					t.Fatalf("entries: got %v, want %v", entries, c.want)
				}
			}
		})
	}
}

// A data offset that the segment does not hold must reach no option byte.
//
// `layers/tcp.go:264-268` assigns `tcp.Contents = data` for such a segment, and that slice
// holds the payload as well as the header. `layers/tcp.go:319` adds the layer before it
// reads the error, so the fingerprinter reads that segment. A read of `tcp.Contents[20:]`
// alone would build part b, the segment size and the window scale out of payload bytes
// that an attacker chooses.
//
// `gopacket` returns from the error path before it enters its own option loop, so the old
// read of `tcp.Options` reported an empty option list here. This test holds that result.
func TestJA4TReadsNoOptionByteFromADataOffsetTheSegmentDoesNotHold(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	frame := buildTCPPacket(t, 12345, 443, true, false, 64240, options).Data()

	// The frame holds a 14-byte Ethernet header and a 20-byte IPv4 header, so the TCP
	// header starts at byte 34. Byte 12 of that header holds the data offset in its high
	// nibble. A value of 15 claims a 60-byte header, and the segment holds 32 bytes.
	const tcpStart = 34
	crafted := make([]byte, len(frame))
	copy(crafted, frame)
	crafted[tcpStart+12] = 0xf0 | (crafted[tcpStart+12] & 0x0f)

	pkt := gopacket.NewPacket(crafted, layers.LayerTypeEthernet, gopacket.Default)
	got := ComputeJA4T(pkt)
	want := "64240_00_00_00"
	if got != want {
		t.Errorf("JA4T for the data offset the segment does not hold: got %q, want %q", got, want)
	}
}

// `FuzzNoExportedFunctionPanicsOnAnyFrame` drives whole frames through `gopacket`, and the
// gopacket decoder rejects an option length that the header does not hold. That target
// therefore reaches no guard below. This target reads the option region directly.
func FuzzTCPOptionEntriesReadsAnyOptionRegion(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02, 0x04, 0x02, 0x00, 0x00})
	f.Add([]byte{0x08, 0x0a, 0x60, 0xb6, 0xa1, 0x8d, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x02, 0x00})
	f.Add([]byte{0x02, 0x01})
	f.Add([]byte{0x02, 0xff})
	f.Add([]byte{0x02})

	f.Fuzz(func(t *testing.T, region []byte) {
		entries, _, _ := tcpOptionEntries(region)
		// Each entry costs at least one option byte, so a region cannot produce more
		// entries than it holds bytes. A read that returns more has advanced by nothing.
		if len(entries) > len(region) {
			t.Fatalf("the region %x produces %d entries for %d bytes", region, len(entries), len(region))
		}
	})
}

// The segment size and the window scale each read a data field, and a short option holds
// no such field.
func TestTCPOptionEntriesReadsNoValueFromAShortOption(t *testing.T) {
	// A segment size option of length 3 holds one data byte, and the value needs two.
	entries, mss, wscale := tcpOptionEntries([]byte{0x02, 0x03, 0xff, 0x03, 0x02})
	if mss != 0 {
		t.Errorf("segment size: got %d, want 0", mss)
	}
	if wscale != 0 {
		t.Errorf("window scale: got %d, want 0", wscale)
	}
	if len(entries) != 2 || entries[0] != "2" || entries[1] != "3" {
		t.Errorf("entries: got %v, want [2 3]", entries)
	}
}

// JA4T and JA4TS read the maximum segment size only from an option of length 4, and the
// window scale only from an option of length 3. The maintainer ruled this on 2026-10-01
// UTC, and #814 holds the ruling and is the reversal path.
//
// The port holds the same rule at `ja4plus/utils/tcp_options.py:115-118`, at tag `v1.3.0`
// of Crank-Git/ja4plus. FoxIO `rust/ja4/src/tcp.rs:76-82` and
// `wireshark/source/packet-ja4.c:1461-1466` at `16b96d95` read the field that Wireshark
// core adds only at those lengths. FoxIO `zeek/src/ja4t.cc:87-93` reads any length, and
// the ruling declines that reading.
//
// No corpus capture holds an option of another length, so each test below builds one.
// Part b still writes the kind of each option. A value that is not read writes the form
// of zero: `00` for the segment size and `00` for the window scale.

// tcpOptionOfLength returns an option of the kind whose data makes the stated length.
// gopacket sets the length byte to the data length plus 2, because the builder fixes
// lengths.
func tcpOptionOfLength(kind layers.TCPOptionKind, data []byte) layers.TCPOption {
	return layers.TCPOption{OptionType: kind, OptionLength: uint8(len(data) + 2), OptionData: data}
}

func TestJA4TReadsTheTCPOptionValuesOnlyAtTheExactLength(t *testing.T) {
	cases := []struct {
		name    string
		options []layers.TCPOption
		want    string
	}{
		{
			// The list reaches seven bytes, so gopacket adds one pad byte of kind 0.
			name: "a segment size option of length 3 sets no value and still writes kind 2",
			options: []layers.TCPOption{
				tcpOptionOfLength(layers.TCPOptionKindMSS, []byte{0x05}),
				tcpOptionNop(),
				tcpOptionWindowScale(7),
			},
			want: "64240_2-1-3-0_00_7",
		},
		{
			name: "a segment size option of length 6 sets no value",
			options: []layers.TCPOption{
				tcpOptionOfLength(layers.TCPOptionKindMSS, []byte{0x05, 0xb4, 0x00, 0x00}),
				tcpOptionWindowScale(7),
				tcpOptionNop(),
				tcpOptionNop(),
				tcpOptionNop(),
			},
			want: "64240_2-3-1-1-1_00_7",
		},
		{
			name: "a window scale option of length 4 sets no value",
			options: []layers.TCPOption{
				tcpOptionOfLength(layers.TCPOptionKindWindowScale, []byte{0x07, 0x00}),
				tcpOptionMSS(1460),
			},
			want: "64240_3-2_1460_00",
		},
		{
			name: "a window scale option of length 2 sets no value",
			options: []layers.TCPOption{
				tcpOptionOfLength(layers.TCPOptionKindWindowScale, nil),
				tcpOptionMSS(1460),
				tcpOptionNop(),
				tcpOptionNop(),
			},
			want: "64240_3-2-1-1_1460_00",
		},
		{
			name: "options of the exact lengths set both values",
			options: []layers.TCPOption{
				tcpOptionMSS(1460),
				tcpOptionNop(),
				tcpOptionWindowScale(7),
			},
			want: "64240_2-1-3_1460_7",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, c.options)
			if got := ComputeJA4T(pkt); got != c.want {
				t.Errorf("JA4T: got %q, want %q", got, c.want)
			}
		})
	}
}

// A SYN-ACK reaches the same rule, because JA4T and JA4TS share one builder. The list
// reaches eleven bytes, so gopacket adds one pad byte of kind 0.
func TestJA4TSReadsNoValueFromAnOptionOfAnotherLength(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionOfLength(layers.TCPOptionKindMSS, []byte{0x05, 0xb4, 0x00, 0x00}),
		tcpOptionNop(),
		tcpOptionOfLength(layers.TCPOptionKindWindowScale, []byte{0x07, 0x00}),
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 64240, options)

	want := "64240_2-1-3-0_00_00"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS: got %q, want %q", got, want)
	}
}

// Part b of JA4T and JA4TS writes the decimal kind of every option the packet carries, and
// not the kinds of a fixed name list. #808 records the defect.
//
// Every FoxIO implementation writes each kind it reads, at FoxIO `16b96d95`.
// `rust/ja4/src/tcp.rs:70` pushes every `tcp.option_kind`, and
// `wireshark/source/packet-ja4.c:1456-1458` appends every `tcp.option_kind` with `"%d-"`.
// `zeek/src/ja4t.cc:69-75` pushes every kind except kind 0, and `docs/specs/foxio/JA4T.md`
// R10 records that one exception as the split that #297 ruled. The port appends every kind
// at `ja4plus/utils/tcp_options.py:112-114`, at tag `v1.3.0`.

// tcpOptionFastOpenCookieRequest returns a TCP Fast Open option that carries no cookie.
// RFC 7413 section 4.1.1 gives that option kind 34 and length 2.
func tcpOptionFastOpenCookieRequest() layers.TCPOption {
	return layers.TCPOption{OptionType: 34, OptionLength: 2}
}

// tcpOptionMultipathCapable returns the MP_CAPABLE option of a version 1 SYN.
// RFC 8684 section 3.1 gives that option kind 30 and length 4. The first data byte holds
// subtype 0 and version 1, and the second byte holds the flags.
func tcpOptionMultipathCapable() layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindMultipathTCP,
		OptionLength: 4,
		OptionData:   []byte{0x01, 0x81},
	}
}

// The option list below reaches eleven bytes, so gopacket adds one pad byte of kind 0.
func TestJA4TWritesTheTCPFastOpenKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionFastOpenCookieRequest(),
		tcpOptionSACKPermitted(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-34-4-3-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the TCP Fast Open option: got %q, want %q", got, want)
	}
}

// The option list below reaches eleven bytes, so gopacket adds one pad byte of kind 0.
func TestJA4TWritesTheMultipathTCPKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionMultipathCapable(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-30-3-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the Multipath TCP option: got %q, want %q", got, want)
	}
}

// A SYN-ACK reaches the same rule, because JA4T and JA4TS share one builder. The option
// list below reaches thirteen bytes, so gopacket adds three pad bytes of kind 0.
func TestJA4TSWritesTheMultipathTCPKindAndTheTCPFastOpenKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionMultipathCapable(),
		tcpOptionFastOpenCookieRequest(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 64240, options)

	got := ComputeJA4TS(pkt)
	want := "64240_2-30-34-3-0-0-0_1460_7"
	if got != want {
		t.Errorf("JA4TS for the two options: got %q, want %q", got, want)
	}
}

// An option kind that no RFC names still reaches part b, and its data sets neither value.
// Kind 253 is an experimental kind under RFC 4727, and kind 255 needs three digits.
func TestTCPOptionEntriesWritesTheDecimalKindOfAnUnnamedOption(t *testing.T) {
	region := []byte{0xfd, 0x04, 0x05, 0xb4, 0xff, 0x03, 0x07, 0x01}
	entries, mss, wscale := tcpOptionEntries(region)
	want := []string{"253", "255", "1"}
	if !slices.Equal(entries, want) {
		t.Errorf("entries: got %v, want %v", entries, want)
	}
	if mss != 0 || wscale != 0 {
		t.Errorf("an unnamed option set a value: segment size %d, window scale %d", mss, wscale)
	}
}

// An unnamed kind carries a length byte, so the bounds checks of a length field apply to
// it. Each region below states a length that the region does not hold.
func TestTCPOptionEntriesStopsAtAMalformedLengthOfAnUnnamedOption(t *testing.T) {
	cases := []struct {
		name   string
		region []byte
		want   []string
	}{
		{"the region ends before the length byte", []byte{0x01, 0x22}, []string{"1"}},
		{"the length byte states zero", []byte{0x22, 0x00, 0x01}, nil},
		{"the length byte states one", []byte{0x1e, 0x01, 0x01}, nil},
		{"the length exceeds the region", []byte{0x1e, 0x0c, 0x01, 0x81}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, _, _ := tcpOptionEntries(c.region)
			if !slices.Equal(entries, c.want) {
				t.Errorf("entries: got %v, want %v", entries, c.want)
			}
		})
	}
}

// The maintainer ruled the JA4T packet selection on 2026-08-13, under #126. JA4T reads any
// SYN whose ACK bit is clear, and it reads no other flag. The port holds the same rule at
// `ja4plus/fingerprinters/ja4t.py:159`. `Crank-Git/ja4plus#603` is open, and it adds the row
// of the `## Parity with ja4plus` section on the port side. A reversal of the ruling changes
// both repositories.
//
// `.claude/rules/rulings.md` records a ruling in a register entry, in a test, or in a row of
// the register table. This test is that record. The ruling writes no entry in
// `testdata/deviations.json`, because the suite compares no value that the rule moves. The
// `## Parity with ja4plus` section of `docs/specs/spec.md` names no row for the rule, and
// #126 writes none.
//
// The rule separates two readings of the reference. `rust/ja4/src/tcp.rs:151` tests the SYN
// bit and the ACK bit, and `rust/ja4/src/tcp.rs:159` asserts `is_initial_syn(0xC2)`.
// `rust/ja4/src/tcp.rs:162` asserts that `0x12` reaches no value, which is the SYN-ACK half.
// `zeek/scripts/fingerprints/ja4t/main.zeek:64` and `wireshark/source/packet-ja4.c:1266` each test the whole
// flag byte against `0x02`, so each one declines a SYN that carries the ECN flags.
//
// The ruling of 2026-08-13 cites the `0xC2` assertion at `rust/ja4/src/tcp.rs:158`, and that
// line holds the comment above the assertion. This file cites `:154`, which holds the
// assertion at the commit in `testdata/foxio.pin`.
//
// The two tests below build the packet that separates the two readings. The corpus holds
// two such SYN packets, and the suite compares neither one. The per-packet vector of
// `gre-sample.pcap` and of `macos_tcp_flags.pcap` names no `ja4.ja4t` field.
// `conformance_test.go:279` drops a value whose method the vector of the capture never
// names.

// synFlags holds the four TCP flags that the JA4T packet selection reads.
type synFlags struct {
	SYN bool
	ACK bool
	ECE bool
	CWR bool
}

// synFlagByte returns byte 13 of the TCP header, which holds the eight low flag bits.
//
// `gopacket` reads each flag into a field of its own at
// `github.com/google/gopacket@v1.1.19/layers/tcp.go:241-248`, so a test that asserts the
// byte proves which packet it built. `layers/tcp.go:270` assigns the whole header to
// `tcp.Contents`.
// #438 moved this project to `github.com/gopacket/gopacket@v1.6.1`, and that fork keeps
// both readings. It assigns the eight flag fields at `layers/tcp.go:303-311`, and it
// assigns `tcp.Contents` at `layers/tcp.go:332`.
// The parameter takes `*testing.T` rather than `testing.TB`. `staticcheck` reads
// `testing.T.Fatalf` as a call that ends the function, and it reads no method of an
// interface that way. No benchmark of this package calls this helper.
func synFlagByte(t *testing.T, packet gopacket.Packet) byte {
	t.Helper()

	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		t.Fatalf("the packet holds no TCP layer")
	}

	const flagOffset = 13
	if len(tcp.Contents) <= flagOffset {
		t.Fatalf("the TCP header holds %d bytes, and the flag byte sits at offset %d", len(tcp.Contents), flagOffset)
	}

	return tcp.Contents[flagOffset]
}

// buildFlaggedTCPPacket returns one TCP packet that carries the four flags of the argument.
//
// `buildTCPPacket` of `ja4t_test.go` sets the SYN flag and the ACK flag alone, and the
// ruling of #126 needs the ECN flags as well. This builder therefore takes the flag set,
// and it writes no option.
func buildFlaggedTCPPacket(t *testing.T, flags synFlags, window uint16) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(443),
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		ECE:     flags.ECE,
		CWR:     flags.CWR,
		Window:  window,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("the serializer failed: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestJA4TReadsASYNThatCarriesTheECNFlags holds the ruling of #126.
//
// The flag byte reads `0xC2`, which is the value `rust/ja4/src/tcp.rs:159` asserts. An
// equality test against `0x02` declines this packet, and the bit test reads it.
func TestJA4TReadsASYNThatCarriesTheECNFlags(t *testing.T) {
	packet := buildFlaggedTCPPacket(t, synFlags{SYN: true, ECE: true, CWR: true}, 29200)

	if flags := synFlagByte(t, packet); flags != 0xC2 {
		t.Fatalf("the packet carries the flag byte %#02x, and the test needs %#02x", flags, 0xC2)
	}

	// The packet carries no option, so ruling #125 writes `00` for part b, part c and part d.
	const expected = "29200_00_00_00"

	if value := ComputeJA4T(packet); value != expected {
		t.Errorf("the ECN-marked SYN produces %q, and the ruling of #126 gives %q", value, expected)
	}
}

// TestJA4TReadsNoSYNThatCarriesTheACKFlag holds the other half of the ruling of #126.
//
// The flag byte reads `0xD2`, which sets the ACK bit as well as the ECN flags. The ruling
// reads the ACK bit alone, so this packet reaches no JA4T value.
func TestJA4TReadsNoSYNThatCarriesTheACKFlag(t *testing.T) {
	packet := buildFlaggedTCPPacket(t, synFlags{SYN: true, ACK: true, ECE: true, CWR: true}, 29200)

	if flags := synFlagByte(t, packet); flags != 0xD2 {
		t.Fatalf("the packet carries the flag byte %#02x, and the test needs %#02x", flags, 0xD2)
	}

	if value := ComputeJA4T(packet); value != "" {
		t.Errorf("the ECN-marked SYN-ACK produces %q, and the ruling of #126 gives no value", value)
	}
}

// The two-digit form of JA4T and JA4TS. Ruling #125 adopted it from `Crank-Git/ja4plus`,
// which settled the question as its own #215 on 2026-08-08.
//
// The three FoxIO implementations disagreed at `27f0cbf9`, so the authority rule settled nothing. Two of
// the three write the two-digit form, and the ruling follows them. Zeek writes `"00"` for
// an empty option list at `zeek/scripts/fingerprints/ja4t/main.zeek:137`, `fmt("%02d", ...)` for part c at
// `zeek/scripts/fingerprints/ja4t/main.zeek:140` and `"00"` for a zero part d at `zeek/scripts/fingerprints/ja4t/main.zeek:143`.
// Wireshark writes the same three forms at `wireshark/source/packet-ja4.c:664-673`. Rust
// wrote one digit at `27f0cbf9`, and it writes the same three forms at `16b96d95`:
// `rust/ja4/src/tcp.rs:136` and `rust/ja4/src/tcp.rs:143`. So the three implementations
// now agree. `docs/specs/foxio/JA4T.md` R26, R27 and R28 hold the reading.
//
// The rule keys on the value, and never on the presence of the option. A SYN that carries
// a Window Scale option of zero writes the same part as a SYN that carries no such
// option. `wireshark/source/packet-ja4.c:668` tests `data->window_scale == 0`, and
// `zeek/scripts/fingerprints/ja4t/main.zeek:142` tests `c$fp$ja4t$syn_opts$window_scale == 0`. Both read the
// value. The tests below build the present-and-zero packet, which no corpus capture
// reaches.
//
// Part c and part d take different forms above zero, and both references agree on that.
// Part c writes `%02d`, so a segment size below 10 carries a leading zero. Part d writes
// `%d`, so a window scale above zero carries none.

// tcpOptionMSS returns a TCP maximum segment size option that carries the value.
func tcpOptionMSS(value uint16) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   mssOptionData(value),
	}
}

// tcpOptionWindowScale returns a TCP window scale option that carries the shift.
func tcpOptionWindowScale(shift byte) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{shift},
	}
}

// tcpOptionNop returns a TCP no-operation option.
//
// Each option list below reaches a length of four bytes, or a multiple of four. gopacket
// pads a shorter list to a 32-bit boundary, and a pad byte decodes as option kind 0.
func tcpOptionNop() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
}

// FR-parity-34. The port holds the same rule as its own #215.
func TestJA4TWritesTwoZeroDigitsForAnEmptyOptionList(t *testing.T) {
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, nil)

	const want = "8192_00_00_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no option is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. The packet carries no maximum segment size option.
func TestJA4TWritesTwoZeroDigitsForAnAbsentSegmentSize(t *testing.T) {
	options := []layers.TCPOption{tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)

	const want = "8192_3-1_00_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no segment size is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. The packet carries a maximum segment size option whose value is zero, so
// the rule keys on the value and not on the presence of the option.
func TestJA4TWritesTwoZeroDigitsForASegmentSizeOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(0), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_00_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose segment size is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. Zeek and Wireshark both write part c as `%02d`, so a segment size below 10
// carries a leading zero.
func TestJA4TPadsASegmentSizeBelowTenToTwoDigits(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(5), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_05_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose segment size is 5 is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. The packet carries no window scale option.
func TestJA4TWritesTwoZeroDigitsForAnAbsentWindowScale(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460)}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)

	const want = "8192_2_1460_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no window scale is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. The packet carries a window scale option whose value is zero, so the rule
// keys on the value and not on the presence of the option. No corpus capture reaches this
// value, and this test is the record of the ruling.
func TestJA4TWritesTwoZeroDigitsForAWindowScaleOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460), tcpOptionWindowScale(0), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_1460_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose window scale is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. Zeek and Wireshark both write part d as `%d` above zero, so a window scale
// of 5 carries no leading zero. The two-digit form covers the zero value alone.
func TestJA4TWritesOneDigitForAWindowScaleAboveZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460), tcpOptionWindowScale(5), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_1460_5"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose window scale is 5 is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-34, FR-parity-35 and FR-parity-36 each cover JA4TS. The image titles itself
// `JA4T/S: TCP Fingerprint`, and `generateTCPFingerprint` writes both methods, so one
// repair covers both.
func TestJA4TSWritesTwoZeroDigitsForAnEmptyOptionList(t *testing.T) {
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, nil)

	const want = "8540_00_00_00"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK that carries no option is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35 on the server side. The SYN-ACK carries a segment size option of zero, so
// the rule keys on the value here too.
func TestJA4TSWritesTwoZeroDigitsForASegmentSizeOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(0), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, options)

	const want = "8540_2-3-1_00_7"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK whose segment size is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36 on the server side. The SYN-ACK carries a window scale option of zero.
func TestJA4TSWritesTwoZeroDigitsForAWindowScaleOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1220), tcpOptionWindowScale(0), tcpOptionNop()}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, options)

	const want = "8540_2-3-1_1220_00"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK whose window scale is zero is %q, and the reference writes %q", got, want)
	}
}
