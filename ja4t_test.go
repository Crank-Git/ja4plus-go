package ja4plus

import (
	"encoding/binary"
	goast "go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"strings"
	"testing"

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
	// Ruling #125 writes each zero part as two digits. `ja4t_two_digit_test.go` holds the
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
// generateTCPFingerprint. Issue #508 deleted the dead nil test of the JA4T caller, and this
// test fails when a later change makes the function return nil.
//
// No test reaches the deleted branch, because no input reaches it. This test therefore
// asserts the contract that made the branch dead.
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

	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			fp := generateTCPFingerprint(one.packet, one.tcp, "ja4t")
			if fp == nil {
				t.Fatalf("generateTCPFingerprint returns nil for %s", one.name)
			}
			if parts := strings.Split(fp.Fingerprint, "_"); len(parts) != 4 {
				t.Errorf("the value %q holds %d parts, want 4", fp.Fingerprint, len(parts))
			}
		})
	}
}

// TestGenerateTCPFingerprintHoldsOneReturnOfACompositeLiteralAddress reads the source of
// generateTCPFingerprint, and it reads no packet. The Go specification states that the
// address of a composite literal allocates storage for a variable, so that address is never
// nil.
//
// Issue #508 deleted the dead nil test of the JA4T caller. This test fails when a later
// change adds a second return statement to the function, or when it returns anything other
// than the address of a composite literal.
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
