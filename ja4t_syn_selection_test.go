package ja4plus

import (
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The maintainer ruled the JA4T packet selection on 2026-08-13, under #126. JA4T reads any
// SYN whose ACK bit is clear, and it reads no other flag. The port holds the same rule at
// `ja4plus/fingerprinters/ja4t.py:159`, and `Crank-Git/ja4plus#603` records the register
// row. A reversal of the ruling changes both repositories.
//
// The rule separates two readings of the reference. `rust/ja4/src/tcp.rs:146` tests the SYN
// bit and the ACK bit, and `rust/ja4/src/tcp.rs:153` asserts `is_initial_syn(0xC2)`.
// `zeek/ja4t/main.zeek:126` and `wireshark/source/packet-ja4.c:1266` each test the whole
// flag byte against `0x02`, so each one declines a SYN that carries the ECN flags.
//
// The two tests below build the packet that separates the readings, because the flag byte
// of the FoxIO corpus reaches no comparison for it. The per-packet vector of
// `gre-sample.pcap` and of `macos_tcp_flags.pcap` names no `ja4.ja4t` field, and
// `conformance_test.go:279` compares a method that the vector of the capture names.

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
// The parameter takes `*testing.T` rather than `testing.TB`, because `staticcheck` reads
// `testing.T.Fatalf` as a call that ends the function and it reads no method of the
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
// The flag byte reads `0xC2`, which is the value `rust/ja4/src/tcp.rs:153` asserts. An
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
