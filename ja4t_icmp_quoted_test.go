package ja4plus

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

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
