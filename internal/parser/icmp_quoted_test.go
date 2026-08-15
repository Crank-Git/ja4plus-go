package parser

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The maintainer ruled split T1 on 2026-08-14, under #484, and the library reads the TCP
// header that an ICMP error message quotes. #484 is the reversal path, and the port half
// is `Crank-Git/ja4plus#610`.
//
// Every test below builds the ICMP payload byte by byte, because a serializer writes a
// consistent length field and the bound tests need an inconsistent one. The payload is
// untrusted input, and `CLAUDE.md` states the bound rule.

// quotedSYNOptions holds the option bytes of the SYN header that `ssh2.pcapng` quotes.
// The list reads MSS, NOP, window scale, NOP, NOP and SACK-permitted, which produces the
// part b value `2-1-3-1-1-4`.
var quotedSYNOptions = []byte{
	2, 4, 0x05, 0xB4, // MSS 1460
	1,       // NOP
	3, 3, 8, // window scale 8
	1,    // NOP
	1,    // NOP
	4, 2, // SACK permitted
}

// buildQuotedTCPHeader returns one TCP SYN header, with the option region of the argument.
// It pads the option region to a multiple of four bytes, and it writes the data offset that
// the padded length states.
func buildQuotedTCPHeader(options []byte, window uint16) []byte {
	padded := append([]byte{}, options...)
	for len(padded)%4 != 0 {
		padded = append(padded, 0)
	}

	header := make([]byte, 20+len(padded))
	binary.BigEndian.PutUint16(header[0:2], 55606)
	binary.BigEndian.PutUint16(header[2:4], 22)
	header[12] = byte((20+len(padded))/4) << 4
	header[13] = 0x02
	binary.BigEndian.PutUint16(header[14:16], window)
	copy(header[20:], padded)

	return header
}

// buildQuotedIPPacket returns one IPv4 packet that carries the transport bytes of the
// argument. `declaredLength` writes the total length field, and a value of 0 writes the
// true length.
func buildQuotedIPPacket(transport []byte, declaredLength uint16) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	length := declaredLength
	if length == 0 {
		length = uint16(20 + len(transport))
	}
	binary.BigEndian.PutUint16(packet[2:4], length)
	packet[8] = 64
	packet[9] = byte(layers.IPProtocolTCP)
	copy(packet[12:16], []byte{172, 16, 225, 48})
	copy(packet[16:20], []byte{172, 16, 225, 46})
	copy(packet[20:], transport)

	return packet
}

// buildICMPPacket returns one ICMP packet of the type and the code of the argument, with
// the payload bytes of the argument.
func buildICMPPacket(t *testing.T, icmpType, icmpCode uint8, payload []byte) gopacket.Packet {
	t.Helper()

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
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("the serializer failed: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestGetTCPLayerReadsNoQuotedHeader holds the reading that `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`
// records at `## Cause 1 — the library reads no TCP header that an ICMP error message quotes`.
func TestGetTCPLayerReadsNoQuotedHeader(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := GetTCPLayer(packet); tcp != nil {
		t.Fatalf("GetTCPLayer read a TCP layer of an ICMP payload, and `gopacket` decodes none")
	}
}

func TestQuotedTCPHeaderReadsTheSYNOfAnICMPDestinationUnreachableMessage(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	tcp := QuotedTCPHeader(packet)
	if tcp == nil {
		t.Fatalf("QuotedTCPHeader read no header of the ICMP payload")
	}
	if !tcp.SYN || tcp.ACK {
		t.Fatalf("the quoted header carries SYN %t and ACK %t", tcp.SYN, tcp.ACK)
	}
	if tcp.Window != 64240 {
		t.Fatalf("the quoted header carries the window %d, and the test needs 64240", tcp.Window)
	}
	if got := uint16(tcp.SrcPort); got != 55606 {
		t.Fatalf("the quoted header carries the source port %d, and the test needs 55606", got)
	}
	if got := len(tcp.Contents); got != 20+len(quotedSYNOptions) {
		t.Fatalf("the quoted header holds %d content bytes, and the test needs %d", got, 20+len(quotedSYNOptions))
	}
}

// TestQuotedTCPHeaderReadsEachICMPTypeThatQuotesAPacket names the five ICMP types that
// carry a quoted header. `wireshark/source/packet-ja4.c:1261` matches `tcp.flags` anywhere
// in the protocol tree, and the dissector decodes a quoted packet for an error message
// alone.
func TestQuotedTCPHeaderReadsEachICMPTypeThatQuotesAPacket(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)

	for _, icmpType := range []uint8{
		layers.ICMPv4TypeDestinationUnreachable,
		layers.ICMPv4TypeSourceQuench,
		layers.ICMPv4TypeRedirect,
		layers.ICMPv4TypeTimeExceeded,
		layers.ICMPv4TypeParameterProblem,
	} {
		packet := buildICMPPacket(t, icmpType, 0, quoted)
		if QuotedTCPHeader(packet) == nil {
			t.Fatalf("QuotedTCPHeader read no header of the ICMP type %d", icmpType)
		}
	}
}

// TestQuotedTCPHeaderReadsNoEchoPayload keeps the library with the dissector. An echo
// request carries no quoted packet, so the dissector decodes no TCP header inside it and it
// writes no JA4T value for that frame.
func TestQuotedTCPHeaderReadsNoEchoPayload(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)

	for _, icmpType := range []uint8{layers.ICMPv4TypeEchoRequest, layers.ICMPv4TypeEchoReply} {
		packet := buildICMPPacket(t, icmpType, 0, quoted)
		if tcp := QuotedTCPHeader(packet); tcp != nil {
			t.Fatalf("QuotedTCPHeader read a header of the ICMP type %d", icmpType)
		}
	}
}

// TestQuotedTCPHeaderReadsNoTruncatedTransportHeader holds the bound that RFC 792 needs.
// An ICMP error message quotes eight bytes of the transport header, and eight bytes hold no
// window and no option.
func TestQuotedTCPHeaderReadsNoTruncatedTransportHeader(t *testing.T) {
	full := buildQuotedTCPHeader(quotedSYNOptions, 64240)
	quoted := buildQuotedIPPacket(full[:8], 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of eight quoted transport bytes")
	}
}

// TestQuotedTCPHeaderReadsNoPayloadThatDeclaresMoreBytesThanItCarries holds the bound of
// the IP total length field. A crafted message declares a length the payload does not hold,
// and the read slices no byte past the end.
func TestQuotedTCPHeaderReadsNoPayloadThatDeclaresMoreBytesThanItCarries(t *testing.T) {
	full := buildQuotedTCPHeader(quotedSYNOptions, 64240)
	quoted := buildQuotedIPPacket(full[:12], 500)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a payload that declares 500 bytes")
	}
}

// TestQuotedTCPHeaderReadsNoHeaderPastTheDeclaredLength holds the second half of the total
// length bound. A declared length below the carried length ends the transport header, and
// the trailing bytes reach no option list.
func TestQuotedTCPHeaderReadsNoHeaderPastTheDeclaredLength(t *testing.T) {
	full := buildQuotedTCPHeader(quotedSYNOptions, 64240)
	quoted := buildQuotedIPPacket(full, uint16(20+len(full)-4))
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header whose data offset passes the declared length")
	}
}

// TestQuotedTCPHeaderReadsNoDataOffsetThatPassesThePayload holds the bound of the TCP data
// offset. A crafted header states a 60-byte header inside 24 carried bytes.
func TestQuotedTCPHeaderReadsNoDataOffsetThatPassesThePayload(t *testing.T) {
	header := buildQuotedTCPHeader(quotedSYNOptions[:4], 64240)
	header[12] = 15 << 4
	quoted := buildQuotedIPPacket(header, 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header whose data offset states 60 bytes")
	}
}

// TestQuotedTCPHeaderReadsNoDataOffsetBelowFiveWords holds the lower bound of the data
// offset. A value below five states a header shorter than the fixed 20 bytes.
func TestQuotedTCPHeaderReadsNoDataOffsetBelowFiveWords(t *testing.T) {
	header := buildQuotedTCPHeader(nil, 64240)
	header[12] = 4 << 4
	quoted := buildQuotedIPPacket(header, 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header whose data offset states four words")
	}
}

// TestQuotedTCPHeaderReadsNoIPHeaderLengthThatPassesThePayload holds the bound of the IP
// header length field.
func TestQuotedTCPHeaderReadsNoIPHeaderLengthThatPassesThePayload(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	quoted[0] = 0x4F
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted[:24])

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a 60-byte IP header inside 24 bytes")
	}
}

// TestQuotedTCPHeaderReadsNoIPHeaderLengthBelowFiveWords holds the lower bound of the IP
// header length field.
func TestQuotedTCPHeaderReadsNoIPHeaderLengthBelowFiveWords(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	quoted[0] = 0x44
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a 16-byte IP header")
	}
}

// TestQuotedTCPHeaderReadsNoLaterFragment bounds the fragment offset. A later fragment of
// the quoted datagram carries no transport header, so the bytes at the header offset hold
// payload.
func TestQuotedTCPHeaderReadsNoLaterFragment(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	binary.BigEndian.PutUint16(quoted[6:8], 1)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a later fragment")
	}
}

// TestQuotedTCPHeaderReadsNoProtocolOtherThanTCP declines a quoted UDP header.
func TestQuotedTCPHeaderReadsNoProtocolOtherThanTCP(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	quoted[9] = byte(layers.IPProtocolUDP)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a quoted UDP datagram")
	}
}

// TestQuotedTCPHeaderReadsNoIPVersionOtherThanFour declines a quoted IPv6 header. No
// capture of the corpus holds an ICMPv6 error message, and this reader decodes none.
func TestQuotedTCPHeaderReadsNoIPVersionOtherThanFour(t *testing.T) {
	quoted := buildQuotedIPPacket(buildQuotedTCPHeader(quotedSYNOptions, 64240), 0)
	quoted[0] = 0x60
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of a quoted IPv6 packet")
	}
}

// TestQuotedTCPHeaderReadsATruncatedMultipathOption bounds one defect of `gopacket`.
//
// `layers/tcp.go:347-353` at v1.6.1 reads `data[1]` and `data[2]` of a Multipath TCP option
// without a length guard, and the `default` branch at `layers/tcp.go:534-538` guards the same
// read. So the option kind `30` as the last byte of the option region panics inside
// `layers.TCP.DecodeFromBytes`. `CLAUDE.md` states that a fingerprinter returns a non-fatal
// error and never a panic, so this reader calls no option decoder of `gopacket`. #510 records
// the defect.
func TestQuotedTCPHeaderReadsATruncatedMultipathOption(t *testing.T) {
	const multipathKind = 30
	header := buildQuotedTCPHeader([]byte{1, 1, 1, multipathKind}, 64240)
	quoted := buildQuotedIPPacket(header, 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	tcp := QuotedTCPHeader(packet)
	if tcp == nil {
		t.Fatalf("QuotedTCPHeader read no header of a well-formed 24-byte quoted header")
	}
	if tcp.Window != 64240 {
		t.Fatalf("the quoted header carries the window %d, and the test needs 64240", tcp.Window)
	}
}

// TestQuotedTCPHeaderReadsAHeaderThatCarriesNoOption reads the shortest quoted header the
// wire permits. The header holds 20 bytes, and its data offset states five words.
//
// The mutation sweep of 2026-08-14 earned this test. Every other test of this file builds an
// option region, so no test reached the lower bound of either length guard, and two surviving
// mutations named that gap. `docs/mutation_settlements/2026-08-14-internal-parser.md` records
// them as S1.
//
//   - `icmp_quoted.go:108` reads `len(transport) < quotedTCPHeaderLength`. The mutant reads
//     `<=`, and it declines a 20-byte transport region.
//   - `icmp_quoted.go:114` reads `dataOffset < quotedTCPHeaderLength`. The mutant reads `<=`,
//     and it declines a data offset of five words.
//
// A SYN that carries no option is well-formed, and `ja4t.go` reads this header, so each
// mutant moves a JA4T value to no value at all.
func TestQuotedTCPHeaderReadsAHeaderThatCarriesNoOption(t *testing.T) {
	header := buildQuotedTCPHeader(nil, 64240)
	if len(header) != quotedTCPHeaderLength {
		t.Fatalf("the test header holds %d bytes, and the lower bound needs %d",
			len(header), quotedTCPHeaderLength)
	}

	quoted := buildQuotedIPPacket(header, 0)
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, quoted)

	tcp := QuotedTCPHeader(packet)
	if tcp == nil {
		t.Fatalf("QuotedTCPHeader read no header of a 20-byte quoted TCP header")
	}
	if !tcp.SYN || tcp.ACK {
		t.Fatalf("the quoted header carries SYN %t and ACK %t", tcp.SYN, tcp.ACK)
	}
	if tcp.DataOffset != 5 {
		t.Fatalf("the quoted header states the data offset %d, and the test needs 5", tcp.DataOffset)
	}
	if tcp.Window != 64240 {
		t.Fatalf("the quoted header carries the window %d, and the test needs 64240", tcp.Window)
	}
	if got := len(tcp.Contents); got != quotedTCPHeaderLength {
		t.Fatalf("the quoted header holds %d content bytes, and the test needs %d",
			got, quotedTCPHeaderLength)
	}
}

// TestQuotedTCPHeaderReadsNoEmptyPayload bounds a message that quotes nothing.
func TestQuotedTCPHeaderReadsNoEmptyPayload(t *testing.T) {
	packet := buildICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 13, nil)

	if tcp := QuotedTCPHeader(packet); tcp != nil {
		t.Fatalf("QuotedTCPHeader read a header of an empty payload")
	}
}

// TestQuotedTCPHeaderReadsNoPacketWithoutAnICMPLayer bounds the caller of a TCP packet.
func TestQuotedTCPHeaderReadsNoPacketWithoutAnICMPLayer(t *testing.T) {
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
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, SYN: true, Window: 1024}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("the serializer failed: %v", err)
	}
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	if held := QuotedTCPHeader(packet); held != nil {
		t.Fatalf("QuotedTCPHeader read a header of a packet that carries no ICMP layer")
	}
}
