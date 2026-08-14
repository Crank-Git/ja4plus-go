package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// dhcpv6ClientDUID is the 14-byte DUID that the inner Client Identifier carries.
var dhcpv6ClientDUID = []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

// dhcpv6OptionBytes returns the wire form of one DHCPv6 option.
// RFC 8415 section 21.1 gives the option a two-byte code, a two-byte length and the data.
func dhcpv6OptionBytes(code uint16, data []byte) []byte {
	out := []byte{byte(code >> 8), byte(code), byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

// dhcpv6SolicitBytes returns the wire form of one SOLICIT message.
// The message carries a Client Identifier and an Option Request option.
func dhcpv6SolicitBytes() []byte {
	out := []byte{0x01, 0x00, 0x01, 0x02}
	out = append(out, dhcpv6OptionBytes(1, dhcpv6ClientDUID)...)
	out = append(out, dhcpv6OptionBytes(6, []byte{0x00, 0x17, 0x00, 0x18})...)
	return out
}

// dhcpv6RelayForwardBytes returns the wire form of one RELAY-FORW message that carries
// the inner message in option 9, Relay Message. RFC 8415 section 9 gives the message a
// one-byte type, a one-byte hop count, a 16-byte link address and a 16-byte peer address.
func dhcpv6RelayForwardBytes(hopCount byte, inner []byte) []byte {
	out := []byte{12, hopCount}
	out = append(out, net.ParseIP("2001:db8::1").To16()...)
	out = append(out, net.ParseIP("fe80::2").To16()...)
	out = append(out, dhcpv6OptionBytes(9, inner)...)
	return out
}

// buildDHCPv6Packet returns one DHCPv6 packet on UDP port 547 that carries the raw
// DHCPv6 message. The caller builds the message, so the test reaches a relay message that
// the gopacket serializer writes no field for.
func buildDHCPv6Packet(tb testing.TB, message []byte) gopacket.Packet {
	tb.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("ff02::1:2"),
	}
	udp := &layers.UDP{SrcPort: 547, DstPort: 547}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(message)); err != nil {
		tb.Fatalf("the serializer returned the error %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestJA4D6WritesTheOuterMessageTypeAloneOnARelayMessage holds FR-parity-54 and
// FR-parity-56 of `docs/specs/features/08-python-parity.md`.
//
// The port's register row `Subfield 1 of JA4D6 on a relay message` holds the reading, and
// the port decided it as D3 of its issue #271 on 2026-08-08. R2 of
// `docs/specs/foxio/JA4D.md` gives part a eleven characters and subfield 1 five of them,
// and the image decides schema. `wireshark/source/packet-ja4.c:1537-1546` appends a
// five-character name for every `dhcpv6.msgtype` field, so it writes `rlayfsolct` and a
// part a of sixteen characters. This project declines that defect.
//
// No FoxIO vector carries a relay message, so these constructed packets are the
// separating input that `.claude/rules/rulings.md` requires.
func TestJA4D6WritesTheOuterMessageTypeAloneOnARelayMessage(t *testing.T) {
	cases := []struct {
		name    string
		message []byte
	}{
		{
			name:    "a relay carries a solicit",
			message: dhcpv6RelayForwardBytes(0, dhcpv6SolicitBytes()),
		},
		{
			// The edge-case table of #57 names this input. Subfield 1 writes the outermost
			// type, and never the type of a nested message.
			name:    "a relay carries a relay",
			message: dhcpv6RelayForwardBytes(1, dhcpv6RelayForwardBytes(0, dhcpv6SolicitBytes())),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp := ComputeJA4D6(buildDHCPv6Packet(t, c.message))
			if fp == "" {
				t.Fatal("the relay message produced no JA4D6 value")
			}
			partA := strings.Split(fp, "_")[0]
			if got := partA[:5]; got != "rlayf" {
				t.Errorf("subfield 1 holds %q, want %q; the whole value is %q", got, "rlayf", fp)
			}
			if strings.Contains(partA, "solct") {
				t.Errorf("part a %q holds the type of a nested message", partA)
			}
		})
	}
}

// dhcpv6NestedRelayBytes returns the wire form of one RELAY-FORW message that nests
// levels relay messages around the inner message.
func dhcpv6NestedRelayBytes(levels int, inner []byte) []byte {
	message := inner
	for i := 0; i < levels; i++ {
		message = dhcpv6RelayForwardBytes(byte(i%256), message)
	}
	return message
}

// TestJA4D6ReadsTheInnerMessageOfARelayMessage holds the reading of issue #370.
//
// The Wireshark dissector reads a field name over the whole dissection tree, so every
// option of the inner message reaches the value. R19 of `docs/specs/foxio/JA4D6.md`
// records that it reads `dhcpv6.option.type`, and R20 records that part b skips no
// option. R11 and R23 record the same field-name read for the client DUID length and for
// the option request list.
//
// The port ships this rule at `ja4plus/fingerprinters/ja4d6.py:161-165`, at tag `v1.1.0`.
// Its issue #271 records the reading as D1 and D2.
//
// No FoxIO vector carries a relay message, so this constructed packet is the separating
// input that `.claude/rules/rulings.md` requires.
func TestJA4D6ReadsTheInnerMessageOfARelayMessage(t *testing.T) {
	solicit := dhcpv6SolicitBytes()
	cases := []struct {
		name    string
		message []byte
		want    string
	}{
		{
			// The inner solicit carries a 14-byte client DUID and an option request list
			// of 23 and 24. Part b holds option 9 and then the two inner options.
			name:    "a relay carries a solicit",
			message: dhcpv6RelayForwardBytes(0, solicit),
			want:    "rlayf0014nn_9-1-6_23-24",
		},
		{
			// Part a holds the outermost message type, and part b holds one option 9 for
			// each relay message.
			name:    "a relay carries a relay",
			message: dhcpv6RelayForwardBytes(1, dhcpv6RelayForwardBytes(0, solicit)),
			want:    "rlayf0014nn_9-9-1-6_23-24",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputeJA4D6(buildDHCPv6Packet(t, c.message)); got != c.want {
				t.Errorf("the relay message reaches %q, want %q", got, c.want)
			}
		})
	}
}

// TestJA4D6StopsTheRelayDescentAtTheNestingBound proves the bound of issue #370.
//
// A crafted relay message nests one message inside another without a limit, so an
// unbounded descent exhausts the stack. The walk enters 32 containers at most, which is
// the bound the port states at `ja4plus/fingerprinters/ja4d6.py:115`, at tag `v1.1.0`.
//
// The message below nests 40 relay messages around a solicit. Part b therefore holds 33
// option codes: one for the option 9 of each level the walk reads. The solicit sits below
// the bound, so subfield 2 reads `0000` and part c reads `00`.
func TestJA4D6StopsTheRelayDescentAtTheNestingBound(t *testing.T) {
	message := dhcpv6NestedRelayBytes(40, dhcpv6SolicitBytes())
	codes := make([]string, maxDHCPv6NestingDepth+1)
	for i := range codes {
		codes[i] = "9"
	}
	want := "rlayf0000nn_" + strings.Join(codes, "-") + "_00"
	if got := ComputeJA4D6(buildDHCPv6Packet(t, message)); got != want {
		t.Errorf("the nested relay message reaches %q, want %q", got, want)
	}
}

// TestJA4D6ReadsATruncatedRelayMessageWithoutAPanic proves the bounds check of the
// descent. Every packet is untrusted input, so the walk reads a relay message whose data
// is shorter than the header it declares.
func TestJA4D6ReadsATruncatedRelayMessageWithoutAPanic(t *testing.T) {
	cases := []struct {
		name  string
		inner []byte
		want  string
	}{
		{
			// The inner message is shorter than the four-byte header of an ordinary
			// message, so the walk reads no inner option.
			name:  "the inner message holds two bytes",
			inner: []byte{0x01, 0x00},
			want:  "rlayf0000nn_9_00",
		},
		{
			// The inner message declares the relay type, and it is shorter than the
			// 34-byte relay header.
			name:  "the inner relay message holds ten bytes",
			inner: []byte{12, 0, 1, 2, 3, 4, 5, 6, 7, 8},
			want:  "rlayf0000nn_9_00",
		},
		{
			// The inner option declares a length that runs past the inner message.
			name:  "the inner option overruns the message",
			inner: []byte{0x01, 0x00, 0x01, 0x02, 0x00, 0x06, 0x7f, 0xff},
			want:  "rlayf0000nn_9_00",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputeJA4D6(buildDHCPv6Packet(t, dhcpv6RelayForwardBytes(0, c.inner))); got != c.want {
				t.Errorf("the truncated relay message reaches %q, want %q", got, c.want)
			}
		})
	}
}

// TestJA4D6WritesElevenCharactersInPartA holds FR-parity-55 of
// `docs/specs/features/08-python-parity.md`. R2 of `docs/specs/foxio/JA4D.md` gives part a
// eleven characters: five for the message type, four for the client identifier length, one
// for the address flag and one for the domain name flag.
func TestJA4D6WritesElevenCharactersInPartA(t *testing.T) {
	solicit := dhcpv6SolicitBytes()
	cases := []struct {
		name    string
		message []byte
	}{
		{"a solicit", solicit},
		{"a relay carries a solicit", dhcpv6RelayForwardBytes(0, solicit)},
		{"a relay carries a relay", dhcpv6RelayForwardBytes(1, dhcpv6RelayForwardBytes(0, solicit))},
		{"the message type reaches no abbreviation", append([]byte{99, 0x00, 0x01, 0x02}, dhcpv6OptionBytes(6, []byte{0x00, 0x17})...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp := ComputeJA4D6(buildDHCPv6Packet(t, c.message))
			if fp == "" {
				t.Fatal("the DHCPv6 message produced no JA4D6 value")
			}
			partA := strings.Split(fp, "_")[0]
			if len(partA) != 11 {
				t.Errorf("part a holds %d characters, want 11; part a is %q", len(partA), partA)
			}
		})
	}
}
