package ja4plus

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestJA4D6_MessageTypeMapping(t *testing.T) {
	tests := []struct {
		code byte
		want string
	}{
		{1, "solct"},
		{2, "advrt"},
		{3, "reqst"},
		{7, "reply"},
		{8, "relse"},
		{11, "inreq"},
	}
	for _, tt := range tests {
		got, ok := dhcpv6MessageMap[tt.code]
		if !ok {
			t.Errorf("missing dhcpv6 message type %d", tt.code)
			continue
		}
		if got != tt.want {
			t.Errorf("dhcpv6 type %d: got %q, want %q", tt.code, got, tt.want)
		}
		if len(got) != 5 {
			t.Errorf("dhcpv6 type %d: abbreviation %q is not 5 chars", tt.code, got)
		}
	}
}

func TestJA4D6_FormatList(t *testing.T) {
	tests := []struct {
		name   string
		values []uint16
		want   string
	}{
		{"empty", nil, "00"},
		{"single", []uint16{1}, "1"},
		{"multiple", []uint16{25, 26, 1, 2}, "25-26-1-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ja4d6FormatU16List(tt.values)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJA4D6_Reset(t *testing.T) {
	// JA4D6 holds no state, so Reset changes no result. Issue #25 removed the results
	// slice, which grew without a bound and which no exported method read.
	f := NewJA4D6()
	pkt := buildDHCPv6SolicitPacket(t)

	before, err := f.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("the DHCPv6 message produced %d results, want 1", len(before))
	}

	f.Reset()

	after, err := f.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(after) != 1 || after[0].Fingerprint != before[0].Fingerprint {
		t.Errorf("the read after Reset produces %v, and the read before it produces %v", after, before)
	}
}

func TestJA4D6_ImplementsFingerprinter(t *testing.T) {
	var _ Fingerprinter = NewJA4D6()
}

// TestJA4D6_FoxIODHCPv6Vectors runs JA4D6 against testdata/foxio/pcap/dhcpv6.pcap
// and asserts the per-packet fingerprints match the FoxIO Wireshark vectors.
// Skipped when the fixture is not present.
func TestJA4D6_FoxIODHCPv6Vectors(t *testing.T) {
	pcapPath := "testdata/foxio/pcap/dhcpv6.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("fixture %s not present; skipping FoxIO vector test", pcapPath)
	}

	packets := loadPCAP(t, pcapPath)

	expected := map[int]string{
		2:  "solct0014nn_1-6-8-25_23-24",
		5:  "advrt0014nn_25-26-1-2_00",
		7:  "reqst0014nn_1-2-6-8-25-26_23-24",
		8:  "reply0014nn_25-26-1-2_00",
		11: "relse0014nn_1-2-6-8-25-26_23-24",
		12: "reply0014nn_1-2-13_00",
	}

	fp := NewJA4D6()
	frame := 0
	matched := 0
	for _, pkt := range packets {
		frame++
		results, err := fp.ProcessPacket(pkt)
		if err != nil {
			t.Errorf("frame %d: ProcessPacket error: %v", frame, err)
			continue
		}
		want, hasExpected := expected[frame]
		if !hasExpected {
			continue
		}
		if len(results) == 0 {
			t.Errorf("frame %d: expected fingerprint %q, got none", frame, want)
			continue
		}
		got := results[0].Fingerprint
		if got != want {
			t.Errorf("frame %d: got %q, want %q", frame, got, want)
		} else {
			matched++
		}
	}
	if matched != len(expected) {
		t.Errorf("matched %d of %d expected vectors", matched, len(expected))
	}
}

// FuzzComputeJA4D6ReadsAnyFrame proves that the DHCPv6 reader returns for any Ethernet
// frame. FR-fuzz-11 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
//
// `ComputeJA4D6` is the entry point of the DHCPv6 reader of this library. `ja4d6.go`
// reads every option, and it descends into a relay message.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
func FuzzComputeJA4D6ReadsAnyFrame(f *testing.F) {
	// The reader accepts each seed below. The first carries one SOLICIT message. The
	// second carries one RELAY-FORW message that holds the SOLICIT message inside it, so
	// the fuzzer reaches the relay descent.
	f.Add(buildDHCPv6Packet(f, dhcpv6SolicitBytes()).Data())
	f.Add(buildDHCPv6Packet(f, dhcpv6RelayForwardBytes(1, dhcpv6SolicitBytes())).Data())

	// The reader writes no value for each seed below. The first holds no byte. The second
	// states an option length of 65535 bytes that the message does not hold.
	f.Add([]byte{})
	f.Add(buildDHCPv6Packet(f, []byte{
		0x01, 0xaa, 0xbb, 0xcc, 0x00, 0x01, 0xff, 0xff, 0x00,
	}).Data())

	f.Fuzz(func(t *testing.T, frame []byte) {
		input := fuzzprop.ExactInput(frame)

		fuzzprop.Check(t, len(input), func() any {
			// Each call decodes one packet of its own. A `gopacket` packet caches the layer
			// it decodes, so a shared packet would make the second call read a cache rather
			// than the frame.
			packet := gopacket.NewPacket(input, layers.LayerTypeEthernet, gopacket.Default)

			return ComputeJA4D6(packet)
		})
	})
}

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
// `levels` relay messages around the inner message.
func dhcpv6NestedRelayBytes(levels int, inner []byte) []byte {
	message := inner
	for i := 0; i < levels; i++ {
		message = dhcpv6RelayForwardBytes(byte(i%256), message)
	}
	return message
}

// TestJA4D6ReadsTheInnerMessageOfARelayMessage holds the reading of issue #370.
//
// `wireshark/source/packet-ja4.c:1500-1578` reads one flat array of the fields of the
// whole dissection tree, and it matches each field on the field name alone. So every
// option of the inner message reaches the value. R19 of `docs/specs/foxio/JA4D6.md`
// records that it reads `dhcpv6.option.type`, and R20 records that part b skips no
// option. R11 and R23 record the same field-name read for the client DUID length and for
// the option request list.
//
// The port ships this rule at `ja4plus/fingerprinters/ja4d6.py:161-165`, at tag `v1.1.0`.
// The port's issue #271 records the reading as D1 and D2.
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

// TestJA4D6ReadsASubfieldOptionOfANestedContainer holds the second half of the reading of
// issue #370.
//
// R11 and R23 of `docs/specs/foxio/JA4D6.md` record that the dissector matches
// `dhcpv6.duid.bytes` and `dhcpv6.requested_option_code` on the field name alone, so a
// container option carries them to the value as an inner message does. The port reads the
// four subfield options at every depth, at `ja4plus/fingerprinters/ja4d6.py:159` of tag
// `v1.1.0`, which calls the subfield reader for every option of the walk.
//
// The message below carries the Client Identifier and the Option Request option inside
// one IA_NA container. No capture of the corpus carries that shape, and the eight
// conformance figures prove it.
func TestJA4D6ReadsASubfieldOptionOfANestedContainer(t *testing.T) {
	// RFC 8415 section 21.4 gives IA_NA a 12-byte header of an IAID, a T1 and a T2.
	iana := make([]byte, 12)
	iana = append(iana, dhcpv6OptionBytes(1, dhcpv6ClientDUID)...)
	iana = append(iana, dhcpv6OptionBytes(6, []byte{0x00, 0x17})...)
	message := []byte{0x01, 0x00, 0x01, 0x02}
	message = append(message, dhcpv6OptionBytes(3, iana)...)

	const want = "solct0014nn_3-1-6_23"
	if got := ComputeJA4D6(buildDHCPv6Packet(t, message)); got != want {
		t.Errorf("the nested container reaches %q, want %q", got, want)
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
