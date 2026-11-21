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

func TestJA4D_MessageTypeMapping(t *testing.T) {
	tests := []struct {
		code byte
		want string
	}{
		{1, "disco"},
		{2, "offer"},
		{3, "reqst"},
		{4, "decln"},
		{5, "dpack"},
		{6, "dpnak"},
		{7, "relse"},
		{8, "infor"},
		{9, "frenw"},
		{10, "lqery"},
		{18, "dhtls"},
	}
	for _, tt := range tests {
		got, ok := dhcpMessageMap[tt.code]
		if !ok {
			t.Errorf("missing message type %d", tt.code)
			continue
		}
		if got != tt.want {
			t.Errorf("message type %d: got %q, want %q", tt.code, got, tt.want)
		}
		if len(got) != 5 {
			t.Errorf("message type %d: abbreviation %q is not 5 chars", tt.code, got)
		}
	}
}

func TestJA4D_FormatList(t *testing.T) {
	tests := []struct {
		name   string
		values []byte
		want   string
	}{
		{"empty", nil, "00"},
		{"single", []byte{61}, "61"},
		{"multiple presence-order", []byte{61, 55}, "61-55"},
		{"params", []byte{1, 3, 6, 42}, "1-3-6-42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ja4dFormatList(tt.values)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJA4D_Reset(t *testing.T) {
	// JA4D holds no state, so Reset changes no result. Issue #25 removed the results
	// slice, which grew without a bound and which no exported method read.
	f := NewJA4D()
	pkt := buildDHCPDiscoverPacket(t)

	before, err := f.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("the DHCP message produced %d results, want 1", len(before))
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

func TestJA4D_ImplementsFingerprinter(t *testing.T) {
	var _ Fingerprinter = NewJA4D()
}

// TestJA4D_FoxIODHCPVectors runs JA4D against testdata/foxio/pcap/dhcp.pcapng
// and asserts the per-packet fingerprints match the FoxIO Wireshark vectors.
// Skipped when the fixture is not present.
func TestJA4D_FoxIODHCPVectors(t *testing.T) {
	pcapPath := "testdata/foxio/pcap/dhcp.pcapng"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("fixture %s not present; skipping FoxIO vector test", pcapPath)
	}

	packets := loadPCAP(t, pcapPath)

	// Expected fingerprints by frame number (1-indexed).
	expected := map[int]string{
		1: "disco0000in_61-55_1-3-6-42",
		2: "offer0000nn_1-58-59-51-54_00",
		3: "reqst0000in_61-54-55_1-3-6-42",
		4: "dpack0000nn_58-59-51-54-1_00",
	}

	fp := NewJA4D()
	frame := 0
	matched := 0
	for _, pkt := range packets {
		frame++
		results, err := fp.ProcessPacket(pkt)
		if err != nil {
			t.Errorf("frame %d: ProcessPacket error: %v", frame, err)
			continue
		}
		if len(results) == 0 {
			continue
		}
		got := results[0].Fingerprint
		want, ok := expected[frame]
		if !ok {
			continue
		}
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

// fuzzDHCPv4Discover returns the bytes of one DHCPDISCOVER message.
//
// The fixed part of a DHCPv4 message is 236 bytes, and the magic cookie and the options
// follow it. The message names three options.
//   - Option 53, the message type.
//   - Option 55, the parameter request list.
//   - Option 255, the end.
func fuzzDHCPv4Discover() []byte {
	message := make([]byte, 236)
	message[0] = 0x01 // The operation code of a request.
	message[1] = 0x01 // The hardware type of Ethernet.
	message[2] = 0x06 // The hardware address length of Ethernet.
	copy(message[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(message[28:34], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})

	message = append(message, 0x63, 0x82, 0x53, 0x63)
	message = append(message, 0x35, 0x01, 0x01)
	message = append(message, 0x37, 0x04, 0x01, 0x03, 0x06, 0x0f)
	message = append(message, 0x3d, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01)

	return append(message, 0xff)
}

// FuzzComputeJA4DReadsAnyFrame proves that the DHCPv4 reader returns for any Ethernet
// frame. FR-fuzz-10 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
//
// `ComputeJA4D` is the entry point of the DHCPv4 reader of this library. `gopacket`
// decodes the DHCPv4 layer, and `ja4d.go` reads every option of it.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
func FuzzComputeJA4DReadsAnyFrame(f *testing.F) {
	// The reader accepts this seed. It carries one DHCPDISCOVER message from the client
	// port to the server port.
	f.Add(panicAuditFrame(f, "udp", 68, 67, fuzzDHCPv4Discover()))

	// The reader writes no value for each seed below.
	//   - The first holds no byte.
	//   - The second holds a 34-byte message. `gopacket` at v1.6.1 refuses a DHCPv4
	//     message under 240 bytes at `layers/dhcpv4.go:126`, and it reads no option of
	//     this message at all.
	//   - The third carries the message on a port that is not a DHCP port.
	f.Add([]byte{})
	f.Add(panicAuditFrame(f, "udp", 68, 67, []byte{
		0x01, 0x01, 0x06, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	}))
	f.Add(panicAuditFrame(f, "udp", 12345, 443, fuzzDHCPv4Discover()))

	f.Fuzz(func(t *testing.T, frame []byte) {
		input := fuzzprop.ExactInput(frame)

		fuzzprop.Check(t, len(input), func() any {
			// Each call decodes one packet of its own. A `gopacket` packet caches the layer
			// it decodes, so a shared packet would make the second call read a cache rather
			// than the frame.
			packet := gopacket.NewPacket(input, layers.LayerTypeEthernet, gopacket.Default)

			return ComputeJA4D(packet)
		})
	})
}

// TestJA4DWritesTheDomainNameFlagFromTheNameInOption81 holds the ruling of issue #371,
// which the maintainer made on 2026-08-14.
//
// The ruling states that part a writes `n` when option 81 carries no domain name, and `d`
// when it carries one. The presence of option 81 decides nothing. R16 of
// `docs/specs/foxio/JA4D.md` records the rank 1 image label
// `Has a Domain name (d) or No domain (n)`, and `.claude/rules/rulings.md`
// `## The source ranking` places an image above every implementation.
//
// `wireshark/source/packet-ja4.c:1521` tests the field `dhcp.fqdn.name`, so the name
// decides the character there. `zeek/scripts/fingerprints/ja4d/main.zeek:66` tests `options?$client_fqdn`, so
// the presence decides it there. The ruling declines the Zeek answer, because the image
// outranks it. The port ships the same rule at `ja4plus/fingerprinters/ja4d.py:161-165` of
// tag `v1.1.0`, and the port half of the ruling is `Crank-Git/ja4plus#615`.
//
// The corpus holds four DHCPv4 messages and no option 81, so no vector separates the two
// answers. `.claude/rules/rulings.md` `## Where a ruling is recorded` therefore requires
// this constructed packet. The test fails when a later change restores the presence rule.
func TestJA4DWritesTheDomainNameFlagFromTheNameInOption81(t *testing.T) {
	// RFC 4702 puts the domain name of option 81 after one flags byte and two rcode
	// bytes. The port holds the same offset as `_DHCP_FQDN_NAME_OFFSET`.
	cases := []struct {
		name    string
		data    []byte
		want    byte
		because string
	}{
		{
			name:    "option 81 carries a domain name",
			data:    []byte{0x00, 0x00, 0x00, 'h', 'o', 's', 't'},
			want:    'd',
			because: "four name bytes follow the flags byte and the two rcode bytes",
		},
		{
			name:    "option 81 carries no domain name",
			data:    []byte{0x00, 0x00, 0x00},
			want:    'n',
			because: "the option stops at the two rcode bytes, so no name byte follows",
		},
		{
			name:    "option 81 carries no byte at all",
			data:    []byte{},
			want:    'n',
			because: "an empty option holds no flags byte and no name byte",
		},
		{
			name:    "option 81 carries one name byte",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			want:    'd',
			because: "the port reads one byte past the offset as a name",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := buildDHCPPacketWithOptions(t, layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
				layers.NewDHCPOption(81, c.data),
			})

			fp := ComputeJA4D(pkt)
			if fp == "" {
				t.Fatal("the DHCP message produced no JA4D value")
			}
			partA := strings.Split(fp, "_")[0]
			if len(partA) != 11 {
				t.Fatalf("part a holds %d characters, want 11; part a is %q", len(partA), partA)
			}
			if got := partA[10]; got != c.want {
				t.Errorf("the domain name flag is %q, want %q, because %s; the whole value is %q",
					string(got), string(c.want), c.because, fp)
			}
		})
	}
}

// TestJA4DReadsOption81OfEveryLengthWithoutAPanic holds the bounds rule of `CLAUDE.md`,
// which states that every packet is untrusted input.
//
// Option 81 carries a length byte, so a crafted message can stop the option inside the
// flags field or inside the rcode fields. The fingerprinter reads the length of the option
// data and it slices no byte, so no length reaches a panic.
func TestJA4DReadsOption81OfEveryLengthWithoutAPanic(t *testing.T) {
	for length := 0; length <= 8; length++ {
		data := make([]byte, length)
		pkt := buildDHCPPacketWithOptions(t, layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
			layers.NewDHCPOption(81, data),
		})

		fp := NewJA4D()
		results, err := fp.ProcessPacket(pkt)
		if err != nil {
			t.Fatalf("ProcessPacket returned the error %v for an option 81 of %d bytes", err, length)
		}
		if len(results) != 1 {
			t.Fatalf("the DHCP message produced %d results for an option 81 of %d bytes, want 1", len(results), length)
		}
	}
}

// buildDHCPPacketWithOptions returns one DHCP packet on UDP port 67 that carries the
// named options in the named order. JA4D reads the options and no other field.
func buildDHCPPacketWithOptions(tb testing.TB, options layers.DHCPOptions) gopacket.Packet {
	tb.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{0, 0, 0, 0},
		DstIP:    net.IP{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	_ = udp.SetNetworkLayerForChecksum(ip)

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x12345678,
		ClientHWAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		Options:      options,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dhcp); err != nil {
		tb.Fatalf("the serializer returned the error %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestJA4DKeepsTheFirstMaximumMessageSizeWhenAMessageRepeatsOption57 holds FR-parity-51
// of `docs/specs/features/08-python-parity.md`.
//
// The port's register row `Subfield 2 of JA4D when a message repeats option 57` holds the
// reading, and the port decided it as D4 of its issue #231 on 2026-08-08. R2 of
// `docs/specs/foxio/JA4D.md` gives part a eleven characters and subfield 2 four of them,
// and the image decides schema. `wireshark/source/packet-ja4.c:1508-1512` appends `"%04d"`
// on each occurrence and reaches a part a of fifteen characters, and this project declines
// that defect. `ja4plus/fingerprinters/ja4d.py:153-158` of the port holds the same guard.
//
// No FoxIO vector carries a repeated option 57, so this constructed packet is the
// separating input that `.claude/rules/rulings.md` requires.
func TestJA4DKeepsTheFirstMaximumMessageSizeWhenAMessageRepeatsOption57(t *testing.T) {
	pkt := buildDHCPPacketWithOptions(t, layers.DHCPOptions{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		// 0x05dc is 1500, and 0x2400 is 9216. The two differ, so the value names the guard.
		layers.NewDHCPOption(layers.DHCPOptMaxMessageSize, []byte{0x05, 0xdc}),
		layers.NewDHCPOption(layers.DHCPOptMaxMessageSize, []byte{0x24, 0x00}),
	})

	fp := ComputeJA4D(pkt)
	if fp == "" {
		t.Fatal("the DHCP message produced no JA4D value")
	}
	partA := strings.Split(fp, "_")[0]
	if got := partA[5:9]; got != "1500" {
		t.Errorf("subfield 2 holds %q, want %q; the whole value is %q", got, "1500", fp)
	}
}

// TestJA4DWritesElevenCharactersInPartA holds FR-parity-52 of
// `docs/specs/features/08-python-parity.md`. R2 of `docs/specs/foxio/JA4D.md` gives part a
// eleven characters: five for the message type, four for the maximum message size, one for
// the requested address flag and one for the domain name flag.
func TestJA4DWritesElevenCharactersInPartA(t *testing.T) {
	cases := []struct {
		name    string
		options layers.DHCPOptions
	}{
		{
			name: "every subfield holds a value",
			options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
				layers.NewDHCPOption(layers.DHCPOptMaxMessageSize, []byte{0x05, 0xdc}),
				layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{192, 168, 1, 10}),
				layers.NewDHCPOption(81, []byte{0x00, 0x00, 0x00, 'h', 'o', 's', 't'}),
			},
		},
		{
			name: "no option 57 and no option 50",
			options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
			},
		},
		{
			name: "the message type reaches no abbreviation",
			options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{99}),
			},
		},
		{
			name: "the maximum message size passes 9999",
			options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
				layers.NewDHCPOption(layers.DHCPOptMaxMessageSize, []byte{0xff, 0xff}),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp := ComputeJA4D(buildDHCPPacketWithOptions(t, c.options))
			if fp == "" {
				t.Fatal("the DHCP message produced no JA4D value")
			}
			partA := strings.Split(fp, "_")[0]
			if len(partA) != 11 {
				t.Errorf("part a holds %d characters, want 11; part a is %q", len(partA), partA)
			}
		})
	}
}

// TestJA4DEmitsNoValueForABootpMessageThatHoldsNoMessageType holds FR-parity-53 of
// `docs/specs/features/08-python-parity.md`.
//
// The port's register row `JA4D on a BOOTP message that carries no option 53` holds the
// reading, and the port decided it as D2 of its issue #231 on 2026-08-08.
// `wireshark/source/packet-ja4.c:1498` sets the emit flag inside the option 53 block
// alone, and `zeek/scripts/fingerprints/ja4d/main.zeek:36-38` emits `00000`. Two references against one keep
// this reading.
//
// No FoxIO vector carries a BOOTP message, so this constructed packet is the separating
// input.
func TestJA4DEmitsNoValueForABootpMessageThatHoldsNoMessageType(t *testing.T) {
	pkt := buildDHCPPacketWithOptions(t, layers.DHCPOptions{
		layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 42}),
	})

	fp := NewJA4D()
	results, err := fp.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}
	if len(results) != 0 {
		t.Errorf("the BOOTP message produced %d results, want 0; the first is %q", len(results), results[0].Fingerprint)
	}
}
