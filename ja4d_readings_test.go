package ja4plus

import (
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

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
// alone, and `zeek/ja4d/main.zeek:43-45` emits `00000`. Two references against one keep
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
