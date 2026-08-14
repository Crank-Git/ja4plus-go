package ja4plus

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

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
// decides the character there. `zeek/ja4d/main.zeek:73` tests `options?$client_fqdn`, so
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
