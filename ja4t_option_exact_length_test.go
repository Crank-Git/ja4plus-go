package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// JA4T and JA4TS read the maximum segment size only from an option of length 4, and the
// window scale only from an option of length 3. The maintainer ruled this on 2026-10-01
// UTC, and #814 holds the ruling and is the reversal path.
//
// The port holds the same rule at `ja4plus/utils/tcp_options.py:115-118`, at tag `v1.3.0`
// of Crank-Git/ja4plus. FoxIO `rust/ja4/src/tcp.rs:76-82` and
// `wireshark/source/packet-ja4.c:1460-1466` at `16b96d95` read the field that Wireshark
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
