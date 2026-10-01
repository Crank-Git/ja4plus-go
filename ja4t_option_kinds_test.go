package ja4plus

import (
	"slices"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// Part b of JA4T and JA4TS writes the decimal kind of every option the packet carries, and
// not the kinds of a fixed name list. #808 records the defect.
//
// Every FoxIO implementation writes each kind it reads, at FoxIO `16b96d95`.
// `rust/ja4/src/tcp.rs:70` pushes every `tcp.option_kind`, and
// `wireshark/source/packet-ja4.c:1456-1458` appends every `tcp.option_kind` with `"%d-"`.
// `zeek/src/ja4t.cc:69-75` pushes every kind except kind 0, and `docs/specs/foxio/JA4T.md`
// R10 records that one exception as the split that #297 ruled. The port appends every kind
// at `ja4plus/utils/tcp_options.py:112-114`, at tag `v1.3.0`.

// tcpOptionFastOpenCookieRequest returns a TCP Fast Open option that carries no cookie.
// RFC 7413 section 4.1.1 gives that option kind 34 and length 2.
func tcpOptionFastOpenCookieRequest() layers.TCPOption {
	return layers.TCPOption{OptionType: 34, OptionLength: 2}
}

// tcpOptionMultipathCapable returns the MP_CAPABLE option of a version 1 SYN.
// RFC 8684 section 3.1 gives that option kind 30 and length 4. The first data byte holds
// subtype 0 and version 1, and the second byte holds the flags.
func tcpOptionMultipathCapable() layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindMultipathTCP,
		OptionLength: 4,
		OptionData:   []byte{0x01, 0x81},
	}
}

// The option list below reaches eleven bytes, so gopacket adds one pad byte of kind 0.
func TestJA4TWritesTheTCPFastOpenKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionFastOpenCookieRequest(),
		tcpOptionSACKPermitted(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-34-4-3-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the TCP Fast Open option: got %q, want %q", got, want)
	}
}

// The option list below reaches eleven bytes, so gopacket adds one pad byte of kind 0.
func TestJA4TWritesTheMultipathTCPKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionMultipathCapable(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-30-3-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the Multipath TCP option: got %q, want %q", got, want)
	}
}

// A SYN-ACK reaches the same rule, because JA4T and JA4TS share one builder. The option
// list below reaches thirteen bytes, so gopacket adds three pad bytes of kind 0.
func TestJA4TSWritesTheMultipathTCPKindAndTheTCPFastOpenKind(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionMultipathCapable(),
		tcpOptionFastOpenCookieRequest(),
		tcpOptionWindowScale(7),
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 64240, options)

	got := ComputeJA4TS(pkt)
	want := "64240_2-30-34-3-0-0-0_1460_7"
	if got != want {
		t.Errorf("JA4TS for the two options: got %q, want %q", got, want)
	}
}

// An option kind that no RFC names still reaches part b, and its data sets neither value.
// Kind 253 is an experimental kind under RFC 4727, and kind 255 needs three digits.
func TestTCPOptionEntriesWritesTheDecimalKindOfAnUnnamedOption(t *testing.T) {
	region := []byte{0xfd, 0x04, 0x05, 0xb4, 0xff, 0x03, 0x07, 0x01}
	entries, mss, wscale := tcpOptionEntries(region)
	want := []string{"253", "255", "1"}
	if !slices.Equal(entries, want) {
		t.Errorf("entries: got %v, want %v", entries, want)
	}
	if mss != 0 || wscale != 0 {
		t.Errorf("an unnamed option set a value: segment size %d, window scale %d", mss, wscale)
	}
}

// An unnamed kind carries a length byte, so the bounds checks of a length field apply to
// it. Each region below states a length that the region does not hold.
func TestTCPOptionEntriesStopsAtAMalformedLengthOfAnUnnamedOption(t *testing.T) {
	cases := []struct {
		name   string
		region []byte
		want   []string
	}{
		{"the region ends before the length byte", []byte{0x01, 0x22}, []string{"1"}},
		{"the length byte states zero", []byte{0x22, 0x00, 0x01}, nil},
		{"the length byte states one", []byte{0x1e, 0x01, 0x01}, nil},
		{"the length exceeds the region", []byte{0x1e, 0x0c, 0x01, 0x81}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, _, _ := tcpOptionEntries(c.region)
			if !slices.Equal(entries, c.want) {
				t.Errorf("entries: got %v, want %v", entries, c.want)
			}
		})
	}
}
