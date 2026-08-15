package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Part b of JA4T and JA4TS holds one entry for each option byte the packet carries. The
// maintainer ruled that count on 2026-08-12, and #297 records the ruling.
//
// `github.com/google/gopacket@v1.1.19` at `layers/tcp.go:279-282` appends one option for
// the first End-of-Option-List byte, assigns the rest of the header to `tcp.Padding`, and
// runs `break OPTIONS`. A reader of `tcp.Options` therefore counts one entry, whatever the
// packet carries. The library reads `tcp.Contents` instead.
// #438 moved this project to `github.com/gopacket/gopacket@v1.6.1`, and that fork keeps
// this reading at `layers/tcp.go:338-344`. So the library still reads `tcp.Contents`.
//
// Four sources write one entry for each byte, and one source writes none.
// `wireshark/source/packet-ja4.c:1456` appends one entry for each `tcp.option_kind` field
// occurrence, and `rust/ja4/src/tcp.rs:70` reads that same field list. The port reads the
// raw option bytes in `ja4plus/utils/tcp_options.py`. The per-packet vectors hold two
// entries. `zeek/ja4t/main.zeek:96-98` breaks the loop before the append, so Zeek writes
// none. `docs/specs/foxio/JA4T.md` R10 marks that break a reference split.
//
// Ruling #125 stays closed. It keys the part width on the value, and this ruling decides
// the entry count.
//
// The port half of this ruling is `Crank-Git/ja4plus#215`, and it is closed. The port needs
// no change, because it already writes one entry for each option byte. The docstring of
// `option_bytes` at `ja4plus/utils/tcp_options.py:51-56` states that it reads the option
// bytes the capture carries. Line 56 of that docstring writes
// `#215 records the reading as D2.`, and that bare number names the port's issue #215.

// tcpOptionEndList returns a TCP End-of-Option-List option.
func tcpOptionEndList() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindEndList, OptionLength: 1}
}

// tcpOptionSACKPermitted returns a TCP selective acknowledgment permitted option.
func tcpOptionSACKPermitted() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
}

// tcpOptionTimestamps returns a TCP timestamps option that carries the eight data bytes.
func tcpOptionTimestamps(data []byte) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindTimestamps,
		OptionLength: 10,
		OptionData:   data,
	}
}

// The option list below reaches twelve bytes, so gopacket adds no pad byte. The bytes are
// `02 04 05 b4 01 03 03 02 04 02 00 00`. The test builds them on a SYN, because JA4T and
// JA4TS share one builder. `TestJA4TSWritesOneEntryForEachEndOfOptionListByte` names the
// capture that carries the bytes.
func TestJA4TWritesOneEntryForEachEndOfOptionListByte(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 64240, options)

	got := ComputeJA4T(pkt)
	want := "64240_2-1-3-4-0-0_1460_2"
	if got != want {
		t.Errorf("JA4T for the two End-of-Option-List bytes: got %q, want %q", got, want)
	}
}

// A SYN-ACK reaches the same rule, because JA4T and JA4TS share one builder.
//
// `browsers-x509.pcapng` frame 31 is a SYN-ACK, and it carries the option bytes above. The
// per-packet vector for that frame holds `ja4.ja4ts` as `64240_2-1-3-4-0-0_1460_2`. Frame
// 30 is the SYN of the same connection, and its `ja4.ja4t` value is
// `64240_2-1-3-1-1-4_1460_8`.
func TestJA4TSWritesOneEntryForEachEndOfOptionListByte(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 64240, options)

	got := ComputeJA4TS(pkt)
	want := "64240_2-1-3-4-0-0_1460_2"
	if got != want {
		t.Errorf("JA4TS for the two End-of-Option-List bytes: got %q, want %q", got, want)
	}
}

// A timestamps option carries eight data bytes, and each one of them can hold zero. A read
// that counts a zero byte rather than an option writes eight surplus entries here.
//
// The option list below reaches twenty-four bytes, so gopacket adds no pad byte.
func TestJA4TCountsNoZeroByteInsideATimestampsOption(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(7),
		tcpOptionNop(),
		tcpOptionNop(),
		tcpOptionTimestamps(make([]byte, 8)),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 29200, options)

	got := ComputeJA4T(pkt)
	want := "29200_2-1-3-1-1-8-4-0-0_1460_7"
	if got != want {
		t.Errorf("JA4T for the zero bytes of the timestamps option: got %q, want %q", got, want)
	}
}

// A maximum segment size option can also carry two zero data bytes, and a window scale
// option can carry one. The list below holds three such bytes and four End-of-Option-List
// bytes, so the two counts separate.
//
// The option list reaches twelve bytes, so gopacket adds no pad byte.
func TestJA4TCountsNoZeroByteInsideAMaximumSegmentSizeOption(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(0),
		tcpOptionNop(),
		tcpOptionWindowScale(0),
		tcpOptionEndList(),
		tcpOptionEndList(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	pkt := buildTCPPacket(t, 12345, 443, true, false, 8192, options)

	got := ComputeJA4T(pkt)
	want := "8192_2-1-3-0-0-0-0_00_00"
	if got != want {
		t.Errorf("JA4T for the zero bytes of the segment size option: got %q, want %q", got, want)
	}
}

// The option bytes are attacker-controlled, and a fingerprinter never panics. Each input
// below states a length that the region does not hold.
func TestTCPOptionEntriesStopsAtAMalformedOptionLength(t *testing.T) {
	cases := []struct {
		name   string
		region []byte
		want   []string
	}{
		{"the region ends before the length byte", []byte{0x02}, nil},
		{"the length byte states zero", []byte{0x02, 0x00, 0x01, 0x01}, nil},
		{"the length byte states one", []byte{0x02, 0x01, 0x01, 0x01}, nil},
		{"the length exceeds the region", []byte{0x02, 0x0a, 0x05, 0xb4}, nil},
		{"the region holds no byte", []byte{}, nil},
		{"a valid option precedes the malformed one", []byte{0x01, 0x00, 0x02, 0xff}, []string{"1", "0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, _, _ := tcpOptionEntries(c.region)
			if len(entries) != len(c.want) {
				t.Fatalf("entries: got %v, want %v", entries, c.want)
			}
			for i := range entries {
				if entries[i] != c.want[i] {
					t.Fatalf("entries: got %v, want %v", entries, c.want)
				}
			}
		})
	}
}

// A data offset that the segment does not hold must reach no option byte.
//
// `layers/tcp.go:264-268` assigns `tcp.Contents = data` for such a segment, and that slice
// holds the payload as well as the header. `layers/tcp.go:319` adds the layer before it
// reads the error, so the fingerprinter reads that segment. A read of `tcp.Contents[20:]`
// alone would build part b, the segment size and the window scale out of payload bytes
// that an attacker chooses.
//
// `gopacket` returns from the error path before it enters its own option loop, so the old
// read of `tcp.Options` reported an empty option list here. This test holds that result.
func TestJA4TReadsNoOptionByteFromADataOffsetTheSegmentDoesNotHold(t *testing.T) {
	options := []layers.TCPOption{
		tcpOptionMSS(1460),
		tcpOptionNop(),
		tcpOptionWindowScale(2),
		tcpOptionSACKPermitted(),
		tcpOptionEndList(),
		tcpOptionEndList(),
	}
	frame := buildTCPPacket(t, 12345, 443, true, false, 64240, options).Data()

	// The frame holds a 14-byte Ethernet header and a 20-byte IPv4 header, so the TCP
	// header starts at byte 34. Byte 12 of that header holds the data offset in its high
	// nibble. A value of 15 claims a 60-byte header, and the segment holds 32 bytes.
	const tcpStart = 34
	crafted := make([]byte, len(frame))
	copy(crafted, frame)
	crafted[tcpStart+12] = 0xf0 | (crafted[tcpStart+12] & 0x0f)

	pkt := gopacket.NewPacket(crafted, layers.LayerTypeEthernet, gopacket.Default)
	got := ComputeJA4T(pkt)
	want := "64240_00_00_00"
	if got != want {
		t.Errorf("JA4T for the data offset the segment does not hold: got %q, want %q", got, want)
	}
}

// `FuzzNoExportedFunctionPanicsOnAnyFrame` drives whole frames through `gopacket`, and the
// gopacket decoder rejects an option length that the header does not hold. That target
// therefore reaches no guard below. This target reads the option region directly.
func FuzzTCPOptionEntriesReadsAnyOptionRegion(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02, 0x04, 0x02, 0x00, 0x00})
	f.Add([]byte{0x08, 0x0a, 0x60, 0xb6, 0xa1, 0x8d, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x02, 0x00})
	f.Add([]byte{0x02, 0x01})
	f.Add([]byte{0x02, 0xff})
	f.Add([]byte{0x02})

	f.Fuzz(func(t *testing.T, region []byte) {
		entries, _, _ := tcpOptionEntries(region)
		// Each entry costs at least one option byte, so a region cannot produce more
		// entries than it holds bytes. A read that returns more has advanced by nothing.
		if len(entries) > len(region) {
			t.Fatalf("the region %x produces %d entries for %d bytes", region, len(entries), len(region))
		}
	})
}

// The segment size and the window scale each read a data field, and a short option holds
// no such field.
func TestTCPOptionEntriesReadsNoValueFromAShortOption(t *testing.T) {
	// A segment size option of length 3 holds one data byte, and the value needs two.
	entries, mss, wscale := tcpOptionEntries([]byte{0x02, 0x03, 0xff, 0x03, 0x02})
	if mss != 0 {
		t.Errorf("segment size: got %d, want 0", mss)
	}
	if wscale != 0 {
		t.Errorf("window scale: got %d, want 0", wscale)
	}
	if len(entries) != 2 || entries[0] != "2" || entries[1] != "3" {
		t.Errorf("entries: got %v, want [2 3]", entries)
	}
}
