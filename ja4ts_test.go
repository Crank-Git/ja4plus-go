package ja4plus

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestJA4TS_SYNACKWithOptions(t *testing.T) {
	options := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindEndList, OptionLength: 1},
	}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 29200, options)

	result := ComputeJA4TS(pkt)
	expected := "29200_2-1-3-1-1-8-4-0_1460_7"
	if result != expected {
		t.Errorf("JA4TS SYN-ACK with options: got %q, want %q", result, expected)
	}
}

func TestJA4TS_SYNOnly(t *testing.T) {
	// SYN-only should not match JA4TS
	pkt := buildTCPPacket(t, 12345, 443, true, false, 29200, nil)
	result := ComputeJA4TS(pkt)
	if result != "" {
		t.Errorf("JA4TS SYN-only: expected empty, got %q", result)
	}
}

func TestJA4TS_ACKOnly(t *testing.T) {
	// ACK-only should not match JA4TS
	pkt := buildTCPPacket(t, 80, 12345, false, true, 65535, nil)
	result := ComputeJA4TS(pkt)
	if result != "" {
		t.Errorf("JA4TS ACK-only: expected empty, got %q", result)
	}
}

func TestJA4TS_Reset(t *testing.T) {
	// JA4TS holds no state, so Reset changes no result. Issue #25 removed the results
	// slice, which grew without a bound and which no exported method read.
	fp := NewJA4TS()
	pkt := buildTCPPacket(t, 443, 12345, true, true, 29200, nil)

	before, _ := fp.ProcessPacket(pkt)
	if len(before) != 1 {
		t.Fatalf("the SYN-ACK packet produced %d results, want 1", len(before))
	}

	fp.Reset()

	after, _ := fp.ProcessPacket(pkt)
	if len(after) != 1 || after[0].Fingerprint != before[0].Fingerprint {
		t.Errorf("the read after Reset produces %v, and the read before it produces %v", after, before)
	}
}
