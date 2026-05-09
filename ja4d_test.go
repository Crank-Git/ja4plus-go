package ja4plus

import (
	"os"
	"testing"
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
	f := NewJA4D()
	f.results = []FingerprintResult{{Type: "ja4d"}}
	f.Reset()
	if f.results != nil {
		t.Errorf("expected nil results after reset, got %v", f.results)
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
