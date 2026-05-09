package ja4plus

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	f := NewJA4D6()
	f.results = []FingerprintResult{{Type: "ja4d6"}}
	f.Reset()
	if f.results != nil {
		t.Errorf("expected nil results after reset, got %v", f.results)
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

	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer handle.Close()

	expected := map[int]string{
		2:  "solct0014nn_1-6-8-25_23-24",
		5:  "advrt0014nn_25-26-1-2_00",
		7:  "reqst0014nn_1-2-6-8-25-26_23-24",
		8:  "reply0014nn_25-26-1-2_00",
		11: "relse0014nn_1-2-6-8-25-26_23-24",
		12: "reply0014nn_1-2-13_00",
	}

	fp := NewJA4D6()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	frame := 0
	matched := 0
	for pkt := range src.Packets() {
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
