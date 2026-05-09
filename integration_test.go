package ja4plus

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type expectedResult struct {
	PacketIndex int    `json:"packet_index"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// packetReader abstracts over pcap and pcapng readers.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

func loadPCAP(t *testing.T, path string) []gopacket.Packet {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("PCAP not found: %s", path)
		return nil
	}
	if len(raw) < 4 {
		t.Fatalf("file too short: %s", path)
	}

	// Detect format by magic bytes (extensions in the FoxIO corpus are
	// inconsistent — http1.pcapng is actually pcap-format).
	//   pcap:   d4c3b2a1 (LE) or a1b2c3d4 (BE)
	//   pcapng: 0a0d0d0a (Section Header Block)
	var src io.Reader = bytes.NewReader(raw)
	var reader packetReader
	switch {
	case raw[0] == 0x0a && raw[1] == 0x0d && raw[2] == 0x0d && raw[3] == 0x0a:
		r, err := pcapgo.NewNgReader(src, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatalf("failed to create pcapng reader: %v", err)
		}
		reader = r
	default:
		r, err := pcapgo.NewReader(src)
		if err != nil {
			t.Fatalf("failed to create pcap reader: %v", err)
		}
		reader = r
	}

	var packets []gopacket.Packet
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp
		pkt.Metadata().CaptureLength = ci.CaptureLength
		pkt.Metadata().Length = ci.Length
		packets = append(packets, pkt)
	}
	return packets
}

func loadExpected(t *testing.T, path string) []expectedResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("Expected results not found: %s", path)
		return nil
	}
	var results []expectedResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("failed to parse expected results: %v", err)
	}
	return results
}

func TestIntegration_JA4T_JA4TS(t *testing.T) {
	matches, _ := filepath.Glob("testdata/*.expected.json")
	if len(matches) == 0 {
		t.Skip("No test fixtures in testdata/. Run: python scripts/gen_expected.py <pcap> > testdata/<name>.expected.json")
	}

	for _, expectedPath := range matches {
		name := filepath.Base(expectedPath)
		pcapBase := expectedPath[:len(expectedPath)-len(".expected.json")]

		// Try .pcap then .pcapng
		pcapPath := pcapBase + ".pcap"
		if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
			pcapPath = pcapBase + ".pcapng"
		}

		t.Run(name, func(t *testing.T) {
			packets := loadPCAP(t, pcapPath)
			expected := loadExpected(t, expectedPath)
			if packets == nil || expected == nil {
				return
			}

			ja4t := NewJA4T()
			ja4ts := NewJA4TS()

			var goResults []expectedResult
			for i, pkt := range packets {
				if results, _ := ja4t.ProcessPacket(pkt); len(results) > 0 {
					goResults = append(goResults, expectedResult{
						PacketIndex: i,
						Type:        "ja4t",
						Fingerprint: results[0].Fingerprint,
					})
				}
				if results, _ := ja4ts.ProcessPacket(pkt); len(results) > 0 {
					goResults = append(goResults, expectedResult{
						PacketIndex: i,
						Type:        "ja4ts",
						Fingerprint: results[0].Fingerprint,
					})
				}
			}

			if len(goResults) != len(expected) {
				t.Errorf("result count: Go=%d, Python=%d", len(goResults), len(expected))
				for i, e := range expected {
					if i < len(goResults) {
						t.Logf("  [%d] Go=%s Python=%s", i, goResults[i].Fingerprint, e.Fingerprint)
					} else {
						t.Logf("  [%d] Go=MISSING Python=%s", i, e.Fingerprint)
					}
				}
				return
			}

			for i, exp := range expected {
				got := goResults[i]
				if got.Fingerprint != exp.Fingerprint {
					t.Errorf("packet %d (%s): Go=%q, Python=%q", exp.PacketIndex, exp.Type, got.Fingerprint, exp.Fingerprint)
				}
			}
		})
	}
}
