package ja4plus

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// The integration test reads the FoxIO corpus.
//
// `docs/specs/features/04-conformance-harness.md` passes the role of
// `scripts/gen_expected.py` and `testdata/http1-with-cookies.expected.json` to the corpus,
// and the two files are removed. The conformance suite of the `conformance` build tag
// compares every value against the FoxIO vector, so this test proves that the library reads
// a corpus capture and produces a value.
//
// `loadPCAP` stays in this file, because `conformance_test.go` reads it. The corpus is not
// tracked, so the test below skips until `make corpus` fetches it.

// corpusCaptureDir holds the fetched FoxIO captures. `.gitignore` keeps them out of git.
const corpusCaptureDir = "testdata/foxio/pcap"

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

// The corpus replaces the removed fixture. `http1-with-cookies.pcapng` is the capture the
// fixture named, and the per-packet vector for it holds a `ja4.ja4t` value and a
// `ja4.ja4ts` value.
//
// This test compares no value. The conformance suite compares every value against the
// FoxIO vector, and a second comparison here would state the expected value twice.
func TestTheLibraryProducesAJA4TValueAndAJA4TSValueOnACorpusCapture(t *testing.T) {
	capture := filepath.Join(corpusCaptureDir, "http1-with-cookies.pcapng")

	if _, err := os.Stat(capture); err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", capture)
	}

	packets := loadPCAP(t, capture)
	if len(packets) == 0 {
		t.Fatalf("%s holds no packet", capture)
	}

	ja4t := NewJA4T()
	ja4ts := NewJA4TS()
	clients, servers := 0, 0

	for _, packet := range packets {
		results, _ := ja4t.ProcessPacket(packet)
		clients += len(results)

		results, _ = ja4ts.ProcessPacket(packet)
		servers += len(results)
	}

	if clients == 0 {
		t.Errorf("the library produces no JA4T value on %s, and the FoxIO vector holds one", capture)
	}

	if servers == 0 {
		t.Errorf("the library produces no JA4TS value on %s, and the FoxIO vector holds one", capture)
	}
}

// The removal cluster of `docs/specs/features/04-conformance-harness.md` states two files
// as removed. A file that returns gives the expected value a second source, and the corpus
// is the source this project reads.
func TestTheRepositoryHoldsNoGeneratedExpectedOutputFile(t *testing.T) {
	for _, path := range []string{
		"scripts/gen_expected.py",
		"testdata/http1-with-cookies.expected.json",
	} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s is present, and the feature file states it as removed", path)
		}
	}
}
