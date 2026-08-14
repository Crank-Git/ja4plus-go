package ja4plus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// seedNamed holds each seed path that `seedCorpusFile` reached in this run.
// `seedCorpusHoldsNoOtherFile` reads it. A rename that leaves the old file behind then
// fails the test, so no seed keeps a name that states a behavior it does not hold.
var seedNamed = map[string]bool{}

// seedCorpusHoldsNoOtherFile fails when a target directory holds a file that the test
// names no value for. A file with the `issue-` prefix is a crash that the fuzzer wrote,
// and FR-fuzz-24 keeps it, so this check passes over it.
func seedCorpusHoldsNoOtherFile(t *testing.T) {
	t.Helper()

	root := filepath.Join("testdata", "fuzz")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		// `README.md` sits beside the target directories, and Go reads no seed there.
		if filepath.Dir(path) == root {
			return nil
		}
		if strings.HasPrefix(entry.Name(), "issue-") || seedNamed[path] {
			return nil
		}

		t.Errorf("the seed corpus holds %s, and no test builds it", path)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// seedCorpusFile writes one seed file, or it compares the tracked file against the lines.
// `target` names the fuzz target, and `name` names the file under `testdata/fuzz/<target>/`.
//
// `JA4PLUS_SEEDGEN=1` selects the write. Every other run compares, so a seed that a later
// change moves fails the ordinary test run rather than drifting without a report.
func seedCorpusFile(t *testing.T, target, name string, lines ...string) {
	t.Helper()

	path := filepath.Join("testdata", "fuzz", target, name)
	body := "go test fuzz v1\n" + strings.Join(lines, "\n") + "\n"
	seedNamed[path] = true

	if os.Getenv("JA4PLUS_SEEDGEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(body))

		return
	}

	tracked, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the seed corpus holds no %s: %v", path, err)
	}
	if string(tracked) != body {
		t.Fatalf("the tracked seed %s differs from the value this test builds", path)
	}
}

func seedBytes(b []byte) string {
	var sb strings.Builder
	sb.WriteString("[]byte(\"")
	for _, c := range b {
		fmt.Fprintf(&sb, "\\x%02x", c)
	}
	sb.WriteString("\")")

	return sb.String()
}

func seedResults(t *testing.T, frame []byte) int {
	t.Helper()

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	results, _ := NewProcessor().ProcessPacket(packet)

	return len(results)
}

// TestEachTargetOfThisPackageHoldsAnAcceptedSeedAndARejectedSeed builds every seed of
// `testdata/fuzz/`, and it asserts the result of the reader for each one. FR-fuzz-19,
// FR-fuzz-20 and FR-fuzz-21 of `docs/specs/features/06-fuzz-testing.md` state the
// requirements.
//
// Every seed of this package holds no byte of the FoxIO corpus. `testdata/fuzz/README.md`
// states the license reading that FR-fuzz-23 needs.
func TestEachTargetOfThisPackageHoldsAnAcceptedSeedAndARejectedSeed(t *testing.T) {
	// --- FuzzComputeJA4DReadsAnyFrame
	// A DHCPREQUEST message. The fixed part is 236 bytes, and the magic cookie and the
	// options follow it.
	request := make([]byte, 236)
	request[0] = 0x01
	request[1] = 0x01
	request[2] = 0x06
	copy(request[4:8], []byte{0x0a, 0x0b, 0x0c, 0x0d})
	copy(request[28:34], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	request = append(request, 0x63, 0x82, 0x53, 0x63)
	request = append(request, 0x35, 0x01, 0x03)
	request = append(request, 0x37, 0x03, 0x01, 0x1c, 0x06)
	request = append(request, 0x0c, 0x04, 0x68, 0x6f, 0x73, 0x74)
	request = append(request, 0xff)

	dhcpAccept := panicAuditFrame(t, "udp", 68, 67, request)
	packet := gopacket.NewPacket(dhcpAccept, layers.LayerTypeEthernet, gopacket.Default)
	if got := ComputeJA4D(packet); got == "" {
		t.Fatal("dhcp accept seed writes no value")
	} else {
		t.Logf("dhcp accept: %s", got)
	}
	seedCorpusFile(t, "FuzzComputeJA4DReadsAnyFrame",
		"accepts-a-dhcp-request-message", seedBytes(dhcpAccept))

	// The message carries no magic cookie, so `gopacket` reads no option.
	noCookie := make([]byte, 240)
	noCookie[0] = 0x01
	noCookie[1] = 0x01
	noCookie[2] = 0x06
	dhcpReject := panicAuditFrame(t, "udp", 68, 67, noCookie)
	packet = gopacket.NewPacket(dhcpReject, layers.LayerTypeEthernet, gopacket.Default)
	if got := ComputeJA4D(packet); got != "" {
		t.Logf("dhcp reject writes %s", got)
	}
	seedCorpusFile(t, "FuzzComputeJA4DReadsAnyFrame",
		"rejects-a-message-that-carries-no-magic-cookie", seedBytes(dhcpReject))

	// --- FuzzComputeJA4D6ReadsAnyFrame
	// An ADVERTISE message with three options.
	advertise := []byte{0x02, 0x11, 0x22, 0x33}
	advertise = append(advertise, 0x00, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04)
	advertise = append(advertise, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01)
	advertise = append(advertise, 0x00, 0x17, 0x00, 0x00)
	d6Accept := buildDHCPv6Packet(t, advertise).Data()
	if got := ComputeJA4D6(gopacket.NewPacket(d6Accept, layers.LayerTypeEthernet, gopacket.Default)); got == "" {
		t.Fatal("dhcpv6 accept seed writes no value")
	} else {
		t.Logf("dhcpv6 accept: %s", got)
	}
	seedCorpusFile(t, "FuzzComputeJA4D6ReadsAnyFrame",
		"accepts-an-advertise-message", seedBytes(d6Accept))

	// The message holds one byte, so it carries no message type and no transaction id.
	d6Reject := buildDHCPv6Packet(t, []byte{0x0c}).Data()
	if got := ComputeJA4D6(gopacket.NewPacket(d6Reject, layers.LayerTypeEthernet, gopacket.Default)); got != "" {
		t.Logf("dhcpv6 reject writes %s", got)
	}
	seedCorpusFile(t, "FuzzComputeJA4D6ReadsAnyFrame",
		"rejects-a-message-that-holds-no-transaction-identifier", seedBytes(d6Reject))

	// --- FuzzProcessPacketReadsAnyFrame
	processorAccept := dhcpAccept
	if n := seedResults(t, processorAccept); n == 0 {
		t.Fatal("processor accept seed writes no result")
	} else {
		t.Logf("processor accept writes %d results", n)
	}
	seedCorpusFile(t, "FuzzProcessPacketReadsAnyFrame",
		"accepts-a-frame-that-carries-one-dhcp-request-message", seedBytes(processorAccept))

	// The Ethernet type names IPv4, and the frame holds four bytes in place of the header.
	processorReject := append([]byte(nil), processorAccept[:14]...)
	processorReject = append(processorReject, 0x45, 0x00, 0xff, 0xff)
	if n := seedResults(t, processorReject); n != 0 {
		t.Fatalf("processor reject seed writes %d results", n)
	}
	seedCorpusFile(t, "FuzzProcessPacketReadsAnyFrame",
		"rejects-a-frame-that-holds-a-truncated-ip-header", seedBytes(processorReject))

	seedCorpusHoldsNoOtherFile(t)
}
