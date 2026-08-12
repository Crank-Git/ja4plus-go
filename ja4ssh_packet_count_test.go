package ja4plus

import (
	"path/filepath"
	"strings"
	"testing"
)

// The SSH packet count of issue #200. `internal/parser/ssh.go` reads the four-byte length
// field of an SSH record, and a cipher hides that field after the key exchange. The library
// therefore counted almost no SSH packet after the key exchange, and 42 JA4SSH comparisons
// of the conformance suite differed.
//
// Two FoxIO implementations state the counting rule, and the two agree.
//
//   - `testdata/foxio/reference/wireshark/source/packet-ja4.c:1469` counts one packet for
//     each `ssh.direction` field of the frame, which the `tshark` SSH dissector writes.
//   - `testdata/foxio/reference/python/ja4ssh.py:94` reads
//     `has_ssh = ('ssh' in x['protos']) or ('direction' in x) or has_ssh_extras`, so it
//     counts the packet that `tshark` labels `ssh`.
//
// The port holds the same rule at `ja4plus/fingerprinters/ja4ssh.py:247`, and its
// `SSHMessageTracker` follows the SSH message boundary. `parser.SSHMessageTracker` is the
// one-to-one Go form of that tracker.

// ja4sshCaptureDir holds the FoxIO captures that `make corpus` fetches.
const ja4sshCaptureDir = "testdata/foxio/pcap"

// ja4sshPacketCountRun holds the values of one run over one capture.
// `Window` holds the value that ProcessPacket returned at a filled window, and `Closed`
// holds the value that CloseOpenWindows returned at the end of the capture.
type ja4sshPacketCountRun struct {
	Window []string
	Closed []string
}

// ja4sshValuesOfCapture returns the JA4SSH values that one capture produces on one port pair.
// It skips the test when the corpus is absent.
//
// It keeps the two emission paths apart, because a value that only CloseOpenWindows reaches
// tells a streaming caller nothing.
func ja4sshValuesOfCapture(t *testing.T, capture string, clientPort uint16) ja4sshPacketCountRun {
	t.Helper()

	packets := loadPCAP(t, filepath.Join(ja4sshCaptureDir, capture))

	processor := NewProcessor()

	var run ja4sshPacketCountRun

	keep := func(results []FingerprintResult, into *[]string) {
		for _, result := range results {
			if result.Type != "ja4ssh" {
				continue
			}

			if result.SrcPort != clientPort && result.DstPort != clientPort {
				continue
			}

			*into = append(*into, result.Fingerprint)
		}
	}

	for _, packet := range packets {
		// A fingerprinter returns a non-fatal error, and this test reads the JA4SSH values
		// alone.
		results, _ := processor.ProcessPacket(packet)
		keep(results, &run.Window)
	}

	keep(processor.CloseOpenWindows(), &run.Closed)

	return run
}

// TestJA4SSHCountsTheSSHPacketsOfSshPcapng holds FR-gaps-2 for `ssh.pcapng` and JA4SSH.
//
// The FoxIO per-stream vector at `testdata/foxio/python/ssh.pcapng.json` holds
// `"JA4SSH.1": "c36s36_c76s124_c0s0"` for stream 0, and the per-packet vector at
// `testdata/foxio/wireshark/ssh.pcapng.json` holds the same value at frame 200. The two
// counts add to 200, so the window fills and ProcessPacket emits the value.
//
// The capture proves that the repair restores emission at the window. Before the repair the
// library counted 7 SSH packets of the 200, so no window ever filled and CloseOpenWindows
// was the only emission path.
func TestJA4SSHCountsTheSSHPacketsOfSshPcapng(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh.pcapng", 57377)

	if len(run.Window) != 1 {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the window of 200 fills once",
			len(run.Window), run.Window)
	}

	if run.Window[0] != "c36s36_c76s124_c0s0" {
		t.Errorf("the value is %q, and the FoxIO vector holds \"c36s36_c76s124_c0s0\"", run.Window[0])
	}
}

// TestJA4SSHCountsTheSSHPacketsOfSshRPcap holds FR-gaps-2 for `ssh-r.pcap` and JA4SSH.
//
// The FoxIO per-stream vector at `testdata/foxio/python/ssh-r.pcap.json` holds five values
// for stream 2, whose client port is 46396. Four windows of 200 SSH packets fill, and the
// fifth value reads the window that the connection holds open at the end of the capture.
//
// This test reads part b of each value, which holds the two SSH packet counts. Part b is the
// field that issue #200 repairs. Part a and part c of the first value carry two differences
// that this issue does not close, and issue #200 records the reading of each one.
//
//   - Part c of the first window reads `c18s82`, and both vectors hold `c19s82`. The bare ACK
//     of the TCP handshake arrives before the first SSH packet, and the library counts no
//     bare ACK on a connection it has not opened yet.
//   - Part a of the first window reads `c76s76`, and the two FoxIO implementations disagree.
//     The per-packet vector at `testdata/foxio/wireshark/ssh-r.pcap.json` holds `c76s76` at
//     frame 706, and the per-stream vector holds `c64s64` for the same window and the same
//     counts.
func TestJA4SSHCountsTheSSHPacketsOfSshRPcap(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh-r.pcap", 46396)

	// The two SSH packet counts of the four windows the FoxIO vector holds.
	counts := []string{"c104s96", "c108s92", "c106s94", "c111s89"}

	if len(run.Window) != len(counts) {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the FoxIO vector holds %d filled windows",
			len(run.Window), run.Window, len(counts))
	}

	for index, expected := range counts {
		produced := ja4sshPacketCountPart(t, run.Window[index])
		if produced != expected {
			t.Errorf("window %d counts %s SSH packets, and the FoxIO vector counts %s",
				index+1, produced, expected)
		}
	}

	if len(run.Closed) != 1 {
		t.Fatalf("CloseOpenWindows produced %d JA4SSH values %v, and the connection holds one window open",
			len(run.Closed), run.Closed)
	}

	if produced := ja4sshPacketCountPart(t, run.Closed[0]); produced != "c66s65" {
		t.Errorf("the open window counts %s SSH packets, and the FoxIO vector counts c66s65", produced)
	}
}

// ja4sshPacketCountPart returns part b of one JA4SSH value, which holds the two SSH packet
// counts.
func ja4sshPacketCountPart(t *testing.T, value string) string {
	t.Helper()

	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		t.Fatalf("the value %q holds %d parts, and a JA4SSH value holds three", value, len(parts))
	}

	return parts[1]
}
