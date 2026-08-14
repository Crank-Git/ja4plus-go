package ja4plus

import (
	"strings"
	"testing"
)

// The maintainer ruled issue #543 on 2026-08-14. The SYN bit test of ruling #126 reaches
// JA4L, and it reaches JA4T as well. `wireshark/source/packet-ja4.c:1266` is one line, and
// both methods read it.
//
// The dissector tests the whole flag byte for equality, so a SYN that carries one more flag
// bit reaches no branch. The connection record never fills, and the per-packet vector file
// names no JA4L key for it. The library reads the SYN bit alone, so it publishes a value
// that the vector file does not hold.
//
// These tests hold the ruling, because the vector set names no key that a comparison could
// separate. `.claude/rules/rulings.md` `## Where a ruling is recorded` requires a register
// entry or a test, and this ruling carries both. Issue #543 is the reversal path.

// ja4lSYNBitRulingIssue names the issue that holds the ruling of 2026-08-14.
const ja4lSYNBitRulingIssue = "#543"

// ja4lSYNBitRulingCitations names each reference location that states the SYN bit test.
var ja4lSYNBitRulingCitations = []string{
	"wireshark/source/packet-ja4.c:1266",
	"wireshark/source/packet-ja4.c:1279",
	"python/ja4.py:563",
	"zeek/ja4l/main.zeek:84",
	"rust/ja4/src/time/tcp.rs:211",
	"rust/ja4/src/time/tcp.rs:212",
}

// ja4lSYNBitDeclines names each per-packet value that declines under the ruling, with the
// value the library produces. The two captures are the only two of the corpus that open a
// connection with a SYN that carries one more flag bit.
var ja4lSYNBitDeclines = map[string]string{
	"gre-sample.pcap/12/JA4LS.1":     "22952_236",
	"gre-sample.pcap/13/JA4L.1":      "36_255",
	"gre-sample.pcap/14/JA4L.1":      "26150_255",
	"macos_tcp_flags.pcap/2/JA4LS.1": "17255_63",
	"macos_tcp_flags.pcap/3/JA4L.1":  "62_64",
	"macos_tcp_flags.pcap/4/JA4L.1":  "393_64",
}

func TestTheRegisterDeclinesEachExtraFlagBitSYNValueUnderRuling126(t *testing.T) {
	held := make(map[string]deviationEntry)
	for _, entry := range readDeviationRegister(t) {
		held[entry.Key] = entry
	}

	for key, ours := range ja4lSYNBitDeclines {
		entry, reached := held[key]
		if !reached {
			t.Errorf("the register holds no entry for %q, and the ruling of %s declines that value",
				key, ja4lSYNBitRulingIssue)

			continue
		}

		if entry.Ruling != "#126" {
			t.Errorf("entry %q names the ruling %q, and the ruling of %s extends ruling #126",
				key, entry.Ruling, ja4lSYNBitRulingIssue)
		}

		// The library produces the value, so the entry is a value decline.
		if entry.Capability {
			t.Errorf("entry %q reports a capability decline, and the library produces %q", key, ours)
		}

		if entry.Ours != ours {
			t.Errorf("entry %q records %q, and the run produces %q", key, entry.Ours, ours)
		}

		// The vector file names no key for the method, so the reference value is empty.
		if entry.Theirs != "" {
			t.Errorf("entry %q records the reference value %q, and the vector file names no key",
				key, entry.Theirs)
		}

		if !strings.Contains(entry.Reason, ja4lSYNBitRulingIssue) {
			t.Errorf("entry %q states the reason %q, and it names no reversal path", key, entry.Reason)
		}
	}
}

func TestTheJA4LTranscriptionStatesThatTheSYNBitTestReachesJA4L(t *testing.T) {
	page := readRepoFile(t, "docs/specs/foxio/JA4L.md")

	for _, citation := range ja4lSYNBitRulingCitations {
		if !strings.Contains(page, citation) {
			t.Errorf("docs/specs/foxio/JA4L.md cites %q nowhere, and the ruling of %s reads that line",
				citation, ja4lSYNBitRulingIssue)
		}
	}

	if !strings.Contains(page, ja4lSYNBitRulingIssue) {
		t.Errorf("docs/specs/foxio/JA4L.md names %s nowhere, and that issue holds the ruling",
			ja4lSYNBitRulingIssue)
	}
}
