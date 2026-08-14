package ja4plus

import (
	"strings"
	"testing"
)

// The maintainer ruled issue #528 on 2026-08-14. JA4L point C is the last QUIC server
// handshake packet, and the library keeps the packet it reads today.
//
// The question was a genuine reference split. Wireshark pins point C to the first server
// handshake packet, and the FoxIO Python implementation, the Rust implementation and the
// Zeek package each move point C to the last one. `wireshark/source/packet-ja4.c:1425`
// carries the comment `keep updating C until D is found`, and the code below that comment
// pins the first packet, so no FoxIO text settles the split.
//
// The per-packet vector set carries the Wireshark reading, so each comparison below reads
// the first server handshake packet and the library reads the last one. Issue #528 is the
// reversal path.

// ja4lPointCRulingIssue names the issue that holds the ruling of 2026-08-14.
const ja4lPointCRulingIssue = "#528"

// ja4lPointCRulingCitations names each reference location that states which server
// handshake packet fills point C.
var ja4lPointCRulingCitations = []string{
	"wireshark/source/packet-ja4.c:1426-1430",
	"python/common.py:109-112",
	"rust/ja4/src/time/udp.rs:181-184",
	"zeek/ja4l/main.zeek:254",
}

// ja4lPointCDecline names one per-packet comparison that the ruling declines.
type ja4lPointCDecline struct {
	ours   string
	theirs string
}

// ja4lPointCDeclines names each per-packet comparison that the point C reading alone
// holds. A candidate that pins point C to the first server handshake packet closes these
// three comparisons and no other one, measured with `make conformance` on 2026-08-14.
var ja4lPointCDeclines = map[string]ja4lPointCDecline{
	"tls3.pcapng/147/JA4L.1": {ours: "59_128_quic", theirs: "90_128_quic"},
	"tls3.pcapng/167/JA4L.1": {ours: "59_128_quic", theirs: "81_128_quic"},
	"tls3.pcapng/312/JA4L.1": {ours: "45_128_quic", theirs: "83_128_quic"},
}

func TestTheRegisterDeclinesEachFirstPacketPointCValueUnderRuling528(t *testing.T) {
	held := make(map[string]deviationEntry)
	for _, entry := range readDeviationRegister(t) {
		held[entry.Key] = entry
	}

	for key, decline := range ja4lPointCDeclines {
		entry, reached := held[key]
		if !reached {
			t.Errorf("the register holds no entry for %q, and the ruling of %s declines that value",
				key, ja4lPointCRulingIssue)

			continue
		}

		if entry.Ruling != ja4lPointCRulingIssue {
			t.Errorf("entry %q names the ruling %q, and the ruling of %s declines that value",
				key, entry.Ruling, ja4lPointCRulingIssue)
		}

		// The library produces the value, so the entry is a value decline.
		if entry.Capability {
			t.Errorf("entry %q reports a capability decline, and the library produces %q", key, decline.ours)
		}

		if entry.Ours != decline.ours {
			t.Errorf("entry %q records %q, and the run produces %q", key, entry.Ours, decline.ours)
		}

		if entry.Theirs != decline.theirs {
			t.Errorf("entry %q records the reference value %q, and the vector holds %q",
				key, entry.Theirs, decline.theirs)
		}

		if !strings.Contains(entry.Reason, ja4lPointCRulingIssue) {
			t.Errorf("entry %q states the reason %q, and it names no reversal path", key, entry.Reason)
		}

		// The reason names the line that pins point C to the first packet, because that line
		// is the whole difference the entry accepts.
		if !strings.Contains(entry.Reason, ja4lPointCRulingCitations[0]) {
			t.Errorf("entry %q states the reason %q, and it cites %q nowhere",
				key, entry.Reason, ja4lPointCRulingCitations[0])
		}
	}
}

func TestTheRegisterHoldsNoOtherEntryUnderRuling528(t *testing.T) {
	for _, entry := range readDeviationRegister(t) {
		if entry.Ruling != ja4lPointCRulingIssue {
			continue
		}

		if _, named := ja4lPointCDeclines[entry.Key]; !named {
			t.Errorf("entry %q names the ruling %s, and the measurement of that ruling reaches %d comparisons",
				entry.Key, ja4lPointCRulingIssue, len(ja4lPointCDeclines))
		}
	}
}

func TestTheJA4LClusterPageRecordsTheRulingOfIssue528(t *testing.T) {
	page := readRepoFile(t, "docs/audit/ja4l-deviation-cluster.md")

	for _, citation := range ja4lPointCRulingCitations {
		if !strings.Contains(page, citation) {
			t.Errorf("docs/audit/ja4l-deviation-cluster.md cites %q nowhere, and the ruling of %s reads that line",
				citation, ja4lPointCRulingIssue)
		}
	}

	if !strings.Contains(page, ja4lPointCRulingIssue) {
		t.Errorf("docs/audit/ja4l-deviation-cluster.md names %s nowhere, and that issue holds the ruling",
			ja4lPointCRulingIssue)
	}

	for key := range ja4lPointCDeclines {
		if !strings.Contains(page, key) {
			t.Errorf("docs/audit/ja4l-deviation-cluster.md names the comparison %q nowhere, and the ruling of %s declines it",
				key, ja4lPointCRulingIssue)
		}
	}
}
