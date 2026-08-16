package repocheck

import (
	"strings"
	"testing"
	"time"
)

// Issue #652 read `browsers-x509.pcapng/128/JA4LS.1` on 2026-08-15. It is the one deviation
// of the JA4L cluster that reached no cause, and this file holds the reading.
//
// Two facts hold the row open, and cause 1 of `docs/audit/ja4l-deviation-cluster.md` states
// only the first one.
//
// Ruling #127 declines part c on a TCP connection. The maintainer ruled it on 2026-08-12
// and kept it on 2026-08-15, so the library writes `2948_229` on the SYN-ACK frame and no
// value on frame 128.
//
// Part c of the vector also discards a whole second. `wireshark/source/packet-ja4.c:1373`
// reads `latency2.nsecs`, which is the sub-second field of `nstime_t`. The interval that
// the field describes is 1028110000 nanoseconds, so the published value states the
// remainder and never the whole interval.
//
// The tests below hold the arithmetic and the register entry. They fail when a later
// reader restates either number, and issue #652 is the reversal path.

// ja4lsSecondsTruncationKey names the one comparison of the corpus that reads a JA4L
// interval above one second.
const ja4lsSecondsTruncationKey = "browsers-x509.pcapng/128/JA4LS.1"

// ja4lsSecondsTruncationVector holds the published FoxIO value, verbatim.
// `testdata/foxio/wireshark/browsers-x509.pcapng.json` states it under `ja4.ja4ls`.
const ja4lsSecondsTruncationVector = "2948_229_14055"

// ja4lsSecondsTruncationRuling names the ruling that declines part c on a TCP connection.
const ja4lsSecondsTruncationRuling = "#127"

// ja4lsSecondsTruncationIssue names the issue that holds the reading.
const ja4lsSecondsTruncationIssue = "#652"

// ja4lsPointD is the capture timestamp of frame 123 of `browsers-x509.pcapng`. It is the
// first client application packet of stream 2, so it fills the point that the Wireshark
// dissector names `timestamp_D`.
var ja4lsPointD = time.Unix(1691545934, 653341000).UTC()

// ja4lsPointE is the capture timestamp of frame 125 of `browsers-x509.pcapng`. It is the
// first server application packet after point D, so it fills `timestamp_E`.
var ja4lsPointE = time.Unix(1691545935, 681451000).UTC()

func TestTheJA4LSVectorOfFrame128ReadsTheSubSecondFieldOfTheDelta(t *testing.T) {
	interval := ja4lsPointE.Sub(ja4lsPointD)

	if interval != 1028110000*time.Nanosecond {
		t.Fatalf("the interval E - D measures %d nanoseconds, and the reading of %s states 1028110000",
			interval.Nanoseconds(), ja4lsSecondsTruncationIssue)
	}

	// A reader of the whole interval writes this value, and no FoxIO vector holds it.
	whole := interval.Nanoseconds() / 2 / 1000
	if whole != 514055 {
		t.Errorf("the whole interval gives %d, and the reading of %s states 514055",
			whole, ja4lsSecondsTruncationIssue)
	}

	// `nstime_t` splits a delta into `secs` and `nsecs`, and the dissector reads `nsecs`
	// alone. The remainder below is that field.
	remainder := int64(interval % time.Second)
	truncated := remainder / 2 / 1000

	parts := strings.Split(ja4lsSecondsTruncationVector, "_")
	if len(parts) != 3 {
		t.Fatalf("the vector %q holds %d parts, and the reading of %s states three",
			ja4lsSecondsTruncationVector, len(parts), ja4lsSecondsTruncationIssue)
	}

	if parts[2] != "14055" {
		t.Fatalf("the vector %q states part c %q, and the reading of %s states 14055",
			ja4lsSecondsTruncationVector, parts[2], ja4lsSecondsTruncationIssue)
	}

	if truncated != 14055 {
		t.Errorf("the `nsecs` field gives %d, and the vector states part c %q",
			truncated, parts[2])
	}
}

func TestTheRegisterDeclinesTheJA4LSVectorOfFrame128UnderRuling127(t *testing.T) {
	for _, entry := range readDeviationRegister(t) {
		if entry.Key != ja4lsSecondsTruncationKey {
			continue
		}

		if entry.Ruling != ja4lsSecondsTruncationRuling {
			t.Errorf("entry %q names the ruling %q, and %s declines part c on a TCP connection",
				entry.Key, entry.Ruling, ja4lsSecondsTruncationRuling)
		}

		// The library writes its value on the SYN-ACK frame, so it produces nothing here.
		if !entry.Capability {
			t.Errorf("entry %q reports a value decline, and the library produces no value on this frame",
				entry.Key)
		}

		if entry.Ours != "" {
			t.Errorf("entry %q records %q, and the library produces no value on this frame",
				entry.Key, entry.Ours)
		}

		if entry.Theirs != ja4lsSecondsTruncationVector {
			t.Errorf("entry %q records the reference value %q, and the vector holds %q",
				entry.Key, entry.Theirs, ja4lsSecondsTruncationVector)
		}

		if !strings.Contains(entry.Reason, ja4lsSecondsTruncationIssue) {
			t.Errorf("entry %q states the reason %q, and it names no reversal path",
				entry.Key, entry.Reason)
		}

		return
	}

	t.Errorf("the register holds no entry for %q, and ruling %s declines that value",
		ja4lsSecondsTruncationKey, ja4lsSecondsTruncationRuling)
}

func TestTheJA4LClusterPageAttributesEveryDeviation(t *testing.T) {
	page := readRepoFile(t, "docs/audit/ja4l-deviation-cluster.md")

	if !strings.Contains(page, "## Cause 7 — the seconds component of the Wireshark delta") {
		t.Error("docs/audit/ja4l-deviation-cluster.md holds no cause 7, and cause 7 attributes the last deviation")
	}

	// The page states the mechanism, so it cites the line that reads the sub-second field.
	if !strings.Contains(page, "wireshark/source/packet-ja4.c:1373") {
		t.Error("docs/audit/ja4l-deviation-cluster.md cites `wireshark/source/packet-ja4.c:1373` nowhere, and that line reads the `nsecs` field")
	}

	if !strings.Contains(page, "**Every deviation of the cluster reaches a cause.**") {
		t.Error("docs/audit/ja4l-deviation-cluster.md reports an unattributed deviation, and cause 7 attributes the last one")
	}
}
