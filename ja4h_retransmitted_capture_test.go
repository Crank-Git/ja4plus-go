package ja4plus

import (
	"os"
	"path/filepath"
	"testing"
)

// This file holds the settled count of #233 against the capture that raised it.
//
// #233 asked whether the library over-emits on `CVE-2018-6794.pcap`, or whether the
// reference reports one value for each distinct request. Neither reading holds. The
// capture carries one HTTP request on each of its two HTTP connections, and it carries
// five TCP retransmissions of each request. So the count of requests is one, and it is
// never four.
//
// Both FoxIO references read the request and decline every retransmission.
// `testdata/foxio/reference/python/ja4.py:598-600` calls `to_ja4h` for a packet whose
// highest layer is `http`, and the tshark HTTP dissector reads no retransmitted segment.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1149` sets `http_req` from an
// `http.request.method` field, and
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1634` emits the value only when
// that field was present.
//
// #446 built the guard that produces this count, and `segmentCarriesNoNewRequest` in
// `ja4h.go` holds it. The synthetic segments of `ja4h_repeated_segment_test.go` prove the
// guard on two packets. This test proves it on the whole capture, where three TCP
// connections interleave and one of the three carries no HTTP request.
//
// A change that re-emits on a retransmission fails this test.

// ja4hRetransmittedCapture is the capture of #233. Frames 8, 9, 15, 26 and 28 repeat frame
// 6, and frames 18, 24, 25, 27 and 29 repeat frame 16.
const ja4hRetransmittedCapture = "CVE-2018-6794.pcap"

// ja4hRetransmittedCaptureValue names the frame that carries each request of the capture,
// and the value the FoxIO vectors publish for it.
//
// `testdata/foxio/python/CVE-2018-6794.pcap.json` holds one entry for stream 0 and one for
// stream 1. `testdata/foxio/wireshark/CVE-2018-6794.pcap.json` attributes a `ja4.ja4h`
// value to frame 6 and to frame 16, and to no other frame.
var ja4hRetransmittedCaptureValue = []struct {
	frame       int
	srcPort     uint16
	fingerprint string
}{
	{frame: 6, srcPort: 53649, fingerprint: "ge11nn07ruru_6cd0fb54989b_000000000000_000000000000"},
	{frame: 16, srcPort: 53656, fingerprint: "ge11nr06ruru_cc6ec9a91856_000000000000_000000000000"},
}

// TestJA4H_ProducesOneValueForEachRequestOfTheRetransmittedCapture holds the reading of
// #233.
//
// The fingerprinter reads every packet of the capture in capture order, and it produces one
// value at each frame that carries a request. A retransmission produces no value.
func TestJA4H_ProducesOneValueForEachRequestOfTheRetransmittedCapture(t *testing.T) {
	capture := filepath.Join(corpusCaptureDir, ja4hRetransmittedCapture)

	if _, err := os.Stat(capture); err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", capture)
	}

	packets := loadPCAP(t, capture)
	if len(packets) == 0 {
		t.Fatalf("%s holds no packet", capture)
	}

	type emission struct {
		frame       int
		srcPort     uint16
		fingerprint string
	}

	var emitted []emission

	fingerprinter := NewJA4H()

	for index, packet := range packets {
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("frame %d returned an error: %v", index+1, err)
		}
		for _, result := range results {
			emitted = append(emitted, emission{
				frame:       index + 1,
				srcPort:     result.SrcPort,
				fingerprint: result.Fingerprint,
			})
		}
	}

	if len(emitted) != len(ja4hRetransmittedCaptureValue) {
		t.Fatalf("the capture produced %d values, and the FoxIO vectors hold %d: %v",
			len(emitted), len(ja4hRetransmittedCaptureValue), emitted)
	}

	for index, want := range ja4hRetransmittedCaptureValue {
		got := emitted[index]
		if got.frame != want.frame {
			t.Errorf("value %d came from frame %d, and the Wireshark vector names frame %d",
				index+1, got.frame, want.frame)
		}
		if got.srcPort != want.srcPort {
			t.Errorf("value %d came from source port %d, and the vector names port %d",
				index+1, got.srcPort, want.srcPort)
		}
		if got.fingerprint != want.fingerprint {
			t.Errorf("value %d reads %q, and the vector holds %q",
				index+1, got.fingerprint, want.fingerprint)
		}
	}
}
