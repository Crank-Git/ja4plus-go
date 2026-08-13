package ja4plus

import (
	"os"
	"testing"
)

// The port's register row `JA4X on a stream that a proxy tunnel carries` holds this
// reading, and the port decided it at its issue #138 on 2026-08-07. JA4X reads the TLS
// record layer without regard to the tunnel protocol that carries it, so a SOCKS4 tunnel
// on port 9901 produces the certificates of the tunneled session. No FoxIO implementation
// publishes a JA4X key for `socks4-https.pcap`, and the maintainer decided that the three
// values stay. The maintainer ruled on 2026-08-13 that a row the port's register already
// holds lands in this repository as a reading.
//
// FR-parity-49 and FR-parity-50 of `docs/specs/features/08-python-parity.md` state the
// rule. The register half of FR-parity-50 is sequenced behind #361, which builds the
// uncovered-value machinery. An entry written before that machinery is an orphan, and
// `conformanceCheckOrphans` fails the run for one.

// ja4xSOCKS4Values holds the three JA4X values that the SOCKS4 tunnel of
// `socks4-https.pcap` produces, in the order the certificate list carries them.
var ja4xSOCKS4Values = []string{
	"14f85a9f494d_3f8190b6b671_80ea7ef3b044",
	"14f85a9f494d_14f85a9f494d_be007da94c85",
	"e7bc7ebc3d9e_14f85a9f494d_9c8ed4a87d4b",
}

// TestJA4XReadsTheTLSRecordLayerOfASOCKS4Tunnel holds FR-parity-49 and the test half of
// FR-parity-50.
//
// The stream carries two conditions that no other capture of the corpus carries together.
// The reader stores the segments out of sequence order, and the server coalesces
// ServerHello and Certificate into one TLS record. #57 repaired both, and this test fails
// when either repair is reversed.
func TestJA4XReadsTheTLSRecordLayerOfASOCKS4Tunnel(t *testing.T) {
	pcapPath := "testdata/foxio/pcap/socks4-https.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("the fixture %s is not present, so this test reads no capture", pcapPath)
	}

	packets := loadPCAP(t, pcapPath)

	fingerprinter := NewJA4X()
	var got []string
	for _, packet := range packets {
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned the error %v", err)
		}
		for _, result := range results {
			// The tunnel carries the session on port 9901, and no port test gates the read.
			if result.SrcPort != 9901 {
				t.Errorf("a JA4X value reached the port %d, want 9901", result.SrcPort)
			}
			got = append(got, result.Fingerprint)
		}
	}

	if len(got) != len(ja4xSOCKS4Values) {
		t.Fatalf("the SOCKS4 tunnel produced %d JA4X values, want %d; the values are %v",
			len(got), len(ja4xSOCKS4Values), got)
	}
	for index, want := range ja4xSOCKS4Values {
		if got[index] != want {
			t.Errorf("JA4X value %d is %q, want %q", index, got[index], want)
		}
	}
}
