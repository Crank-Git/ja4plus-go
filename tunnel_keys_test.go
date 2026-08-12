package ja4plus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tunnelSkipWithoutCapture skips the test when the corpus holds no such capture.
func tunnelSkipWithoutCapture(t *testing.T, capture string) {
	t.Helper()

	path := filepath.Join(corpusCaptureDir, capture)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", path)
	}
}

// The reported key of a tunneled connection pairs the outer address with the inner port.
// The grouping key reads the inner address pair.
//
// The capture is `gre-erspan-vxlan.pcap` and the method is JA4L. The capture mirrors one
// session, so every packet travels from `100.20.9.2` to `100.20.9.1` and the outer pair
// names no direction. `testdata/foxio/python/gre-erspan-vxlan.pcap.json` holds
// `"src": "100.20.9.2"`, `"dst": "100.20.9.1"`, `"srcport": "65174"` and
// `"dstport": "80"`.
//
// `docs/specs/spec.md` `## Changelog` records the ruling of 2026-08-11, which adopts
// `Crank-Git/ja4plus` issue #242 under `.claude/rules/parity.md` rule 2.
func TestJA4LReportsTheOuterAddressPairAndTheInnerPortPairOnTheERSPANAndVXLANCapture(t *testing.T) {
	tunnelSkipWithoutCapture(t, "gre-erspan-vxlan.pcap")

	packets := loadPCAP(t, filepath.Join(corpusCaptureDir, "gre-erspan-vxlan.pcap"))
	if len(packets) == 0 {
		t.Fatalf("gre-erspan-vxlan.pcap holds no packet")
	}

	processor := NewProcessor()

	var held bool

	for _, packet := range packets {
		results, _ := processor.ProcessPacket(packet)

		for _, result := range results {
			if result.Type != "ja4l" {
				continue
			}

			held = true

			if result.SrcIP != "100.20.9.2" || result.DstIP != "100.20.9.1" {
				t.Errorf("JA4L reports the address pair %s and %s, and the vector holds 100.20.9.2 and 100.20.9.1",
					result.SrcIP, result.DstIP)
			}

			if result.SrcPort != 65174 || result.DstPort != 80 {
				t.Errorf("JA4L reports the port pair %d and %d, and the vector holds 65174 and 80",
					result.SrcPort, result.DstPort)
			}
		}
	}

	if !held {
		t.Errorf("JA4L produces no value on gre-erspan-vxlan.pcap")
	}
}

// GetShardKey follows the grouping key, so it returns the inner address pair.
// The capture is `gre-erspan-vxlan.pcap`. The outer pair `100.20.9.2` and `100.20.9.1`
// carries both directions of one session, so a shard key that read it would route two
// connections to one shard and would name no direction.
func TestGetShardKeyReadsTheInnerAddressPairOnTheERSPANAndVXLANCapture(t *testing.T) {
	tunnelSkipWithoutCapture(t, "gre-erspan-vxlan.pcap")

	packets := loadPCAP(t, filepath.Join(corpusCaptureDir, "gre-erspan-vxlan.pcap"))
	if len(packets) == 0 {
		t.Fatalf("gre-erspan-vxlan.pcap holds no packet")
	}

	processor := NewProcessor()
	key := processor.GetShardKey(packets[0])

	if !strings.Contains(key, "10.16.27.12") || !strings.Contains(key, "10.16.27.131") {
		t.Errorf("GetShardKey returns %q, and the inner address pair is 10.16.27.12 and 10.16.27.131", key)
	}

	if strings.Contains(key, "100.20.9.") {
		t.Errorf("GetShardKey returns %q, and it holds the outer address pair", key)
	}

	// Both directions of one session reach one key, so a sharded caller keeps one
	// connection in one Processor.
	if reply := processor.GetShardKey(packets[1]); reply != key {
		t.Errorf("GetShardKey returns %q for the request and %q for the reply", key, reply)
	}
}

// The reported port pair reads the inner transport layer on a Geneve capture, and the
// reported address pair reads the outer layer.
//
// The capture is `tcpdump-geneve.pcap` and the method is JA4L. The outer transport is UDP
// on port 6081, and a result that read it would name the tunnel and not the connection.
// `testdata/foxio/python/tcpdump-geneve.pcap.json` holds `"src": "20.0.0.2"`,
// `"srcport": "51225"` and `"dstport": "22"`.
func TestJA4LReadsTheInnerTransportLayerOnTheGeneveCapture(t *testing.T) {
	tunnelSkipWithoutCapture(t, "tcpdump-geneve.pcap")

	packets := loadPCAP(t, filepath.Join(corpusCaptureDir, "tcpdump-geneve.pcap"))
	if len(packets) == 0 {
		t.Fatalf("tcpdump-geneve.pcap holds no packet")
	}

	processor := NewProcessor()

	var held bool

	for _, packet := range packets {
		results, _ := processor.ProcessPacket(packet)

		for _, result := range results {
			if result.Type != "ja4l" {
				continue
			}

			held = true

			if result.SrcPort == 6081 || result.DstPort == 6081 {
				t.Errorf("JA4L reports the port pair %d and %d, which names the Geneve tunnel",
					result.SrcPort, result.DstPort)
			}

			if result.SrcIP != "20.0.0.2" || result.DstIP != "20.0.0.1" {
				t.Errorf("JA4L reports the address pair %s and %s, and the vector holds 20.0.0.2 and 20.0.0.1",
					result.SrcIP, result.DstIP)
			}
		}
	}

	if !held {
		t.Errorf("JA4L produces no value on tcpdump-geneve.pcap")
	}
}

// The reported address pair reads the outer layer on a GRE capture, and the time-to-live
// reads the outer layer with it.
//
// The capture is `gre-sample.pcap` and the method is JA4L. The capture separates the two
// address layers and the two time-to-live values: the outer layer carries `172.27.1.66`
// with a time-to-live of 255, and the inner layer carries `66.59.111.190` with a
// time-to-live of 64. `testdata/foxio/python/gre-sample.pcap.json` holds
// `"src": "172.27.1.66"`, `"client_ttl": "255"` and `"JA4L-C": "26150_255"`.
func TestJA4LReadsTheOuterTimeToLiveOnTheGRECapture(t *testing.T) {
	tunnelSkipWithoutCapture(t, "gre-sample.pcap")

	packets := loadPCAP(t, filepath.Join(corpusCaptureDir, "gre-sample.pcap"))
	if len(packets) == 0 {
		t.Fatalf("gre-sample.pcap holds no packet")
	}

	processor := NewProcessor()

	var held bool

	for _, packet := range packets {
		results, _ := processor.ProcessPacket(packet)

		for _, result := range results {
			if result.Type != "ja4l" || !strings.HasPrefix(result.Fingerprint, "JA4L-C=") {
				continue
			}

			if result.SrcPort != 40264 && result.DstPort != 40264 {
				continue
			}

			held = true

			// The fingerprint reads `JA4L-C=<latency>_<time-to-live>`.
			if !strings.HasSuffix(result.Fingerprint, "_255") {
				t.Errorf("JA4L produces %q, and the outer time-to-live of the client is 255",
					result.Fingerprint)
			}

			if result.SrcIP != "172.27.1.66" && result.DstIP != "172.27.1.66" {
				t.Errorf("JA4L reports the address pair %s and %s, and the outer pair holds 172.27.1.66",
					result.SrcIP, result.DstIP)
			}
		}
	}

	if !held {
		t.Errorf("JA4L produces no value for the SSH connection of gre-sample.pcap")
	}
}

// CleanupConnection reads the reported key, so it removes a tunneled connection.
//
// The capture is `gre-erspan-vxlan.pcap` and the method is JA4L. The grouping key holds
// the inner address pair `10.16.27.12` and `10.16.27.131`, and every result reports the
// outer pair `100.20.9.2` and `100.20.9.1`. A caller holds the reported pair alone, so a
// cleanup that read the grouping key would leave the state table full.
//
// `ja4plus/fingerprinters/ja4l.py:216` holds the same rule, and FR-gaps-14c states it.
func TestJA4LCleanupConnectionRemovesATunneledConnectionByTheReportedKey(t *testing.T) {
	tunnelSkipWithoutCapture(t, "gre-erspan-vxlan.pcap")

	packets := loadPCAP(t, filepath.Join(corpusCaptureDir, "gre-erspan-vxlan.pcap"))
	if len(packets) == 0 {
		t.Fatalf("gre-erspan-vxlan.pcap holds no packet")
	}

	fingerprinter := NewJA4L()

	var result FingerprintResult

	for _, packet := range packets {
		results, _ := fingerprinter.ProcessPacket(packet)
		if len(results) > 0 {
			result = results[0]
			break
		}
	}

	if result.Fingerprint == "" {
		t.Fatalf("JA4L produces no value on gre-erspan-vxlan.pcap")
	}

	// The grouping key reads the inner pair, so the state table proves the two keys differ.
	for key := range fingerprinter.connections {
		if strings.Contains(key, result.SrcIP) {
			t.Fatalf("the state table holds the key %q, and the reported address %s reaches it directly",
				key, result.SrcIP)
		}
	}

	held := len(fingerprinter.connections)
	if held == 0 {
		t.Fatalf("JA4L holds no connection state after it produced %q", result.Fingerprint)
	}

	fingerprinter.CleanupConnection(result.SrcIP, result.SrcPort, result.DstIP, result.DstPort, "tcp")

	if got := len(fingerprinter.connections); got != held-1 {
		t.Errorf("CleanupConnection leaves %d of %d connections, and it removes the one the caller named",
			got, held)
	}
}
