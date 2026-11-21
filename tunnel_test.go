package ja4plus

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// tunnelSerializeOptions fills the length fields and the checksums, so each builder below
// states the fields the test reads and no other field.
var tunnelSerializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// tunnelSerialize returns the bytes of the layers, or it fails the test.
func tunnelSerialize(t *testing.T, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, tunnelSerializeOptions, parts...); err != nil {
		t.Fatalf("the builder does not serialize the layers: %v", err)
	}

	return buffer.Bytes()
}

// tunnelInnerFrame returns one Ethernet frame that carries one TCP SYN packet.
// The five-layer test reads this frame as the innermost packet.
func tunnelInnerFrame(t *testing.T) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 51000,
		DstPort: 443,
		SYN:     true,
		Window:  8192,
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder does not set the network layer for the checksum: %v", err)
	}

	return tunnelSerialize(t, ethernet, ip, tcp)
}

// tunnelWrapInGRE returns the payload inside one IPv4 header and one GRE header.
// The protocol names the payload, so the caller states an Ethernet type the GRE header
// carries.
func tunnelWrapInGRE(t *testing.T, payload []byte, protocol layers.EthernetType) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolGRE,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	gre := &layers.GRE{Protocol: protocol}

	return tunnelSerialize(t, ip, gre, gopacket.Payload(payload))
}

// tunnelOuterFrame returns the payload inside one Ethernet header that names IPv4.
func tunnelOuterFrame(t *testing.T, payload []byte) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 1, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	return tunnelSerialize(t, ethernet, gopacket.Payload(payload))
}

// tunnelNestedGREPacket returns one packet that nests the named count of GRE tunnel layers.
// Each GRE layer carries one IPv4 packet, and the innermost packet carries one TCP SYN.
func tunnelNestedGREPacket(t *testing.T, depth int) gopacket.Packet {
	t.Helper()

	// The innermost GRE layer carries an IPv4 packet, so the builder drops the Ethernet
	// header of the inner frame and keeps the IPv4 packet it holds.
	inner := tunnelInnerFrame(t)[14:]

	for range depth {
		inner = tunnelWrapInGRE(t, inner, layers.EthernetTypeIPv4)
	}

	return gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)
}

// The parser stops at a depth of four tunnel layers, because a crafted packet can
// nest one tunnel inside another without a bound. FR-gaps-12 states the limit.
func TestTheProcessorProducesNoFingerprintWhenAPacketNestsFiveTunnelLayers(t *testing.T) {
	packet := tunnelNestedGREPacket(t, 5)

	if depth := parser.TunnelDepth(packet); depth != 5 {
		t.Fatalf("the builder nests %d tunnel layers, and the test needs 5", depth)
	}

	processor := NewProcessor()
	results, errs := processor.ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints, and FR-gaps-12 allows none", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelDepthExceeded) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the depth limit", errs)
	}
}

// FR-gaps-11 reads a nested tunnel to a depth of four layers.
func TestTheProcessorReadsAPacketThatNestsFourTunnelLayers(t *testing.T) {
	packet := tunnelNestedGREPacket(t, 4)

	if depth := parser.TunnelDepth(packet); depth != 4 {
		t.Fatalf("the builder nests %d tunnel layers, and the test needs 4", depth)
	}

	results, errs := NewProcessor().ProcessPacket(packet)

	// The innermost packet carries one TCP SYN, so JA4T produces one fingerprint from it.
	// A count of zero states that the processor read no inner packet at the depth limit.
	if len(results) == 0 {
		t.Errorf("the processor produces no fingerprint at a depth of four, and FR-gaps-11 allows the depth")
	}

	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelDepthExceeded) || errors.Is(err, parser.ErrTunnelPayloadUnread) {
			t.Errorf("the processor returns %v at a depth of four, and FR-gaps-11 allows the depth", err)
		}
	}
}

// A GRE packet that carries an unknown protocol type holds no inner packet the parser
// reads, so the processor returns a non-fatal error and produces no fingerprint.
func TestTheProcessorProducesNoFingerprintWhenAGREPacketCarriesAnUnknownProtocolType(t *testing.T) {
	// `0x9999` reaches no entry of the gopacket Ethernet type table at v1.1.19, so the GRE
	// layer names a payload the parser does not decode.
	const unknownProtocol = layers.EthernetType(0x9999)

	inner := tunnelWrapInGRE(t, tunnelInnerFrame(t)[14:], unknownProtocol)
	packet := gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)

	results, errs := NewProcessor().ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints from an unread tunnel payload", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelPayloadUnread) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the unread tunnel payload", errs)
	}
}

// A VXLAN packet with a truncated inner frame holds no inner packet the parser reads. The
// processor returns a non-fatal error, and it does not panic.
func TestTheProcessorProducesNoFingerprintWhenAVXLANPacketCarriesATruncatedInnerFrame(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	udp := &layers.UDP{SrcPort: 41000, DstPort: 4789}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder does not set the network layer for the checksum: %v", err)
	}

	// The inner Ethernet header needs 14 bytes, and this frame holds 6 of them.
	truncated := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	vxlan := &layers.VXLAN{ValidIDFlag: true, VNI: 42}

	inner := tunnelSerialize(t, ip, udp, vxlan, gopacket.Payload(truncated))
	packet := gopacket.NewPacket(tunnelOuterFrame(t, inner), layers.LayerTypeEthernet, gopacket.Default)

	results, errs := NewProcessor().ProcessPacket(packet)

	if len(results) != 0 {
		t.Errorf("the processor produces %d fingerprints from a truncated inner frame", len(results))
	}

	held := false
	for _, err := range errs {
		if errors.Is(err, parser.ErrTunnelPayloadUnread) {
			held = true
		}
	}

	if !held {
		t.Errorf("the processor returns %v, and none of it names the unread tunnel payload", errs)
	}
}

// TunnelDepth counts every tunnel layer of the packet, and it counts none for a packet
// that carries no tunnel.
func TestTunnelDepthCountsNoLayerForAPacketThatCarriesNoTunnel(t *testing.T) {
	packet := gopacket.NewPacket(tunnelInnerFrame(t), layers.LayerTypeEthernet, gopacket.Default)

	if depth := parser.TunnelDepth(packet); depth != 0 {
		t.Errorf("TunnelDepth returns %d for a packet that carries no tunnel, and 0 is the count", depth)
	}
}

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

// buildVXLANTCPSYNPacket returns one VXLAN packet that carries a TCP SYN packet inside it.
// The outer address pair names the tunnel, and the inner address pair names the connection.
//
// No capture of the FoxIO corpus holds one tunneled connection alone, so no vector proves
// that CleanupConnection empties both state maps. This function builds the separating
// packet. The tunnel is VXLAN, and RFC 7348 section 5 states the port 4789.
func buildVXLANTCPSYNPacket(t *testing.T) gopacket.Packet {
	t.Helper()

	outerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	outerIP := &layers.IPv4{
		SrcIP:    net.ParseIP(tunnelOuterSrcIP),
		DstIP:    net.ParseIP(tunnelOuterDstIP),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      255,
	}
	outerUDP := &layers.UDP{SrcPort: vxlanUDPPort, DstPort: vxlanUDPPort}
	if err := outerUDP.SetNetworkLayerForChecksum(outerIP); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returns the error %v", err)
	}

	vxlan := &layers.VXLAN{ValidIDFlag: true, VNI: 100}

	innerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		EthernetType: layers.EthernetTypeIPv4,
	}
	innerIP := &layers.IPv4{
		SrcIP:    net.ParseIP(tunnelInnerSrcIP),
		DstIP:    net.ParseIP(tunnelInnerDstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	innerTCP := &layers.TCP{
		SrcPort: tunnelInnerSrcPort,
		DstPort: tunnelInnerDstPort,
		SYN:     true,
		Window:  64240,
	}
	if err := innerTCP.SetNetworkLayerForChecksum(innerIP); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returns the error %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		outerEth, outerIP, outerUDP, vxlan, innerEth, innerIP, innerTCP)
	if err != nil {
		t.Fatalf("SerializeLayers returns the error %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(1, 0)

	return packet
}

// CleanupConnection empties both state maps when the caller names the grouping key.
//
// The index holds the reported key, and the fallback path treats the key the caller gave
// as the grouping key. That path removes the connection and leaves the index entry, so one
// entry leaks for every tunneled connection. Issue #193 holds the reading, and
// `.claude/rules/concurrency.md` requires a removal path for every state map.
func TestJA4LCleanupConnectionEmptiesBothMapsWhenTheCallerNamesTheGroupingKey(t *testing.T) {
	packet := buildVXLANTCPSYNPacket(t)

	fingerprinter := NewJA4L()
	if _, err := fingerprinter.ProcessPacket(packet); err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}

	if len(fingerprinter.connections) != 1 || len(fingerprinter.groupingKeys) != 1 {
		t.Fatalf("the fingerprinter holds %d connections and %d index entries, and the packet opens one of each",
			len(fingerprinter.connections), len(fingerprinter.groupingKeys))
	}

	// The caller names the inner address pair, which is the grouping key.
	fingerprinter.CleanupConnection(tunnelInnerSrcIP, tunnelInnerSrcPort, tunnelInnerDstIP, tunnelInnerDstPort, "tcp")

	if got := len(fingerprinter.connections); got != 0 {
		t.Errorf("CleanupConnection leaves %d connections, and the caller named the only one", got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d index entries, and every entry of a removed connection goes with it", got)
	}
}
