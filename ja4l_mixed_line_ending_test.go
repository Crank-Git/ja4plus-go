package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// #685 read the JA4L request completeness gate on 2026-08-15 UTC, and this file holds the
// separating packet of that reading.
//
// **The gate held two fixed byte groups, `\r\n\r\n` and `\n\n`, and the pair declined the
// terminator `\n\r\n`.** So one request moved the JA4L client measurement point, and a
// request with any other terminator did not.
//
// **The reading found its own deciding source, and it is not the ruling of #298.** #298
// ruled the header block terminator of `internal/parser/http.go`, which answers where a
// JA4H value ends its header block. This gate answers a different question: does the
// reference route the packet to a cache that holds no measurement point.
// `python/common.py:78` routes on `hl`. `python/ja4.py:398` sets `hl` from the layer name
// that tshark reports. So the Wireshark HTTP dissector decides.
//
// **Wireshark v4.6.0 reads `\n\r\n` as a complete header block.** `epan/tvbuff.c:4203`
// compiles the line-end pattern over both `\r` and `\n`, so a bare line feed ends a line.
// `epan/req_resp_hdrs.c:143` then breaks out of the header loop on the first line of
// length 0. The two readings reach one repair, and they reach it for two reasons.
//
// **No capture of the FoxIO corpus holds a mixed terminator**, so this test builds the
// packet that no vector reaches. `.claude/rules/rulings.md` `## Where a ruling is recorded`
// asks for exactly that. **Issue #685 is the reversal path.**

// mixedLineEndingRequest holds an HTTP request whose header block ends `\n\r\n`.
// Each header line ends with one line feed, and the empty line ends with `\r\n`.
const mixedLineEndingRequest = "GET / HTTP/1.1\nHost: example.com\n\r\n"

// buildJA4LPayloadACK builds the bare ACK of a handshake, and it carries one payload.
// The initial sequence numbers of the connection are 0, so the absolute 1 that this packet
// carries is the relative 1 that clientPoint reads.
//
// **`buildTCPStreamPacket` in `ja4l_test.go` builds the same packet, and it reads IPv6 as
// well.** This helper fixes the sequence numbers and the ports that its own case needs, and
// that caller takes both. **A later change may fold the two together.** Batch #708 recorded
// the duplication and made no code change, because a consolidation of a test helper is no
// documentation repair.
func buildJA4LPayloadACK(t testing.TB, srcIP, dstIP net.IP, ttl uint8, payload string) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      ttl,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		ACK:     true,
		Seq:     1,
		Ack:     1,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte(payload)))
	if err != nil {
		t.Fatalf("failed to serialize the packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestTheRequestGateReadsEveryPairOfLineEndingsAsOneTerminator(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		held    bool
	}{
		{
			name:    "two carriage return line feeds",
			payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			held:    true,
		},
		{
			name:    "two line feeds",
			payload: "GET / HTTP/1.1\nHost: example.com\n\n",
			held:    true,
		},
		{
			name:    "a carriage return line feed and then a line feed",
			payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\n",
			held:    true,
		},
		{
			name:    "a line feed and then a carriage return line feed",
			payload: mixedLineEndingRequest,
			held:    true,
		},
		{
			name:    "no empty line",
			payload: "GET / HTTP/1.1\r\nHost: example.com\r\n",
			held:    false,
		},
		{
			name:    "no request line",
			payload: "not a request\r\n\r\n",
			held:    false,
		},
	}

	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			read := holdsACompleteHTTPRequest([]byte(one.payload))
			if read != one.held {
				t.Errorf("the gate reports %t for %q, and the reading of #685 states %t",
					read, one.payload, one.held)
			}
		})
	}
}

// ja4lClientValueForPayload drives a whole handshake and returns the JA4L-C value that the
// third packet produces. It returns the empty string when the packet produces none.
func ja4lClientValueForPayload(t *testing.T, payload string) string {
	t.Helper()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clientIP := net.IP{192, 168, 1, 1}
	serverIP := net.IP{10, 0, 0, 1}

	fingerprinter := NewJA4L()

	syn := buildTCPPacketWithIPs(t, clientIP, serverIP, 64, 12345, 80, true, false)
	syn.Metadata().Timestamp = base
	if _, err := fingerprinter.ProcessPacket(syn); err != nil {
		t.Fatalf("the SYN packet returned an error: %v", err)
	}

	synAck := buildTCPPacketWithIPs(t, serverIP, clientIP, 64, 80, 12345, true, true)
	synAck.Metadata().Timestamp = base.Add(100 * time.Millisecond)
	if _, err := fingerprinter.ProcessPacket(synAck); err != nil {
		t.Fatalf("the SYN-ACK packet returned an error: %v", err)
	}

	request := buildJA4LPayloadACK(t, clientIP, serverIP, 64, payload)
	request.Metadata().Timestamp = base.Add(150 * time.Millisecond)
	results, err := fingerprinter.ProcessPacket(request)
	if err != nil {
		t.Fatalf("the request packet returned an error: %v", err)
	}

	for _, result := range results {
		if strings.HasPrefix(result.Fingerprint, "JA4L-C=") {
			return result.Fingerprint
		}
	}

	return ""
}

func TestAMixedLineEndingRequestMovesNoClientMeasurementPoint(t *testing.T) {
	// The positive control proves that this harness reaches the client measurement point.
	// A payload that ends no header block reaches the cache of any other TCP packet, so it
	// moves the point and it completes a value. Without this control the negative case
	// below would pass for any reason that produces no result at all.
	partial := "GET / HTTP/1.1\r\nHost: example.com\r\n"
	if value := ja4lClientValueForPayload(t, partial); value == "" {
		t.Fatalf("the partial request produced no JA4L-C value, so this test proves nothing"+
			" about the gate; the harness reaches no client measurement point for %q", partial)
	}

	// The reference routes a packet that tshark reports as `http` to a cache that holds no
	// measurement point, so a whole request completes no JA4L-C value.
	if value := ja4lClientValueForPayload(t, mixedLineEndingRequest); value != "" {
		t.Errorf("the request packet produced %q, and the reading of #685 states that"+
			" a whole request moves no client measurement point", value)
	}
}
