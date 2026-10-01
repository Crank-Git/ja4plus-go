package ja4plus

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The tests of this file hold #795: JA4 reads a TLS ClientHello that spans more than one
// TCP segment. Each case ports a case of `tests/test_ja4_tcp_client_hello_reassembly.py` of
// the port at tag `v1.3.0`. Crank-Git/ja4plus#772 records the defect in the port, and
// Crank-Git/ja4plus#784 holds the repair and the four bounds.

// The FoxIO values of `sigalg-grease.pcapng`, verbatim from
// `testdata/foxio/python/sigalg-grease.pcapng.json` at FoxIO commit `16b96d95`.
const (
	sigalgGreaseJA4   = "t13d1517h2_8daaf6152771_cb7bf5808d99"
	sigalgGreaseJA4o  = "t13d1517h2_acb858a92679_88bf22a3e888"
	sigalgGreaseJA4r  = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
	sigalgGreaseJA4ro = "t13d1517h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_fe0d,0010,0017,0033,44cd,ff01,000a,000d,0023,002b,000b,ca34,002d,0000,0005,001b,0012_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
)

var (
	tcpHelloClientIP = net.IP{192, 168, 0, 1}
	tcpHelloServerIP = net.IP{10, 10, 10, 1}
)

const (
	tcpHelloClientPort = 56544
	tcpHelloServerPort = 443
	tcpHelloFirstSeq   = 1230333283
)

// tcpHelloSegment holds the fields of one constructed TCP segment.
type tcpHelloSegment struct {
	payload  []byte
	seq      uint32
	srcPort  uint16
	fin      bool
	rst      bool
	ack      bool
	toClient bool
	at       time.Time
}

// build returns the segment as a packet. A zero port names the client port.
func (s tcpHelloSegment) build(t testing.TB) gopacket.Packet {
	t.Helper()

	clientPort := s.srcPort
	if clientPort == 0 {
		clientPort = tcpHelloClientPort
	}

	src, dst := tcpHelloClientIP, tcpHelloServerIP
	srcPort, dstPort := clientPort, uint16(tcpHelloServerPort)

	if s.toClient {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}

	ip := &layers.IPv4{SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP, Version: 4, TTL: 64}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     s.seq,
		ACK:     s.ack || (!s.fin && !s.rst),
		PSH:     len(s.payload) > 0,
		FIN:     s.fin,
		RST:     s.rst,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(s.payload)); err != nil {
		t.Fatalf("the segment does not serialize: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = s.at

	return packet
}

// tcpHelloLongClientHello returns one ClientHello record of more than 2000 bytes. A
// padding extension makes it long, as a post-quantum key share makes the hello of a
// current browser long.
func tcpHelloLongClientHello() []byte {
	return parser.BuildClientHello(0x0303, []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		[]parser.TLSExtension{
			parser.MakeSNIExtension("example.com"),
			parser.MakeALPNExtension("h2", "http/1.1"),
			parser.MakeSupportedVersionsClientExtension(0x0304, 0x0303),
			parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804, 0x0401),
			{Typ: 0x0015, Data: make([]byte, 1900)},
		})
}

// tcpHelloCut returns the segments that cut the bytes at each offset, in stream order.
func tcpHelloCut(data []byte, seq uint32, offsets ...int) []tcpHelloSegment {
	bounds := append(append([]int{0}, offsets...), len(data))

	segments := make([]tcpHelloSegment, 0, len(bounds)-1)
	for i := 0; i+1 < len(bounds); i++ {
		segments = append(segments, tcpHelloSegment{
			payload: data[bounds[i]:bounds[i+1]],
			seq:     seq + uint32(bounds[i]),
		})
	}

	return segments
}

// tcpHelloFeed returns the JA4 value of each segment, in the order the fingerprinter read
// them. An empty string names a segment that gave no value.
func tcpHelloFeed(t *testing.T, fingerprinter *JA4Fingerprinter, segments []tcpHelloSegment) []string {
	t.Helper()

	values := make([]string, 0, len(segments))

	for _, segment := range segments {
		results, _ := fingerprinter.ProcessPacket(segment.build(t))

		switch len(results) {
		case 0:
			values = append(values, "")
		case 1:
			values = append(values, results[0].Fingerprint)
		default:
			t.Fatalf("one segment gave %d results", len(results))
		}
	}

	return values
}

// tcpHelloWholeValue returns the JA4 value that one segment of the whole hello gives.
func tcpHelloWholeValue(t *testing.T, hello []byte) string {
	t.Helper()

	results, err := NewJA4().ProcessPacket(tcpHelloSegment{payload: hello, seq: tcpHelloFirstSeq}.build(t))
	if err != nil || len(results) != 1 || results[0].Fingerprint == "" {
		t.Fatalf("one segment of the whole hello gives (%v, %v), want one value", results, err)
	}

	return results[0].Fingerprint
}

func tcpHelloAssertValues(t *testing.T, got []string, want ...string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("the segments gave %q, want %q", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the segments gave %q, want %q", got, want)
		}
	}
}

func tcpHelloAssertHeld(t *testing.T, fingerprinter *JA4Fingerprinter, want int) {
	t.Helper()

	if got := len(fingerprinter.tcpHellos); got != want {
		t.Errorf("the fingerprinter holds %d partial hellos, want %d", got, want)
	}

	if got := fingerprinter.tcpHelloKeys.count(); got != want {
		t.Errorf("the recency order names %d partial hellos, want %d", got, want)
	}
}

// TestJA4ReadsTheClientHelloThatFrame4AndFrame5OfSigalgGreasePcapng holds the FoxIO
// vector, and it skips when the corpus is absent. The ClientHello record is 2034 bytes.
// Frame 4 carries 1400 bytes of it, and frame 5 carries 639 bytes.
func TestJA4ReadsTheClientHelloThatFrame4AndFrame5OfSigalgGreasePcapng(t *testing.T) {
	packets := loadPCAP(t, filepath.Join("testdata", "foxio", "pcap", "sigalg-grease.pcapng"))

	fingerprinter := NewJA4()

	var produced []FingerprintResult

	for _, packet := range packets {
		results, _ := fingerprinter.ProcessPacket(packet)
		produced = append(produced, results...)
	}

	if len(produced) != 1 {
		t.Fatalf("the capture gives %d JA4 values, want one", len(produced))
	}

	result := produced[0]
	if result.Fingerprint != sigalgGreaseJA4 || result.OriginalOrder != sigalgGreaseJA4o ||
		result.Raw != sigalgGreaseJA4r || result.RawOriginalOrder != sigalgGreaseJA4ro {
		t.Errorf("the capture gives %+v, want the four FoxIO forms", result)
	}

	if result.SrcIP != "192.168.0.1" || result.SrcPort != 56544 || result.DstIP != "10.10.10.1" || result.DstPort != 443 {
		t.Errorf("the value names %s:%d -> %s:%d, want the client connection",
			result.SrcIP, result.SrcPort, result.DstIP, result.DstPort)
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsTheValueOnTheSegmentThatCompletesTwoSegments(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	fingerprinter := NewJA4()

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, tcpHelloCut(hello, tcpHelloFirstSeq, 1400)), "", want)
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsTheSameFourFormsAsOneSegmentOfTheWholeHello(t *testing.T) {
	hello := tcpHelloLongClientHello()

	whole, err := NewJA4().ProcessPacket(tcpHelloSegment{payload: hello, seq: tcpHelloFirstSeq}.build(t))
	if err != nil || len(whole) != 1 {
		t.Fatalf("one segment of the whole hello gives (%v, %v)", whole, err)
	}

	fingerprinter := NewJA4()
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)

	if _, err := fingerprinter.ProcessPacket(segments[0].build(t)); err != nil {
		t.Fatalf("the segment that opens the hello returns the error %v", err)
	}

	cut, err := fingerprinter.ProcessPacket(segments[1].build(t))
	if err != nil || len(cut) != 1 {
		t.Fatalf("the segment that completes the hello gives (%v, %v)", cut, err)
	}

	if cut[0].Fingerprint != whole[0].Fingerprint || cut[0].Raw != whole[0].Raw ||
		cut[0].OriginalOrder != whole[0].OriginalOrder || cut[0].RawOriginalOrder != whole[0].RawOriginalOrder {
		t.Errorf("two segments give %+v, and one segment gives %+v", cut[0], whole[0])
	}

	if cut[0].SrcPort != tcpHelloClientPort || cut[0].DstPort != tcpHelloServerPort ||
		cut[0].SrcIP != tcpHelloClientIP.String() || cut[0].DstIP != tcpHelloServerIP.String() {
		t.Errorf("the value names %s:%d -> %s:%d, want the client connection",
			cut[0].SrcIP, cut[0].SrcPort, cut[0].DstIP, cut[0].DstPort)
	}
}

func TestJA4EmitsTheValueOnTheSegmentThatCompletesThreeSegments(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, tcpHelloFirstSeq, 600, 1300))
	tcpHelloAssertValues(t, got, "", "", want)
}

// Seven bytes hold the record header and two of the four handshake header bytes.
func TestJA4StartsAStreamOnASegmentThatCutsTheHandshakeHeader(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, tcpHelloFirstSeq, 7))
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4EmitsOneValueWhenTheFirstSegmentArrivesTwice(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], segments[0], segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4EmitsTheValueWhenTwoSegmentsOverlap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq},
		{payload: hello[1300:], seq: tcpHelloFirstSeq + 1300},
	})
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4EmitsTheValueAcrossAWrapOfTheSequenceNumber(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)

	got := tcpHelloFeed(t, NewJA4(), tcpHelloCut(hello, 0xFFFFFFFF-700, 1400))
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4HoldsNoStreamForAHelloThatOneSegmentHolds(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: hello, seq: tcpHelloFirstSeq}})
	tcpHelloAssertValues(t, got, want)
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4EmitsNoValueWhileASegmentIsMissing(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 600, 1300)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], segments[2]})
	tcpHelloAssertValues(t, got, "", "")
	tcpHelloAssertHeld(t, fingerprinter, 1)
}

// A gap reads as zeros nowhere. The value comes from the segment that fills the gap, so
// it equals the value of the whole hello.
func TestJA4FillsTheGapFromTheSegmentThatArrivesAndNeverFromZeros(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 600, 1300)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], segments[2], segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4EmitsNoValueWhenTheLaterSegmentArrivesFirst(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[1], segments[0]})
	tcpHelloAssertValues(t, got, "", "")
}

// A byte before the first hello byte would move the start of the stream, and the stream
// would then open with no TLS record.
func TestJA4IgnoresASegmentThatStartsBeforeTheHello(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	segments := tcpHelloCut(hello, tcpHelloFirstSeq, 1400)
	earlier := tcpHelloSegment{payload: make([]byte, 100), seq: tcpHelloFirstSeq - 100}

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{segments[0], earlier, segments[1]})
	tcpHelloAssertValues(t, got, "", "", want)
}

func TestJA4HoldsNoStreamForAHelloLongerThanTheByteCap(t *testing.T) {
	declared := maxJA4TCPHelloBytes
	record := []byte{0x16, 0x03, 0x01, byte((declared - 4) >> 8), byte(declared - 4)}
	handshake := []byte{0x01, byte((declared - 8) >> 16), byte((declared - 8) >> 8), byte(declared - 8)}
	payload := append(append(record, handshake...), 0x03, 0x03)
	fingerprinter := NewJA4()

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: payload, seq: 1}})
	tcpHelloAssertValues(t, got, "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// A sender of one-byte segments reaches the segment cap long before the byte cap.
func TestJA4ReleasesAStreamThatReachesTheSegmentCap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	segments := []tcpHelloSegment{{payload: hello[:9], seq: tcpHelloFirstSeq}}

	for offset := 9; offset < 9+maxJA4TCPHelloSegments+5; offset++ {
		segments = append(segments, tcpHelloSegment{
			payload: hello[offset : offset+1],
			seq:     tcpHelloFirstSeq + uint32(offset),
		})
	}

	fingerprinter := NewJA4()

	for _, value := range tcpHelloFeed(t, fingerprinter, segments) {
		if value != "" {
			t.Fatalf("a stream of one-byte segments gave the value %q", value)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4HoldsNoMoreStreamsThanTheEntryCap(t *testing.T) {
	hello := tcpHelloLongClientHello()
	fingerprinter := NewJA4()

	for port := 1024; port < 1024+maxJA4TCPHelloStreams+10; port++ {
		segment := tcpHelloSegment{payload: hello[:1400], seq: tcpHelloFirstSeq, srcPort: uint16(port)}
		if _, err := fingerprinter.ProcessPacket(segment.build(t)); err != nil {
			t.Fatalf("the segment of port %d returns the error %v", port, err)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, maxJA4TCPHelloStreams)
}

func TestJA4EmitsNoValueAfterTheStreamPassesTheMaximumAge(t *testing.T) {
	hello := tcpHelloLongClientHello()
	start := time.Unix(1000, 0)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq, at: start},
		{payload: hello[1400:], seq: tcpHelloFirstSeq + 1400, at: start.Add(ja4TCPHelloAge + time.Second)},
	})
	tcpHelloAssertValues(t, got, "", "")
}

func TestJA4EmitsTheValueInsideTheMaximumAge(t *testing.T) {
	hello := tcpHelloLongClientHello()
	want := tcpHelloWholeValue(t, hello)
	start := time.Unix(1000, 0)

	got := tcpHelloFeed(t, NewJA4(), []tcpHelloSegment{
		{payload: hello[:1400], seq: tcpHelloFirstSeq, at: start},
		{payload: hello[1400:], seq: tcpHelloFirstSeq + 1400, at: start.Add(ja4TCPHelloAge - time.Second)},
	})
	tcpHelloAssertValues(t, got, "", want)
}

func TestJA4ReleasesTheStreamOnAClosingClientSegment(t *testing.T) {
	cases := []struct {
		name  string
		close tcpHelloSegment
	}{
		{"FIN and ACK", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, fin: true, ack: true}},
		{"RST", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, rst: true}},
		{"RST and ACK", tcpHelloSegment{seq: tcpHelloFirstSeq + 1400, rst: true, ack: true}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
			fingerprinter := NewJA4()

			got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], testCase.close})
			tcpHelloAssertValues(t, got, "", "")
			tcpHelloAssertHeld(t, fingerprinter, 0)

			tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, segments[1:]), "")
		})
	}
}

func TestJA4ReleasesTheClientStreamOnAServerReset(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{segments[0], {seq: 1, rst: true, toClient: true}})
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The caller names the server endpoint first, so the removal reads both directions.
func TestJA4CleanupConnectionReleasesThePartialHello(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, segments[:1])
	tcpHelloAssertHeld(t, fingerprinter, 1)

	fingerprinter.CleanupConnection(tcpHelloServerIP.String(), tcpHelloServerPort,
		tcpHelloClientIP.String(), tcpHelloClientPort, "tcp")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4ResetReleasesThePartialHello(t *testing.T) {
	segments := tcpHelloCut(tcpHelloLongClientHello(), tcpHelloFirstSeq, 1400)
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, segments[:1])
	tcpHelloAssertHeld(t, fingerprinter, 1)

	fingerprinter.Reset()
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForAPayloadThatIsNoTLSRecord(t *testing.T) {
	fingerprinter := NewJA4()
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: request, seq: 1}}), "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForAServerHelloRecord(t *testing.T) {
	fingerprinter := NewJA4()
	cutServerHello := []byte{0x16, 0x03, 0x03, 0x04, 0xba, 0x02, 0x00, 0x04, 0xb6, 0x03, 0x03}

	got := tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{{payload: cutServerHello, seq: 1, toClient: true}})
	tcpHelloAssertValues(t, got, "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The reassembled bytes reach the reader that one segment reaches, so the two paths agree.
// The reader of this library refuses a hello that stops after the version field.
func TestJA4GivesTheResultOfOneSegmentForAShortHelloThatTwoSegmentsCarry(t *testing.T) {
	short := append([]byte{0x16, 0x03, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x06},
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff)

	alone, aloneErr := NewJA4().ProcessPacket(tcpHelloSegment{payload: short, seq: 1}.build(t))

	fingerprinter := NewJA4()
	segments := tcpHelloCut(short, 1, 9)

	if _, err := fingerprinter.ProcessPacket(segments[0].build(t)); err != nil {
		t.Fatalf("the segment that opens the hello returns the error %v", err)
	}

	cut, cutErr := fingerprinter.ProcessPacket(segments[1].build(t))

	if len(alone) != len(cut) || (aloneErr == nil) != (cutErr == nil) {
		t.Errorf("one segment gives (%v, %v), and two segments give (%v, %v)", alone, aloneErr, cut, cutErr)
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// The handshake header claims 1 byte, and the reader needs 2 for the version.
func TestJA4LeavesNothingForACompletedRecordThatHoldsNoClientHello(t *testing.T) {
	truncated := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}
	fingerprinter := NewJA4()

	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, tcpHelloCut(truncated, 1, 9)), "", "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

func TestJA4StartsNoStreamForASegmentAfterTheValue(t *testing.T) {
	hello := tcpHelloLongClientHello()
	fingerprinter := NewJA4()

	tcpHelloFeed(t, fingerprinter, tcpHelloCut(hello, tcpHelloFirstSeq, 1400))

	after := tcpHelloSegment{
		payload: append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, make([]byte, 32)...),
		seq:     tcpHelloFirstSeq + uint32(len(hello)),
	}
	tcpHelloAssertValues(t, tcpHelloFeed(t, fingerprinter, []tcpHelloSegment{after}), "")
	tcpHelloAssertHeld(t, fingerprinter, 0)
}

// Every length of a hostile segment is attacker input. A record header that claims the
// largest length and a handshake header that claims the largest length open no stream,
// and no segment panics.
func TestJA4ReadsHostileSegmentsWithoutAPanicOrAStream(t *testing.T) {
	payloads := [][]byte{
		{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff},
		{0x14, 0x03, 0x03, 0xff, 0xff, 0x16, 0x03, 0x01, 0x00, 0x10, 0x01},
		{0x16, 0x03},
	}

	fingerprinter := NewJA4()

	for index, payload := range payloads {
		if results, _ := fingerprinter.ProcessPacket(tcpHelloSegment{payload: payload, seq: uint32(index)}.build(t)); len(results) != 0 {
			t.Errorf("the hostile payload %x gives %v", payload, results)
		}
	}

	tcpHelloAssertHeld(t, fingerprinter, 0)
}
