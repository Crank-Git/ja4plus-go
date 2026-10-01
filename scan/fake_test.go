package scan

import (
	"container/heap"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The fake network below ports `tests/scan_fakes.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. It sends no packet and it opens no socket. Its clock moves only when the
// scanner waits, so a scan of 120 seconds runs in no time.

var fakeScannerIP = netip.MustParseAddr("198.51.100.1")

// script holds what one fake target sends after it receives the SYN.
type script struct {
	// offsets holds the delay after the SYN of each response.
	offsets []time.Duration
	// flags holds the TCP flags of each response, in the same order.
	flags []string
	// window is the window field of every response. Zero means 64240.
	window uint16
	// ackDelta is the acknowledgment number minus the sequence number of the SYN.
	ackDelta uint32
	// srcPort is the source port of each response. Zero means the scanned port.
	srcPort uint16
	// payload is the TCP payload of every response.
	payload []byte
}

func synAckScript(offsets ...float64) script {
	s := script{ackDelta: 1}
	for _, offset := range offsets {
		s.offsets = append(s.offsets, seconds(offset))
		s.flags = append(s.flags, "SA")
	}

	return s
}

func flagScript(offsets []float64, flags ...string) script {
	s := script{ackDelta: 1, flags: flags}
	for _, offset := range offsets {
		s.offsets = append(s.offsets, seconds(offset))
	}

	return s
}

type sentSYN struct {
	target   netip.Addr
	srcPort  uint16
	sequence uint32
}

type queuedFrame struct {
	at    time.Time
	order int
	frame []byte
}

type frameQueue []queuedFrame

func (q frameQueue) Len() int { return len(q) }
func (q frameQueue) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].order < q[j].order
	}

	return q[i].at.Before(q[j].at)
}
func (q frameQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *frameQueue) Push(x any)   { *q = append(*q, x.(queuedFrame)) }
func (q *frameQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]

	return last
}

// fakeNetwork holds a fake clock, the SYN packets the scanner sent, and the frames the
// targets send back.
type fakeNetwork struct {
	t       testing.TB
	now     time.Time
	scripts map[netip.Addr]script
	port    uint16
	sent    []sentSYN
	queue   frameQueue
	order   int
	onSend  func(netip.Addr)
	closed  bool
	// sendErr and receiveErr fail the matching call when they return an error.
	sendErr    func(target netip.Addr) error
	receiveErr func() error
}

func newFakeNetwork(t testing.TB, scripts map[netip.Addr]script, port uint16) *fakeNetwork {
	return &fakeNetwork{t: t, now: time.Unix(1_000_000, 0), scripts: scripts, port: port}
}

func (n *fakeNetwork) clock() time.Time { return n.now }

func (n *fakeNetwork) Close() error {
	n.closed = true
	return nil
}

func (n *fakeNetwork) Send(target netip.Addr, srcPort uint16, sequence uint32) (netip.Addr, bool, error) {
	if n.sendErr != nil {
		if err := n.sendErr(target); err != nil {
			return netip.Addr{}, false, err
		}
	}

	if n.onSend != nil {
		n.onSend(target)
	}

	n.sent = append(n.sent, sentSYN{target, srcPort, sequence})

	if s, held := n.scripts[target]; held {
		for index, offset := range s.offsets {
			n.push(n.now.Add(offset), n.responseFrame(target, srcPort, sequence, s, s.flags[index]))
		}
	}

	return fakeScannerIP, true, nil
}

func (n *fakeNetwork) responseFrame(target netip.Addr, srcPort uint16, sequence uint32, s script, flags string) []byte {
	n.t.Helper()

	window := s.window
	if window == 0 {
		window = 64240
	}

	sourcePort := s.srcPort
	if sourcePort == 0 {
		sourcePort = n.port
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sourcePort), DstPort: layers.TCPPort(srcPort),
		Seq: 5000, Ack: sequence + s.ackDelta, Window: window,
	}

	for _, flag := range flags {
		switch flag {
		case 'S':
			tcp.SYN = true
		case 'A':
			tcp.ACK = true
		case 'R':
			tcp.RST = true
		case 'P':
			tcp.PSH = true
		case 'F':
			tcp.FIN = true
		}
	}

	if tcp.SYN {
		tcp.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}
	}

	return serializeFrame(n.t, &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: target.AsSlice(), DstIP: fakeScannerIP.AsSlice(),
	}, tcp, gopacket.Payload(s.payload))
}

func serializeFrame(t testing.TB, ip *layers.IPv4, rest ...gopacket.SerializableLayer) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC: testGatewayMAC[:], DstMAC: testScannerMAC[:], EthernetType: layers.EthernetTypeIPv4,
	}

	if tcp, isTCP := rest[0].(*layers.TCP); isTCP {
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("set the checksum layer: %v", err)
		}
	}

	buffer := gopacket.NewSerializeBuffer()
	layersToWrite := append([]gopacket.SerializableLayer{ethernet, ip}, rest...)

	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, layersToWrite...); err != nil {
		t.Fatalf("serialize the frame: %v", err)
	}

	return buffer.Bytes()
}

func (n *fakeNetwork) push(at time.Time, frame []byte) {
	heap.Push(&n.queue, queuedFrame{at: at, order: n.order, frame: frame})
	n.order++
}

func (n *fakeNetwork) Receive(timeout time.Duration) ([]byte, time.Time, bool, error) {
	if n.receiveErr != nil {
		if err := n.receiveErr(); err != nil {
			return nil, time.Time{}, false, err
		}
	}

	if n.queue.Len() > 0 && !n.queue[0].at.After(n.now.Add(timeout)) {
		next := heap.Pop(&n.queue).(queuedFrame)
		if next.at.After(n.now) {
			n.now = next.at
		}

		return next.frame, next.at, true, nil
	}

	n.now = n.now.Add(timeout)

	return nil, time.Time{}, false, nil
}
