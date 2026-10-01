package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/capture"
	"github.com/gopacket/gopacket"
)

// The cases below port `tests/test_ja4tscan_link.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. No case opens a socket: each case passes a fake link, a fake routing table and
// a fake neighbor table, and it reads the frames that the network hands to the link.

const linkIface = "en9"

var (
	linkScannerIP  = netip.MustParseAddr("198.51.100.1")
	linkGateway    = netip.MustParseAddr("198.51.100.254")
	linkNeighbor   = netip.MustParseAddr("198.51.100.7")
	linkGatewayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0xfe}
	linkNeighborMA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x07}
)

type fakeRead struct {
	frame []byte
	at    time.Time
}

// fakeLink records each frame written, and it returns queued frames to each read.
type fakeLink struct {
	now     *time.Time
	written [][]byte
	inbox   []fakeRead
	onWrite func(frame []byte)
	closed  bool
	readErr error
}

func (l *fakeLink) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if l.readErr != nil {
		return nil, gopacket.CaptureInfo{}, l.readErr
	}

	if len(l.inbox) == 0 {
		*l.now = l.now.Add(10 * time.Millisecond)
		return nil, gopacket.CaptureInfo{}, capture.ErrReadTimeout
	}

	next := l.inbox[0]
	l.inbox = l.inbox[1:]

	return next.frame, gopacket.CaptureInfo{Timestamp: next.at}, nil
}

func (l *fakeLink) WritePacketData(frame []byte) error {
	l.written = append(l.written, append([]byte(nil), frame...))
	if l.onWrite != nil {
		l.onWrite(frame)
	}

	return nil
}

func (l *fakeLink) Close() error {
	l.closed = true
	return nil
}

func syns(link *fakeLink) [][]byte {
	var out [][]byte

	for _, frame := range link.written {
		if binary.BigEndian.Uint16(frame[12:14]) == etherTypeIPv4 {
			out = append(out, frame)
		}
	}

	return out
}

func fakeRoute(target netip.Addr) (capture.Route, error) {
	bytes4 := target.As4()

	switch {
	case bytes4[0] == 127:
		return capture.Route{Interface: "lo0", Source: netip.MustParseAddr("127.0.0.1"), Loopback: true}, nil
	case bytes4[0] == 203:
		return capture.Route{Interface: "en7", Source: netip.MustParseAddr("203.0.113.1")}, nil
	case bytes4[0] == 198:
		return capture.Route{Interface: linkIface, Source: linkScannerIP}, nil
	case bytes4[0] == 10:
		return capture.Route{}, errors.New("no route")
	}

	return capture.Route{Interface: linkIface, Source: linkScannerIP, Gateway: linkGateway}, nil
}

type linkFixture struct {
	network  *linkNetwork
	link     *fakeLink
	now      time.Time
	resolved []netip.Addr
	warnings []string
}

func newLinkFixture(t *testing.T) *linkFixture {
	t.Helper()

	f := &linkFixture{now: time.Unix(1_000_000, 0)}
	f.link = &fakeLink{now: &f.now}
	neighbors := map[netip.Addr]net.HardwareAddr{linkGateway: linkGatewayMAC, linkNeighbor: linkNeighborMA}

	f.network = &linkNetwork{
		port:  443,
		iface: linkIface,
		mac:   [6]byte(testScannerMAC),
		link:  f.link,
		route: fakeRoute,
		neighbor: func(address netip.Addr, iface string) (net.HardwareAddr, bool) {
			f.resolved = append(f.resolved, address)
			mac, held := neighbors[address]
			return mac, held && iface == linkIface
		},
		clock: func() time.Time { return f.now },
		warn:  func(line string) { f.warnings = append(f.warnings, line) },
		hops:  newHopCache(MaxTargets),
	}

	return f
}

func (f *linkFixture) send(t *testing.T, target string) (netip.Addr, bool) {
	t.Helper()

	source, sent, err := f.network.Send(netip.MustParseAddr(target), 50001, 1234)
	if err != nil {
		t.Fatalf("Send(%s): %v", target, err)
	}

	return source, sent
}

func TestATargetBehindTheGatewayGetsOneFrameToTheGateway(t *testing.T) {
	f := newLinkFixture(t)

	source, sent := f.send(t, "192.0.2.10")
	if !sent || source != linkScannerIP {
		t.Fatalf("Send returns %v, %v", source, sent)
	}

	frames := syns(f.link)
	if len(frames) != 1 {
		t.Fatalf("the link holds %d frames, want 1", len(frames))
	}

	frame := frames[0]
	if !bytes.Equal(frame[0:6], linkGatewayMAC) || !bytes.Equal(frame[6:12], testScannerMAC[:]) {
		t.Errorf("the Ethernet addresses are %x and %x", frame[0:6], frame[6:12])
	}

	if !bytes.Equal(frame[30:34], []byte{192, 0, 2, 10}) || binary.BigEndian.Uint16(frame[36:38]) != 443 {
		t.Errorf("the frame goes to %v port %d", frame[30:34], binary.BigEndian.Uint16(frame[36:38]))
	}

	if len(f.warnings) != 0 {
		t.Errorf("the send warns %v", f.warnings)
	}
}

func TestATargetOnTheLinkGetsAFrameToItsOwnAddress(t *testing.T) {
	f := newLinkFixture(t)
	f.send(t, linkNeighbor.String())

	if frames := syns(f.link); len(frames) != 1 || !bytes.Equal(frames[0][0:6], linkNeighborMA) {
		t.Errorf("the link holds %d frames to %x", len(frames), frames)
	}
}

func TestTheAddressOfOneNextHopResolvesOnce(t *testing.T) {
	f := newLinkFixture(t)
	f.send(t, "192.0.2.10")
	f.send(t, "192.0.2.11")

	if len(f.resolved) != 1 || f.resolved[0] != linkGateway || len(syns(f.link)) != 2 {
		t.Errorf("the network resolved %v and sent %d frames", f.resolved, len(syns(f.link)))
	}
}

func TestANextHopWithNoAddressGetsNoFrameAndOneWarning(t *testing.T) {
	f := newLinkFixture(t)

	if _, sent := f.send(t, "198.51.100.9"); sent {
		t.Error("Send reports a SYN to a next hop with no address")
	}

	if len(syns(f.link)) != 0 || len(f.warnings) != 1 || !strings.Contains(f.warnings[0], "198.51.100.9") {
		t.Errorf("the link holds %d SYN frames and the warnings are %q", len(syns(f.link)), f.warnings)
	}
}

// The neighbor table holds no entry, so the network asks for the address on the link, as
// `getmacbyip` of `scapy` does for the port. A frame that arrives during the wait stays for
// the next receive.
func TestANextHopThatAnswersTheAddressRequestGetsAFrame(t *testing.T) {
	f := newLinkFixture(t)
	other := netip.MustParseAddr("198.51.100.8")
	otherMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x08}
	early := []byte("a frame that arrives during the address request")

	f.link.onWrite = func(frame []byte) {
		if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
			return
		}

		if target := netip.AddrFrom4([4]byte(frame[38:42])); target != other {
			t.Errorf("the address request asks for %v, want %v", target, other)
		}

		f.link.inbox = append(f.link.inbox,
			fakeRead{frame: early, at: f.now},
			fakeRead{frame: arpReplyFrame(otherMAC, other, testScannerMAC, linkScannerIP), at: f.now})
	}

	if _, sent := f.send(t, other.String()); !sent {
		t.Fatalf("Send sends nothing, and the warnings are %q", f.warnings)
	}

	if frames := syns(f.link); len(frames) != 1 || !bytes.Equal(frames[0][0:6], otherMAC) {
		t.Errorf("the SYN goes to %x", frames)
	}

	frame, _, received, err := f.network.Receive(time.Second)
	if err != nil || !received || !bytes.Equal(frame, early) {
		t.Errorf("the next receive returns %q, %v, %v, want the frame of the wait", frame, received, err)
	}
}

func TestATargetOnAnotherInterfaceGetsNoFrameAndOneWarning(t *testing.T) {
	for _, target := range []string{"203.0.113.5", "127.0.0.1", "10.0.0.1"} {
		f := newLinkFixture(t)

		if _, sent := f.send(t, target); sent || len(f.link.written) != 0 || len(f.warnings) != 1 {
			t.Errorf("%s: Send reports %v, wrote %d frames and warned %q", target, sent, len(f.link.written), f.warnings)
		}
	}
}

func TestNoFrameWithinTheTimeoutReturnsNothing(t *testing.T) {
	f := newLinkFixture(t)
	start := f.now

	if _, _, received, err := f.network.Receive(500 * time.Millisecond); received || err != nil {
		t.Errorf("Receive returns %v, %v", received, err)
	}

	if f.now.Sub(start) < 500*time.Millisecond {
		t.Errorf("Receive returned after %v, want 500ms", f.now.Sub(start))
	}
}

func TestAFrameReturnsItsCaptureTimeAndItsBytes(t *testing.T) {
	f := newLinkFixture(t)
	at := time.Unix(1234, 500_000_000)
	f.link.inbox = []fakeRead{{frame: []byte{1, 2}, at: at}}

	frame, got, received, err := f.network.Receive(time.Second)
	if err != nil || !received || !bytes.Equal(frame, []byte{1, 2}) || !got.Equal(at) {
		t.Errorf("Receive returns %v, %v, %v, %v", frame, got, received, err)
	}
}

func TestAFrameWithNoCaptureTimeReadsTheClock(t *testing.T) {
	f := newLinkFixture(t)
	f.link.inbox = []fakeRead{{frame: []byte{1}}}

	if _, got, _, _ := f.network.Receive(time.Second); !got.Equal(f.now) {
		t.Errorf("the receive time is %v, want the clock %v", got, f.now)
	}
}

func TestAReadErrorReachesTheScan(t *testing.T) {
	f := newLinkFixture(t)
	failure := errors.New("network is down")
	f.link.readErr = failure

	if _, _, _, err := f.network.Receive(time.Second); !errors.Is(err, failure) {
		t.Errorf("Receive returns %v, want the read error", err)
	}
}

func TestTheSentFrameParsesAsTheSYNOfTheTarget(t *testing.T) {
	f := newLinkFixture(t)
	f.send(t, "192.0.2.10")

	got, ok := parseFrame(syns(f.link)[0])
	if !ok || got.srcIP != linkScannerIP || got.dstIP != netip.MustParseAddr("192.0.2.10") || got.flags != tcpFlagSYN {
		t.Errorf("the frame reads as %+v, %v", got, ok)
	}
}

func TestCloseClosesTheLink(t *testing.T) {
	f := newLinkFixture(t)
	if err := f.network.Close(); err != nil || !f.link.closed {
		t.Errorf("Close returns %v, and the link closed is %v", err, f.link.closed)
	}
}

// The next-hop cache holds each entry for at most RetransmitWait unread, and at most
// MaxTargets entries. The batch gate of #776 added the age bound.
func TestANextHopUnreadPastTheMaximumAgeIsResolvedAgain(t *testing.T) {
	f := newLinkFixture(t)
	f.send(t, linkNeighbor.String())
	f.now = f.now.Add(RetransmitWait + time.Second)
	f.send(t, linkNeighbor.String())

	if len(f.resolved) != 2 {
		t.Errorf("the network resolved %v, want the neighbor twice", f.resolved)
	}
}

func TestANextHopInsideTheMaximumAgeStaysInTheCache(t *testing.T) {
	f := newLinkFixture(t)
	f.send(t, linkNeighbor.String())
	f.now = f.now.Add(RetransmitWait - time.Second)
	f.send(t, linkNeighbor.String())

	if len(f.resolved) != 1 {
		t.Errorf("the network resolved %v, want the neighbor once", f.resolved)
	}
}

// arpReplyFrame returns the address reply of the sender to the target.
func arpReplyFrame(senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC [6]byte, targetIP netip.Addr) []byte {
	return arpFrame(arpOpReply, targetMAC, [6]byte(senderMAC), senderIP, targetMAC, targetIP)
}

func TestAnAddressReplyFromAnotherSenderAnswersNothing(t *testing.T) {
	reply := arpReplyFrame(linkGatewayMAC, linkGateway, testScannerMAC, linkScannerIP)

	if _, ok := parseARPReply(reply, linkNeighbor); ok {
		t.Error("a reply of the gateway answers a request for the neighbor")
	}

	for end := range len(reply) {
		if _, ok := parseARPReply(reply[:end], linkGateway); ok {
			t.Errorf("a reply cut to %d bytes answers the request", end)
		}
	}
}

func TestTheNextHopCacheHoldsAtMostItsBound(t *testing.T) {
	f := newLinkFixture(t)
	f.network.hops = newHopCache(2)

	largest := 0

	for index := range 5 {
		f.send(t, netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + index)}).String())
		largest = max(largest, f.network.hops.order.Len())
	}

	if largest != 2 || len(f.network.hops.entries) != f.network.hops.order.Len() {
		t.Errorf("the cache held %d entries, want 2", largest)
	}
}
