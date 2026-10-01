package scan

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/capture"
	"github.com/gopacket/gopacket"
)

// The fields of an address request of RFC 826, for IPv4 over Ethernet.
const (
	etherTypeARP  = 0x0806
	arpFrameBytes = ethernetHeaderBytes + 28
	arpOpRequest  = 1
	arpOpReply    = 2
)

// arpWait bounds the wait for an address reply. A neighbor on the link answers within
// milliseconds, so a next hop that sends no reply in one second sends none.
const arpWait = time.Second

// maxPendingFrames bounds the frames that the network keeps from the wait for an address
// reply. A busy interface delivers frames without a bound, so a later frame is dropped.
const maxPendingFrames = 4096

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// frameLink is the part of `capture.Link` that the network reads, so a test passes a fake.
type frameLink interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	WritePacketData(frame []byte) error
	Close() error
}

type pendingFrame struct {
	frame []byte
	at    time.Time
}

// linkNetwork sends each SYN as an Ethernet frame on one interface, and it reads each
// response from the same interface.
type linkNetwork struct {
	port  uint16
	iface string
	mac   [6]byte
	link  frameLink
	// route and neighbor read the tables of the kernel, and a test passes fakes.
	route    func(netip.Addr) (capture.Route, error)
	neighbor func(netip.Addr, string) (net.HardwareAddr, bool)
	clock    func() time.Time
	warn     func(string)
	hops     *hopCache
	// pending holds the frames that arrived during the wait for an address reply.
	pending []pendingFrame
}

// OpenNetwork returns the network of this host for a scan of the port. The route to the
// first target names the interface, and every SYN leaves through that interface.
//
// The SYN leaves as an Ethernet frame, as zmap writes it. The send primitive lives in
// `internal/capture`, and the maintainer ruled that placement on 2026-10-01 in #796. Each
// warning reaches the warn function.
//
// It returns an error when the first target routes through a loopback interface, when the
// interface holds no Ethernet address, and when the host refuses the link.
// `capture.PermissionDenied` reads a refused privilege. A macOS build without the `libpcap`
// build tag returns an error that names the tag.
//
// **The returned Network serves one goroutine, and it is not safe for concurrent use.** It
// holds a next-hop cache and a list of pending frames, and no lock guards either one. The
// goroutine that runs the Scanner makes every call, and that goroutine calls Close after
// the scan. `.claude/rules/concurrency.md` states the shard pattern for one `Processor`,
// and one network for each Scanner is the same pattern. OpenNetwork itself holds no shared
// state, so two goroutines can each open a network of their own.
func OpenNetwork(port uint16, first netip.Addr, warn func(string)) (Network, error) {
	route, err := capture.LookupRoute(first)
	if err != nil {
		return nil, err
	}

	if route.Loopback {
		return nil, fmt.Errorf("scan: %v routes through the loopback interface %s, and the scan sends Ethernet frames", first, route.Interface)
	}

	iface, err := net.InterfaceByName(route.Interface)
	if err != nil {
		return nil, fmt.Errorf("scan: the host holds no interface %s: %w", route.Interface, err)
	}

	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("scan: the interface %s holds no Ethernet address", route.Interface)
	}

	link, err := capture.OpenLink(route.Interface)
	if err != nil {
		return nil, err
	}

	if warn == nil {
		warn = func(string) {}
	}

	return &linkNetwork{
		port:     port,
		iface:    route.Interface,
		mac:      [6]byte(iface.HardwareAddr),
		link:     link,
		route:    capture.LookupRoute,
		neighbor: capture.LookupNeighbor,
		clock:    time.Now,
		warn:     warn,
		hops:     newHopCache(MaxTargets),
	}, nil
}

// Send sends one SYN frame to the target. A target that routes through another interface or
// through a loopback interface gets no SYN, and so does a target whose next hop states no
// link-layer address. Each case writes one warning.
func (n *linkNetwork) Send(target netip.Addr, srcPort uint16, sequence uint32) (netip.Addr, bool, error) {
	route, err := n.route(target)
	if err != nil {
		n.warn(fmt.Sprintf("Warning: the host states no route to %v. The scan sends it no SYN.", target))
		return netip.Addr{}, false, nil
	}

	if route.Loopback {
		n.warn(fmt.Sprintf("Warning: %v routes through the loopback interface. The scan sends it no SYN.", target))
		return netip.Addr{}, false, nil
	}

	if route.Interface != n.iface {
		n.warn(fmt.Sprintf("Warning: %v routes through the interface %s, and the scan sends through %s. "+
			"The scan sends it no SYN.", target, route.Interface, n.iface))
		return netip.Addr{}, false, nil
	}

	hop := target
	if route.Gateway.IsValid() {
		hop = route.Gateway
	}

	mac, resolved, err := n.resolve(hop, route.Source)
	if err != nil {
		return netip.Addr{}, false, err
	}

	if !resolved {
		n.warn(fmt.Sprintf("Warning: the next hop %v of %v answered no address request. The scan sends it no SYN.", hop, target))
		return netip.Addr{}, false, nil
	}

	frame := buildSYN(synFrame{
		srcMAC:   n.mac,
		dstMAC:   mac,
		srcIP:    route.Source.As4(),
		dstIP:    target.As4(),
		srcPort:  srcPort,
		dstPort:  n.port,
		sequence: sequence,
		// FoxIO writes the send time in whole seconds, and the option keeps 32 bits.
		timestamp: uint32(n.clock().Unix()),
	})

	if err := n.link.WritePacketData(frame); err != nil {
		return netip.Addr{}, false, err
	}

	return route.Source, true, nil
}

// resolve returns the link-layer address of the next hop. It reads the cache, then the
// neighbor table of the kernel, and then it asks on the link, as `getmacbyip` of `scapy`
// does for the port. The cache keeps a failed answer too, so a dead gateway costs one wait.
func (n *linkNetwork) resolve(hop, source netip.Addr) ([6]byte, bool, error) {
	now := n.clock()

	if mac, resolved, held := n.hops.get(hop, now); held {
		return mac, resolved, nil
	}

	if mac, held := n.neighbor(hop, n.iface); held && len(mac) == 6 {
		n.hops.put(hop, [6]byte(mac), true, now)
		return [6]byte(mac), true, nil
	}

	mac, resolved, err := n.request(hop, source)
	if err != nil {
		return mac, false, err
	}

	n.hops.put(hop, mac, resolved, n.clock())

	return mac, resolved, nil
}

// request sends one address request for the next hop, and it waits arpWait for the reply.
// Every other frame of the wait stays for the next receive.
func (n *linkNetwork) request(hop, source netip.Addr) ([6]byte, bool, error) {
	if err := n.link.WritePacketData(arpFrame(arpOpRequest, broadcastMAC, n.mac, source, [6]byte{}, hop)); err != nil {
		return [6]byte{}, false, err
	}

	deadline := n.clock().Add(arpWait)

	for n.clock().Before(deadline) {
		frame, at, received, err := n.read()
		if err != nil {
			return [6]byte{}, false, err
		}

		if !received {
			continue
		}

		if mac, answered := parseARPReply(frame, hop); answered {
			return mac, true, nil
		}

		if len(n.pending) < maxPendingFrames {
			n.pending = append(n.pending, pendingFrame{frame: frame, at: at})
		}
	}

	return [6]byte{}, false, nil
}

// read reads one frame from the link, and false when the link delivers none before its
// read deadline.
func (n *linkNetwork) read() ([]byte, time.Time, bool, error) {
	frame, info, err := n.link.ReadPacketData()
	if errors.Is(err, capture.ErrReadTimeout) {
		return nil, time.Time{}, false, nil
	}

	if err != nil {
		return nil, time.Time{}, false, err
	}

	at := info.Timestamp
	if at.IsZero() {
		at = n.clock()
	}

	return frame, at, true, nil
}

// Receive returns a frame of the wait for an address reply first, and then it reads the
// link until the timeout ends. The link reads for at most 10 ms, so the wait ends at most
// 10 ms after the timeout.
func (n *linkNetwork) Receive(timeout time.Duration) ([]byte, time.Time, bool, error) {
	if len(n.pending) > 0 {
		next := n.pending[0]
		n.pending = n.pending[1:]

		return next.frame, next.at, true, nil
	}

	deadline := n.clock().Add(timeout)

	for {
		frame, at, received, err := n.read()
		if err != nil || received {
			return frame, at, received, err
		}

		if !n.clock().Before(deadline) {
			return nil, time.Time{}, false, nil
		}
	}
}

// Close releases the link.
func (n *linkNetwork) Close() error {
	return n.link.Close()
}

// arpFrame returns an Ethernet frame that carries one address message of RFC 826.
func arpFrame(op uint16, dst, senderMAC [6]byte, senderIP netip.Addr, targetMAC [6]byte, targetIP netip.Addr) []byte {
	frame := make([]byte, arpFrameBytes)
	copy(frame[0:6], dst[:])
	copy(frame[6:12], senderMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	message := frame[ethernetHeaderBytes:]
	binary.BigEndian.PutUint16(message[0:2], 1)
	binary.BigEndian.PutUint16(message[2:4], etherTypeIPv4)
	message[4] = 6
	message[5] = 4
	binary.BigEndian.PutUint16(message[6:8], op)
	copy(message[8:14], senderMAC[:])
	sender := senderIP.As4()
	copy(message[14:18], sender[:])
	copy(message[18:24], targetMAC[:])
	target := targetIP.As4()
	copy(message[24:28], target[:])

	return frame
}

// parseARPReply returns the link-layer address of the next hop when the frame is its
// address reply. Every frame is hostile input, so the reader bounds each read.
func parseARPReply(frame []byte, hop netip.Addr) ([6]byte, bool) {
	if len(frame) < arpFrameBytes || binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return [6]byte{}, false
	}

	message := frame[ethernetHeaderBytes:]
	if binary.BigEndian.Uint16(message[0:2]) != 1 || binary.BigEndian.Uint16(message[2:4]) != etherTypeIPv4 ||
		message[4] != 6 || message[5] != 4 || binary.BigEndian.Uint16(message[6:8]) != arpOpReply {
		return [6]byte{}, false
	}

	if netip.AddrFrom4([4]byte(message[14:18])) != hop {
		return [6]byte{}, false
	}

	return [6]byte(message[8:14]), true
}

// hopCache holds the link-layer address of each next hop that a send read.
//
// It holds at most limit entries, and it drops an entry that no send read for
// RetransmitWait. The state table of a Scanner holds a target for at most that wait, so an
// older entry serves no target that the table holds. The batch gate of
// `Crank-Git/ja4plus#776` added the age bound.
type hopCache struct {
	limit   int
	entries map[netip.Addr]*list.Element
	// order holds the entries from the least recently read to the most recently read.
	order *list.List
}

type hopEntry struct {
	hop      netip.Addr
	mac      [6]byte
	resolved bool
	readAt   time.Time
}

func newHopCache(limit int) *hopCache {
	return &hopCache{limit: limit, entries: map[netip.Addr]*list.Element{}, order: list.New()}
}

// get returns the entry of the next hop, and false when the cache holds none. A read renews
// the age of the entry.
func (c *hopCache) get(hop netip.Addr, now time.Time) ([6]byte, bool, bool) {
	c.expire(now)

	element, held := c.entries[hop]
	if !held {
		return [6]byte{}, false, false
	}

	entry := element.Value.(*hopEntry)
	entry.readAt = now
	c.order.MoveToBack(element)

	return entry.mac, entry.resolved, true
}

// put stores the answer for the next hop. It drops the least recently read entry when the
// cache is full.
func (c *hopCache) put(hop netip.Addr, mac [6]byte, resolved bool, now time.Time) {
	c.expire(now)

	if element, held := c.entries[hop]; held {
		c.order.Remove(element)
		delete(c.entries, hop)
	}

	for c.order.Len() >= c.limit {
		c.drop(c.order.Front())
	}

	c.entries[hop] = c.order.PushBack(&hopEntry{hop: hop, mac: mac, resolved: resolved, readAt: now})
}

// expire drops each entry that no send read for RetransmitWait.
func (c *hopCache) expire(now time.Time) {
	for c.order.Len() > 0 {
		front := c.order.Front()
		if now.Sub(front.Value.(*hopEntry).readAt) <= RetransmitWait {
			return
		}

		c.drop(front)
	}
}

func (c *hopCache) drop(element *list.Element) {
	delete(c.entries, element.Value.(*hopEntry).hop)
	c.order.Remove(element)
}
