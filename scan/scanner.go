package scan

import (
	"container/list"
	"errors"
	"fmt"
	"iter"
	"math"
	"math/rand/v2"
	"net/netip"
	"time"
)

// RetransmitWait is the wait after the SYN of a target for its later responses.
// S13 of the port's `docs/specs/foxio/JA4TScan.md` at tag `v1.3.0` records the cooldown of
// 120 seconds that the FoxIO wrapper passes to zmap.
const RetransmitWait = 120 * time.Second

// NoRetransmitWait is the wait when the scan reads the first response alone. It is the
// zmap default that the same rule records.
const NoRetransmitWait = 8 * time.Second

// MaxTargets is the largest count of targets that the state table of a Scanner holds.
// The FoxIO module holds the same count at `ja4tscan/module_ja4tscan.c:169`, and
// FR-active-scan-18 of the port states it.
const MaxTargets = 10000

// maxSynAckResponses bounds the responses that one target stores. The first SYN-ACK and ten
// retransmissions fill part e, and R12 rule 4 of `docs/specs/foxio/JA4T.md` counts no
// more. So a target that floods grows no list.
const maxSynAckResponses = 11

// RFC 6335 section 6 names 49152 to 65535 as the dynamic ports, so a source port in that
// range names no service of the scanning host.
const (
	sourcePortLow  = 49152
	sourcePortHigh = 65535
)

// The TCP flag bits that the reply rule reads.
const (
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
	// segmentFlagMask covers FIN, SYN, RST, PSH, ACK and URG. It leaves out ECE and CWR,
	// because RFC 3168 section 6.1.1 lets a SYN-ACK carry ECE.
	segmentFlagMask = 0x3F
)

// isAnswer reports whether the flags answer a SYN: SYN and ACK, RST, or RST and ACK.
//
// A target sets the acknowledgment number of any segment, so that number alone names no
// answer. FR-active-scan-15 of the port states the rule, and the register of
// `docs/specs/spec.md` records the departure from `ja4tscan/module_ja4tscan.c:310`, which
// reads no flag.
func isAnswer(flags uint8) bool {
	switch flags & segmentFlagMask {
	case tcpFlagSYN | tcpFlagACK, tcpFlagRST, tcpFlagRST | tcpFlagACK:
		return true
	}

	return false
}

// Network sends the SYN of each target and receives the frames that answer it.
//
// OpenNetwork returns the network of the host. A test passes a fake network, so a scan runs
// with no packet and no socket.
type Network interface {
	// Send sends one SYN to the target from the source port, with the sequence number.
	// It returns the source address of the SYN, and false when it sent nothing. An error
	// states a socket failure, and it stops the scan.
	Send(target netip.Addr, srcPort uint16, sequence uint32) (netip.Addr, bool, error)
	// Receive waits at most the timeout for one Ethernet frame. It returns the frame and
	// its receive time, and false when no frame arrived. An error states a socket
	// failure, and it stops the scan.
	Receive(timeout time.Duration) ([]byte, time.Time, bool, error)
	// Close releases the network.
	Close() error
}

// Config states what NewScanner needs.
type Config struct {
	// Port is the TCP port of every target. It is above zero.
	Port uint16
	// Rate is the SYN count for each second. It is above zero.
	Rate float64
	// Retransmit is true to read every retransmission for RetransmitWait. False reads the
	// first response alone for NoRetransmitWait.
	Retransmit bool
	// Network sends each SYN and receives each response.
	Network Network
	// Clock returns the time that the wait reads. Nil reads time.Now.
	Clock func() time.Time
	// OnResult takes each result. Nil drops it.
	OnResult func(Result)
	// OnWarning takes each warning line. Nil drops it.
	OnWarning func(string)
	// Rand supplies the source port and the sequence number of each SYN. Nil reads the
	// global source of `math/rand/v2`.
	Rand *rand.Rand
}

// Result holds the value of one target and the endpoints of its responses.
//
// The target sent the responses that the value reads, so the target is the source.
// `ja4tscan/module_ja4tscan.c:153` records the same address as `ip_src_num`.
type Result struct {
	// Value is the JA4TScan value.
	Value string
	// Target is the address of the target.
	Target netip.Addr
	// TargetPort is the scanned port.
	TargetPort uint16
	// Scanner is the address of the scanning host.
	Scanner netip.Addr
	// ScannerPort is the source port of the SYN.
	ScannerPort uint16
	// Time is the receive time of the last response that the value reads.
	Time time.Time
}

// probe holds one target from its SYN until its wait ends.
type probe struct {
	target    netip.Addr
	srcPort   uint16
	sequence  uint32
	sentAt    time.Time
	scannerIP netip.Addr
	responses []Response
	// closed is true once a response ends the reading of the target.
	closed bool
}

// Scanner sends one SYN to each target and writes one result for each target that answers.
//
// The state table holds each target from its SYN until its wait ends, in send order. It
// holds at most MaxTargets entries, and no entry outlives its wait. The scanner sends no SYN
// while the table is full, so no target loses its wait.
//
// **One Scanner serves one goroutine.** It holds a state table that no lock guards, and it
// owns its Network for the whole scan. Run one Scanner for each scan. No SyncProcessor
// pattern applies, because the scan path is not the packet path of `Processor`.
type Scanner struct {
	config   Config
	interval time.Duration
	wait     time.Duration
	// table orders the probes by send time, and probes finds the element of a target.
	table  *list.List
	probes map[netip.Addr]*list.Element
}

// NewScanner returns a Scanner for the configuration.
// It returns an error when the port is zero, when the rate is not a finite number above
// zero, or when the configuration names no network.
func NewScanner(config Config) (*Scanner, error) {
	if config.Port == 0 {
		return nil, errors.New("scan: the port is zero, and a port is 1 to 65535")
	}

	if !(config.Rate > 0) || math.IsInf(config.Rate, 0) {
		return nil, fmt.Errorf("scan: the rate %v is not a finite number above zero", config.Rate)
	}

	if config.Network == nil {
		return nil, errors.New("scan: the configuration names no network")
	}

	if config.Clock == nil {
		config.Clock = time.Now
	}

	wait := NoRetransmitWait
	if config.Retransmit {
		wait = RetransmitWait
	}

	return &Scanner{
		config:   config,
		interval: time.Duration(float64(time.Second) / config.Rate),
		wait:     wait,
		table:    list.New(),
		probes:   map[netip.Addr]*list.Element{},
	}, nil
}

// Run sends one SYN to each target, and it returns when the wait of the last target ends.
//
// A target that the table already holds gets no second SYN. Run returns the first error of
// the network, and the results that it wrote before that error stay written.
func (s *Scanner) Run(targets iter.Seq[netip.Addr]) error {
	nextSend := s.config.Clock()

	for target := range targets {
		for s.table.Len() >= MaxTargets {
			if err := s.receiveUntil(s.oldest().sentAt.Add(s.wait)); err != nil {
				return err
			}
		}

		if err := s.receiveUntil(nextSend); err != nil {
			return err
		}

		if err := s.start(target); err != nil {
			return err
		}

		nextSend = nextSend.Add(s.interval)
		if now := s.config.Clock(); now.After(nextSend) {
			nextSend = now
		}
	}

	for s.table.Len() > 0 {
		if err := s.receiveUntil(s.oldest().sentAt.Add(s.wait)); err != nil {
			return err
		}
	}

	return nil
}

// Flush ends the wait of every target now, and it writes each result.
// A caller runs it after an interrupt, so each target writes what it already sent.
func (s *Scanner) Flush() {
	for s.table.Len() > 0 {
		s.finish(s.remove(s.table.Front()))
	}
}

func (s *Scanner) oldest() *probe {
	return s.table.Front().Value.(*probe)
}

func (s *Scanner) remove(element *list.Element) *probe {
	p := s.table.Remove(element).(*probe)
	delete(s.probes, p.target)

	return p
}

func (s *Scanner) random() uint64 {
	if s.config.Rand != nil {
		return s.config.Rand.Uint64()
	}

	return rand.Uint64()
}

// start sends the SYN to one target and adds the target to the table.
func (s *Scanner) start(target netip.Addr) error {
	if _, held := s.probes[target]; held {
		return nil
	}

	srcPort := uint16(sourcePortLow + s.random()%(sourcePortHigh-sourcePortLow+1))
	sequence := uint32(s.random())

	scannerIP, sent, err := s.config.Network.Send(target, srcPort, sequence)
	if err != nil {
		return fmt.Errorf("scan: send the SYN to %v: %w", target, err)
	}

	if !sent {
		return nil
	}

	s.probes[target] = s.table.PushBack(&probe{
		target: target, srcPort: srcPort, sequence: sequence, sentAt: s.config.Clock(), scannerIP: scannerIP,
	})

	return nil
}

// receiveUntil reads responses until the clock reaches the deadline, and it ends each
// expired wait.
func (s *Scanner) receiveUntil(deadline time.Time) error {
	for {
		now := s.config.Clock()
		s.expire(now)

		if !now.Before(deadline) {
			return nil
		}

		frame, at, received, err := s.config.Network.Receive(deadline.Sub(now))
		if err != nil {
			return fmt.Errorf("scan: receive a response: %w", err)
		}

		if !received {
			continue
		}

		if r, parsed := parseFrame(frame); parsed {
			s.accept(at, r)
		}
	}
}

// expire ends the wait of each target whose wait ended at or before the clock time.
func (s *Scanner) expire(now time.Time) {
	for s.table.Len() > 0 && !s.oldest().sentAt.Add(s.wait).After(now) {
		s.finish(s.remove(s.table.Front()))
	}
}

// accept stores one reply where it answers the SYN of a target that the table holds.
//
// A RST may acknowledge the sequence number itself or the sequence number plus one.
// `ja4tscan/module_ja4tscan.c:250-262` accepts both, and every other answer needs the
// second.
func (s *Scanner) accept(at time.Time, r reply) {
	element, held := s.probes[r.srcIP]
	if !held {
		return
	}

	p := element.Value.(*probe)
	if p.closed || r.srcPort != s.config.Port || r.dstPort != p.srcPort || !isAnswer(r.flags) {
		return
	}

	isRST := r.flags&tcpFlagRST != 0
	if r.acknowledgment != p.sequence+1 && (!isRST || r.acknowledgment != p.sequence) {
		return
	}

	// The reader returns a slice of the receive buffer, and a later receive can reuse it.
	response := Response{Time: at, Header: append([]byte(nil), r.header...)}

	switch {
	case isRST:
		p.responses = append(p.responses, response)
		p.closed = true
	case len(p.responses) < maxSynAckResponses:
		p.responses = append(p.responses, response)
	}

	if !s.config.Retransmit {
		p.closed = true
	}
}

// finish writes the result of one target, and it warns where the target never retransmitted.
func (s *Scanner) finish(p *probe) {
	value, answered := Value(p.responses)
	if !answered {
		return
	}

	if s.config.OnResult != nil {
		s.config.OnResult(Result{
			Value:       value,
			Target:      p.target,
			TargetPort:  s.config.Port,
			Scanner:     p.scannerIP,
			ScannerPort: p.srcPort,
			Time:        p.responses[len(p.responses)-1].Time,
		})
	}

	// A SYN-ACK with no retransmission usually means that the kernel of this host sent a
	// RST, so FR-active-scan-9 of the port warns the operator.
	if s.config.Retransmit && len(p.responses) == 1 && value != ResetValue && s.config.OnWarning != nil {
		s.config.OnWarning(fmt.Sprintf(
			"Warning: %v sent one SYN-ACK and no retransmission in %d seconds. "+
				"The kernel of this host may have sent it a RST, so check the firewall rules above.",
			p.target, int(s.wait.Seconds())))
	}
}
