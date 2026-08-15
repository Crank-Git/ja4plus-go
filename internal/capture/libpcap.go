//go:build libpcap

package capture

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// snapshotLength is the count of bytes that libpcap copies from each frame.
//
// A truncated frame gives a fingerprinter a truncated TLS ClientHello, and a truncated
// ClientHello produces a wrong fingerprint. 65536 exceeds the largest frame of every link
// type this backend opens, so no capture truncates a packet.
const snapshotLength = 65536

// pcapHandle is the libpcap backend, and the `libpcap` build tag selects it.
//
// `pcap/pcap_unix.go` at gopacket v1.6.1 imports `C`, so this file needs cgo.
// FR-capture-12 keeps it behind the build tag, and `CLAUDE.md` `## Stack` states that no
// released binary carries it.
//
// One goroutine owns one pcapHandle, as the doc comment of Handle states.
type pcapHandle struct {
	handle *pcap.Handle
}

// open returns the libpcap capture handle for the interface that the options name.
// It returns an error when libpcap opens no interface of that name.
// It returns an error when the host refuses the capture device. `openError` carries the
// errno of that refusal, and FR-capture-35 reads it.
// It returns an error when libpcap compiles no program for the capture filter.
func open(opts Options) (Handle, error) {
	// The fourth argument is the read deadline, and `readDeadline` states it. libpcap then
	// returns `pcap.NextErrorTimeoutExpired` on an idle interface, and `ReadPacketData`
	// below returns `ErrReadTimeout` for it. **The two backends report an idle interface one
	// way**, because the pure-Go backend reports the same answer at the same deadline.
	//
	// **This argument read `pcap.BlockForever` until 2026-08-14**, and #78 passed that value
	// so that the two backends behaved the same. Issue #610 measured the cost of the shared
	// answer: a read that blocks forever reaches the stop request never, so one `SIGINT`
	// stopped no monitor on an interface that carries no traffic. Issue #610 is the reversal
	// path.
	//
	// `OpenLive` sets non-blocking mode for a deadline above zero, and `waitForPacket` then
	// waits `timeoutMillis(p.timeout)` for one packet. `gopacket@v1.6.1/pcap/pcap.go:169`
	// and `gopacket@v1.6.1/pcap/pcap_unix.go:700` hold the two readings.
	// Verified against: <https://pkg.go.dev/github.com/gopacket/gopacket/pcap>, read from the
	// module cache at `github.com/gopacket/gopacket@v1.6.1` on 2026-08-14.
	//
	// The third argument sets promiscuous mode, and this backend takes none.
	// `pcapgo.NewEthernetHandle` sets none either, so the two backends read one packet set.
	handle, err := pcap.OpenLive(opts.Interface, snapshotLength, false, readDeadline)
	if err != nil {
		return nil, openError(opts.Interface, err)
	}

	if opts.Filter != "" {
		// `SetBPFFilter` calls `C.pcap_compile` and then `C.pcap_setfilter`, so libpcap
		// compiles the whole filter grammar here and the kernel drops a packet that the
		// filter rejects. The maintainer ruled #564 on 2026-08-14, and this backend is the
		// one that applies a capture filter.
		//
		// The call runs after the open, because `pcap_compile` reads the link type of the
		// handle. A program compiled for another link type selects the wrong bytes.
		if filterErr := handle.SetBPFFilter(opts.Filter); filterErr != nil {
			handle.Close()
			return nil, filterError(opts.Filter, filterErr)
		}
	}

	return &pcapHandle{handle: handle}, nil
}

// filterError returns the error that Open reports when libpcap compiles no program for the
// capture filter. It holds the filter text and the parser error, because the operator
// repairs the expression.
func filterError(filter string, cause error) error {
	return fmt.Errorf("capture: libpcap compiles no program for the filter %q: %w", filter, cause)
}

// ReadPacketData returns the bytes of the next packet, and the capture information of that
// packet.
// It returns `ErrReadTimeout` when the interface delivers no packet before the read
// deadline.
//
// It calls `ReadPacketData` of `pcap.Handle`, which copies the bytes out of the read
// buffer. `ZeroCopyReadPacketData` returns the buffer itself, and the next read overwrites
// it, so this backend declines that method.
func (p *pcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := p.handle.ReadPacketData()
	if err != nil {
		return nil, info, readError(err)
	}
	return data, info, nil
}

// readError returns the error that ReadPacketData reports for the failure that libpcap
// returned.
//
// It returns `ErrReadTimeout` for the read deadline, because a deadline states no failure
// of the capture. `pcap.NextErrorTimeoutExpired` is the value that libpcap returns for it,
// and `gopacket@v1.6.1/pcap/pcap.go:335` returns that value when the deadline is above
// zero.
//
// The caller calls this function inside the branch of a failed read, so the failure is
// never nil.
func readError(cause error) error {
	if errors.Is(cause, pcap.NextErrorTimeoutExpired) {
		return ErrReadTimeout
	}

	return fmt.Errorf("capture: the interface returns no packet: %w", cause)
}

// LinkType returns the link type that libpcap reports for the interface.
//
// It calls `pcap_datalink`, so the value states what the host delivers. A loopback
// interface of macOS reports `layers.LinkTypeNull`, and an Ethernet interface reports
// `layers.LinkTypeEthernet`. This backend reads the value and states no constant, because
// libpcap opens more link types than the packet socket of Linux does.
func (p *pcapHandle) LinkType() layers.LinkType {
	return p.handle.LinkType()
}

// DropCount returns the count of packets libpcap dropped since the handle opened.
//
// It returns false when libpcap reports no statistics for the handle, and FR-capture-33
// writes `unknown` for that answer. It returns false for a negative count too, because a
// count below zero states no drop total.
//
// `pcap.Handle.Stats` calls `pcap_stats`, which fills `PacketsDropped` from `ps_drop`. The
// manual page states the count: `number of packets dropped because there was no room in
// the operating system's buffer when they arrived, because packets weren't being read fast
// enough`. It states the period too: `The values represent packet statistics from the
// start of the run to the time of the call.` So this backend accumulates nothing, and the
// pure-Go backend of `pcapgo_linux.go` accumulates a delta.
// Verified against: <https://www.tcpdump.org/manpages/pcap_stats.3pcap.html>, retrieved
// 2026-08-14. The Go binding is `gopacket@v1.6.1/pcap/pcap_unix.go:278`.
func (p *pcapHandle) DropCount() (uint64, bool) {
	stats, err := p.handle.Stats()
	if err != nil {
		return 0, false
	}

	if stats.PacketsDropped < 0 {
		return 0, false
	}

	return uint64(stats.PacketsDropped), true
}

// Close releases the libpcap handle. It returns no error.
//
// `pcap.Handle.Close` of gopacket v1.6.1 returns no value, so this backend reports no
// close failure. The interface states an error return because the pure-Go backend of
// `pcapgo_linux.go` closes a packet socket, and a socket close reports one.
func (p *pcapHandle) Close() error {
	p.handle.Close()
	return nil
}
