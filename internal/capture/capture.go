// Package capture opens a capture handle on one live interface.
//
// The build selects one capture backend. `pcapgo_linux.go` holds the pure-Go backend, and
// it builds on Linux alone. A build that carries no build tag selects the fallback of
// `unsupported.go` on another platform. That build compiles, and `Open` returns an error
// on it.
//
// A build that carries the `libpcap` build tag selects the backend of `libpcap.go`. That
// backend needs cgo, and FR-capture-12 states the build constraint that contains it.
//
// The package writes nothing to standard output and nothing to standard error. It returns
// an error, and `cmd/ja4plus` prints it. `CLAUDE.md` `## Conventions` states that rule.
package capture

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Options states what Open needs to open a capture handle.
type Options struct {
	// Interface names the interface the monitor reads.
	Interface string
	// Filter holds the capture filter, which is a Berkeley Packet Filter expression.
	// An empty value applies no filter.
	Filter string
}

// Handle reads packets from one live interface.
//
// One goroutine owns one Handle. The goroutine that reads the handle also closes it,
// because the backend holds one read buffer for the handle.
// `.claude/rules/concurrency.md` `## The contract` states the same model for `Processor`.
//
// The monitor opens one handle for the whole run, and FR-capture-14 states that rule.
type Handle interface {
	// ReadPacketData returns the bytes of the next packet, and the capture information
	// of that packet. It blocks until the interface delivers a packet.
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	// LinkType returns the link type of the bytes that ReadPacketData returns.
	LinkType() layers.LinkType
	// DropCount returns the count of packets the capture backend dropped since the handle
	// opened. It returns false when the backend reports no count, and FR-capture-33 of
	// `docs/specs/features/13-live-capture.md` writes `unknown` for that answer.
	//
	// The goroutine that reads the handle calls this method, and no second goroutine calls
	// it. The pure-Go backend accumulates a delta that the kernel resets at each read, so a
	// second caller takes a count that the first caller then loses.
	DropCount() (uint64, bool)
	// Close releases the capture handle.
	Close() error
}

// dropAccumulator holds the total drop count of a backend that reports a delta.
//
// The packet socket of Linux resets its counter at each read, so a backend that reads it
// twice sees two deltas and never a total. `packet(7)` states the reset:
// `Receiving statistics resets the internal counters.`
// Verified against: <https://man7.org/linux/man-pages/man7/packet.7.html>, retrieved
// 2026-08-14.
//
// One goroutine owns one accumulator, because one goroutine owns the handle that holds it.
// The type carries no build constraint, so a test of every platform reads it.
type dropAccumulator struct {
	// total holds the count of packets the backend dropped since the handle opened.
	total uint64
}

// add records one delta, and it returns the total since the handle opened.
// The total holds 64 bits and the delta holds 32, because a monitor that runs for weeks
// passes the width of one delta.
func (a *dropAccumulator) add(delta uint32) uint64 {
	a.total += uint64(delta)

	return a.total
}

// PermissionDenied reports whether the host refused the capture handle because the process
// holds too little privilege. `cmd/ja4plus` reads this answer, and FR-capture-35 of
// `docs/specs/features/13-live-capture.md` states the message that follows it.
//
// It reads the error chain with `errors.Is`, and it reads no message text. The text of a
// capture failure comes from a C library, from a Go library and from the locale of the
// host, so a match on the text reports a failure that no host stated.
//
// The host states the refusal as an errno. `socket(2)` states EACCES:
// `Permission to create a socket of the specified type and/or protocol is denied.`
// `packet(7)` states EPERM: `User has insufficient privileges to carry out this operation.`
// Verified against: <https://man7.org/linux/man-pages/man2/socket.2.html> and
// <https://man7.org/linux/man-pages/man7/packet.7.html>, retrieved 2026-08-14.
func PermissionDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// captureOpenError is the error that a capture backend returns when it opens no handle.
//
// It carries more than one cause, because the message of the backend and the errno of the
// host are two different records of one failure. `errors.Is` reads every cause, so
// `PermissionDenied` reaches the errno and a caller still reaches the message.
type captureOpenError struct {
	// message states the interface and the text of the backend.
	message string
	// causes holds the cause of the backend, and the errno of the host when the host
	// refuses a capture handle.
	causes []error
}

// Error returns the message that the operator reads.
func (e *captureOpenError) Error() string {
	return e.message
}

// Unwrap returns every cause of the failure, so errors.Is reads each one.
func (e *captureOpenError) Unwrap() []error {
	return e.causes
}

// openError returns the error that a capture backend reports when it opens no handle for
// the interface that the caller names.
//
// It carries the errno of the host when the host refuses a capture handle, because a
// capture library flattens that errno into its message text.
// `gopacket@v1.6.1/pcapgo/capture.go:299` writes
// `return nil, fmt.Errorf("couldn't open packet socket: %s", err)`, which holds `%s` and
// never `%w`. `gopacket@v1.6.1/pcap/pcap_unix.go:249` writes
// `return nil, errors.New(C.GoString(buf))`, which reads the error buffer of libpcap. So
// the cause of either backend carries no errno, and `captureRefusal` recovers one.
//
// It returns the cause alone when the host holds no interface of that name. The edge-case
// table of `docs/specs/features/13-live-capture.md` states one message that names the
// interface for that case. A host that refuses a capture handle refuses it for every
// interface, so the probe would report a permission failure for a name that names nothing.
func openError(name string, cause error) error {
	err := &captureOpenError{
		message: fmt.Sprintf("capture: the host opens no interface %s: %s", name, cause.Error()),
		causes:  []error{cause},
	}

	if _, lookupErr := net.InterfaceByName(name); lookupErr != nil {
		return err
	}

	if refusal := captureRefusal(); refusal != nil {
		err.causes = append(err.causes, refusal)
	}

	return err
}

// Open returns a capture handle for the interface that the options name.
// It returns an error when the options name no interface.
// It returns an error when the build selects no capture backend.
func Open(opts Options) (Handle, error) {
	if opts.Interface == "" {
		return nil, errors.New("capture: the options name no interface")
	}

	return open(opts)
}
