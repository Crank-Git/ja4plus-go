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

// Open returns a capture handle for the interface that the options name.
// It returns an error when the options name no interface.
// It returns an error when the build selects no capture backend.
func Open(opts Options) (Handle, error) {
	if opts.Interface == "" {
		return nil, errors.New("capture: the options name no interface")
	}

	return open(opts)
}
