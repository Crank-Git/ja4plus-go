// Package capture opens a capture handle on one live interface.
//
// The build selects one capture backend. `pcapgo_linux.go` holds the pure-Go backend, and
// it builds on Linux alone. A build that selects no backend compiles, and `Open` returns
// an error on it.
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
	// Close releases the capture handle.
	Close() error
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
