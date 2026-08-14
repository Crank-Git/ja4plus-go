//go:build linux && !libpcap

package capture

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

// ethernetHandle is the pure-Go backend, and it reads one packet socket.
//
// `pcapgo/capture.go` at gopacket v1.6.1 opens with `//go:build linux`, and it imports no
// C. So this backend reaches Linux alone, and the default build holds no cgo.
type ethernetHandle struct {
	handle *pcapgo.EthernetHandle
	// drops holds the total drop count, because the packet socket reports a delta.
	drops dropAccumulator
}

// open returns the pure-Go capture handle for the interface that the options name.
// It returns an error when the host holds no interface of that name.
// It returns an error when the host refuses the packet socket. `openError` carries the
// errno of that refusal, and FR-capture-35 reads it.
// It returns an error when the options carry a capture filter, because the maintainer
// ruled on 2026-08-14 that the pure-Go backend applies none.
func open(opts Options) (Handle, error) {
	handle, err := pcapgo.NewEthernetHandle(opts.Interface)
	if err != nil {
		return nil, openError(opts.Interface, err)
	}

	if opts.Filter != "" {
		program, compileErr := compileFilter(opts.Filter)
		if compileErr != nil {
			_ = handle.Close()
			return nil, compileErr
		}
		// `compileFilter` returns an error for every filter under the ruling of #564, so
		// no run reaches the line below today. The call site stays, because a reversal of
		// that ruling restores the program and changes one function.
		// `SetBPF` attaches the program to the packet socket, so the kernel drops a
		// packet that the filter rejects.
		if err := handle.SetBPF(program); err != nil {
			_ = handle.Close()
			return nil, fmt.Errorf("capture: the packet socket takes no filter program: %w", err)
		}
	}

	return &ethernetHandle{handle: handle}, nil
}

// ReadPacketData returns the bytes of the next packet, and the capture information of that
// packet.
//
// It calls `ReadPacketData` of `pcapgo.EthernetHandle`, which copies the bytes out of the
// read buffer. `ZeroCopyReadPacketData` returns the buffer itself, and the next read
// overwrites it, so this backend declines that method.
func (e *ethernetHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := e.handle.ReadPacketData()
	if err != nil {
		return nil, info, fmt.Errorf("capture: the interface returns no packet: %w", err)
	}
	return data, info, nil
}

// LinkType returns `layers.LinkTypeEthernet`.
//
// `pcapgo.NewEthernetHandle` binds an `AF_PACKET` socket with the protocol `ETH_P_ALL`,
// and that socket delivers the link-layer header of the interface. The name of the
// constructor states the link layer the backend reads.
func (e *ethernetHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// DropCount returns the count of packets the packet socket dropped since the handle
// opened. FR-capture-34 states that the pure-Go backend reads the count from the packet
// socket.
//
// It returns false when the socket option reports no value. That answer covers one sample
// alone, and a later sample reports a count again. FR-capture-33 writes `unknown` for it.
//
// `EthernetHandle.Stats` reads `PACKET_STATISTICS` with `getsockopt`, and it returns
// `*unix.TpacketStats`. The doc comment of `gopacket@v1.6.1/pcapgo/capture.go:273` states
// the delta: `This will be the number of packets/dropped packets since the last call to
// stats (not the cummulative sum!)`. So this method accumulates each delta, and the
// accumulator holds the total that the statistics line reports.
// Verified against: <https://pkg.go.dev/github.com/gopacket/gopacket/pcapgo>, read from
// the module cache at `github.com/gopacket/gopacket@v1.6.1` on 2026-08-14.
func (e *ethernetHandle) DropCount() (uint64, bool) {
	stats, err := e.handle.Stats()
	if err != nil {
		return 0, false
	}

	return e.drops.add(stats.Drops), true
}

// Close releases the packet socket.
func (e *ethernetHandle) Close() error {
	if err := e.handle.Close(); err != nil {
		return fmt.Errorf("capture: the packet socket does not close: %w", err)
	}
	return nil
}

// compileFilter returns an error for every capture filter, and it returns no BPF program.
//
// **The maintainer ruled #564 on 2026-08-14, and the pure-Go backend applies no capture
// filter.** No compiler of a Berkeley Packet Filter expression reaches this build:
// `golang.org/x/net/bpf` assembles an instruction slice and parses no expression, and
// `pcap.CompileBPFFilter` calls `C.pcap_compile`, which needs cgo. A compiler for a subset
// of the expression grammar would give the two backends two grammars, so one filter would
// select two packet sets. The ruling declines that outcome, and the error names the build
// command that applies a filter.
//
// Issue #564 is the reversal path. FR-capture-15 of
// `docs/specs/features/13-live-capture.md` states the ruling.
func compileFilter(expr string) ([]bpf.RawInstruction, error) {
	return nil, fmt.Errorf(
		"capture: the pure-Go backend applies no capture filter, and it declines the filter %q. "+
			"Build with the libpcap build tag to apply a capture filter: "+
			"go build -tags libpcap ./cmd/ja4plus", expr)
}
