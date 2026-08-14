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
}

// open returns the pure-Go capture handle for the interface that the options name.
// It returns an error when the host holds no interface of that name.
// It returns an error when the capture filter reaches no compiler.
func open(opts Options) (Handle, error) {
	handle, err := pcapgo.NewEthernetHandle(opts.Interface)
	if err != nil {
		return nil, fmt.Errorf("capture: the host opens no interface %s: %w", opts.Interface, err)
	}

	if opts.Filter != "" {
		program, compileErr := compileFilter(opts.Filter)
		if compileErr != nil {
			_ = handle.Close()
			return nil, compileErr
		}
		// FR-capture-15 applies the capture filter as a BPF program. `SetBPF` attaches
		// the program to the packet socket, so the kernel drops a packet the filter
		// rejects.
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

// Close releases the packet socket.
func (e *ethernetHandle) Close() error {
	if err := e.handle.Close(); err != nil {
		return fmt.Errorf("capture: the packet socket does not close: %w", err)
	}
	return nil
}

// compileFilter returns the BPF program of one capture filter.
//
// It returns an error for every expression today, because this module holds no compiler
// that reads a Berkeley Packet Filter expression. `golang.org/x/net/bpf` assembles an
// instruction slice and it parses no expression. `pcap.CompileBPFFilter` compiles an
// expression, and `pcap/pcap_unix.go` includes `<pcap.h>`, so it needs cgo.
//
// TODO(#564): Compile the capture filter on the pure-Go path.
func compileFilter(expr string) ([]bpf.RawInstruction, error) {
	return nil, fmt.Errorf("capture: the pure-Go backend compiles no capture filter, and the filter is %q", expr)
}
