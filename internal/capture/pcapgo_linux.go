//go:build linux && !libpcap

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

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
	// linkType holds the link type of the interface that `open` read. `open` refuses an
	// interface whose hardware type reaches no link type, so this field is never zero.
	linkType layers.LinkType
	// drops holds the total drop count, because the packet socket reports a delta.
	drops dropAccumulator
}

// open returns the pure-Go capture handle for the interface that the options name.
// It returns an error when the host holds no interface of that name.
// It returns an error when the host refuses the packet socket. `openError` carries the
// errno of that refusal, and FR-capture-35 reads it.
// It returns an error when the options carry a capture filter, because the maintainer
// ruled on 2026-08-14 that the pure-Go backend applies none.
// It returns an error when the interface carries no Ethernet header, and issue #609 states
// the reason: a wrong link type emits a wrong fingerprint and reports no error.
func open(opts Options) (Handle, error) {
	handle, err := pcapgo.NewEthernetHandle(opts.Interface)
	if err != nil {
		return nil, openError(opts.Interface, err)
	}

	// The hardware type is read after the open, because `NewEthernetHandle` reports the
	// name failure and the permission failure that `openError` reads. A refusal here closes
	// the packet socket, so the handle leaks no file descriptor.
	linkType, err := readLinkType(opts.Interface)
	if err != nil {
		_ = handle.Close()
		return nil, err
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

	return &ethernetHandle{handle: handle, linkType: linkType}, nil
}

// readLinkType returns the link type of the bytes that the packet socket delivers for the
// interface that the caller names.
// It returns an error when the interface carries no Ethernet header.
// It returns an error when the kernel states no hardware type for the interface.
//
// The kernel states the hardware type of an interface in the `ifi_type` field of
// `struct ifinfomsg`, and `rtnetlink(7)` names that field `Device type`. A dump of
// `RTM_GETLINK` answers with one `RTM_NEWLINK` message for each interface, and
// `net/interface_linux.go` of the standard library reads the same dump the same way.
// Verified against: <https://man7.org/linux/man-pages/man7/rtnetlink.7.html>, retrieved
// 2026-08-14.
//
// It reads the two fields with `binary.NativeEndian` and never with `unsafe`, because
// netlink writes each field in the byte order of the host. The offsets come from
// `syscall.IfInfomsg`, which holds the pad byte that the manual page leaves out: `Family`
// at 0, the pad at 1, `Type` at 2 and `Index` at 4.
func readLinkType(name string) (layers.LinkType, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("capture: the host states no index for the interface %s: %w", name, err)
	}

	dump, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("capture: the kernel lists no interface: %w", err)
	}

	messages, err := syscall.ParseNetlinkMessage(dump)
	if err != nil {
		return 0, fmt.Errorf("capture: the interface list of the kernel does not parse: %w", err)
	}

	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		if len(message.Data) < syscall.SizeofIfInfomsg {
			continue
		}
		if int(int32(binary.NativeEndian.Uint32(message.Data[4:8]))) != iface.Index {
			continue
		}

		return linkTypeForHardwareType(name, binary.NativeEndian.Uint16(message.Data[2:4]))
	}

	return 0, fmt.Errorf("capture: the kernel states no hardware type for the interface %s", name)
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

// LinkType returns the link type that `open` read from the hardware type of the interface.
//
// `pcapgo.NewEthernetHandle` binds an `AF_PACKET` socket with the protocol `ETH_P_ALL`,
// and that socket delivers the link-layer header of the interface. **So the interface
// decides the link layer, and the name of the constructor decides nothing.** A `tun`
// interface, a `sit` interface, a PPP interface and a WireGuard interface each carry no
// Ethernet header.
//
// An earlier comment read the name of the constructor as the answer, and it returned
// `layers.LinkTypeEthernet` for every interface. Issue #609 records that defect: the
// monitor emitted a wrong fingerprint and it reported no error. `open` now refuses an
// interface that carries no Ethernet header, so this method states a link type that
// matches the interface.
func (e *ethernetHandle) LinkType() layers.LinkType {
	return e.linkType
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
