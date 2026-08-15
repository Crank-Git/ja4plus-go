package capture

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"
)

// The two constants below hold the hardware type that the kernel states for an interface.
// `if_arp.h` of Linux names each one, and `syscall` of Go holds the same value:
// `ARPHRD_ETHER = 0x1` and `ARPHRD_LOOPBACK = 0x304`.
// `TestTheHardwareTypeConstantsHoldTheValueOfTheKernel` in `pcapgo_linux_test.go` reads
// the two against `syscall`, so a later kernel value does not leave this file behind.
//
// This file carries no build constraint, so a test of every platform reads the map below.
// `dropAccumulator` of `capture.go` carries the same reading. `syscall.ARPHRD_ETHER`
// reaches Linux alone, and a constraint here would leave the map untested on macOS.
const (
	// arphrdEther names an interface that carries an Ethernet header.
	arphrdEther uint16 = 0x1
	// arphrdLoopback names the loopback device, which carries an Ethernet header too.
	arphrdLoopback uint16 = 0x304
)

// linkTypeForHardwareType returns the link type of the bytes that a packet socket delivers
// for an interface of the hardware type that the caller states.
//
// It returns an error for every other hardware type. The message names the interface, the
// hardware type and the build that reads more link types.
//
// Issue #609 records the defect that the refusal repairs. The backend stated
// `layers.LinkTypeEthernet` for every interface. So a tunnel interface decoded as
// Ethernet, and the monitor emitted a wrong fingerprint without an error. A refusal costs
// the operator one interface, and a wrong fingerprint costs every comparison that the
// value is for.
//
// The map holds the two hardware types that carry an Ethernet header, and it holds no
// third. `map_arphrd_to_dlt` at `pcap-linux.c:1871` decides each one. `pcap-linux.c:1878`
// and `pcap-linux.c:1952` map `ARPHRD_ETHER` and `ARPHRD_LOOPBACK` to `DLT_EN10MB`, which
// is the value that `layers.LinkTypeEthernet` holds. `pcap-linux.c:2275` maps
// `ARPHRD_NONE` to `DLT_RAW`, and `pcap-linux.c:2123` maps `ARPHRD_SIT` to `DLT_RAW`.
// `pcap-linux.c:2067` maps `ARPHRD_PPP` to `DLT_LINUX_SLL` or to `DLT_RAW`.
// `pcap-linux.c:2313` states `handle->linktype = -1` for a type the function does not name.
// Verified against:
// <https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap-linux.c>,
// retrieved 2026-08-14. Each line above reads the `libpcap-1.10.5` tag.
//
// The libpcap backend of `libpcap.go` reads the link type from `pcap_datalink`, so it
// opens an interface that this map refuses. The error names that build.
func linkTypeForHardwareType(name string, hardwareType uint16) (layers.LinkType, error) {
	switch hardwareType {
	case arphrdEther, arphrdLoopback:
		return layers.LinkTypeEthernet, nil
	default:
		return 0, fmt.Errorf(
			"capture: the interface %s states the hardware type %d, and the pure-Go backend "+
				"decodes an Ethernet header alone. Build with the libpcap build tag to read "+
				"this interface: go build -tags libpcap ./cmd/ja4plus", name, hardwareType)
	}
}
