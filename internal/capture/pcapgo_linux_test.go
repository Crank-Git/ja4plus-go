//go:build linux && !libpcap

package capture

import (
	"strings"
	"syscall"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// Every test of this file opens no interface that the host holds, so no test needs
// `CAP_NET_RAW`. `pcapgo.NewEthernetHandle` reads the interface name before it opens the
// packet socket.

func TestOpenNamesTheInterfaceThatTheHostDoesNotHold(t *testing.T) {
	const name = "an-interface-that-no-host-holds"

	handle, err := Open(Options{Interface: name})
	if err == nil {
		_ = handle.Close()
		t.Fatalf("Open returned no error for the interface %s", name)
	}
	if handle != nil {
		t.Errorf("Open returned the handle %v beside the error", handle)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("the error %q names no interface", err)
	}
}

// TestTheHardwareTypeConstantsHoldTheValueOfTheKernel reads the two constants of
// `linktype.go` against `syscall`.
//
// `linktype.go` carries no build constraint, so it states each value rather than reading
// `syscall.ARPHRD_ETHER`. This test holds the two together, and it fails when a later
// kernel value leaves the map behind.
func TestTheHardwareTypeConstantsHoldTheValueOfTheKernel(t *testing.T) {
	if arphrdEther != uint16(syscall.ARPHRD_ETHER) {
		t.Errorf("arphrdEther holds %d, and the kernel states %d", arphrdEther, syscall.ARPHRD_ETHER)
	}
	if arphrdLoopback != uint16(syscall.ARPHRD_LOOPBACK) {
		t.Errorf("arphrdLoopback holds %d, and the kernel states %d", arphrdLoopback, syscall.ARPHRD_LOOPBACK)
	}
}

// TestReadLinkTypeReadsTheLoopbackInterfaceAsEthernet reads the hardware type of a real
// interface, so it covers the netlink dump that `readLinkType` parses.
//
// It reads the loopback device, because every host holds one and the read needs no
// privilege. It opens no packet socket, so it needs no `CAP_NET_RAW`.
func TestReadLinkTypeReadsTheLoopbackInterfaceAsEthernet(t *testing.T) {
	linkType, err := readLinkType("lo")
	if err != nil {
		t.Fatalf("readLinkType returns no link type for the loopback device: %v", err)
	}
	if linkType != layers.LinkTypeEthernet {
		t.Errorf("readLinkType states the link type %v for the loopback device", linkType)
	}
}

func TestReadLinkTypeNamesTheInterfaceThatTheHostDoesNotHold(t *testing.T) {
	const name = "an-interface-that-no-host-holds"

	linkType, err := readLinkType(name)
	if err == nil {
		t.Fatalf("readLinkType states the link type %v for the interface %s", linkType, name)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("the error %q names no interface", err)
	}
}

func TestCompileFilterHoldsTheFilterTextInTheError(t *testing.T) {
	// The maintainer ruled #564 on 2026-08-14, and the pure-Go backend applies no capture
	// filter. The error names the filter, the build tag and the build command, so the
	// operator reads what to do. `cmd/ja4plus` prints it, and #79 owns that print site.
	const filter = "tcp port 443"

	program, err := compileFilter(filter)
	if err == nil {
		t.Fatalf("compileFilter compiled the filter %s", filter)
	}
	if program != nil {
		t.Errorf("compileFilter returned %d instructions beside the error", len(program))
	}

	for _, want := range []string{filter, "libpcap", "go build -tags libpcap ./cmd/ja4plus"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q holds no %q", err, want)
		}
	}
}

func TestOpenDeclinesEveryCaptureFilter(t *testing.T) {
	// The interface name reaches no host, so the run needs no `CAP_NET_RAW`. The filter
	// check runs after the open, and this test states the error of the open path alone
	// when the host holds no such interface.
	handle, err := Open(Options{Interface: "an-interface-that-no-host-holds", Filter: "tcp port 443"})
	if err == nil {
		_ = handle.Close()
		t.Fatal("Open returned no error for a capture filter")
	}
	if handle != nil {
		t.Errorf("Open returned the handle %v beside the error", handle)
	}
}
