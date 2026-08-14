//go:build linux && !libpcap

package capture

import (
	"strings"
	"testing"
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

func TestCompileFilterHoldsTheFilterTextInTheError(t *testing.T) {
	// The pure-Go path reaches no compiler today, and `compileFilter` names the filter so
	// that `cmd/ja4plus` prints the text the operator wrote.
	const filter = "tcp port 443"

	program, err := compileFilter(filter)
	if err == nil {
		t.Fatalf("compileFilter compiled the filter %s", filter)
	}
	if program != nil {
		t.Errorf("compileFilter returned %d instructions beside the error", len(program))
	}
	if !strings.Contains(err.Error(), filter) {
		t.Errorf("the error %q holds no filter text", err)
	}
}
