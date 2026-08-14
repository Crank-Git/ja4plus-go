package capture

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// stubHandle proves that a type outside this file satisfies Handle. #78 and #79 write two
// more implementations against the same interface, so a compile-time check guards it.
type stubHandle struct{}

func (stubHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}

func (stubHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func (stubHandle) DropCount() (uint64, bool) { return 0, true }

func (stubHandle) Close() error { return nil }

var _ Handle = stubHandle{}

func TestOpenReturnsAnErrorWhenTheOptionsNameNoInterface(t *testing.T) {
	handle, err := Open(Options{})
	if err == nil {
		t.Fatal("Open returned no error for an empty interface name")
	}
	if handle != nil {
		t.Errorf("Open returned the handle %v beside the error", handle)
	}
	if !strings.Contains(err.Error(), "interface") {
		t.Errorf("the error %q names no interface", err)
	}
}

func TestOpenNamesThePackageInEveryError(t *testing.T) {
	// Each error of this package reaches the operator through `cmd/ja4plus`, so the
	// prefix states which package produced it.
	cases := []Options{
		{},
		{Interface: "an-interface-that-no-host-holds"},
	}

	for _, opts := range cases {
		_, err := Open(opts)
		if err == nil {
			t.Fatalf("Open returned no error for the options %+v", opts)
		}
		if !strings.HasPrefix(err.Error(), "capture: ") {
			t.Errorf("the error %q holds no `capture: ` prefix", err)
		}
	}
}
