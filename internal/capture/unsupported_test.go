//go:build !linux && !libpcap

package capture

import (
	"runtime"
	"strings"
	"testing"
)

func TestOpenReportsThatTheBuildHoldsNoCaptureBackend(t *testing.T) {
	handle, err := Open(Options{Interface: "en0"})
	if err == nil {
		t.Fatal("Open returned no error on a platform that holds no capture backend")
	}
	if handle != nil {
		t.Errorf("Open returned the handle %v beside the error", handle)
	}
	if !strings.Contains(err.Error(), runtime.GOOS) {
		t.Errorf("the error %q names no platform", err)
	}
}
