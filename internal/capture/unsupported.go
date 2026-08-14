//go:build !linux && !libpcap

package capture

import (
	"fmt"
	"runtime"
)

// open reports that the build selects no capture backend.
//
// The pure-Go backend builds on Linux alone, and the `libpcap` build tag selects the
// second backend. A build that carries neither reaches this file, and FR-capture-13 needs
// it to compile.
//
// TODO(#78): State the build tag and the build command that FR-capture-24 names.
func open(_ Options) (Handle, error) {
	return nil, fmt.Errorf("capture: this build holds no capture backend for %s", runtime.GOOS)
}
