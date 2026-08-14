//go:build !linux && !libpcap

package capture

import (
	"errors"
	"runtime"
)

// open reports that the build selects no capture backend.
//
// The pure-Go backend builds on Linux alone, and the `libpcap` build tag selects the
// second backend. A build that carries neither reaches this file, and FR-capture-13 needs
// it to compile.
func open(_ Options) (Handle, error) {
	return nil, errors.New(unsupportedMessage(runtime.GOOS))
}

// unsupportedMessage returns the message that Open reports on the platform the caller
// names. The message states the repair that the platform holds.
//
// The two platforms get two messages, because the repair differs. macOS holds libpcap, so
// the user rebuilds with the tag and gets a monitor: FR-capture-24 names the tag and the
// build command. This project declines Windows capture, so no build repairs it:
// FR-capture-25 names the platform, and the `## Out of scope` section of
// `docs/specs/features/13-live-capture.md` holds the decline. A Windows message that named
// the tag would send the user to a build that repairs nothing.
//
// The release workflow builds five platforms, and the two branches below cover each one
// that reaches this file. Linux reaches the pure-Go backend, Windows reaches the first
// branch, and macOS reaches the second.
func unsupportedMessage(goos string) string {
	if goos == "windows" {
		return "capture: the monitor reads no interface on windows. " +
			"The command ja4plus analyze reads a capture file on every platform."
	}

	return "capture: the monitor needs the libpcap build tag on " + goos + ". " +
		"Build the program with the command go build -tags libpcap ./cmd/ja4plus."
}
