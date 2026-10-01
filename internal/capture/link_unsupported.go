//go:build !linux && !libpcap

package capture

import (
	"errors"
	"runtime"
)

// openLink reports that the build selects no link backend.
func openLink(_ string) (Link, error) {
	return nil, errors.New(unsupportedLinkMessage(runtime.GOOS))
}

// unsupportedLinkMessage returns the one line that the scan reports on the platform that
// goos names.
//
// The maintainer ruled on 2026-10-01 in #796 that a macOS build without the `libpcap`
// build tag stops the scan with one line that names the tag. This project declines live
// capture on Windows, so no build repairs that platform, and its line names no tag.
func unsupportedLinkMessage(goos string) string {
	if goos == "windows" {
		return "capture: the scan sends no packet on windows"
	}

	return "capture: the scan needs the libpcap build tag on " + goos + ". " +
		"Build the program with the command go build -tags libpcap ./cmd/ja4plus."
}
