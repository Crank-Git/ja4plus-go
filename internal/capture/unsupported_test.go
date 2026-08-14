//go:build !linux && !libpcap

package capture

import (
	"runtime"
	"strings"
	"testing"
)

// buildCommand is the command that FR-capture-24 names. The message states it verbatim, so
// a user copies one line and gets a monitor.
const buildCommand = "go build -tags libpcap ./cmd/ja4plus"

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

func TestOpenReportsTheMessageOfTheRunningPlatform(t *testing.T) {
	_, err := Open(Options{Interface: "en0"})
	if err == nil {
		t.Fatal("Open returned no error on a platform that holds no capture backend")
	}
	if err.Error() != unsupportedMessage(runtime.GOOS) {
		t.Errorf("Open reports %q, and the message of %s is %q",
			err, runtime.GOOS, unsupportedMessage(runtime.GOOS))
	}
}

func TestTheDarwinMessageNamesTheBuildTagAndTheBuildCommand(t *testing.T) {
	// FR-capture-24: libpcap is present on macOS, so the user repairs the failure with one
	// build. The message names the tag and the command that applies it.
	message := unsupportedMessage("darwin")

	for _, want := range []string{"darwin", "libpcap", buildCommand} {
		if !strings.Contains(message, want) {
			t.Errorf("the darwin message %q names no %q", message, want)
		}
	}
}

func TestTheWindowsMessageNamesNoBuildTag(t *testing.T) {
	// FR-capture-25: the `## Out of scope` section of
	// `docs/specs/features/13-live-capture.md` declines Windows capture. A message that
	// names the tag sends the user to a build that repairs nothing.
	message := unsupportedMessage("windows")

	if !strings.Contains(message, "windows") {
		t.Errorf("the windows message %q names no platform", message)
	}
	for _, unwanted := range []string{"libpcap", "-tags", "go build"} {
		if strings.Contains(message, unwanted) {
			t.Errorf("the windows message %q names %q, and no build repairs Windows", message, unwanted)
		}
	}
}

func TestTheWindowsMessageNamesTheCommandThatReadsACaptureFile(t *testing.T) {
	// FR-capture-27: the capture-file command runs on every platform and needs no tag. The
	// Windows message states what the user does instead of a watch.
	message := unsupportedMessage("windows")

	if !strings.Contains(message, "ja4plus analyze") {
		t.Errorf("the windows message %q names no command that reads a capture file", message)
	}
}

func TestEveryUnsupportedMessageNamesThePackage(t *testing.T) {
	// Each error of this package reaches the operator through `cmd/ja4plus`, so the prefix
	// states which package produced it.
	for _, goos := range []string{"darwin", "windows", "freebsd"} {
		message := unsupportedMessage(goos)
		if !strings.HasPrefix(message, "capture: ") {
			t.Errorf("the message of %s is %q, and it holds no `capture: ` prefix", goos, message)
		}
		if !strings.Contains(message, goos) {
			t.Errorf("the message of %s is %q, and it names no platform", goos, message)
		}
	}
}
