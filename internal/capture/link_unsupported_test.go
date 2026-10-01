//go:build !linux && !libpcap

package capture

import (
	"strings"
	"testing"
)

// The maintainer ruled on 2026-10-01 in #796 that a macOS build without the `libpcap` build
// tag stops the scan with one line that names the tag. This test holds that answer.
func TestTheScanOnMacOSWithoutTheTagStatesOneLineThatNamesTheTag(t *testing.T) {
	message := unsupportedLinkMessage("darwin")

	if !strings.Contains(message, "libpcap build tag") || !strings.Contains(message, buildCommand) || strings.Contains(message, "\n") {
		t.Errorf("the message %q is not one line that names the tag and the build command", message)
	}
}

func TestTheScanOnWindowsNamesNoTag(t *testing.T) {
	if message := unsupportedLinkMessage("windows"); strings.Contains(message, "libpcap") {
		t.Errorf("the Windows message %q names a tag that repairs nothing", message)
	}
}

func TestOpenLinkReportsThatTheBuildHoldsNoLinkBackend(t *testing.T) {
	link, err := OpenLink("en0")
	if err == nil || link != nil {
		t.Errorf("OpenLink returns %v and %v on a build with no link backend", link, err)
	}
}
