//go:build darwin

package capture

import (
	"errors"
	"fmt"
	"syscall"
)

// bpfDeviceCount is the count of BPF devices that the probe below reads.
//
// `bpf(4)` states the device names: `The packet filter appears as a character special
// device, /dev/bpf0, /dev/bpf1, etc.` It states that a device in use answers with one
// errno: `A separate device file is required for each minor device.  If a file is in use,
// the open will fail and errno will be set to EBUSY.` So the probe reads more than one
// device, and it stops at the first device that states an answer of its own.
// Verified against `man 4 bpf` on macOS 15, read on 2026-08-14.
//
// A host that runs 4 capture programs already reports EBUSY on each of these devices, and
// `captureRefusal` then returns nil. The operator reads the message of libpcap for that
// run, and no message names a capability the host holds.
const bpfDeviceCount = 4

// captureRefusal returns the errno that macOS states when it refuses a BPF device, and it
// returns nil when macOS opens one.
//
// The probe opens the device that libpcap opens, and it reads the answer as an errno.
// `openError` needs that errno, because libpcap flattens it into an error buffer.
//
// macOS names no capability, so FR-capture-36 names `CAP_NET_RAW` for Linux alone. The
// message of `cmd/ja4plus` states the repair that this platform holds.
//
// The probe closes a device that macOS opens, so it holds no file descriptor and it reads
// no packet. It binds the device to no interface, so it needs no interface name.
func captureRefusal() error {
	for device := 0; device < bpfDeviceCount; device++ {
		name := fmt.Sprintf("/dev/bpf%d", device)

		fd, err := syscall.Open(name, syscall.O_RDONLY, 0)
		if err == nil {
			_ = syscall.Close(fd)

			return nil
		}

		if PermissionDenied(err) {
			return fmt.Errorf("open %s: %w", name, err)
		}

		// A device in use states EBUSY, and the next device answers the question. Every
		// other errno states that this host reaches no BPF device at all, and no capability
		// repairs that.
		if !errors.Is(err, syscall.EBUSY) {
			return nil
		}
	}

	return nil
}
