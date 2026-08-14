//go:build linux

package capture

import "syscall"

// packetSocketProtocol is the protocol number that the probe below passes to `socket(2)`.
//
// It computes `0x0300` on every host, because it swaps the two bytes of `ETH_P_ALL`
// unconditionally. `gopacket@v1.6.1/endian/endian.go:13-18` swaps on a little-endian host
// alone, so `endian.Htons(unix.ETH_P_ALL)` reads `0x0003` on a big-endian host. **So this
// constant and the value that `pcapgo.NewEthernetHandle` passes differ on `s390x`,
// `ppc64` and `mips`.**
//
// **The probe needs no particular protocol number, so that difference costs nothing.**
// `packet(7)` states the field: `protocol is the IEEE 802.3 protocol number in network
// byte order.` It states what a value other than `ETH_P_ALL` selects: `All incoming
// packets of that protocol type will be passed to the packet socket before they are
// passed to the protocols implemented in the kernel.` So `0x0300` selects a packet set,
// and `captureRefusal` reads the errno of `socket(2)` and never a packet.
// Verified against: <https://man7.org/linux/man-pages/man7/packet.7.html>, retrieved
// 2026-08-14.
//
// An earlier comment stated that this constant and `endian.Htons(unix.ETH_P_ALL)` hold one
// value. **The Epic 13 documentation round measured the difference on 2026-08-14**, and
// issue #76 holds that measurement. The round repaired this comment and it changed no
// arithmetic, because a change of the value is a change of behavior.
const packetSocketProtocol = int(syscall.ETH_P_ALL>>8) | int(syscall.ETH_P_ALL&0xff)<<8

// captureRefusal returns the errno that the kernel states when it refuses a packet socket,
// and it returns nil when the kernel opens one.
//
// The probe asks the kernel the question that the backend asked, and it reads the answer
// as an errno. `openError` needs that errno, because each capture library flattens it into
// a message text.
//
// One probe answers for both backends of this package. `packet(7)` states the rule that
// each one meets: `In order to create a packet socket, a process must have the CAP_NET_RAW
// capability in the user namespace that governs its network namespace.`
// Verified against: <https://man7.org/linux/man-pages/man7/packet.7.html>, retrieved
// 2026-08-14.
//
// The probe closes a socket that the kernel opens, so it holds no file descriptor and it
// reads no packet. It binds the socket to no interface, so it needs no interface name.
func captureRefusal() error {
	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		packetSocketProtocol,
	)
	if err != nil {
		return err
	}

	_ = syscall.Close(fd)

	return nil
}
