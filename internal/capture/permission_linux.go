//go:build linux

package capture

import "syscall"

// packetSocketProtocol holds `ETH_P_ALL` in network byte order, which is the protocol that
// a packet socket takes.
//
// `pcapgo.NewEthernetHandle` passes `endian.Htons(unix.ETH_P_ALL)`, and this constant
// states the same value. A constant costs no call, and the probe below opens the socket
// that the backend opens.
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
