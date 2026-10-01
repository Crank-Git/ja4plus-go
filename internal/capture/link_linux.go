//go:build linux && !libpcap

package capture

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// packetLink is the pure-Go Link. It reads through `pcapgo.EthernetHandle`, and it writes
// through a second packet socket that receives nothing.
//
// `pcapgo.EthernetHandle` of gopacket v1.7.2 declares no write method, so this backend
// opens its own send socket. `packet(7)` states the send: `When you send packets, it is
// enough to specify sll_family, sll_addr, sll_halen, sll_ifindex, and sll_protocol.` A
// protocol of 0 binds the socket to no packet type, so the kernel delivers no frame to it.
// Verified against: <https://man7.org/linux/man-pages/man7/packet.7.html>, retrieved
// 2026-09-30, and `pcapgo/capture.go` of gopacket v1.7.2 in the module cache.
type packetLink struct {
	handle *pcapgo.EthernetHandle
	reader *deadlineReader
	sendFD int
	index  int
}

// openLink returns the pure-Go Link for the interface. `openError` carries the errno of a
// refused packet socket, and PermissionDenied reads it.
func openLink(name string) (Link, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("capture: the host holds no interface %s: %w", name, err)
	}

	linkType, err := readLinkType(name)
	if err != nil {
		return nil, err
	}

	if linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("capture: the interface %s carries no Ethernet header, and the scan sends Ethernet frames", name)
	}

	sendFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, openError(name, fmt.Errorf("capture: the host opens no send socket: %w", err))
	}

	handle, err := pcapgo.NewEthernetHandle(name)
	if err != nil {
		_ = syscall.Close(sendFD)
		return nil, openError(name, err)
	}

	return &packetLink{
		handle: handle,
		reader: newDeadlineReader(handle, linkReadDeadline),
		sendFD: sendFD,
		index:  iface.Index,
	}, nil
}

func (l *packetLink) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := l.reader.read()
	if errors.Is(err, ErrReadTimeout) {
		return nil, info, err
	}

	if err != nil {
		return nil, info, fmt.Errorf("capture: the interface returns no frame: %w", err)
	}

	return data, info, nil
}

// WritePacketData sends the frame to the destination address of its Ethernet header.
func (l *packetLink) WritePacketData(frame []byte) error {
	if len(frame) < 14 {
		return fmt.Errorf("capture: the frame holds %d bytes, and an Ethernet header holds 14", len(frame))
	}

	address := &syscall.SockaddrLinklayer{
		Protocol: uint16(frame[12])<<8 | uint16(frame[13]),
		Ifindex:  l.index,
		Halen:    6,
	}
	copy(address.Addr[:], frame[0:6])

	if err := syscall.Sendto(l.sendFD, frame, 0, address); err != nil {
		return fmt.Errorf("capture: the interface sends no frame: %w", err)
	}

	return nil
}

// Close stops the read goroutine and closes both sockets.
func (l *packetLink) Close() error {
	l.reader.stop()

	return errors.Join(l.handle.Close(), syscall.Close(l.sendFD))
}
