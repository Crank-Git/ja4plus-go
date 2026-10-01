package capture

import (
	"errors"

	"github.com/gopacket/gopacket"
)

// Link reads Ethernet frames from one interface and writes Ethernet frames to it.
//
// Package `scan` sends each JA4TScan SYN through a Link. The maintainer ruled on
// 2026-10-01 in #796 that the send primitive lives in this package, so the socket rule of
// #613 holds without a change. FR-active-scan-25 of the port requires a link-layer SYN,
// because a SYN from a raw IP socket leaves state in the connection tracker of the host.
//
// One goroutine owns one Link, as the doc comment of Handle states for a Handle.
type Link interface {
	// ReadPacketData returns the bytes of the next frame and its capture information.
	// It returns ErrReadTimeout when the interface delivers no frame within 10 ms. That
	// answer states no failure, and the caller reads the interface again.
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	// WritePacketData sends one Ethernet frame on the interface.
	WritePacketData(frame []byte) error
	// Close releases the interface.
	Close() error
}

// OpenLink returns a Link on the interface that the name states.
//
// It returns an error when the name is empty, when the host holds no such interface, when
// the interface carries no Ethernet header, and when the host refuses the privilege.
// PermissionDenied reads the last case. It returns an error when the build selects no link
// backend: a build for macOS needs the `libpcap` build tag.
func OpenLink(name string) (Link, error) {
	if name == "" {
		return nil, errors.New("capture: the scan names no interface")
	}

	return openLink(name)
}
