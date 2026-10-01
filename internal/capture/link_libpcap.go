//go:build libpcap

package capture

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// pcapLink is the libpcap Link, and the `libpcap` build tag selects it.
//
// The maintainer ruled on 2026-10-01 in #796 that macOS sends the SYN through this build,
// as `ja4plus watch` reads through it. A released binary is built with `CGO_ENABLED=0`, so
// it scans on Linux alone. `pcap.Handle.WritePacketData` calls `pcap_sendpacket`.
// Verified against: <https://pkg.go.dev/github.com/gopacket/gopacket/pcap>, read from the
// module cache at `github.com/gopacket/gopacket@v1.7.2` on 2026-09-30.
type pcapLink struct {
	handle *pcap.Handle
}

func openLink(name string) (Link, error) {
	handle, err := pcap.OpenLive(name, snapshotLength, false, linkReadDeadline)
	if err != nil {
		return nil, openError(name, err)
	}

	if handle.LinkType() != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("capture: the interface %s carries no Ethernet header, and the scan sends Ethernet frames", name)
	}

	return &pcapLink{handle: handle}, nil
}

func (l *pcapLink) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := l.handle.ReadPacketData()
	if err != nil {
		return nil, info, readError(err)
	}

	return data, info, nil
}

func (l *pcapLink) WritePacketData(frame []byte) error {
	if err := l.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("capture: the interface sends no frame: %w", err)
	}

	return nil
}

func (l *pcapLink) Close() error {
	l.handle.Close()
	return nil
}
