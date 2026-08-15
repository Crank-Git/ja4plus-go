package capture

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// Issue #609 records the defect that this file holds. The pure-Go backend stated
// `layers.LinkTypeEthernet` for every interface, so a tunnel interface decoded as Ethernet
// and the monitor emitted a wrong fingerprint without an error.
//
// This file carries no build constraint, so a test of every platform reads the map.
// `dropAccumulator` of `capture.go` carries the same reading.

func TestLinkTypeForHardwareTypeReadsAnEthernetInterfaceAsEthernet(t *testing.T) {
	linkType, err := linkTypeForHardwareType("eth0", arphrdEther)
	if err != nil {
		t.Fatalf("the map refuses the hardware type %d: %v", arphrdEther, err)
	}
	if linkType != layers.LinkTypeEthernet {
		t.Errorf("the map states the link type %v, and the interface carries an Ethernet header", linkType)
	}
}

func TestLinkTypeForHardwareTypeReadsALoopbackInterfaceAsEthernet(t *testing.T) {
	// The loopback device of Linux carries an Ethernet header, and `map_arphrd_to_dlt` of
	// `pcap-linux.c` maps `ARPHRD_LOOPBACK` to `DLT_EN10MB`. So `ja4plus watch --interface
	// lo` reads a link type that matches the interface.
	linkType, err := linkTypeForHardwareType("lo", arphrdLoopback)
	if err != nil {
		t.Fatalf("the map refuses the hardware type %d: %v", arphrdLoopback, err)
	}
	if linkType != layers.LinkTypeEthernet {
		t.Errorf("the map states the link type %v, and the interface carries an Ethernet header", linkType)
	}
}

// TestLinkTypeForHardwareTypeRefusesAHardwareTypeThatCarriesNoEthernetHeader builds the
// separating case of issue #609.
//
// Each hardware type below carries no Ethernet header, and `map_arphrd_to_dlt` of
// `pcap-linux.c` maps none of them to `DLT_EN10MB`. A map that returned
// `layers.LinkTypeEthernet` for one of them emits a wrong fingerprint and reports no error.
func TestLinkTypeForHardwareTypeRefusesAHardwareTypeThatCarriesNoEthernetHeader(t *testing.T) {
	cases := []struct {
		name         string
		iface        string
		hardwareType uint16
		decimal      string
	}{
		{name: "a tun interface in IP mode", iface: "tun0", hardwareType: 0xfffe, decimal: "65534"},
		{name: "a WireGuard interface", iface: "wg0", hardwareType: 0xfffe, decimal: "65534"},
		{name: "a sit interface", iface: "sit0", hardwareType: 0x308, decimal: "776"},
		{name: "a PPP interface", iface: "ppp0", hardwareType: 0x200, decimal: "512"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			linkType, err := linkTypeForHardwareType(c.iface, c.hardwareType)
			if err == nil {
				t.Fatalf("the map states the link type %v for the hardware type %d", linkType, c.hardwareType)
			}

			message := err.Error()
			want := []string{c.iface, c.decimal, "libpcap", "go build -tags libpcap ./cmd/ja4plus"}
			for _, text := range want {
				if !strings.Contains(message, text) {
					t.Errorf("the error %q holds no %q", message, text)
				}
			}
		})
	}
}
