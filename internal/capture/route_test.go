package capture

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
)

// linuxRouteFixture holds `/proc/net/route` of a little-endian host with one default route
// through 192.168.1.1 and one link route for 192.168.1.0/24. A big-endian host writes each
// address in the other byte order, so the fixture reads on a little-endian host alone.
const linuxRouteFixture = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth9	0002A8C0	00000000	0000	0	0	0	00FFFFFF	0	0	0
broken	zz	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

const linuxNeighborFixture = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.7      0x1         0x2         aa:bb:cc:dd:ee:07     *        wlan0
not-an-address   0x1         0x2         aa:bb:cc:dd:ee:08     *        eth0
`

func littleEndianHost(t *testing.T) {
	t.Helper()

	switch runtime.GOARCH {
	case "s390x", "ppc64", "mips", "mips64":
		t.Skip("the fixture writes the addresses of a little-endian host")
	}
}

func TestTheLinuxRouteReaderReadsEachUsableRow(t *testing.T) {
	littleEndianHost(t)

	entries := parseLinuxRoutes(linuxRouteFixture)
	if len(entries) != 3 {
		t.Fatalf("the reader reads %d rows, want 3: %+v", len(entries), entries)
	}

	first := entries[0]
	if first.iface != "eth0" || first.prefix != netip.MustParsePrefix("0.0.0.0/0") ||
		first.gateway != netip.MustParseAddr("192.168.1.1") || first.metric != 100 {
		t.Errorf("the default route reads as %+v", first)
	}

	if link := entries[1]; link.prefix != netip.MustParsePrefix("192.168.1.0/24") || link.gateway.IsValid() {
		t.Errorf("the link route reads as %+v", link)
	}
}

func TestTheRouteSelectionReadsTheLongestPrefixAndThenTheLowestMetric(t *testing.T) {
	littleEndianHost(t)

	entries := parseLinuxRoutes(linuxRouteFixture)

	onLink, _ := selectRoute(entries, netip.MustParseAddr("192.168.1.50"))
	if onLink.iface != "eth0" || onLink.gateway.IsValid() {
		t.Errorf("an address of the link selects %+v", onLink)
	}

	remote, _ := selectRoute(entries, netip.MustParseAddr("203.0.113.9"))
	if remote.iface != "eth0" || remote.gateway != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("a remote address selects %+v, want the default route of the lower metric", remote)
	}

	if _, found := selectRoute(nil, netip.MustParseAddr("203.0.113.9")); found {
		t.Error("an empty table selects a route")
	}
}

func TestTheLinuxNeighborReaderReadsEachCompleteRow(t *testing.T) {
	entries := parseLinuxNeighbors(linuxNeighborFixture)
	if len(entries) != 2 {
		t.Fatalf("the reader reads %d rows, want 2: %+v", len(entries), entries)
	}

	if entries[0].address != netip.MustParseAddr("192.168.1.1") || entries[0].iface != "eth0" ||
		entries[0].hardware.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("the first row reads as %+v", entries[0])
	}
}

func TestTheSourceAddressIsTheAddressWhoseNetworkHoldsTheNextHop(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.IPv4(10, 0, 0, 5).To4(), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.IPv4(192, 168, 1, 20).To4(), Mask: net.CIDRMask(24, 32)},
	}

	if source, _ := sourceAddress(addrs, netip.MustParseAddr("192.168.1.1")); source != netip.MustParseAddr("192.168.1.20") {
		t.Errorf("the source is %v, want 192.168.1.20", source)
	}

	if source, _ := sourceAddress(addrs, netip.MustParseAddr("203.0.113.1")); source != netip.MustParseAddr("10.0.0.5") {
		t.Errorf("the source is %v, want the first IPv4 address", source)
	}

	if _, found := sourceAddress(addrs[:1], netip.MustParseAddr("203.0.113.1")); found {
		t.Error("an interface with no IPv4 address states a source")
	}
}

func TestLookupRouteRefusesAnIPv6Target(t *testing.T) {
	if _, err := LookupRoute(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("LookupRoute accepts an IPv6 target")
	}
}

// The routing table of the host reaches the loopback address on every host this project
// builds for, and the read opens no socket.
func TestLookupRouteReadsTheRoutingTableOfTheHost(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the scan reads a routing table on Linux and macOS alone")
	}

	route, err := LookupRoute(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("LookupRoute: %v", err)
	}

	if !route.Loopback || route.Source != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("the loopback address routes as %+v", route)
	}
}

func TestOpenLinkRefusesAnEmptyName(t *testing.T) {
	if link, err := OpenLink(""); err == nil || link != nil {
		t.Errorf("OpenLink accepts an empty name and returns %v", link)
	}
}
