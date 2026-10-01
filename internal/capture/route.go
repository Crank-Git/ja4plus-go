package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Route states how the host reaches one IPv4 target.
//
// The scan of package `scan` writes an Ethernet frame itself, so it needs the three answers
// that the kernel finds for a packet it sends: the interface, the next hop and the source
// address. Each lookup reads a table of the kernel, and none of them opens a socket.
type Route struct {
	// Interface names the interface that reaches the target.
	Interface string
	// Gateway is the next hop. It is the zero Addr when the target is on the link.
	Gateway netip.Addr
	// Source is an IPv4 address of the interface.
	Source netip.Addr
	// Loopback is true when the interface is a loopback interface.
	Loopback bool
}

// routeEntry is one IPv4 row of the routing table of the kernel.
type routeEntry struct {
	iface   string
	prefix  netip.Prefix
	gateway netip.Addr
	metric  int
	// source is the source address that the row states. It is the zero Addr when the
	// addresses of the interface decide the source.
	source netip.Addr
}

// selectRoute returns the row with the longest prefix that holds the target, and the
// lowest metric among rows of that length. That is the order in which the kernel selects a
// route.
func selectRoute(entries []routeEntry, target netip.Addr) (routeEntry, bool) {
	var best routeEntry

	found := false

	for _, entry := range entries {
		if !entry.prefix.Contains(target) {
			continue
		}

		if !found || entry.prefix.Bits() > best.prefix.Bits() ||
			(entry.prefix.Bits() == best.prefix.Bits() && entry.metric < best.metric) {
			best = entry
			found = true
		}
	}

	return best, found
}

// LookupRoute returns the route of the host to the IPv4 target.
// It returns an error when the target is no IPv4 address, when the host states no route
// to it, and when the interface of the route holds no IPv4 address.
func LookupRoute(target netip.Addr) (Route, error) {
	if !target.Is4() {
		return Route{}, fmt.Errorf("capture: the target %v is no IPv4 address", target)
	}

	entry, err := hostRoute(target)
	if err != nil {
		return Route{}, err
	}

	iface, err := net.InterfaceByName(entry.iface)
	if err != nil {
		return Route{}, fmt.Errorf("capture: the host holds no interface %s: %w", entry.iface, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return Route{}, fmt.Errorf("capture: the interface %s states no address: %w", entry.iface, err)
	}

	hop := target
	if entry.gateway.IsValid() {
		hop = entry.gateway
	}

	source, found := entry.source, entry.source.IsValid()
	if !found {
		source, found = sourceAddress(addrs, hop)
	}

	if !found {
		return Route{}, fmt.Errorf("capture: the interface %s holds no IPv4 address", entry.iface)
	}

	return Route{
		Interface: entry.iface,
		Gateway:   entry.gateway,
		Source:    source,
		Loopback:  iface.Flags&net.FlagLoopback != 0,
	}, nil
}

// sourceAddress returns the IPv4 address of the interface whose network holds the next hop,
// or the first IPv4 address of the interface when no network holds it.
func sourceAddress(addrs []net.Addr, hop netip.Addr) (netip.Addr, bool) {
	var first netip.Addr

	for _, addr := range addrs {
		network, isNetwork := addr.(*net.IPNet)
		if !isNetwork {
			continue
		}

		prefix, err := netip.ParsePrefix(network.String())
		if err != nil || !prefix.Addr().Is4() {
			continue
		}

		if prefix.Contains(hop) {
			return prefix.Addr(), true
		}

		if !first.IsValid() {
			first = prefix.Addr()
		}
	}

	return first, first.IsValid()
}

// LookupNeighbor returns the link-layer address that the neighbor table of the kernel holds
// for the IPv4 address on the interface. It returns false when the table holds no complete
// entry for it.
func LookupNeighbor(address netip.Addr, iface string) (net.HardwareAddr, bool) {
	entries, err := neighborTable()
	if err != nil {
		return nil, false
	}

	for _, entry := range entries {
		if entry.address == address && entry.iface == iface {
			return entry.hardware, true
		}
	}

	return nil, false
}

// neighborEntry is one complete row of the neighbor table of the kernel.
type neighborEntry struct {
	address  netip.Addr
	hardware net.HardwareAddr
	iface    string
}

// Linux states the IPv4 routing table in `/proc/net/route`. `fib_route_seq_show` of
// `net/ipv4/fib_trie.c` writes each row with the format
// `"%s\t%08X\t%08X\t%04X\t%d\t%u\t%u\t%08X\t%d\t%u\t%u"`, and it passes each address as a
// `__be32`. So each address field holds the four bytes of the address as one hexadecimal
// number in the byte order of the host. `fib_flag_trans` of the same file sets `RTF_UP`
// and `RTF_GATEWAY`. `proc_net(5)` documents no `/proc/net/route` entry.
// Verified against: <https://github.com/torvalds/linux/blob/master/net/ipv4/fib_trie.c>,
// retrieved 2026-10-01 UTC.
const (
	linuxRouteFlagUp      = 0x1
	linuxRouteFlagGateway = 0x2
	// linuxNeighborComplete is `ATF_COM` of `include/uapi/linux/if_arp.h`: the entry holds
	// a resolved link-layer address.
	linuxNeighborComplete = 0x2
)

// parseLinuxRoutes returns the rows of `/proc/net/route`. It skips a row it cannot read,
// because one malformed row names no route of the others.
func parseLinuxRoutes(content string) []routeEntry {
	var entries []routeEntry

	lines := bufio.NewScanner(strings.NewReader(content))
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}

		destination, destErr := linuxHexAddr(fields[1])
		gateway, gatewayErr := linuxHexAddr(fields[2])
		flags, flagsErr := strconv.ParseUint(fields[3], 16, 32)
		metric, metricErr := strconv.Atoi(fields[6])
		mask, maskErr := linuxHexAddr(fields[7])

		if err := errors.Join(destErr, gatewayErr, flagsErr, metricErr, maskErr); err != nil {
			continue
		}

		if flags&linuxRouteFlagUp == 0 {
			continue
		}

		bits, isContiguous := maskBits(mask)
		if !isContiguous {
			continue
		}

		entry := routeEntry{iface: fields[0], prefix: netip.PrefixFrom(destination, bits).Masked(), metric: metric}
		if flags&linuxRouteFlagGateway != 0 {
			entry.gateway = gateway
		}

		entries = append(entries, entry)
	}

	return entries
}

// selectLinuxRoute returns the row that the kernel of Linux selects for the target.
//
// The kernel reads the `local` table before the `main` table, and `/proc/net/route`
// states the `main` table alone. The `local` table routes 127.0.0.0/8 and each address of
// the host itself through the loopback interface, so this function reads those targets
// first. Content is the text of `/proc/net/route`, local holds the IPv4 addresses of the
// host, and loopback names its loopback interface. It returns an error when no row
// reaches the target, and when a loopback target finds no loopback interface.
func selectLinuxRoute(content string, local []netip.Addr, loopback string, target netip.Addr) (routeEntry, error) {
	if entry, isLocal, err := selectLocalRoute(local, loopback, target); isLocal {
		return entry, err
	}

	entry, found := selectRoute(parseLinuxRoutes(content), target)
	if !found {
		return routeEntry{}, fmt.Errorf("capture: the host states no route to %v", target)
	}

	return entry, nil
}

// selectLocalRoute returns the loopback row for a target in 127.0.0.0/8 or a target that
// local holds, and true. The kernel sends a packet to such a target through the loopback
// interface, whatever row of the other tables holds it. It returns false for every other
// target, and an error when the host holds no loopback interface.
func selectLocalRoute(local []netip.Addr, loopback string, target netip.Addr) (routeEntry, bool, error) {
	isLocal := slices.Contains(local, target)
	if !target.IsLoopback() && !isLocal {
		return routeEntry{}, false, nil
	}

	if loopback == "" {
		return routeEntry{}, true, fmt.Errorf("capture: the host holds no loopback interface for %v", target)
	}

	entry := routeEntry{iface: loopback, prefix: netip.PrefixFrom(target, 32)}
	if isLocal {
		entry.source = target
	}

	return entry, true, nil
}

// localAddresses returns the IPv4 addresses of the host and the name of its loopback
// interface.
func localAddresses() ([]netip.Addr, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", fmt.Errorf("capture: the host states no interface: %w", err)
	}

	var (
		local    []netip.Addr
		loopback string
	)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && loopback == "" {
			loopback = iface.Name
		}

		// An interface that states no address holds no address of the host.
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			network, isNetwork := addr.(*net.IPNet)
			if !isNetwork {
				continue
			}

			if address, isAddr := netip.AddrFromSlice(network.IP); isAddr && address.Unmap().Is4() {
				local = append(local, address.Unmap())
			}
		}
	}

	return local, loopback, nil
}

// linuxHexAddr reads one address field of `/proc/net/route`.
func linuxHexAddr(field string) (netip.Addr, error) {
	value, err := strconv.ParseUint(field, 16, 32)
	if err != nil {
		return netip.Addr{}, err
	}

	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], uint32(value))

	return netip.AddrFrom4(raw), nil
}

// maskBits returns the prefix length of a contiguous netmask, and false for a mask that
// is not contiguous.
func maskBits(mask netip.Addr) (int, bool) {
	raw := mask.As4()
	ones, size := net.IPMask(raw[:]).Size()

	return ones, size == 32
}

// parseLinuxNeighbors returns the complete rows of `/proc/net/arp`. `proc_net(5)` states
// the file: `This holds an ASCII readable dump of the kernel ARP table used for address
// resolutions.` Its columns are `IP address`, `HW type`, `Flags`, `HW address`, `Mask` and
// `Device`.
// Verified against: <https://man7.org/linux/man-pages/man5/proc_net.5.html>, retrieved
// 2026-10-01 UTC.
func parseLinuxNeighbors(content string) []neighborEntry {
	var entries []neighborEntry

	lines := bufio.NewScanner(strings.NewReader(content))
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 6 {
			continue
		}

		address, addrErr := netip.ParseAddr(fields[0])
		flags, flagsErr := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		hardware, hardwareErr := net.ParseMAC(fields[3])

		if errors.Join(addrErr, flagsErr, hardwareErr) != nil || flags&linuxNeighborComplete == 0 || len(hardware) != 6 {
			continue
		}

		entries = append(entries, neighborEntry{address: address, hardware: hardware, iface: fields[5]})
	}

	return entries
}
