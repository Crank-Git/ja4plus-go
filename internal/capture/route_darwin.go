//go:build darwin

package capture

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// The routing table of macOS answers a `sysctl` read, and `golang.org/x/net/route` parses
// it. The read opens no socket. The `RTAX_*` order of `route(4)` places the destination at
// index 0, the gateway at index 1 and the netmask at index 2 of each message.
// Verified against: <https://pkg.go.dev/golang.org/x/net/route>, read from the module cache
// at `golang.org/x/net@v0.59.0` on 2026-09-30, and `man 4 route` of macOS 27.0.
const (
	rtaxDestination = 0
	rtaxGateway     = 1
	rtaxNetmask     = 2
)

func routeMessages(typ route.RIBType, arg int) ([]*route.RouteMessage, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, typ, arg)
	if err != nil {
		return nil, fmt.Errorf("capture: the kernel states no routing table: %w", err)
	}

	messages, err := route.ParseRIB(typ, rib)
	if err != nil {
		return nil, fmt.Errorf("capture: the routing table of the kernel does not parse: %w", err)
	}

	var routes []*route.RouteMessage

	for _, message := range messages {
		if routeMessage, isRoute := message.(*route.RouteMessage); isRoute {
			routes = append(routes, routeMessage)
		}
	}

	return routes, nil
}

func messageAddr(message *route.RouteMessage, index int) route.Addr {
	if index < len(message.Addrs) {
		return message.Addrs[index]
	}

	return nil
}

func inet4(addr route.Addr) (netip.Addr, bool) {
	if inet, isInet := addr.(*route.Inet4Addr); isInet {
		return netip.AddrFrom4(inet.IP), true
	}

	return netip.Addr{}, false
}

func routeTable() ([]routeEntry, error) {
	messages, err := routeMessages(route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}

	var entries []routeEntry

	for _, message := range messages {
		// A scoped route serves a socket that binds one interface, and the kernel selects
		// it for no other packet.
		if message.Flags&syscall.RTF_UP == 0 || message.Flags&syscall.RTF_IFSCOPE != 0 {
			continue
		}

		destination, isInet := inet4(messageAddr(message, rtaxDestination))
		if !isInet {
			continue
		}

		bits := 32
		if message.Flags&syscall.RTF_HOST == 0 {
			bits = 0
			if mask, hasMask := inet4(messageAddr(message, rtaxNetmask)); hasMask {
				ones, contiguous := maskBits(mask)
				if !contiguous {
					continue
				}

				bits = ones
			}
		}

		iface, err := net.InterfaceByIndex(message.Index)
		if err != nil {
			continue
		}

		entry := routeEntry{iface: iface.Name, prefix: netip.PrefixFrom(destination, bits).Masked()}
		if message.Flags&syscall.RTF_GATEWAY != 0 {
			gateway, isGateway := inet4(messageAddr(message, rtaxGateway))
			if !isGateway {
				continue
			}

			entry.gateway = gateway
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// neighborTable reads the routes that carry `RTF_LLINFO`, which `arp -a` reads too. The
// gateway of each such route is the link-layer address of the neighbor.
func neighborTable() ([]neighborEntry, error) {
	messages, err := routeMessages(route.RIBType(syscall.NET_RT_FLAGS), syscall.RTF_LLINFO)
	if err != nil {
		return nil, err
	}

	var entries []neighborEntry

	for _, message := range messages {
		address, isInet := inet4(messageAddr(message, rtaxDestination))
		link, isLink := messageAddr(message, rtaxGateway).(*route.LinkAddr)

		if !isInet || !isLink || len(link.Addr) != 6 {
			continue
		}

		iface, err := net.InterfaceByIndex(message.Index)
		if err != nil {
			continue
		}

		entries = append(entries, neighborEntry{address: address, hardware: net.HardwareAddr(link.Addr), iface: iface.Name})
	}

	return entries, nil
}
