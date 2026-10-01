//go:build linux

package capture

import (
	"fmt"
	"net/netip"
	"os"
)

func hostRoute(target netip.Addr) (routeEntry, error) {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return routeEntry{}, fmt.Errorf("capture: the kernel states no routing table: %w", err)
	}

	local, loopback, err := localAddresses()
	if err != nil {
		return routeEntry{}, err
	}

	return selectLinuxRoute(string(content), local, loopback, target)
}

func neighborTable() ([]neighborEntry, error) {
	content, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("capture: the kernel states no neighbor table: %w", err)
	}

	return parseLinuxNeighbors(string(content)), nil
}
