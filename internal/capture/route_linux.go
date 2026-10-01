//go:build linux

package capture

import (
	"fmt"
	"os"
)

func routeTable() ([]routeEntry, error) {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("capture: the kernel states no routing table: %w", err)
	}

	return parseLinuxRoutes(string(content)), nil
}

func neighborTable() ([]neighborEntry, error) {
	content, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("capture: the kernel states no neighbor table: %w", err)
	}

	return parseLinuxNeighbors(string(content)), nil
}
