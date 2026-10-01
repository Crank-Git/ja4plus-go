package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"strings"
)

// ParseTargets returns the IPv4 targets that one target argument names.
//
// FR-active-scan-14 of the port names three forms: one address, one network in CIDR form,
// or a file that holds one address on each line. A network names every address it holds,
// as zmap does, and the sequence holds no list in memory. A file names each address once.
//
// It returns an error before the first SYN in three cases.
//
//   - The argument names an IPv6 target, or a file line holds one.
//   - A file line holds no IPv4 address. The error names the line.
//   - The argument is no address, no network and no readable file.
func ParseTargets(text string) (iter.Seq[netip.Addr], error) {
	if address, err := netip.ParseAddr(text); err == nil {
		if !address.Is4() {
			return nil, fmt.Errorf("the target %s is IPv6, and the scanner reads IPv4 alone", text)
		}

		return func(yield func(netip.Addr) bool) { yield(address) }, nil
	}

	if prefix, err := netip.ParsePrefix(text); err == nil {
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("the target %s is IPv6, and the scanner reads IPv4 alone", text)
		}

		return networkAddresses(prefix.Masked()), nil
	}

	content, err := os.ReadFile(text)
	if err != nil {
		return nil, fmt.Errorf("the target %q is no IPv4 address, no IPv4 network and no readable file", text)
	}

	targets, err := fileTargets(text, content)
	if err != nil {
		return nil, err
	}

	return func(yield func(netip.Addr) bool) {
		for _, target := range targets {
			if !yield(target) {
				return
			}
		}
	}, nil
}

// networkAddresses yields every address of the network, from the first to the last.
func networkAddresses(prefix netip.Prefix) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for address := prefix.Addr(); address.IsValid() && prefix.Contains(address); address = address.Next() {
			if !yield(address) {
				return
			}
		}
	}
}

// fileTargets returns the addresses of a target file in order, each one once.
func fileTargets(name string, content []byte) ([]netip.Addr, error) {
	var targets []netip.Addr

	seen := map[netip.Addr]bool{}
	lines := bufio.NewScanner(bytes.NewReader(content))
	// A target file holds one address on each line, and a longer line holds no address.
	lines.Buffer(make([]byte, 0, 256), 64*1024)

	for number := 1; lines.Scan(); number++ {
		line := strings.TrimSpace(lines.Text())
		if line == "" {
			continue
		}

		address, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("line %d of %s holds no IPv4 address: %q", number, name, line)
		}

		if !address.Is4() {
			return nil, fmt.Errorf("line %d of %s holds %s, and the scanner reads IPv4 alone", number, name, line)
		}

		if !seen[address] {
			seen[address] = true
			targets = append(targets, address)
		}
	}

	if err := lines.Err(); err != nil {
		return nil, fmt.Errorf("read the target file %s: %w", name, err)
	}

	return targets, nil
}
