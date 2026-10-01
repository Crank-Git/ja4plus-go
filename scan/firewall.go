package scan

import "strings"

// iptablesRules holds the four rules of `ja4tscan/ja4tscan.py:15-18`, verbatim.
var iptablesRules = []string{
	"iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
	"iptables -t filter -A INPUT -p icmp -j ACCEPT",
	"iptables -t filter -A INPUT -i lo -j ACCEPT",
	"iptables -t filter -A INPUT -j DROP",
}

// iptablesRemovals holds the four removals of `ja4tscan/ja4tscan.py:22-25`, in the order
// that the wrapper runs them.
var iptablesRemovals = []string{
	"iptables -t filter -D INPUT -j DROP",
	"iptables -t filter -D INPUT -i lo -j ACCEPT",
	"iptables -t filter -D INPUT -p icmp -j ACCEPT",
	"iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
}

// pfRules holds the pf equivalent of the four rules, one line for each rule. The port's
// `docs/specs/features/12-active-scan.md` at tag `v1.3.0` states the reading of each line.
var pfRules = []string{
	"pass out all",
	"pass in quick inet proto icmp all",
	"pass in quick on lo0 all",
	"block drop in all",
}

const rulePreamble = "ja4plus scan changes no firewall state. The kernel of this host answers each " +
	"SYN-ACK with a RST, and the RST stops the retransmissions that part e reads.\n" +
	"The last rule drops every other inbound packet until you remove it."

// FirewallRules returns the firewall rules that the operator adds before a scan, as lines of
// text, for the operating system that goos names.
//
// The maintainer ruled on 2026-09-30 that the scanner states the rules and never applies
// them. Linux gets the four `iptables` rules of the FoxIO wrapper and their four removals.
// Every other system gets the four pf rules.
func FirewallRules(goos string) string {
	var lines []string

	if goos == "linux" {
		lines = append(lines, rulePreamble, "Add these rules before the scan:")
		lines = append(lines, iptablesRules...)
		lines = append(lines, "Remove them after the scan:")
		lines = append(lines, iptablesRemovals...)
	} else {
		lines = append(lines, rulePreamble, "Add these pf rules before the scan:")
		lines = append(lines, pfRules...)
		lines = append(lines, "Remove them after the scan.")
	}

	return strings.Join(lines, "\n")
}
