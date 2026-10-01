// Package scan computes the JA4TScan value of a host by an active TCP scan.
//
// JA4TScan is the one FoxIO method that sends packets. The scanner sends one TCP SYN to
// each target, and it reads the SYN-ACK of the target and every retransmission of it. The
// value describes how the TCP stack of the target answers and how it retransmits. FoxIO
// publishes the scanner at `https://github.com/FoxIO-LLC/ja4tscan`, and this project reads
// commit `d01bfec4`.
//
// **The package is opt-in and separate.** No passive fingerprinter and no `Processor`
// imports it, so a capture read sends no packet. `internal/repocheck` holds that boundary.
// The maintainer ruled it on 2026-09-30, and `Crank-Git/ja4plus#775` holds the ruling.
//
// **The package changes no firewall state.** FirewallRules returns the rules that the
// operator adds, so that the kernel of the scanning host sends no RST for the SYN-ACK of a
// target. The package never applies them.
//
// The package reads IPv4 alone. OpenNetwork sends through the link-layer handle of
// `internal/capture`, and the maintainer ruled that placement on 2026-10-01 in #796. A
// build for macOS needs the `libpcap` build tag for that handle.
//
// The package writes nothing to standard output and nothing to standard error. Each
// warning reaches the OnWarning function of Config, and `cmd/ja4plus` prints it.
package scan
