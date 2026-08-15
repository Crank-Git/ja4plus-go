// Package ja4plus computes JA4+ network fingerprints from the packets that gopacket
// decodes.
//
// # Methods
//
// This package implements eleven methods, and ten fingerprinters carry them.
// JA4LFingerprinter writes both JA4L and JA4LS, so the count of fingerprinters is one
// below the count of methods. Read the ten as a count of fingerprinters, and never as a
// count of methods.
//
// The list below names each method and the input it reads.
//
//   - JA4 reads a TLS client hello. A TCP connection carries one, and a QUIC initial
//     packet carries one.
//   - JA4S reads a TLS server hello.
//   - JA4H reads an HTTP request.
//   - JA4X reads an X.509 certificate.
//   - JA4SSH reads a window of SSH packets.
//   - JA4T reads a TCP SYN packet.
//   - JA4TS reads a TCP SYN-ACK packet.
//   - JA4L reads the client timing of a TCP handshake, or of a QUIC exchange.
//   - JA4LS reads the server timing of the same exchange.
//   - JA4D reads a DHCP packet.
//   - JA4D6 reads a DHCPv6 packet.
//
// The list above names what this package implements, and it names no FoxIO list. Three
// FoxIO records at commit 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8 name three different
// sets of methods, so no single FoxIO record states the set above.
// testdata/foxio.pin holds that commit.
//
// Processor holds the ten fingerprinters, and it gives every packet to each one. The list
// above holds eleven rows, because JA4LFingerprinter carries two of them. A caller that
// wants one method alone builds the fingerprinter that carries it. A
// fingerprinter returns a non-fatal error, and it returns no panic, because every packet
// is untrusted input.
//
// # Build toolchain
//
// The language version and the build toolchain answer two different questions, and this
// section states both. A language version decides which consumer compiles the module. A
// build toolchain decides which standard library a built binary links.
//
// The go.mod file declares the Go 1.25 language version. A language version is not a
// toolchain, so a consumer on a Go 1.25 toolchain compiles this module.
//
// The maintainer moved the version from 1.24 to 1.25 on 2026-08-15, and issue #725 holds
// the ruling. The gopacket v1.7.1 dependency declares go 1.25.0 in its own go.mod, and it
// repairs a decoder panic on untrusted input. A Go 1.24 consumer no longer compiles this
// module, and the ruling lands in v1.1.0.
//
// The minimum build toolchain is go1.25.13. It is the oldest toolchain this project
// measured at zero called vulnerabilities of the standard library. On 2026-08-14,
// govulncheck v1.6.0 reported 13 for go1.24.13, 0 for go1.25.13, 4 for go1.26.5 and 0 for
// go1.26.6. So a later toolchain is not a clean toolchain by itself, and a user on the Go
// 1.26 line takes go1.26.6 or later.
//
// Every count above moves without a change to this repository, because the vulnerability
// database is live. The README states the measurement, and it names the command that
// re-takes it.
//
// # Network
//
// This package performs no network input and no network output. It imports no HTTP client,
// so no call of it reaches the network. LookupFingerprint reads the embedded table or the
// cache file, and it makes no request.
//
// One function of this library reaches the network, and it lives in another package:
// LookupFingerprintRemote of github.com/Crank-Git/ja4plus-go/ja4db. A program that imports
// the core package alone links no HTTP client.
//
// The maintainer ruled that boundary on 2026-08-14, and docs/audit/network-boundary.md
// holds the record, the three options and the reason.
//
// # Concurrency
//
// One Processor serves one goroutine, and one fingerprinter serves one goroutine. Every
// fingerprinter holds state that no lock guards. Two goroutines that share one instance
// write a data race. The race detector reports the race. The library does not detect it
// at run time.
//
// A caller who wants more than one goroutine takes one of two patterns.
//
//   - Route each packet with [Processor.GetShardKey], and give each goroutine its own
//     Processor. The key holds the sorted five-tuple, so a packet and its reply reach
//     one Processor.
//   - Share one [SyncProcessor], which serializes every call with one mutex.
//
// The first pattern gives higher throughput, because the per-packet path acquires no
// lock. The second pattern costs one mutex acquisition for each packet. The README shows
// both patterns as code.
//
// # License
//
// This repository holds material under two licenses, and NOTICE at the repository root
// states which license covers which material.
//
// The BSD 3-Clause license covers the original Go code, and LICENSE at the repository
// root holds that text. FoxIO licenses the JA4 method under BSD 3-Clause, and it
// publishes that text as LICENSE-JA4.
//
// FoxIO License 1.1 covers the other methods that this package implements: JA4S, JA4H,
// JA4T, JA4TS, JA4L, JA4LS, JA4X, JA4SSH, JA4D and JA4D6. FoxIO License 1.1 permits
// non-commercial use only. A commercial user contacts FoxIO for those methods, and this
// project gives no legal advice.
//
// This package embeds the file data/ja4plus-mapping.csv, and that file comes from FoxIO.
// FoxIO License 1.1 covers it, so every program that links this package carries FoxIO
// material. data/README.md names the source of the file.
//
// FoxIO publishes FoxIO License 1.1 at
// https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE.
package ja4plus
