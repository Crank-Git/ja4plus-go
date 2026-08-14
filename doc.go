// Package ja4plus computes JA4+ network fingerprints from the packets that gopacket
// decodes.
//
// # Build toolchain
//
// The language version and the build toolchain are two different statements, and this
// section states both.
//
// The go.mod file declares the Go 1.24 language version. A language version is not a
// toolchain, so a consumer on a Go 1.24 toolchain compiles this module.
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
