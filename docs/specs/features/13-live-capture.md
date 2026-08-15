---
id: live-capture
feature: Live capture
epic: "Epic 13: Live capture"
status: issued
issues: [76, 77, 78, 79, 80, 81, 82]
mockups: [mockups/03-watch-output.html]
---

## Purpose

The port ships a monitor. `ja4plus watch` there reads an interface until the operator
stops it, and it reports its counts on one line. This project reads capture files only.

Round 2 listed live capture as a non-goal. The maintainer ruled on 2026-08-11 that only a
capability Go cannot achieve stays out of scope, and Go can achieve this one.

**The capability is not equal on every platform, and this feature set states the
boundary.** `gopacket@v1.6.1/pcapgo/capture.go:6` holds `//go:build linux`, so the pure-Go
capture handle reaches Linux alone. `gopacket@v1.6.1/afpacket/afpacket.go:7` holds the
same constraint, so `afpacket` reaches Linux alone too. macOS therefore needs libpcap
through cgo, and the maintainer chose an opt-in build tag for it.

## The cgo containment

`CLAUDE.md` stated "No cgo. The build cross-compiles to five platforms." before this epic.
**The `libpcap` build tag contradicts that sentence for one build**, so this feature set
contains the contradiction three ways and it then rewrites the sentence. Acceptance
criterion 10 below records that rewrite. `CLAUDE.md` states the containment on 2026-08-14.

1. **The default build selects the pure-Go backend and holds no cgo.** `CGO_ENABLED=0`
   builds every package of this module.
2. **No released binary carries cgo.** `.github/workflows/release.yml` builds the five
   artifacts, and no build command of that file carries `-tags`.
3. **CI compiles the tagged path on a macOS runner and gates nothing else on it.** The
   check proves the code builds, and the release does not ship it.

A macOS user who wants the monitor builds from source with `-tags libpcap`. FR-capture-24
makes the program say so.

## User stories

- As a monitor operator, I want a long-running process that reads an interface and never
  exhausts memory, so that I can leave it running.
- As a monitor operator, I want to know how many packets the capture backend dropped, so
  that I know whether the fingerprints are complete.
- As a monitor operator, I want the process to stop cleanly on a termination signal, so
  that the last window is not lost.
- As a user who runs both libraries, I want `ja4plus watch` to mean the same thing in
  both, so that I do not learn two commands.
- As a macOS user, I want a clear message that names the build tag, so that I am not left
  guessing why the command is missing.

## Functional requirements

### The command

- **FR-capture-1** — `ja4plus watch` reads packets from one interface.
- **FR-capture-2** — `--interface` names the interface.
- **FR-capture-3** — `--bpf` passes a capture filter to the capture backend.
- **FR-capture-4** — `--types` filters the methods, matching the capture-file command.
- **FR-capture-5** — The output format options match the capture-file command.
- **FR-capture-6** — The command writes fingerprints to standard output.
- **FR-capture-7** — The command writes the statistics line to standard error.
- **FR-capture-8** — `--stats-interval` sets the seconds between statistics lines. The
  default is 60.
- **FR-capture-9** — `--stats-interval 0` writes one statistics line at exit and no other.

### The capture backend

- **FR-capture-10** — `internal/capture` exports one interface that opens a handle and
  returns packets.
- **FR-capture-11** — The pure-Go backend uses `pcapgo.NewEthernetHandle` and carries the
  build constraint `linux`.
- **FR-capture-12** — The libpcap backend carries the build constraint `libpcap`.
- **FR-capture-13** — A build that selects no backend compiles, and `watch` reports that
  the platform is unsupported.
- **FR-capture-14** — The handle stays open across the whole run. The monitor opens it
  once.
- **FR-capture-15** — The pure-Go backend applies no capture filter. It returns an error
  that names the filter, the `libpcap` build tag and the build command.

**FR-capture-15 changed on 2026-08-14, and this file records the change rather than the
result alone.** The requirement read
`The pure-Go backend applies the capture filter as a BPF program.` until that day. **The
maintainer ruled #564**, and the ruling lives in comment 5294952561 of that issue.

**The reason: no compiler of a capture filter reaches the default build.** #77 measured
three candidates in the module cache on 2026-08-14.

| What | What it does | Why it reaches no filter |
|---|---|---|
| `pcapgo.EthernetHandle.SetBPF` | Takes `[]bpf.RawInstruction`. | It parses no expression. `gopacket@v1.6.1/pcapgo/capture.go:207`. |
| `golang.org/x/net/bpf` | Assembles an instruction slice. | It holds no parser. `golang.org/x/net@v0.39.0/bpf/asm.go:14`. |
| `pcap.CompileBPFFilter` | Compiles an expression. | It calls `C.pcap_compile`, so it needs cgo. `gopacket@v1.6.1/pcap/pcap.go:434` and `pcap/pcap_unix.go:300`. |

**A compiler for a subset of the grammar reaches two packet sets from one filter**, because
the libpcap backend compiles the whole grammar. The ruling declines that outcome, and a
fingerprint exists to be compared.

**The libpcap backend applies a capture filter**, and FR-capture-12 names it.
`pcap.CompileBPFFilter` serves that path.

**Issue #564 is the reversal path.** A reversal adds a pure-Go compiler as a dependency, or
it writes a compiler in this repository, and it re-reads the three rows above at the
versions of that day.

### The monitor loop

- **FR-capture-16** — The monitor owns one `Processor` on one goroutine, and takes no
  lock.
- **FR-capture-17** — The monitor reads the stop request after each packet.
- **FR-capture-18** — `SIGINT` and `SIGTERM` set the stop request.
- **FR-capture-19** — A second signal exits at once.
- **FR-capture-20** — The monitor calls `Processor.CloseOpenWindows` after the stop
  request, and prints the results.
- **FR-capture-21** — The monitor holds a connection table that records the time each
  connection last sent a packet.
- **FR-capture-22** — The monitor calls `CleanupConnection` for a connection that has sent
  no packet for the idle timeout. The default is 5 minutes.
- **FR-capture-23** — The connection table has a maximum entry count. The oldest entry is
  evicted when the count is reached.

### The unsupported platform

- **FR-capture-24** — On macOS, a build without the `libpcap` tag reports: the monitor
  needs the `libpcap` build tag on this platform, and names the build command.
- **FR-capture-25** — On Windows, the command reports that the monitor is unsupported.
- **FR-capture-26** — The message goes to standard error, and the exit status is non-zero.
- **FR-capture-27** — The capture-file command works on every platform, with no tag.

### The statistics line

- **FR-capture-28** — The line reports the uptime in whole seconds.
- **FR-capture-29** — The line reports the count of packets read.
- **FR-capture-30** — The line reports the count of fingerprints emitted.
- **FR-capture-31** — The line reports the drop count.
- **FR-capture-32** — The line reports the count of connections the table holds.
- **FR-capture-33** — A backend that reports no drop count writes `unknown`.
- **FR-capture-34** — The pure-Go backend reads the drop count from the packet socket.

### Privileges

- **FR-capture-35** — The command reports a permission failure with the capability the
  host needs.
- **FR-capture-36** — The message names `CAP_NET_RAW` on Linux.
- **FR-capture-37** — The command opens no interface until it has parsed every option.

## User flows

### An operator watches an interface

1. The operator runs `sudo ja4plus watch --interface eth0 --bpf "tcp port 443"`.
2. The program opens the handle and prints nothing until the first fingerprint.
3. Every 60 seconds the program writes one statistics line to standard error.
4. The operator sends `SIGINT`.
5. The program stops reading, prints the open windows, writes a final statistics line and
   exits with status 0.

### A macOS user runs the monitor

1. The user runs `ja4plus watch --interface en0`.
2. The program reports that the monitor needs the `libpcap` build tag, and names the
   command `go build -tags libpcap ./cmd/ja4plus`.
3. The user builds with the tag and runs the command again.

## Screens & states

`mockups/03-watch-output.html` shows the standard-output stream and the statistics line
side by side, plus the permission failure and the unsupported-platform message.

| State | What the operator sees |
|---|---|
| Starting | Nothing on standard output. No statistics line before the first interval. |
| Running | One line per fingerprint on standard output. One statistics line per interval on standard error. |
| Stopping | The open-window results, then one final statistics line. |
| No permission | One message that names the capability, on standard error. Exit status 1. |
| Unsupported platform | One message that names the build tag or the platform. Exit status 1. |

## Behaviour rules

- **The core package opens no interface.** The monitor lives in `cmd/ja4plus` and in
  `internal/capture`, and `internal/capture` is inside the library. The maintainer ruled
  that extent on 2026-08-15, and `docs/audit/network-boundary.md` holds the amendment.
  **Issue #613 is the reversal path.** The rule that the library performs no remote lookup
  outside `ja4db/` holds unchanged.
- **The monitor sends no packet.** It reads an interface and writes nothing to it.
- **A live capture never ends by itself.** Every bound is a bound the monitor sets: the
  idle timeout, the maximum entry count and the statistics interval.
- **The statistics line is diagnostic output.** It goes to standard error so that a
  redirect of standard output holds fingerprints alone.
- **One `Processor`, one goroutine.** The monitor takes the fast path and needs no
  `SyncProcessor`.

## Data touched

| File | Change |
|---|---|
| `internal/capture/capture.go` | New. The backend interface. |
| `internal/capture/pcapgo_linux.go` | New. Build tag `linux`. |
| `internal/capture/libpcap.go` | New. Build tag `libpcap`. |
| `internal/capture/unsupported.go` | New. The fallback that FR-capture-13 needs. |
| `cmd/ja4plus/watch.go` | New. The command, the loop, the signals, the connection table. |
| `cmd/ja4plus/statistics.go` | New. The statistics line and the goroutine that writes it. |
| `cmd/ja4plus/main.go` | The subcommand joins the parser. |
| `CLAUDE.md` | The no-cgo sentence states the containment. |
| `.github/workflows/ci.yml` | A macOS job compiles the tagged path. |
| `.github/workflows/release.yml` | No artifact carries the tag. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `gopacket/pcapgo` | v1.6.1 | <https://pkg.go.dev/github.com/gopacket/gopacket/pcapgo> |
| `gopacket/pcap` | v1.6.1 | <https://pkg.go.dev/github.com/gopacket/gopacket/pcap> |
| `os/signal` | Go 1.24 | <https://pkg.go.dev/os/signal> |
| Linux packet socket | `packet(7)` | <https://man7.org/linux/man-pages/man7/packet.7.html> |

**`pcapgo.NewEthernetHandle` is Linux-only, and it holds no cgo.**
`gopacket@v1.6.1/pcapgo/capture.go:6` holds `//go:build linux`, and the file imports no C.
Read 2026-08-14 from the module cache at `github.com/gopacket/gopacket@v1.6.1`.

**`gopacket/afpacket` is not used, because it reaches Linux alone.**
`gopacket@v1.6.1/afpacket/afpacket.go:7` holds `//go:build linux`, and
`gopacket@v1.6.1/afpacket/header.go:7` holds the same line. **No file of that package
imports C at v1.6.1**, so `afpacket` reaches macOS no better than `pcapgo` does. Read
2026-08-14 from the same module cache.

**The two paragraphs above read `github.com/gopacket/gopacket` at v1.6.1, and an earlier
draft read `github.com/google/gopacket` at v1.1.19.** #438 moved the module on 2026-08-13,
and the Epic 13 round re-read each constraint at the version `go.mod` requires. **The
earlier draft stated `// +build linux,go1.9`, and no file of v1.6.1 holds that term.**

## Edge cases & failures

| Case | Expected behaviour |
|---|---|
| The interface does not exist. | One message that names the interface. Exit status 1. No handle opened. |
| The capture filter does not compile. | One message that holds the filter text and the parser error. Exit status 1. |
| The interface carries no traffic. | The statistics line still appears each interval. The monitor does not block on a read forever. |
| The process lacks `CAP_NET_RAW`. | FR-capture-35 and FR-capture-36 cover it. |
| A packet arrives while the stop request is set. | The monitor reads it and then stops. No packet is half-processed. |
| Two signals arrive quickly. | FR-capture-19 exits at once, and the open windows are lost. |
| The connection table reaches its maximum. | The oldest entry is evicted. Its fingerprint may be incomplete, and that is the documented cost of a bound. |
| The interface is removed while the monitor runs. | The read returns an error. The monitor writes one message and exits with status 1. |
| The capture backend reports no drop count. | The field reads `unknown`. FR-capture-33 covers it. |

## Acceptance criteria

1. `ja4plus watch --interface lo` on Linux prints a fingerprint for traffic that a test
   generates on the loopback interface.
2. `CGO_ENABLED=0 go build ./...` succeeds for every package.
3. `go build -tags libpcap ./cmd/ja4plus` succeeds on a macOS runner in CI.
4. No artifact of `.github/workflows/release.yml` is built with the `libpcap` tag. **This
   repository holds no `.goreleaser.yaml` on 2026-08-14**, and #105 moves the release to
   GoReleaser later. A criterion that named that file measured nothing.
5. `SIGINT` stops the monitor, and the exit status is 0.
6. The monitor prints the open windows after the stop request.
7. A run of 100000 packets holds resident memory below a recorded ceiling.
8. The statistics line holds every field of FR-capture-28 through FR-capture-32.
9. On macOS without the tag, `watch` names the tag and the build command, and exits 1.
10. `CLAUDE.md` states the cgo containment rather than an absolute.

## Out of scope

- Windows capture. No pure-Go backend exists, and Npcap adds a second cgo path.
- Sending any packet. The monitor reads only.
- A daemon, a service file or an init script. The operator runs the command.
- Writing a capture file from the monitor. `tcpdump` already does that.
- A remote capture source.

## Open questions

1. **Does the released binary set stay at five platforms?** The monitor works on the Linux
   binaries and not on the macOS ones. A sixth artifact built with the tag would need a
   macOS runner and would carry cgo, which FR-capture-3 of the containment forbids. This
   feature set ships five and documents the source build.
2. **What is the memory ceiling that acceptance criterion 7 records?** The port states a
   number for its own run. This project measures its own and records it in
   `features/03-concurrency.md`, because the two runtimes are not comparable.
3. **Does `watch` need `SyncProcessor` for a future multi-goroutine mode?** FR-capture-16
   takes the single-goroutine path. A sharded monitor is a later change, and the freeze
   makes the exported surface hard to extend afterwards.
