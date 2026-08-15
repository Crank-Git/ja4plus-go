# Live capture

!!! warning "Live capture is not built yet"

    **This library reads a capture file, and it opens no network interface.** The
    command-line program holds no subcommand that captures live traffic, and the module
    holds no capture package. This page states what exists today, and it states what the
    design plans.

    Measured on 2026-08-14 against the branch that this site is built from. `ls internal/`
    reports `dbcache/`, `keylog/` and `parser/`, and it reports no `capture/`. **Epic 13
    builds the capture package on a branch of its own, and that branch has not reached this
    one.**

## What exists today

**The program reads a capture file through `analyze`.**

```bash
ja4plus analyze capture.pcap
ja4plus analyze capture.pcapng
```

The program picks the reader from the first four bytes of the file, and never from the file
extension. So both commands above read, and a path that carries no extension reads too. The
[usage guide](usage.md) states the subcommand, every option and the format choice.

**The library reads no file at all.** A fingerprinter takes a `gopacket.Packet`, and the
caller decides where that packet came from. `cmd/ja4plus` holds the only file-reading code
in this repository.

**That interface is what makes live capture a small change for a caller.** A program that
already builds a `gopacket.Packet` from an interface passes it to `ProcessPacket` today,
with no new library code.

## Capture live traffic today

**A user who needs live traffic captures to a file, and then reads that file.**

```bash
tcpdump -i en0 -w capture.pcap
ja4plus analyze capture.pcap
```

**A Go program reads an interface with a capture package of its own choice**, and it hands
each packet to `ProcessPacket`. The [usage guide](usage.md) holds the loop that does it,
and only the source of the packets changes.

## What the design plans

The specification holds a live-capture feature, and the tracker holds it as Epic 13. **No
requirement of it is built on the branch that this site is built from.** The list below
describes a plan, and never a shipped interface.

| Planned part | What the design states |
|---|---|
| The subcommand | `ja4plus watch` opens an interface and prints fingerprints as they arrive. |
| The package | `internal/capture` exports one interface that opens a handle and returns packets. |
| The pure-Go backend | It uses `pcapgo.NewEthernetHandle`, and it carries the build constraint `linux`. |
| The libpcap backend | It carries the build constraint `libpcap`, and it uses cgo. |
| macOS | Without the build tag, the program reports the tag that the platform needs. |
| Windows | The program reports that the platform is unsupported. |

**Read the tracker for the current state, and never this table.** A page states the tree
that built it, and Epic 13 moves.

## Why two backends

**`pcapgo.NewEthernetHandle` reaches Linux alone.** It captures without cgo, so it suits
the default build of this project. The default build holds no cgo, and the
[implementation notes](implementation-notes.md) state that rule.

**The `libpcap` build tag exists so that live capture reaches macOS.** It selects a cgo
path. That path builds no release artifact, because every released binary is built without
cgo.

So the two backends answer one question each. The pure-Go backend keeps the default build
free of cgo. The libpcap backend gives a macOS user a way to capture at all.

## The capture filter needs the `libpcap` build tag

**The maintainer ruled the capture filter on 2026-08-14, under issue #564.** **The pure-Go
backend applies no capture filter.** A capture filter needs the `libpcap` build tag, and
`--bpf` therefore names that tag.

The ruling reads three measurements, taken at the versions `go.mod` pins.

| What | What it does |
|---|---|
| `pcapgo.EthernetHandle.SetBPF` | It attaches an instruction slice, and it parses no expression. |
| `golang.org/x/net/bpf` | It assembles an instruction slice, and it holds no parser. |
| `pcap.CompileBPFFilter` | It compiles an expression, and it calls `C.pcap_compile`. |

**So the compilation of a filter expression needs cgo, and the default build holds no
cgo.** The maintainer declined two other answers. A pure-Go compiler adds a third module at
the API freeze, and a compiler written here gives the two backends two grammars. **One
filter string that selects two packet sets is the worst outcome for a fingerprint**, which
exists to be compared.

**The ruling states what a live-capture build must do, and this branch holds no such
build.** It states that a build without the `libpcap` tag refuses `--bpf` and names the
tag. **No `--bpf` option reaches the program of this branch**, so no user meets that
refusal today. **Issue #564 is the reversal path.**

## What this page does not describe

- **No `watch` subcommand exists.** The program answers `watch` with
  `unknown command: watch`, it prints the usage text, and it exits 1.
- **No `--bpf` option exists.** `analyze` takes `--json`, `--csv`, `--types` and
  `--lookup`, and no other option.
- **No drop count and no statistics line exist**, because no capture backend produces
  either one.
