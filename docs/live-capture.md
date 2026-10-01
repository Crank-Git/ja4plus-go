# Live capture

**`ja4plus watch` reads one network interface, and it prints each fingerprint when it
arrives.** `analyze` reads a capture file, and the [usage guide](usage.md) states that
subcommand. **The library reads no interface and no file.** A fingerprinter takes a
`gopacket.Packet`, and the caller decides where that packet came from.

## Run the monitor

```bash
ja4plus watch --interface eth0
```

The program reads the interface until the operator stops it. The usage text of the
[usage guide](usage.md) names each option, and `parseWatchArgs` in `cmd/ja4plus/watch.go`
reads them.

| Option | What it does |
|---|---|
| `--interface <name>` | The monitor reads this interface. The option is required. |
| `--bpf <filter>` | The libpcap build applies the capture filter. The default build refuses it. |
| `--stats-interval <seconds>` | The seconds between two statistics lines. The default is 60. The value `0` writes one line at exit. |
| `--json` | The program writes one JSON object for each fingerprint, on one line. |
| `--csv` | The program writes a header row, and then one row for each fingerprint. |
| `--types <list>` | The program emits the named methods alone. |
| `--lookup` | The program adds the application name for each fingerprint. |
| `--lookup-remote` | The program adds the application name, and it asks `ja4db.com` for each fingerprint that the mapping table does not hold. |

**The output options of `watch` differ from those of `analyze` in one way.** `analyze`
writes one JSON array, because a capture file ends. A monitor ends when the operator stops
it, so `watch` writes one object on each line.

### Stop the monitor

**The first `SIGINT` or `SIGTERM` stops the monitor.** The monitor finishes the packet it
holds. It writes `ja4plus: stopping, closing open windows` to standard error, and it prints
the JA4SSH windows that no packet closed. It then writes the statistics line, and it exits
with status 0.

**A second signal ends the program at once**, and the program then loses every open window.

### The statistics line

The monitor writes one statistics line to standard error at each interval, and one at exit:

```text
ja4plus: uptime=60s packets=1520 fingerprints=48 dropped=0 connections=12
```

`dropped` counts the packets that the capture backend lost. A backend that reports no
count writes `dropped=unknown`.

## The remote lookup delays the capture

**A remote lookup runs on the goroutine that reads the interface.** While the program waits
for `ja4db.com`, it reads no packet. So a slow lookup service delays the capture by up to
2 seconds for each new fingerprint.

- **The drop counter reports the effect.** A packet that arrives during the wait fills the
  capture buffer, and a full buffer loses packets.
- **The program caches a failure as a miss.** A fingerprint that timed out sends no second
  request, and its application stays empty.
- **The first stop request cancels a lookup in flight.** The close of the open windows sends
  no new request.

`watchRemoteLookupDeadline` in `cmd/ja4plus/watch.go` holds the 2 second deadline.
`analyze` keeps the 10 second client timeout of `ja4db`, because a capture file loses no
packet while the program waits. A run without `--lookup-remote` and without
`JA4PLUS_DB_LOOKUP=1` sends no request, and it costs no delay.

## The platforms

| Platform | Build | What `watch` does |
|---|---|---|
| Linux | The default build | It reads the interface through the pure-Go backend. |
| macOS | The `libpcap` build tag | It reads the interface through libpcap. |
| macOS | The default build | It names the `libpcap` build tag, and it exits 1. |
| Windows | Any build | It states that the monitor reads no interface on Windows, and it exits 1. |

**A capture needs a privilege.** On Linux the program needs `CAP_NET_RAW`. On macOS it
needs access to a `/dev/bpf` device. A refused open writes a message that names the
repair, and `watchPermissionMessage` in `cmd/ja4plus/watch.go` holds each message.

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

**A default build refuses `--bpf`, and the message names the tag.** `compileFilter` in
`internal/capture/pcapgo_linux.go` writes that message. **Issue #564 is the reversal path.**
