# Usage

This page states how a user runs the command-line program, and how a developer calls the
library. The [output-schema page](output-schema.md) states each field that a run emits.

## The command-line program

### Install the program

```bash
go install github.com/Crank-Git/ja4plus-go/cmd/ja4plus@latest
```

### The subcommands

The program prints this usage text for `--help`, for `help` and for `-h`:

```text
ja4plus - JA4+ network fingerprinting tool

Usage:
  ja4plus analyze <pcap-file> [options]
  ja4plus cert <cert-file>
  ja4plus db update
  ja4plus db info
  ja4plus --version

Analyze options:
  --json          Output as JSON
  --csv           Output as CSV
  --types <list>  Comma-separated fingerprint types (e.g. ja4,ja4t)
                  Types: %s
                  ja4l prints the client value and the server value.
                  ja4ls prints the server value alone.
  --lookup        Include application lookup for each fingerprint

Database commands:
  db update       Download the latest ja4plus-mapping.csv from FoxIO
  db info         Print info about the active database (embedded vs cached)
```

`printUsage` in `cmd/ja4plus/main.go` writes that text to standard error, and it fills
`%s` with the method tokens that the next section names.

**The program answers every other first argument with an error.** It writes
`unknown command: %s` to standard error, it prints the usage text, and it exits 1.

!!! note "The program reads a capture file, and it opens no interface"

    `analyze` takes a path. The program holds no subcommand that opens a network
    interface. The [live-capture page](live-capture.md) states what exists today.

### `analyze` reads one capture file

```bash
ja4plus analyze capture.pcap
```

The program picks the reader from the file extension. A path that ends `.pcapng` reaches
`pcapgo.NewNgReader`, and every other path reaches `pcapgo.NewReader`. `runAnalyze` in
`cmd/ja4plus/main.go` holds that choice.

At the end of the file the program calls `CloseOpenWindows`. That call emits the JA4SSH
value of a window that the capture left open.

### The options of `analyze`

| Option | What it does |
|---|---|
| `--json` | The program writes one JSON array. |
| `--csv` | The program writes CSV, with a header row. |
| `--types <list>` | The program emits the named methods alone. |
| `--lookup` | The program adds the application name for each fingerprint. |

**The program takes an option and its value as two arguments.** Write
`--types ja4,ja4t`, and never `--types=ja4,ja4t`. The parser reads the value from the next
argument, and it answers an unknown option with `unknown option: %s`.

**`--json` outranks `--csv`.** A run that sets both writes JSON, because the output switch
tests the JSON flag first.

### The method tokens of `--types`

`methodTokens` in `cmd/ja4plus/types.go` holds the accepted tokens:

```text
ja4, ja4s, ja4h, ja4t, ja4ts, ja4l, ja4ls, ja4x, ja4ssh, ja4d, ja4d6
```

A token that names no method fails the run. The program writes
`--types names no method: %s`, and it names every accepted token on the next line.

**`ja4l` and `ja4ls` select different values.** `ja4l` prints the client value and the
server value. `ja4ls` prints the server value alone. One fingerprinter writes both
values, and the [implementation notes](implementation-notes.md) state why.

### `cert` reads one certificate file

```bash
ja4plus cert server.pem
```

The subcommand prints the JA4X value of the certificate, and the caller names no format.
`isPEM` in `cmd/ja4plus/main.go` picks the encoding. A file that opens with the ten
characters `-----BEGIN` reaches `ComputeJA4XFromPEM`, and every other file reaches
`ComputeJA4XFromDER`.

A file that reaches neither value fails the run. The program writes
`could not compute JA4X fingerprint (invalid or unsupported certificate format)`.

### `db` reports and updates the mapping table

```bash
ja4plus db info
ja4plus db update
```

`db info` prints the source of the active database, the path and the entry count. The
source is the embedded table or the cached table.

**`db update` reaches the network, and no other subcommand does.** It downloads
`ja4plus-mapping.csv` from FoxIO into the cache. FoxIO License 1.1 covers that file, and
the [license page](licensing.md) states the terms.

## The library

### Read a capture file

This program opens a capture file, runs every fingerprinter against each packet, and
prints one line for each result:

```go
package main

import (
    "fmt"
    "os"

    ja4plus "github.com/Crank-Git/ja4plus-go"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/pcapgo"
)

func main() {
    f, _ := os.Open("capture.pcap")
    defer f.Close()

    reader, _ := pcapgo.NewReader(f)
    proc := ja4plus.NewProcessor()

    for {
        data, ci, err := reader.ReadPacketData()
        if err != nil {
            break
        }
        pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
        pkt.Metadata().Timestamp = ci.Timestamp

        results, _ := proc.ProcessPacket(pkt)
        for _, r := range results {
            fmt.Printf("[%s] %s:%d -> %s:%d  %s\n",
                r.Type, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Fingerprint)
        }
    }
}
```

**Set the packet timestamp.** The line that writes `pkt.Metadata().Timestamp` is not
decoration. JA4L measures a delay, so a packet without a timestamp gives it nothing to
measure.

**`ProcessPacket` returns two slices.** The first holds the results, and the second holds
the errors. An error of one fingerprinter is non-fatal, so the caller reads both slices
and continues.

### `Processor` and the individual fingerprinters

`NewProcessor` builds every fingerprinter of this library and dispatches each packet to
all of them. A caller who wants one method builds that fingerprinter instead. The
constructors are `NewJA4`, `NewJA4S`, `NewJA4H`, `NewJA4T`, `NewJA4TS`, `NewJA4L`,
`NewJA4X`, `NewJA4SSH`, `NewJA4D` and `NewJA4D6`.

**`NewJA4SSH` takes the window size, and a value of `0` or less selects the default.** The
default window is 200 packets.

Every fingerprinter satisfies the `Fingerprinter` interface, which `types.go` declares:

| Method | What it does |
|---|---|
| `ProcessPacket` | Reads one packet, and returns the results and the error. |
| `Reset` | Drops every connection that the fingerprinter holds. |
| `CleanupConnection` | Drops the state of one named connection. |

**Call `CleanupConnection` for a connection that ends.** A long-running caller that never
calls it holds the state of every connection it has seen.

### Close the open windows at the end of the input

JA4SSH emits one value for each window of packets, so the last window of a capture stays
open. `CloseOpenWindows` on `Processor` emits every open window, and
`CloseConnectionWindow` emits the window of one connection.

Call `CloseOpenWindows` once, after the last packet. A caller that skips the call loses
the final JA4SSH value of every connection.

### The one-shot functions

A caller who already holds the bytes calls a one-shot function instead of a
fingerprinter. `ComputeJA4XFromPEM` and `ComputeJA4XFromDER` each take a byte slice and
return the value, and the `cert` subcommand calls them.

### The database lookup

`LookupFingerprint` returns the record that the mapping table holds for a fingerprint,
and it returns `nil` when the table holds none. **It performs no network input and no
network output.**

**The function that reaches the network lives in a package of its own.**
`ja4db.LookupFingerprintRemote`, at `github.com/Crank-Git/ja4plus-go/ja4db`, asks
`ja4db.com` for a fingerprint the local table does not hold. **The `ja4plus` package
imports no HTTP client**, so a caller who imports it alone links none. The maintainer ruled
that boundary on 2026-08-14.

**A caller of `ja4db.LookupFingerprintRemote` passes a context, a `*ja4db.RemoteLookupConfig`
and the fingerprint.** The config names the endpoint and the HTTP client. **The function
returns a `*ja4plus.LookupResult`**, so one result type serves the local table and the
remote endpoint. The `README.md` of the repository holds the call.

`GetDatabaseInfo` reports the active source, the path and the entry count. The `db info`
subcommand prints that record.

## More than one goroutine

**One `Processor` serves one goroutine.** Read the
[concurrency page](concurrency.md) before you share one. That page states the two
supported patterns, and it holds a program for each.
