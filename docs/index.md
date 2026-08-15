# ja4plus-go

`ja4plus-go` is a Go library and a command-line program for JA4+ network fingerprinting.
It reads packets through `gopacket`. JA4+ is a set of standards that FoxIO publishes, and
this library is an independent Go implementation.

The source of this site and of the library is at
<https://github.com/Crank-Git/ja4plus-go>.

!!! warning "Read the license before you use this library"

    The original Go code is BSD 3-Clause. FoxIO licenses every method except JA4 under
    FoxIO License 1.1. That license permits non-commercial use only.
    The [license page](licensing.md) states the split, and the `NOTICE` file at the
    repository root holds the FoxIO terms.

## Install

Install the library into a module:

```bash
go get github.com/Crank-Git/ja4plus-go@latest
```

Install the command-line program:

```bash
go install github.com/Crank-Git/ja4plus-go/cmd/ja4plus@latest
```

`go.mod` declares the language version `go 1.24.0`. The minimum build toolchain is a
separate question, and the [implementation notes](implementation-notes.md) answer it.

## Read one capture

The program reads a capture file and prints one row for each fingerprint:

```bash
ja4plus analyze capture.pcap
```

The [usage guide](usage.md) states every subcommand and every option. The
[output-schema page](output-schema.md) states every field that the program emits.

## Fingerprint from Go

`NewProcessor` returns a `Processor`. `ProcessPacket` runs every fingerprinter of this
library against one packet, and it returns the results and the non-fatal errors together.
The [usage guide](usage.md) holds a program that compiles and runs.

## Read these before you build against the library

- **[The concurrency contract](concurrency.md).** One `Processor` serves one goroutine.
  Two goroutines that share one `Processor` write a data race. Read this page first.
- **[The output schema](output-schema.md).** It states each field of a result, and it
  states which fields the command-line program prints.
- **[Packet throughput](throughput.md).** It holds a measurement, and it states the
  machine that produced it.

## The rest of this site

| Page | What it answers |
|---|---|
| [Usage](usage.md) | How a user runs the program, and how a developer calls the library. |
| [Output schema](output-schema.md) | Which fields the program emits, in each of the three formats. |
| [Live capture](live-capture.md) | Whether this library reads a live interface today. |
| [Concurrency](concurrency.md) | How a caller uses more than one goroutine. |
| [Packet throughput](throughput.md) | What one packet costs, and how a reader measures it again. |
| [Implementation notes](implementation-notes.md) | Which decisions shape the code, and why. |
| [Parity with the port](parity.md) | How each name of the Python port maps onto this library. |
| [Licensing](licensing.md) | Which license covers which material. |

## What this library declines

The `Non-goals` section of the specification records each decline, and two of them reach a
user directly.

- **Wire-speed performance is out of scope.** The project measures the packet throughput,
  and it sets no target. The [packet-throughput page](throughput.md) holds the
  measurement.
- **This project seeks no commercial license from FoxIO.** A commercial user contacts
  FoxIO. The [license page](licensing.md) states that path.
