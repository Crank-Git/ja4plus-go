<p align="center"><img src="assets/logo.png" width="300"></p>

`ja4plus-go` is a Go library and a command-line program for JA4+ network fingerprinting.
It implements eleven JA4+ methods, and ten fingerprinters carry them. It reads TLS, TCP,
HTTP, SSH, X.509 and DHCP characteristics, and it decodes a QUIC Initial packet.

JA4+ is a set of network fingerprinting standards that [FoxIO](https://foxio.io)
publishes. This library is an independent Go implementation. The
[FoxIO JA4+ repository](https://github.com/FoxIO-LLC/ja4) holds the original
specification.

[![CI](https://github.com/Crank-Git/ja4plus-go/actions/workflows/ci.yml/badge.svg)](https://github.com/Crank-Git/ja4plus-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Crank-Git/ja4plus-go.svg)](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go)
[![License](https://img.shields.io/badge/license-BSD--3--Clause%20and%20FoxIO%201.1-blue.svg)](LICENSE)

**Documentation: <https://crank-git.github.io/ja4plus-go/>** — the usage guide, the output schema, the concurrency contract, the packet-throughput measurement and the licensing terms.

## Supported Fingerprint Types

| Type | Protocol | Description |
|------|----------|-------------|
| JA4 | TLS/QUIC | Client fingerprint from ClientHello messages |
| JA4S | TLS/QUIC | Server fingerprint from ServerHello messages |
| JA4H | HTTP | Client fingerprint from request headers and cookies |
| JA4T | TCP | Client OS fingerprint from SYN packets |
| JA4TS | TCP | Server fingerprint from SYN-ACK packets |
| JA4L | TCP/QUIC | Light distance and latency estimation |
| JA4LS | TCP/QUIC | Server light distance and latency estimation |
| JA4X | X.509 | Certificate structure fingerprint from OID sequences |
| JA4SSH | SSH | Session type classification from traffic patterns |
| JA4D | DHCPv4 | Per-packet DHCPv4 fingerprint (FoxIO PR #267/#270) |
| JA4D6 | DHCPv6 | Per-packet DHCPv6 fingerprint |

The table above holds eleven rows, and ten fingerprinters carry those methods.
`JA4LFingerprinter` writes JA4L and it writes JA4LS, so one fingerprinter carries two of
the rows. Read the ten as a count of fingerprinters, and never as a count of methods.

The library decrypts a QUIC Initial packet (RFC 9001 and RFC 9369) and it reads the TLS
ClientHello inside.

## Installation

The module requires Go 1.24 or later. **That sentence states a language version, and the
`or later` names the toolchain that compiles the module.** It names no toolchain that
builds a binary free of a called vulnerability, and the section below names that one.

```bash
go get github.com/Crank-Git/ja4plus-go@latest
```

`v1.0.0` freezes the exported API. `docs/api/v1.md` records every exported name with its
signature, and a test fails when the surface and that record differ.

**The command states `@latest`, and it states no version.** `@latest` resolves to the
newest published tag, so the command works before the `v1.0.0` tag exists and after it
lands. A command that names an unpublished tag fails, and the module proxy holds no
`v1.0.0` tag on 2026-08-15 UTC. `docs/index.md` and `docs/usage.md` state the same form.

### The language version and the build toolchain

**These two statements answer two different questions, and this section states both.**

- **A language version decides which consumer compiles the module.**
- **A build toolchain decides which standard library a built binary links.**

**The language version is 1.24.** `go.mod` declares `go 1.24.0`, and a language version is
not a toolchain. So a consumer on a Go 1.24 toolchain compiles this module, and this
section does not narrow who consumes the library.

**The minimum build toolchain is go1.25.13.** A user who builds a binary from this source
takes go1.25.13 or a later toolchain, and the measurement below states why. `go1.25.13` is
the oldest toolchain this project measured at zero called vulnerabilities, and no claim
here covers a patch that the table does not name.

`govulncheck` reads the standard library of the `go` command on the PATH, so the toolchain
decides the result. `govulncheck` v1.6.0 reported this on 2026-08-14, against the
vulnerability database that <https://vuln.go.dev> published at 2026-08-13 21:43:54 UTC:

| Toolchain | Called standard library vulnerabilities | Exit status |
|---|---|---|
| go1.24.13 | 13 | 3 |
| go1.25.13 | 0 | 0 |
| go1.26.5 | 4 | 3 |
| go1.26.6 | 0 | 0 |

**A later toolchain is not a clean toolchain by itself.** go1.26.5 is later than go1.25.13,
and it carries four. So a user on the Go 1.26 line takes go1.26.6 or later.

**No Go 1.24 patch clears the 13.** go1.24.13 is the newest Go 1.24 patch, and each
advisory names a fix in a go1.25.x release or a later one.

**Every count above moves without a change to this repository**, because the vulnerability
database is live. Run `make vuln` to re-take the measurement on your own toolchain.

**This project builds and releases on the range `~1.26.6`.**
`.github/workflows/ci.yml` names that range for every job, and
`.github/workflows/release.yml` names it for every released binary.

## CLI

Pre-built binaries are available on the [Releases](https://github.com/Crank-Git/ja4plus-go/releases) page. Or build from source:

```bash
go install github.com/Crank-Git/ja4plus-go/cmd/ja4plus@latest
```

```bash
# Analyze a PCAP file
ja4plus analyze capture.pcap

# JSON output for SIEM ingestion
ja4plus analyze capture.pcap --json

# Only specific fingerprint types
ja4plus analyze capture.pcap --types ja4,ja4t

# CSV output
ja4plus analyze capture.pcap --csv

# Include fingerprint identification
ja4plus analyze capture.pcap --lookup

# Watch one live interface
ja4plus watch --interface eth0

# The analyze options hold the same meaning on the monitor
ja4plus watch --interface eth0 --json --types ja4,ja4t --lookup

# One statistics line every 10 seconds, on standard error
ja4plus watch --interface eth0 --stats-interval 10

# Fingerprint a certificate
ja4plus cert server.der
ja4plus cert server.pem

# Update / inspect the local lookup database
ja4plus db update
ja4plus db info
```

### One run, and the output it writes

`make corpus` fetches the FoxIO corpus, and the capture below comes from it. Run the
command from the repository root:

```bash
ja4plus analyze testdata/foxio/pcap/tls12.pcap
```

The program writes these two lines:

```text
Type  Source                 Destination         Fingerprint
ja4   192.168.133.129:36372  34.117.237.239:443  t13d1715h2_5b57614c22b0_3d5424432f57
```

`TestTheReadmeCommandLineOutputMatchesTheProgram` in `readme_code_blocks_test.go` runs
that command and it compares the output to the block above. The test skips when the
worktree holds no corpus.

### The capture filter of `ja4plus watch`

**A capture filter needs the `libpcap` build tag.** The default build holds no cgo, and it
reaches no compiler of a filter expression. So the default build declines `--bpf`, and it
names the build command:

```bash
go build -tags libpcap ./cmd/ja4plus
ja4plus watch --interface eth0 --bpf "tcp port 443"
```

**The maintainer ruled this on 2026-08-14, and issue #564 is the reversal path.** The
monitor reads every packet of the interface without the tag, and `--types` filters the
methods on any build. `docs/specs/features/13-live-capture.md` FR-capture-15 states the
ruling.

**The same tag reaches the monitor on macOS**, because the pure-Go capture handle builds on
Linux alone. The monitor reads no interface on Windows, and `ja4plus analyze` reads a
capture file on every platform.

## Go API

### Quick Start

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

### Individual Fingerprinters

```go
ja4  := ja4plus.NewJA4()
ja4s := ja4plus.NewJA4S()
ja4h := ja4plus.NewJA4H()
ja4t := ja4plus.NewJA4T()
ja4ts := ja4plus.NewJA4TS()
ja4l := ja4plus.NewJA4L()
ja4x := ja4plus.NewJA4X()
ja4ssh := ja4plus.NewJA4SSH(0) // 0 = default 200-packet window
ja4d := ja4plus.NewJA4D()
ja4d6 := ja4plus.NewJA4D6()
```

All fingerprinters share a common interface:

| Method | Description |
|--------|-------------|
| `ProcessPacket(pkt)` | Process a packet, returns `[]FingerprintResult` or nil |
| `Reset()` | Clears all collected state |
| `CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)` | Removes the state that the named connection holds |

`JA4SSHFingerprinter` also implements `WindowCloser` and `ConnectionWindowCloser`. **Each
interface carries one method**, so a type that implements one of them reaches that method's
dispatch and never loses the other. The maintainer ruled the split on 2026-08-12, and issue
#268 records the ruling.

| Interface | Method | Description |
|--------|--------|-------------|
| `WindowCloser` | `CloseOpenWindows()` | Emits the window each connection holds open, and returns the results |
| `ConnectionWindowCloser` | `CloseConnectionWindow(srcIP, srcPort, dstIP, dstPort, proto)` | Emits the window one connection holds open, removes that connection, and returns the results |

JA4SSH emits one value for every 200 SSH packets of a connection. A connection whose last
window never reaches that count holds the window open, and no packet emits it. Call
`CloseOpenWindows` when the packet source ends, or lose that window. When one connection
ends before the packet source does, call `CloseConnectionWindow` for it instead.
`Processor` and `SyncProcessor` each carry both methods. `CloseOpenWindows` reaches every
fingerprinter that implements `WindowCloser`. `CloseConnectionWindow` reaches every
fingerprinter that implements `ConnectionWindowCloser`. A fingerprinter that implements one
of the two interfaces alone reaches that interface's method.

```go
proc := ja4plus.NewProcessor()
for _, pkt := range packets {
    results, _ := proc.ProcessPacket(pkt)
    _ = results
}

// The capture ends, so emit the window each connection holds open.
trailing := proc.CloseOpenWindows()
```

### One-Shot Functions

Each one-shot function below computes one fingerprint, and it holds no connection state:

```go
fp := ja4plus.ComputeJA4(packet)
fp := ja4plus.ComputeJA4S(packet)
fp := ja4plus.ComputeJA4H(packet)
fp := ja4plus.ComputeJA4T(packet)
fp := ja4plus.ComputeJA4TS(packet)
fp := ja4plus.ComputeJA4D(packet)
fp := ja4plus.ComputeJA4D6(packet)
fp := ja4plus.ComputeJA4XFromDER(certBytes)
fp := ja4plus.ComputeJA4XFromPEM(pemBytes)
fp := ja4plus.ComputeJA4XFromPacket(packet)
```

Note: JA4L, JA4LS and JA4SSH are multi-packet methods, and none of them reaches a one-shot
function. Use `NewJA4L` and `NewJA4SSH` instead. `NewJA4L` serves JA4L and JA4LS, and the
library exports no `NewJA4LS`.

### Fingerprint Lookup

ja4plus-go includes a bundled database of known JA4+ fingerprints from FoxIO's [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv).

```go
result := ja4plus.LookupFingerprint("t13d1516h2_8daaf6152771_02713d6af862")
if result != nil {
    fmt.Println(result.Application) // "Chromium Browser"
}
```

#### Which functions reach the network

**The `ja4plus` package performs no network input and no network output.** It imports no
HTTP client, so a program that imports it alone reaches no network. `LookupFingerprint`
reads the embedded table or the cache file, and it makes no request.

**One function of this library reaches the network, and it lives in another package.**
`LookupFingerprintRemote` of `github.com/Crank-Git/ja4plus-go/ja4db` asks the `ja4db.com`
service for one record. A caller reaches it only when it imports that package.

```go
import (
	"context"
	"net/http"
	"time"

	"github.com/Crank-Git/ja4plus-go/ja4db"
)

// lookupRemote asks the ja4db.com service for the record of one fingerprint.
// The caller supplies the client, so the caller owns the timeout.
func lookupRemote(ctx context.Context, fingerprint string) error {
	cfg := &ja4db.RemoteLookupConfig{HTTPClient: &http.Client{Timeout: 10 * time.Second}}

	result, err := ja4db.LookupFingerprintRemote(ctx, cfg, fingerprint)
	if err != nil {
		return err
	}
	_ = result

	return nil
}
```

The command-line program carries its own HTTP client, and `ja4plus db update` downloads the
mapping file. The maintainer ruled the boundary on 2026-08-14, and
`docs/audit/network-boundary.md` holds the record and the reason.

### All-In-One Processor

Runs all 10 fingerprinters on each packet:

```go
proc := ja4plus.NewProcessor()
results, errs := proc.ProcessPacket(packet)
```

## Concurrency

One `Processor` serves one goroutine, and one fingerprinter serves one goroutine. Every
fingerprinter holds state that no lock guards. Two goroutines that share one instance
write a data race. The race detector reports the race. The library does not detect it at
run time.

A caller who wants more than one goroutine takes one of two patterns.

### The sharded pattern

`GetShardKey` returns one key for both directions of one connection, so a packet and its
reply reach one `Processor`. This pattern gives higher throughput, because the per-packet
path acquires no lock.

```go
// processSharded runs one Processor for each shard and returns every result.
// Each goroutine owns its Processor, so no lock guards the per-packet path.
func processSharded(packets []gopacket.Packet, shards int) []ja4plus.FingerprintResult {
	inputs := make([]chan gopacket.Packet, shards)
	outputs := make(chan []ja4plus.FingerprintResult, shards)

	var wg sync.WaitGroup
	for i := range inputs {
		inputs[i] = make(chan gopacket.Packet, 16)

		wg.Add(1)
		go func(in <-chan gopacket.Packet) {
			defer wg.Done()

			proc := ja4plus.NewProcessor()

			var results []ja4plus.FingerprintResult
			for packet := range in {
				got, _ := proc.ProcessPacket(packet)
				results = append(results, got...)
			}

			outputs <- results
		}(inputs[i])
	}

	// GetShardKey holds no state, so the router calls it on its own Processor.
	router := ja4plus.NewProcessor()
	for _, packet := range packets {
		key := router.GetShardKey(packet)
		if key == "" {
			// The packet carries neither a TCP layer nor a UDP layer.
			continue
		}

		inputs[shardIndex(key, shards)] <- packet
	}

	for _, in := range inputs {
		close(in)
	}
	wg.Wait()
	close(outputs)

	var all []ja4plus.FingerprintResult
	for results := range outputs {
		all = append(all, results...)
	}

	return all
}

// shardIndex returns the shard that owns the key. The key holds the sorted five-tuple,
// so a packet and its reply reach one shard and one Processor.
func shardIndex(key string, shards int) int {
	digest := fnv.New32a()
	_, _ = digest.Write([]byte(key))

	return int(digest.Sum32() % uint32(shards))
}
```

### The shared pattern

`SyncProcessor` wraps a `Processor` and serializes every call with one mutex. It costs one
mutex acquisition for each packet. `SyncProcessor` exports `ProcessPacket`, `Reset`,
`CleanupConnection`, `CloseOpenWindows`, `CloseConnectionWindow` and `GetShardKey`, and it
exposes no way to reach the inner `Processor`.

```go
// processShared shares one SyncProcessor between the workers and returns every result.
// The mutex serializes every call, so this pattern gives lower throughput than a shard
// for each goroutine.
func processShared(packets []gopacket.Packet, workers int) []ja4plus.FingerprintResult {
	proc := ja4plus.NewSyncProcessor()

	input := make(chan gopacket.Packet, 16)
	outputs := make(chan []ja4plus.FingerprintResult, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var results []ja4plus.FingerprintResult
			for packet := range input {
				got, _ := proc.ProcessPacket(packet)
				results = append(results, got...)
			}

			outputs <- results
		}()
	}

	for _, packet := range packets {
		input <- packet
	}
	close(input)

	wg.Wait()
	close(outputs)

	var all []ja4plus.FingerprintResult
	for results := range outputs {
		all = append(all, results...)
	}

	return all
}
```

The test file `concurrency_doc_test.go` holds both functions above and runs them, so the
code that this section shows compiles.

## Fingerprint Formats

| Type | Format | Example |
|------|--------|---------|
| JA4 | `{proto}{ver}{sni}{ciphers}{exts}{alpn}_{hash}_{hash}` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `{proto}{ver}{exts}{alpn}_{cipher}_{hash}` | `t130200_1301_a56c5b993250` |
| JA4H | `{method}{ver}{cookie}{ref}{cnt}{lang}_{h}_{h}_{h}` | `ge11cr0800_edb4461d7a83_...` |
| JA4T | `{window}_{options}_{mss}_{wscale}` | `65535_2-4-8-1-3_1460_7` |
| JA4TS | `{window}_{options}_{mss}_{wscale}[_{synack_delays}]` | `14600_2-4-8-1-3_1460_0` |
| JA4L | `JA4L-{C\|S}={latency_us}_{ttl}` | `JA4L-S=2500_56` |
| JA4X | `{issuer}_{subject}_{extensions}` | `a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2` |
| JA4SSH | `c{mode}s{mode}_c{pkts}s{pkts}_c{acks}s{acks}` | `c36s36_c51s80_c69s0` |
| JA4D | `{type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}` | `disco0000in_61-55_1-3-6-42` |
| JA4D6 | `{type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}` | `solct0014nn_1-6-8-25_23-24` |

A JA4TS value carries `synack_delays` only when the server sent two SYN-ACK packets or
more. That part holds the delay of each SYN-ACK after the first, in whole seconds, joined
by `-`. A RST that the server sends on such a connection appends `-R` and the delay of the
RST, which gives `65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6`. One `JA4TSFingerprinter` reads
every packet of the connection, and `ComputeJA4TS` reads one packet and writes four parts.

## Conformance

`make conformance` tests this library against the FoxIO corpus at commit
[`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`](https://github.com/FoxIO-LLC/ja4/tree/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8).
`testdata/foxio.pin` holds that commit, and `make corpus` fetches the corpus at it. The
corpus is FoxIO-licensed material, so this repository tracks the pin and never the
captures.

The suite compares every value this library computes against the FoxIO vector for the
same packet, and it reports one entry for each difference. `testdata/deviations.json` is the register: it holds one entry for each
accepted difference, with the issue that ruled it. The suite fails on a difference that
the register does not hold, and it fails on a register entry whose comparison now
matches.

The run reports these figures, measured on 2026-08-15 UTC at the pinned commit:

| Figure | Count |
|---|---|
| Matches | 1754 |
| Deviations | 2 |
| Accepted deviations | 850 |
| Register keys | 882 |

**The 2 deviations are the two comparisons that the register does not hold**, and each one
awaits a maintainer ruling. They are `ssh2.pcapng/33/JA4L-S` and `tls3.pcapng/25/JA4L-S`.
Issue #675 and issue #686 hold them, so `make conformance` exits 2 on this tree.

**The FoxIO reference decides every disputed value.** Where this library and a FoxIO
vector disagree, this library is wrong. `docs/specs/foxio/` transcribes each FoxIO image
as numbered rules, and every ruling of this project cites one of them.

## Known Limitations

**QUIC multi-packet ClientHello reassembly:** When a QUIC ClientHello is large enough to span multiple QUIC Initial packets (e.g., with many extensions or a pre_shared_key extension), the CRYPTO frame reassembly may not recover the complete handshake message. This can result in a slightly different extension count and hash compared to the Python reference implementation. In practice this affects a small number of QUIC connections with unusually large ClientHellos. TCP/TLS fingerprinting is unaffected.

## Dependencies

- [gopacket](https://github.com/gopacket/gopacket) for packet capture and dissection
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) for QUIC HKDF key derivation
- No cgo required for PCAP file analysis (uses pure Go `pcapgo`)
- Every released binary is built with `CGO_ENABLED=0`. `.goreleaser.yaml` sets it in the
  build environment, and `release_cgo_test.go` guards it. **No workflow of this repository
  sets that variable.** The release workflow runs `go test -race`, the race detector needs
  cgo, and a workflow-level setting would stop that step before it reached the build.
  `TestNoWorkflowSetsCgoEnabled` holds that property. #105 moved the setting on
  2026-08-15 UTC.

## Development

```bash
git clone https://github.com/Crank-Git/ja4plus-go.git
cd ja4plus-go
go test -v -race ./...
```

## Security

Report a vulnerability privately at
<https://github.com/Crank-Git/ja4plus-go/security/advisories/new>. The report reaches the
maintainer, and it reaches no public page. Never open a public issue for a vulnerability.

**Every packet this library reads is untrusted input.** A fingerprinter parses a header
that an attacker writes, so a bounds defect there is reachable from the network. Report a
crash, a hang, an out-of-range read, or a value that escapes its documented format.

Private vulnerability reporting is enabled on this repository, measured 2026-08-15 UTC. A
repository setting moves without a change to this repository, so that sentence carries its
date.

## License

The BSD 3-Clause license in [LICENSE](LICENSE) covers the original Go code, and FoxIO licenses the JA4 method under [LICENSE-JA4](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4).
[FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE) covers JA4S, JA4H, JA4T, JA4TS, JA4L, JA4LS, JA4X, JA4SSH, JA4D and JA4D6, and it permits non-commercial use only.
A commercial user contacts [FoxIO](https://foxio.io) for those methods, and [NOTICE](NOTICE) holds the FoxIO terms.

## Acknowledgments

JA4+ was created by John Althouse at [FoxIO](https://foxio.io). This library is an independent implementation of the published specification. For the original spec and reference implementation, see [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4).

Also see the Python implementation: [github.com/Crank-Git/ja4plus](https://github.com/Crank-Git/ja4plus).
