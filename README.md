A Go library and CLI for JA4+ network fingerprinting. Implements all eight JA4+ methods for identifying and classifying network traffic based on TLS, TCP, HTTP, SSH, and X.509 characteristics. Supports QUIC Initial packet parsing.

JA4+ is a set of network fingerprinting standards created by [FoxIO](https://foxio.io). This library is an independent Go implementation of the published specification. For the original spec, see the [FoxIO JA4+ repository](https://github.com/FoxIO-LLC/ja4).

[![CI](https://github.com/Crank-Git/ja4plus-go/actions/workflows/ci.yml/badge.svg)](https://github.com/Crank-Git/ja4plus-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Crank-Git/ja4plus-go.svg)](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Supported Fingerprint Types

| Type | Protocol | Description |
|------|----------|-------------|
| JA4 | TLS/QUIC | Client fingerprint from ClientHello messages |
| JA4S | TLS/QUIC | Server fingerprint from ServerHello messages |
| JA4H | HTTP | Client fingerprint from request headers and cookies |
| JA4T | TCP | Client OS fingerprint from SYN packets |
| JA4TS | TCP | Server fingerprint from SYN-ACK packets |
| JA4L | TCP/QUIC | Light distance and latency estimation |
| JA4X | X.509 | Certificate structure fingerprint from OID sequences |
| JA4SSH | SSH | Session type classification from traffic patterns |

QUIC Initial packets (RFC 9001/9369) are automatically decrypted to extract TLS ClientHellos.

## Installation

```bash
go get github.com/Crank-Git/ja4plus-go
```

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

# Fingerprint a certificate
ja4plus cert server.der
ja4plus cert server.pem
```

## Go API

### Quick Start

```go
package main

import (
    "fmt"
    "os"

    ja4plus "github.com/Crank-Git/ja4plus-go"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcapgo"
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
```

All fingerprinters share a common interface:

| Method | Description |
|--------|-------------|
| `ProcessPacket(pkt)` | Process a packet, returns `[]FingerprintResult` or nil |
| `Reset()` | Clears all collected state |

### One-Shot Functions

For stateless fingerprinting without maintaining state:

```go
fp := ja4plus.ComputeJA4(packet)
fp := ja4plus.ComputeJA4S(packet)
fp := ja4plus.ComputeJA4H(packet)
fp := ja4plus.ComputeJA4T(packet)
fp := ja4plus.ComputeJA4TS(packet)
fp := ja4plus.ComputeJA4XFromDER(certBytes)
fp := ja4plus.ComputeJA4XFromPEM(pemBytes)
```

Note: JA4L and JA4SSH require multi-packet state and have no one-shot function. Use their fingerprinter constructors instead.

### Fingerprint Lookup

ja4plus-go includes a bundled database of known JA4+ fingerprints from FoxIO's [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv).

```go
result := ja4plus.LookupFingerprint("t13d1516h2_8daaf6152771_02713d6af862")
if result != nil {
    fmt.Println(result.Application) // "Chromium Browser"
}
```

### All-In-One Processor

Runs all 8 fingerprinters on each packet:

```go
proc := ja4plus.NewProcessor()
results, errs := proc.ProcessPacket(packet)
```

## Fingerprint Formats

| Type | Format | Example |
|------|--------|---------|
| JA4 | `{proto}{ver}{sni}{ciphers}{exts}{alpn}_{hash}_{hash}` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `{proto}{ver}{exts}{alpn}_{cipher}_{hash}` | `t130200_1301_a56c5b993250` |
| JA4H | `{method}{ver}{cookie}{ref}{cnt}{lang}_{h}_{h}_{h}` | `ge11cr0800_edb4461d7a83_...` |
| JA4T | `{window}_{options}_{mss}_{wscale}` | `65535_2-4-8-1-3_1460_7` |
| JA4TS | `{window}_{options}_{mss}_{wscale}` | `14600_2-4-8-1-3_1460_0` |
| JA4L | `JA4L-{C\|S}={latency_us}_{ttl}` | `JA4L-S=2500_56` |
| JA4X | `{issuer}_{subject}_{extensions}` | `a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2` |
| JA4SSH | `c{mode}s{mode}_c{pkts}s{pkts}_c{acks}s{acks}` | `c36s36_c51s80_c69s0` |

## Dependencies

- [gopacket](https://github.com/google/gopacket) for packet capture and dissection
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) for QUIC HKDF key derivation
- No cgo required for PCAP file analysis (uses pure Go `pcapgo`)

## Development

```bash
git clone https://github.com/Crank-Git/ja4plus-go.git
cd ja4plus-go
go test -v -race ./...
```

## License

This library is released under the **BSD 3-Clause License**.

The JA4+ fingerprinting specifications were created by [FoxIO](https://foxio.io). JA4 (TLS Client) is open source under BSD-3-Clause per FoxIO. Other JA4+ methods (JA4S, JA4H, JA4T, JA4TS, JA4L, JA4X, JA4SSH) implement FoxIO's specifications under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE), which is permissive for academic, internal business, and security research use.

See [LICENSE](LICENSE) for full details.

## Acknowledgments

JA4+ was created by John Althouse at [FoxIO](https://foxio.io). This library is an independent implementation of the published specification. For the original spec and reference implementation, see [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4).

Also see the Python implementation: [github.com/Crank-Git/ja4plus](https://github.com/Crank-Git/ja4plus).
