---
id: active-scan
feature: Active scan
epic: "Batch #821: JA4TScan"
status: issued
issues: [796]
mockups: []
---

## Purpose

FoxIO names twelve methods, and JA4TScan is the one method that sends packets. The
scanner sends one TCP SYN to a host, and it reads the SYN-ACK and every retransmission of
it. The value describes how the TCP stack of that host answers and how it retransmits.

This project declined JA4TScan on the reading that FoxIO publishes nothing to implement.
FoxIO publishes the scanner at `https://github.com/FoxIO-LLC/ja4tscan`, and commit
`d01bfec4` of that repository falsifies the reading. **The maintainer reversed the decline
on 2026-09-30**, in `Crank-Git/ja4plus#775`. The port shipped the scanner first, in
`Crank-Git/ja4plus#776`, and #796 ports it here.

## Where the requirements live

**This page cites the port, and it copies no requirement.** The port holds the
requirements in `docs/specs/features/12-active-scan.md` at tag `v1.3.0`, as
FR-active-scan-1 to FR-active-scan-25. It holds the transcription of the FoxIO scanner in
`docs/specs/foxio/JA4TScan.md` at the same tag, as rules S1 to S17.
`.claude/rules/ste.md` `### A value of another repository is cited, and never mirrored`
states why this page holds no copy.

**Parity rule 2 makes the port the reference for the interface.** This project shipped no
scanner, so the flags, the defaults and the value form follow the port.

## The rulings

The maintainer ruled six design questions on 2026-09-30, and they bind both repositories.

1. The library changes no firewall state. The command writes the four `iptables` INPUT rules
   of the FoxIO wrapper, or four pf rules on macOS, and it warns when a SYN-ACK arrives with
   no retransmission.
2. The scanner is opt-in and separate. No passive package and no `Processor` imports it.
3. Part a to part d use the JA4TS form. So the FoxIO F5 example writes
   `4380_2-4-8_1460_00_3-6-12`, and the published value is `4380_2-4-8_1460_0_3-6-12`.
4. A target whose first answer carries RST writes `0_rst-ack`. ICMP or no answer writes no
   value.
5. The scanner reads IPv4 alone.
6. The firewall rule text is the four rules of the FoxIO wrapper.

**The maintainer ruled two build questions of this repository on 2026-10-01**, in #796.

| Question | Answer | Test that holds it |
|---|---|---|
| Where the send code lives | `internal/capture/` holds the send primitive, and package `scan` calls it. The socket rule of #613 holds without a change. | `TestNoProductionFileOutsideTheCaptureBackendOpensASocket` |
| The macOS send path | The `libpcap` build tag, as `ja4plus watch` uses. A released binary scans on Linux alone. A macOS build without the tag stops with one line that names the tag. | `TestTheScanOnMacOSWithoutTheTagStatesOneLineThatNamesTheTag` |

**Neither build answer moves a fingerprint value**, so no register row and no port issue
follows them. #796 is the reversal path for both.

## What this project builds

| Part | Where | Port counterpart at `v1.3.0` |
|---|---|---|
| The value | `Value` in `scan/value.go` | `ja4plus/scan/value.py` |
| The SYN frame and the reply reader | `buildSYN` and `parseFrame` in `scan/frames.go` | `ja4plus/scan/frames.py` |
| The scan loop and the state table | `Scanner` in `scan/scanner.go` | `ja4plus/scan/scanner.py` |
| The firewall rules | `FirewallRules` in `scan/firewall.go` | `firewall_rules` of `ja4plus/scan/scanner.py` |
| The link network | `OpenNetwork` in `scan/link.go` | `ja4plus/scan/link.py` |
| The send primitive and the route lookup | `OpenLink` and `LookupRoute` in `internal/capture/` | `scapy` |
| The subcommand | `runScanCommand` in `cmd/ja4plus/scan.go` | `ja4plus/scan/command.py` |

**`Value` gives the responses to a JA4TS fingerprinter**, so one rule writes both methods.
A scan value and the passive JA4TS value of the same SYN-ACK hold the same part a to
part d, and `TestAScanValueHoldsThePartsAToDOfThePassiveJA4TSValue` holds that property.

## Where this project departs from the FoxIO module

The port's register holds one row for each departure, and this project holds the same
answer for each one.

| What | The FoxIO module | This project |
|---|---|---|
| Part b | One `0` for any run of End of Option List bytes, at S6. | One `0` for each such byte. |
| Part d | A zero scale writes `0`, at S8. | A zero scale writes `00`. |
| Part e | A delay of exactly one half second rounds down, at S10. | It rounds away from zero. |
| The reply flags | `ja4tscan/module_ja4tscan.c:310` reads no flag. | The reader accepts SYN and ACK, RST, or RST and ACK, and it drops every other segment. |

## Where this repository differs from the port

Each difference below is a choice of the Go program, and no difference moves a value.

- **The output schema is the schema of this program.** The JSON object holds the fields that
  `ja4plus watch --json` writes, with the `type` value `ja4tscan`. The port writes its own
  eleven-field schema.
- **A refused option exits with status 1**, as every other command of this program does.
  The port exits with status 2, because `argparse` does.
- **A first target that routes through a loopback interface stops the scan.** The port opens
  the socket and warns at each send.
- **A next hop that the neighbor table does not hold gets one address request** on the
  link, as `getmacbyip` of `scapy` sends for the port. The network keeps every other frame
  of that wait for the scan.

## Acceptance criteria

- [x] The value of each of the eight published examples matches, with the F5 example in
      the JA4TS form. `TestTheResponsesOfEachPublishedExampleProduceItsValue`.
- [x] The SYN carries the header values of S2 and the option bytes of S3.
      `TestTheOptionsAreTheFoxIOBytesThenTheTimestampThenOneZeroByte`.
- [x] No passive package imports `scan`. `TestNoPassivePackageImportsTheScanner`.
- [x] No production file runs a firewall command. `TestNoProductionFileRunsAFirewallCommand`.
- [x] No test opens a raw socket. Each case of `scan` and of `cmd/ja4plus` passes a fake
      network.

## Out of scope

- IPv6. The maintainer ruled IPv4 alone on 2026-09-30.
- More than one port in one scan. The FoxIO wrapper scans one port.
- A lookup of a scan value in the FoxIO mapping.
- JA4TScan inside `Processor`, `ja4plus analyze` or `ja4plus watch`.
- Windows. Live capture already excludes it.

Verified against: `https://github.com/FoxIO-LLC/ja4tscan` at `d01bfec4`, through the port's
transcription at tag `v1.3.0`, read on 2026-10-01 UTC.
