# JA4TScan

**JA4TScan fingerprints the TCP stack of a host by an active scan.** The scanner sends one
crafted TCP SYN to the host, and it reads the SYN-ACK and every retransmission of it. It is
the one method of this library that sends packets.

**The scanner is opt-in and separate.** Package `scan` holds it, and no fingerprinter and no
`Processor` imports that package. A capture read therefore sends no packet.

## The value

**Part a to part d are the JA4TS parts of the first SYN-ACK.** The [JA4TS](ja4ts.md) page
holds them. The maintainer ruled that form on 2026-09-30, so a scan value and the passive
JA4TS value of the same SYN-ACK hold the same four parts.

**Part e holds the delay of each retransmission**, in whole seconds, and it follows the
JA4TS delay rule. A RST after a retransmission adds `R` and its delay. Part e counts ten
retransmissions and no more.

| What the host sends | The value |
|---|---|
| A SYN-ACK and retransmissions | `64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6`, for example. |
| One SYN-ACK and no retransmission | Part a to part d alone, and a warning. |
| A RST as its first answer | `0_rst-ack`. |
| An ICMP message, or no answer | No value. |

**The F5 Big IP example of FoxIO writes part d as `0`, and this library writes `00`.** A
zero window scale writes `00` in the JA4TS form, so this library writes
`4380_2-4-8_1460_00_3-6-12` for those responses.

## Run a scan

```text
sudo ja4plus scan 203.0.113.0/28 --port 443
```

The target is one IPv4 address, one IPv4 network in CIDR form, or a file that holds one IPv4
address on each line. **The scanner reads IPv4 alone.**

| Option | Default | What it sets |
|---|---|---|
| `--port` | 80 | The TCP port of every target. |
| `--rate` | 10 | The SYN count for each second. |
| `--retransmit` | `yes` | `yes` waits 120 seconds for retransmissions. `no` reads the first answer alone, and it waits 8 seconds. |
| `--format` | `table` | `table`, `json` or `csv`. |
| `--output` | Standard output | A file for the results. `--force` replaces a file that exists. |

## The firewall rules

**The scanner changes no firewall state.** The kernel of the scanning host answers each
SYN-ACK with a RST, and the RST stops the retransmissions that part e reads. So before the
first SYN, the command writes the rules that stop that RST to standard error. The operator
adds them before the scan and removes them after it.

On Linux, the command writes the four `iptables` rules of the FoxIO wrapper and the four
commands that remove them. On macOS, it writes four pf rules. **The last rule drops every
other inbound packet until the operator removes it.**

## Where the scanner runs

| Platform | What the scan needs |
|---|---|
| Linux | The `CAP_NET_RAW` capability. Every released binary scans on Linux. |
| macOS | A build with the `libpcap` build tag, and write access to the `/dev/bpf*` devices. A released binary stops with one line that names the tag. |
| Windows | The scanner sends no packet on Windows. |

**The scanner writes each SYN as an Ethernet frame**, as zmap does. A SYN from a raw IP
socket leaves state in the connection tracker of the host, and the firewall rules then pass
the SYN-ACK to the kernel. `docs/specs/features/17-active-scan.md` states the reading and
its source.

## The source

FoxIO publishes the scanner at `https://github.com/FoxIO-LLC/ja4tscan`, and this library
reads commit `d01bfec4`. The port `Crank-Git/ja4plus` transcribes it at tag `v1.3.0`, and
this library cites that transcription. FoxIO License 1.1 covers the method.
