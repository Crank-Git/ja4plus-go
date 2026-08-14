# JA4L

**JA4L measures the client latency of one connection.** The value describes how far the
client sits from the point of capture, and it reads no content of any packet.

**One Go type writes JA4L and JA4LS.** `JA4LFingerprinter` measures both sides of one
connection, so one state table serves both. The [JA4LS](ja4ls.md) page states the server
half.

## The value

**One JA4L value holds three parts, and one underscore separates each pair of parts.** R1
to R4 of `docs/specs/foxio/JA4L.md` hold the reading, and the image example is
`JA4L=5191_42_45014`.

| Part | What it holds | Rules |
|---|---|---|
| a | The one-way latency, in microseconds. | R5 to R10 |
| b | The observed time-to-live of the client packet. | R11 to R13 |
| c | The one-way application handshake latency. | R14 to R16 |

**Part a is half of the interval between two measurement points.** R6 holds the reading.
**On a TCP connection the two points are the client ACK and the server SYN-ACK**, under R7.
**On a QUIC connection they are the client handshake packet and the last server handshake
packet**, under R8.

**Part b writes the time-to-live that the packet carries, and no step subtracts it from an
initial value.** R11 to R13 hold the reading.

## Two image rules that no FoxIO implementation builds

**The image states an estimated hop count**, under R17, and the formula is
`Estimated Hop Count = Estimated Initial TTL - Observed TTL`. **R18 records that no
reference implementation writes one.**

**The image also states a distance formula and a propagation-delay factor table**, under
R19 to R21. **R22 records that no reference implementation computes a distance.**

**So this library writes neither one.** A value that no FoxIO implementation produces is a
value that no comparison can check.

## What this library emits

`JA4LFingerprinter` produces the value. `NewJA4L` builds one, and `ProcessPacket` reads one
packet. **This library exports no one-shot function for JA4L.** The method reads several
packets, and a one-shot function would export connection state that the concurrency
contract keeps unexported. The maintainer ruled that in issue #356 on 2026-08-13.

**The value carries a label, and the label separates JA4L from JA4LS.**

| Label | Which method | Which side |
|---|---|---|
| `JA4L-C` | JA4L | The client. |
| `JA4L-S` | JA4LS | The server. |

**The `Type` field holds `ja4l` for both labels.** So a caller reads the label of the value
to tell the two methods apart, and it does not read the `Type` field.

**The value writes two parts on a TCP connection, and three on a QUIC connection.** The two
parts are part a and part b of the table above. **The third part of a QUIC value holds the
protocol marker `quic`, and it holds no application handshake latency.** Issue #197 and
issue #127 hold the reading, and `emitResult` in `ja4l.go` writes the marker.

**So this library writes no part c of the image form.** Ruling #127 declines it on a TCP
connection, and R29 of `docs/specs/foxio/JA4L.md` records the reference split behind it.

**The latency is half of the interval, in microseconds, and it never falls below 1.** Go
truncates an integer division toward zero, so a sub-microsecond interval would otherwise
write `0`. Issue #166 records the measurement.

### The QUIC measurement

**The fingerprinter holds four measurement points for a QUIC connection.**

| Point | What fills it |
|---|---|
| A | The first client packet. |
| B | The first server handshake packet. |
| C | The last server handshake packet before point D fills. |
| D | The first client packet after point C fills. |

**A server sends one to five handshake packets, so every server handshake packet moves
point C.** `processUDP` in `ja4l.go` holds that rule. **Point D fills both values at once**,
and the fingerprinter writes the JA4LS value from `B - A` and the JA4L value from `D - C`.

**The fingerprinter reads the direction of a QUIC flow from the UDP port alone.** A flow
whose two ports are both 443, or neither, reaches no value.

## Four questions that the FoxIO implementations split on

**The part count.** R29 records that the Zeek package and the Wireshark dissector write
three parts, and that the reference Rust and the reference Python write two.

**The protocol marker on QUIC.** R31 records four different answers.

**The IPv6 hop limit.** R32 records the split.

**Which packet fills point C.** R33 records that the four implementations differ. Issue
#196 holds it.

## Two questions the maintainer holds today

**Whether a coalesced QUIC datagram fills point C.** Issue #449 records the reading and
parks the question. The Wireshark dissector reads every QUIC packet of a datagram, and the
reference Python and the reference Rust each read the first packet alone. **No line of this
library answers it.**

**Whether the SYN selection rule of issue #126 reaches JA4L.** Issue #543 records the
question, states three candidate answers and recommends no one of them. **The maintainer
holds it**, and `docs/audit/per-packet-ja4l-thirty-uncovered.md` holds the reading.

## Where the register records a difference

**The register keys the two vector sets differently, so JA4L reaches two key forms.** The
per-stream form is `JA4L-C`, and the per-packet form is `JA4L.1`. The counts below were
measured on this branch.

| Key | Ruling | Entries |
|---|---|---|
| `JA4L-C` | `#197` | 7 |
| `JA4L-C` | `#361` | 4 |
| `JA4L.1` | `#196` | 38 |

**Ruling `#196` is the maintainer's, of 2026-08-12.** The [JA4LS](ja4ls.md) page holds the
server half of the same table.
