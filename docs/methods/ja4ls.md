# JA4LS

**JA4LS measures the server latency of one connection.** It is the server half of the pair
that the [JA4L](ja4l.md) page opens, and the two methods share one Go type.

## No FoxIO image specifies JA4LS

**`JA4L.png` states no server rule, so the reference implementations state every rule of
this method.** R25 to R28 of `docs/specs/foxio/JA4L.md` hold that reading, and each FoxIO
implementation publishes a JA4LS value anyway.

**Three methods of the JA4+ set reach no image of their own name.** JA4LS is one. JA4TS is
the second, and `JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so that image does
specify the schema of JA4TS. JA4TScan is the third, and FoxIO publishes nothing at all for
it.

## The value

**The value takes the shape of a JA4L value, and it measures the other side.** R26 to R28
hold each rule.

| Part | What it holds |
|---|---|
| a | The one-way latency, in microseconds, between the server SYN-ACK and the client SYN. |
| b | The observed time-to-live of the server SYN-ACK. |

**On a QUIC connection part a measures the first server handshake packet against the first
client packet.** The [JA4L](ja4l.md) page names the four measurement points.

## What this library emits

**`JA4LFingerprinter` produces both methods, and no separate type exists for JA4LS.**
`NewJA4L` builds one, and `ProcessPacket` reads one packet.

| What identifies the value | The value |
|---|---|
| The label inside the fingerprint | `JA4L-S` |
| The `Type` field of the result | `ja4l` |

**A caller reads the label to separate JA4LS from JA4L.** The `Type` field holds `ja4l` for
both methods, because one fingerprinter writes both. `emitResult` in `ja4l.go` writes each
label.

**One connection produces one JA4LS value.** A retransmitted SYN-ACK produces no second
value, and a connection whose server measurement point never fills produces no value at
all.

**The value writes two parts on a TCP connection, and three on a QUIC connection.** The
third part holds the protocol marker `quic`.

## Four requirements that carry a provisional amendment

`docs/specs/features/12-ja4ls.md` holds the requirements of this method. **Four of them
carry an amendment that the maintainer has not confirmed.** A later reader reads each one
as unconfirmed, and never as settled.

| Requirement | What it states | Reversal path |
|---|---|---|
| FR-ja4ls-7 | Part b writes the observed time-to-live, and no branch computes a hop count. | Issue #60 |
| FR-ja4ls-8 | Part a is half of the interval, and no propagation factor reaches the value. | Issue #60 |
| FR-ja4ls-11 | `Processor` holds no type filter, and the command-line program holds the filter instead. | Issue #61 |
| FR-ja4ls-22 | The requirement names the per-stream vector set alone. | Issue #63 |

**FR-ja4ls-22 is a scope decision, and never a ruling.** It writes no register entry, and
it states no rule about a fingerprint value.

## Where the register records a difference

**The register keys the two vector sets differently, so JA4LS reaches two key forms.** The
per-stream form is `JA4L-S`, and the per-packet form is `JA4LS.1`. The counts below were
measured on this branch.

| Key | Ruling | Entries |
|---|---|---|
| `JA4L-S` | `#197` | 6 |
| `JA4L-S` | `#361` | 4 |
| `JA4LS.1` | `#196` | 3 |

**One open issue holds the per-packet values that no register entry covers.** Issue #376
records the reading, and `docs/audit/per-packet-ja4l-absence.md` holds the measurement.
