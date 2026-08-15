# The JA4S segment span: the measured cost of a candidate change

**Issue #650 measured cause 6 of `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md` on
2026-08-15.** That page attributed the cost and it measured none. This page builds the
candidate change, it measures the result, and it discards the change.

**The measured net is negative. No candidate change reaches a positive net.** So the
library keeps the behavior it holds today, and this page states the two questions the
maintainer must rule.

## The base

`make conformance` at `5cf4a40`, on 2026-08-15.

| Figure | Value |
|---|---|
| Deviations | 267 |
| Matches | 1754 |
| Register keys | 617 |
| Per-packet deviations | 223 |
| Per-stream deviations | 44 |

**12 unaccepted per-packet JA4S deviations name cause 6**, and this page measured each one.
Every one reads `the vector holds a value the library does not produce`.

| Capture | Frame | Keys |
|---|---|---|
| `browsers-x509.pcapng` | 8 | `JA4S.1`, `JA4S_r.1` |
| `latest.pcapng` | 163 | `JA4S.1`, `JA4S_r.1` |
| `latest.pcapng` | 197 | `JA4S.1`, `JA4S_r.1` |
| `ssh2.pcapng` | 237 | `JA4S.1`, `JA4S_r.1` |
| `ssh2.pcapng` | 259 | `JA4S.1`, `JA4S_r.1` |
| `tls-handshake.pcapng` | 151 | `JA4S.1`, `JA4S_r.1` |

## The candidate change needs no TCP reassembler

**The cluster page states that the work reuses the TCP reassembler, and the measurement
shows that no reassembler reaches the value.** The ServerHello stays whole inside the first
TCP segment. The record that carries it spans several segments, and the record length is
the one field that declines the hello.

`ParseServerHello` in `internal/parser/tls.go` bounds the read on the record length. A TLS
handshake record carries one or more handshake messages, so that field bounds the group and
never the hello.

**The port repaired the same bound in `Crank-Git/ja4plus#151`**, and its measurement names
the segment sizes. On the three streams it read, the ServerHello ends at byte 94, at byte
107 and at byte 98, and each first segment holds 1452 or 1460 bytes.

So the candidate change reads the handshake message length at offset 6, and it bounds every
later read at the end of the hello.

## What the candidate change measured

`make conformance` with the candidate change, on 2026-08-15.

| Figure | Base | Candidate | Move |
|---|---|---|---|
| Deviations | 267 | 291 | +24 |
| Matches | 1754 | 1754 | 0 |
| Per-packet deviations | 223 | 235 | +12 |
| Per-stream deviations | 44 | 56 | +12 |

**The candidate change closes 0 deviations and it opens 24.** No comparison moved from a
deviation to a match, and the match count states that.

### The library computes the FoxIO value exactly

The candidate change produces `t1206h2_c030_044dc9b3196d` on `browsers-x509.pcapng`, and
the per-packet vector holds that same value. **The parse is right, and the value is right.**

### The per-packet cost: the reference publishes on another frame

**The library publishes the value on the frame that carries the ServerHello, and the
Wireshark reference publishes it on the frame that completes the record.** The two frames
differ, and the per-packet comparison is keyed by frame.

| Capture | The library publishes on | The vector holds it on |
|---|---|---|
| `browsers-x509.pcapng` | 6 | 8 |
| `latest.pcapng` | 159 | 163 |
| `latest.pcapng` | 193 | 197 |
| `ssh2.pcapng` | 233 | 237 |
| `ssh2.pcapng` | 255 | 259 |
| `tls-handshake.pcapng` | 149 | 151 |

So each stream reports two deviations in place of one. The frame the vector names still
reads `the vector holds a value the library does not produce`, and the frame the library
names now reads `the library produces a value the vector does not hold`.

**The 12 deviations that the cluster page attributed to cause 6 close only when the library
also selects the reference frame.** That selection is the work a TCP reassembler does, and
it is not the work the bound repair does.

### The per-stream cost is independent of the frame

**The per-stream vector holds no JA4S key for any of the 6 streams**, so the value the
library produces is a surplus on every one.

| Capture | Stream |
|---|---|
| `browsers-x509.pcapng` | 0 |
| `latest.pcapng` | 9 |
| `latest.pcapng` | 10 |
| `ssh2.pcapng` | 11 |
| `ssh2.pcapng` | 12 |
| `tls-handshake.pcapng` | 43 |

Each stream opens `JA4S` and `JA4S_r`, so the per-stream set opens 12 deviations.

**A per-stream value names its stream and it names no frame.** So the frame that publishes
the value moves no per-stream comparison, and these 12 open under every candidate change.

## No candidate change reaches a positive net

**The 12 per-stream deviations are measured, and they open whichever frame publishes the
value.** So the best net that any candidate change reaches is 12 closed against 12 opened.

| Candidate | Per-packet closed | Per-packet opened | Per-stream opened | Net |
|---|---|---|---|---|
| The bound repair, measured | 0 | 12 | 12 | −24 |
| The bound repair with frame selection | 12 | 0 | 12 | 0 |

**The first row is a measurement. The second row is a bound**, because the per-stream figure
of the second row is the measured figure of the first row.

**The rule of #650 declines both.** A net of about zero closes the issue with a register
decline and no code change.

## The two questions the maintainer rules

**Neither question is this session's to answer**, because
`.claude/rules/rulings.md` `## Stop conditions` names the first stop condition: the FoxIO
implementations disagree with each other.

### Question 1 — the register decline of the 12 per-packet deviations

The Wireshark reference publishes a JA4S for each of the 6 streams. The Python reference
publishes none for the same 6 streams. **The two references disagree about whether the value
exists**, and no FoxIO text settles the disagreement.

`docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md` `## What this reading does not answer`
records that nobody has determined the Python reference's reason. It names two facts, and it
states that the two facts do not compose into one reason.

**A register entry records a ruling**, so these 12 entries wait for the maintainer.

### Question 2 — the divergence from the port

**The port holds the bound repair today and this library does not.** `Crank-Git/ja4plus#151`
landed it, and `ja4plus/utils/tls_utils.py` at tag `v1.1.0` reads the handshake message
length.

So the port produces a JA4S on these 6 streams and this library produces none. The port
records that behavior in its own register, at `tests/foxio_deviations.json` of tag `v1.1.0`,
under the keys `browsers-x509.pcapng/JA4S`, `latest.pcapng/JA4S` and `ssh2.pcapng/JA4S`.
Each entry names `Crank-Git/ja4plus#151`.

**The port reached that answer under a rule this repository does not hold.** The port's
`.claude/rules/external-apis.md` reads the FoxIO Rust snapshot as a tie-break at stream
granularity, so a value that the Rust snapshot holds and the Python file omits is a gain
there. **This repository compares against the Wireshark per-packet vectors and the Python
per-stream vectors, and it reads no Rust snapshot.** So one behavior scores as a gain in the
port and as a loss here.

**That divergence is live, and no row of the register in `docs/specs/spec.md` records it.**
`.claude/rules/parity.md` states that a ruling lands in both repositories or in neither, so
the maintainer rules this one.

**This session opened no issue in the port.** The library builds no change, so the change
opens no new parity difference. The divergence that exists today is a gap of this library,
and question 2 states it.

## What this page does not answer

- **Why the Python reference publishes no JA4S for the 6 streams.** This page runs the
  reference never, and it repeats the open question of the cluster page.
- **What a frame-selection candidate change measures.** This page builds no such change. The
  second row of the table above is a bound and never a measurement.
- **Whether the Wireshark reference or the Python reference states the right answer.** That
  is question 1, and the maintainer rules it.
