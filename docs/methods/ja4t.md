# JA4T

**JA4T fingerprints one TCP SYN packet.** The value describes the TCP stack of the client,
and it reads no payload. **The image that specifies it titles itself
`JA4T/S: TCP Fingerprint`**, so one image specifies JA4T and [JA4TS](ja4ts.md) together.

## The value

**One JA4T value holds five parts, and one underscore separates each pair of parts.** R4
and R5 of `docs/specs/foxio/JA4T.md` hold the reading, and R3 records the image example
`JA4T=65535_2-1-3-1-1-4_1460_8_1-2-4-8-R6`.

| Part | What it holds | Rules |
|---|---|---|
| a | The TCP window size. | R6 and R7 |
| b | The TCP option kinds, in order. | R8 to R10 |
| c | The TCP maximum segment size. | R11 |
| d | The TCP window scale. | R12 |
| e | The retransmission timings. | R13 to R18 |

**Part a writes the raw window size, and no step applies the window-scale multiplier.**
R6 and R7 hold it.

**Part b writes each option kind, and a hyphen separates each pair.** R8 to R10 hold it.

**Part e carries the retransmission timings, and the image labels it for the scanner
method.** R13 records the image label:

> TCP Retransmission Timings (only on JA4TScan)

**So a JA4T value of this library holds four parts, and it writes no part e.** The
[JA4TS](ja4ts.md) page holds part e, because R16 records that the Zeek package and the
Wireshark dissector each write it on a JA4TS value.

## What this library emits

`JA4TFingerprinter` produces the value. `NewJA4T` builds one, and `ProcessPacket` reads one
packet. `ComputeJA4T` reads one packet and returns one value.

**The fingerprinter holds no state.** `Reset` and `CleanupConnection` each do nothing,
because one packet decides one value.

**The value takes the form `{window}_{options}_{mss}_{wscale}`.**
`generateTCPFingerprint` in `ja4t.go` writes it, and the same function writes the JA4TS
value.

| Field | What the library writes for an absent value |
|---|---|
| The option list | `00` |
| The maximum segment size | Two digits, zero-padded |
| The window scale | `00` |

**The `Type` field holds `ja4t`.**

## Which packet the fingerprinter reads

**The fingerprinter reads a TCP packet that carries the SYN flag and no ACK flag.** It
tests the two flag bits, and it tests no other bit of the flag byte. **So a SYN that also
carries an ECN flag still produces a value.**

**The maintainer ruled that selection at issue #126 on 2026-08-13**, which is the reading
of the reference Rust over the split that R29 records. `ja4t.go` holds the comment, and
`ja4t_syn_selection_test.go` holds the tests. **The measurement that earned the ruling: 2
of 38 captures of the corpus carry an ECN-marked SYN, across 4 packets.**

**The fingerprinter also reads a TCP header that an ICMP error quotes**, under ruling #484,
and `ja4t_icmp_quoted_test.go` holds it.

## Seven questions that the FoxIO implementations split on

`docs/specs/foxio/JA4T.md` records each one.

| What splits | Rule |
|---|---|
| Whether part b writes one entry for each option byte, or skips a pad byte. | R10 |
| How a part e delay rounds. | R24 |
| How a reset delay rounds. | R25 |
| What an empty option list writes. | R26 |
| What a maximum segment size of zero writes. | R27 |
| What a window scale of zero writes. | R28 |
| Whether the SYN selection tests two bits or the whole flag byte. | R29 |

R30 records one more split, and it reaches the reset packet of a JA4TS value.

**The maintainer ruled the option-byte question at issue #297 on 2026-08-12**, and this
library writes one entry for each option byte. The Zeek package is the one outlier.

## Where the register records a difference

**`testdata/deviations.json` holds no entry whose key names JA4T**, measured on this
branch. So this method carries no accepted difference from a FoxIO value.
