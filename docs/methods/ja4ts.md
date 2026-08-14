# JA4TS

**JA4TS fingerprints one TCP SYN-ACK packet.** It is the server half of the pair that the
[JA4T](ja4t.md) page opens, and it adds part e, which holds the retransmission timings.

## One image specifies two methods

**`JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so it specifies the schema of
JA4TS.** R1 and R2 of `docs/specs/foxio/JA4T.md` hold that reading. **The image states no
separate server rule**, so the reference implementations state which packet the method
reads.

## The value

**The value takes the shape of a JA4T value, and it adds part e.** The
[JA4T](ja4t.md) page holds part a to part d.

| Part | What it holds | Rules |
|---|---|---|
| a | The TCP window size of the SYN-ACK. | R6 and R7 |
| b | The TCP option kinds of the SYN-ACK, in order. | R8 to R10 |
| c | The TCP maximum segment size. | R11 |
| d | The TCP window scale. | R12 |
| e | The delay of each SYN-ACK after the first, in whole seconds. | R13 to R18 |

**A hyphen separates each pair of part e delays**, under R14. **A reset writes the letter
`R` before its delay**, under R15. **Part e appears only when a connection carries more
than one SYN-ACK**, under R17.

### Part e holds ten delays

**The image states no count of its own.** R18 records that, and it records the split: the
Zeek package bounds part e at ten delays, and the Wireshark dissector bounds it at nine.

**A deleted FoxIO text specification states the count.**
`docs/specs/foxio/deleted-text-specifications.md` holds it, under the `### JA4T.md`
heading:

> The max is 10 retransmissions counted and the timeout is 2 minutes after the last SYNACK.

**The project manager applied ten under a delegation on 2026-08-13, and the maintainer has
not confirmed it.** Issue #369 records the delegated ruling and it names the reversal path.
**A delegated ruling stays provisional until the maintainer confirms it**, so a reader
reads this count as unconfirmed and never as settled.

## What this library emits

`JA4TSFingerprinter` produces the value. `NewJA4TS` builds one, and `ProcessPacket` reads
one packet. `ComputeJA4TS` reads one packet and returns one value.

**The fingerprinter reads a TCP packet that carries the SYN flag and the ACK flag.** It
holds one state entry for each connection, so it can count the SYN-ACKs after the first
one.

**A packet that carries the RST flag also produces a value**, for a connection that already
sent a SYN-ACK.

**Three constants bound the state.**

| Constant | Value | Why |
|---|---|---|
| `maxJA4TSDelays` | 10 | The count that issue #369 applied. |
| `ja4tsSynAckTimeout` | 120 seconds | The timeout that the FoxIO text specification states. |
| `maxJA4TSConnections` | 1000 | A long run must not grow one map without a bound. |

**The delay rounds to the nearest second, half away from zero.** That is the Wireshark
reading over the split that R24 records, and the maintainer ruled it on 2026-08-13. **The
port already ships that rule**, so a truncation here would have moved a shipped port value.

**The `Type` field holds `ja4ts`.**

## One reading past the ten-delay cap

**A connection that passed the cap reads the eleventh timestamp for its reset delay.**
Issue #369 records that as its second question, and
`TestJA4TS_ReadsTheEleventhSynAckForTheResetDelayPastTheCap` holds the behavior. **No
capture of the FoxIO corpus reaches an eleventh SYN-ACK**, so that test is the one place
the rule is measured.

## Two readings about the reference implementations

**The reference Rust writes no JA4TS value at all.** R21 records it.

**The Zeek package times a connection out after 120 seconds, and it stops at the next
packet from the connection originator.** R22 and R23 record it, and the Wireshark dissector
holds neither rule.

## Where the register records a difference

`testdata/deviations.json` holds four entries under the key `JA4TS.1`, measured on this
branch.

| Ruling | Entries | The reason it records |
|---|---|---|
| `#502` | 3 | Ruling #502 of 2026-08-14 declines a client RST, because `wireshark/source/packet-ja4.c:1600` keys the connection by the stream and `ja4tsConnKey` keys it by the server endpoint. |
| `#503` | 1 | FR-parity-42 makes this library read the reset bit alone, and `wireshark/source/packet-ja4.c:1296` tests the flag byte of frame 119 for equality. |

**R30 records the split behind ruling `#503`.**
