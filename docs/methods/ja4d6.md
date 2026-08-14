# JA4D6

**JA4D6 fingerprints one DHCPv6 message.** It takes the shape of a [JA4D](ja4d.md) value,
and three of its fields read different sources.

## One FoxIO implementation builds it

**The Wireshark dissector is the one FoxIO implementation of JA4D6.**
`docs/specs/foxio/JA4D6.md` records the reading, and it states the consequence:

> No reference split can exist on this page, because two implementations cannot disagree.

**The Zeek package states that it awaits DHCPv6 support.** The reference Rust and the
reference Python each build nothing for this method.

## The value

**One JA4D6 value holds three parts, and one underscore separates each pair of parts.** R4
to R6 hold the reading, and the image example is
`JA4D6=solct0014nn_8-1-3-39-16-6_17-23-24-39`.

| Part | What it holds | Rules |
|---|---|---|
| a | Four fields, concatenated with no delimiter. | R7 to R18 |
| b | The DHCPv6 option list. | R19 to R22 |
| c | The option request list. | R23 to R25 |

### Part a holds four fields

| Field | Width | What it holds | Rules |
|---|---|---|---|
| 1 | 5 | The DHCPv6 message type, as a code from a table of 37 entries. | R7 to R10 |
| 2 | 4 | The length of the client identifier. | R11 to R16 |
| 3 | 1 | `i` when the message carries an identity association for a temporary address. | R17 |
| 4 | 1 | `d` when the message carries a client domain, and `n` otherwise. | R18 |

**Field 2 is the one field whose meaning differs from JA4D.** JA4D holds the maximum
message size there, and JA4D6 holds the client identifier length. **The field reads DHCPv6
option 1 alone, and the first occurrence decides it**, under R11 to R16. **It caps at
`9999`, and an absent value writes `0000`.**

### Part b differs from JA4D

**JA4D names four options to ignore, and JA4D6 names none.** R20 holds that sentence.
**A hyphen separates each pair of values in part b and in part c, and an empty list writes
`00`.**

## What this library emits

`JA4D6Fingerprinter` produces the value. `NewJA4D6` builds one, and `ProcessPacket` reads
one packet.

**The fingerprinter holds no state.** `Reset` and `CleanupConnection` each do nothing.

**One DHCPv6 message produces one result.** The message reaches the fingerprinter on UDP
port 546 or port 547.

**The `Type` field holds `ja4d6`.**

### The nested option walk

**A DHCPv6 message nests options inside containers, and this library descends into each
one.** `walkDHCPv6Options` in `ja4d6.go` reads these containers.

| Container | Option number |
|---|---|
| Identity association for non-temporary addresses | 3 |
| Identity association for temporary addresses | 4 |
| Address | 5 |
| Relay message | 9 |
| Identity association for prefix delegation | 25 |
| Prefix | 26 |

**A bound of 32 levels stops the descent.** A crafted message can nest a container without
a bound, so the walk needs a limit that the packet does not choose.

**Issue #370 widened the descent on 2026-08-14.** Before that change the walk descended
into the relay message alone. **Field 3, field 4, part b and part c now read every
container above.** `TestJA4D6ReadsASubfieldOptionOfANestedContainer` holds the behavior.

**Field 1 still writes the message type of the outer message.** `ProcessPacket` in
`ja4d6.go` reads it, and no inner message changes it.

## How the conformance suite compares this method

**The Wireshark dissector publishes JA4D and JA4D6 under one field name, `ja4.ja4d`.** R26
and R27 record it. **So the FoxIO corpus holds no value under a JA4D6 name**, and the
conformance suite compares a JA4D6 value under the method JA4D. FR-conformance-25 states
that rule.

## Where the register records a difference

**`testdata/deviations.json` holds no entry whose key names JA4D6**, measured on this
branch. So this method carries no accepted difference from a FoxIO value.
