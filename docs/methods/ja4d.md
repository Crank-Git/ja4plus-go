# JA4D

**JA4D fingerprints one DHCPv4 message.** The value describes what the client asked the
server for, so it identifies the operating system that built the request.

## The value

**One JA4D value holds three parts, and one underscore separates each pair of parts.** R5
of `docs/specs/foxio/JA4D.md` holds the separator, and the image example is
`JA4D=reqst1500in_55-57-61-51-12_1-121-3-6-15-108-114-119-252`.

| Part | What it holds | Rules |
|---|---|---|
| a | Four fields, concatenated with no delimiter. | R6 to R16 |
| b | The DHCP option list. | R17 to R19 |
| c | The parameter request list. | R20 to R23 |

### Part a holds four fields

| Field | Width | What it holds | Rules |
|---|---|---|---|
| 1 | 5 | The DHCP message type, as a code from a table. | R8 to R10 |
| 2 | 4 | The maximum DHCP message size. | R13 and R14 |
| 3 | 1 | `i` when the client requested a specific address, and `n` otherwise. | R15 |
| 4 | 1 | `d` when the message carries a domain name, and `n` otherwise. | R16 |

**An unknown message type writes five digits, and an absent one writes `00000`.** R9 and
R10 hold the two. **The maximum message size caps at `9999`**, under R13, and an absent one
writes `0000` under R14.

### Part b and part c

**Part b writes the option list, and it ignores four option numbers: 50, 53, 81 and 255.**
R17 to R19 hold the reading. **Part c writes the parameter request list, and it ignores
nothing.** R20 to R23 hold it. **A hyphen separates each pair of values, and an empty list
writes `00`.**

## What this library emits

`JA4DFingerprinter` produces the value. `NewJA4D` builds one, and `ProcessPacket` reads
one packet.

**The fingerprinter holds no state.** `Reset` and `CleanupConnection` each do nothing,
because one message decides one value.

**One DHCPv4 message that carries option 53 produces one result.** The message reaches the
fingerprinter on UDP port 67 or port 68. **The fingerprinter writes one value for each
message, and it aggregates nothing**, which is the rule R24 records for the Zeek package.

**The `Type` field holds `ja4d`.**

## One question this page carries

**The FoxIO implementations split on the skip set of part b.** R25 records it. The Zeek
package skips options 50, 53, 81 and 255, which matches the image. The Wireshark dissector
skips option 0 in place of option 81, and it writes option 255. **This library follows the
Zeek package and the image**, and `dhcpExcludedOptions` in `ja4d.go` holds the set.

## The ruling on field 4 of part a

**The maintainer ruled issue #371 on 2026-08-14.** **The domain name inside option 81
decides the field, and the presence of the option decides nothing.** R16 records the image
label that the ruling reads:

> Has a Domain name (d) or No domain (n)

`wireshark/source/packet-ja4.c:1521` tests the field `dhcp.fqdn.name`, and
`zeek/ja4d/main.zeek:73` tests the presence. **The ruling declines the Zeek answer, because
an image outranks an implementation.** `ProcessPacket` in `ja4d.go` writes `d` when option
81 holds more than 3 bytes, and it writes `n` otherwise.

**No capture of the FoxIO corpus carries an option 81 at all**, and the program of issue
#371 reported `captures=37 dhcpv4_messages=4 option81_occurrences=0 option81_no_name=0`.
**So the ruling moves no fingerprint value of the corpus, and it binds a live capture.**

**Issue #371 is the reversal path**, and the port half is `Crank-Git/ja4plus#615`.

## One defect of the reference that this library declines

**A repeated occurrence of option 57 concatenates in one FoxIO implementation.** R2 gives
field 2 of part a four characters, so one occurrence decides it. **This library declines
that defect**, under FR-parity-51, and the port ruled the same question on 2026-08-08.

## Where the register records a difference

**`testdata/deviations.json` holds no entry whose key names JA4D**, measured on this
branch. So this method carries no accepted difference from a FoxIO value.
