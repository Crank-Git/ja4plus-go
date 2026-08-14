# JA4S

**JA4S fingerprints one TLS server hello.** The value describes what the server chose from
what the client offered, so it pairs with the [JA4](ja4.md) value of the same connection.

## The value

**One JA4S value holds three parts, and one underscore separates each pair of parts.** R1
of `docs/specs/foxio/JA4S.md` holds the reading, and the image example is
`t120400_c030_4e8089b08790`.

| Part | What it holds | Rules |
|---|---|---|
| a | The protocol character, the TLS version, the extension count and two ALPN characters. | R3 to R14 |
| b | The one cipher suite that the server chose. | R15 to R17 |
| c | A truncated hash of the server extension list. | R18 to R23 |

**FoxIO publishes no text specification for JA4S, so the image is the one FoxIO source for
the schema.** `docs/specs/foxio/JA4S.md` records that absence.

### Part a

**The protocol character and the version map are the ones that JA4 uses.** R3, R4 and R5
hold that sharing. **The version reads the highest value of the server
`supported_versions` extension**, under R6 and R7.

**The extension count takes two characters, and it caps at `99`.** R8 and R9 hold it.

**The two ALPN characters are the first character and the last character of the chosen
ALPN value**, under R11 and R12. **A server that chose no ALPN value writes `00`**, under
R13.

### Part b differs from JA4

**Part b holds one cipher suite as four lowercase hex characters, and it hashes nothing.**
R15 to R17 hold the reading. **A server chooses one cipher suite, so the part needs no
list and no hash.**

### Part c differs from JA4 in two ways

**The extension list keeps the wire order, and no step sorts it.** R19 holds it.
**The list includes the server-name extension and the ALPN extension**, under R20, and the
JA4 part c excludes both. **An empty list writes the zero sentinel `000000000000`**, under
R23.

## What this library emits

`JA4SFingerprinter` produces the value. `NewJA4S` builds one, and `ProcessPacket` reads
one packet. `ComputeJA4S` reads one packet and returns one value.

**One TLS server hello over TCP produces one result.** A QUIC server initial packet also
produces one result, and the fingerprinter matches it against the client destination
connection identifier that it stored earlier.

**The result carries two forms of the fingerprint.**

| Field | What it holds |
|---|---|
| `Fingerprint` | The JA4S value. |
| `Raw` | `JA4S_r`, the unhashed form with the wire order. |

**`RawOriginalOrder` stays empty for JA4S.** FoxIO publishes `JA4S_r` and it publishes no
`JA4S_ro`, so the `_r` suffix already names the wire order here. Issue #275 records the
measurement, and `computeJA4SPair` in `ja4s.go` holds the rule.

**The `Type` field holds `ja4s`.**

## One question that the FoxIO implementations split on

**The GREASE values of the extension count and the extension list.** R10 records that the
reference Python and the reference Rust keep them, and that the Wireshark dissector and the
Zeek package remove them. **This library keeps them**, and `computeJA4SPair` in `ja4s.go`
states that difference from JA4.

**R14 records the same ALPN split that the [JA4](ja4.md) page states.**

## Where the register records a difference

`testdata/deviations.json` holds 34 entries under `JA4S` and 34 under `JA4S_r`, measured on
this branch. **29 of each 34 sit under ruling `#42`**, for the same QUIC reason that the
[JA4](ja4.md) page quotes.

**The other 5 of each 34 sit under ruling `#387`**, and each one records this reason:

> The stream carries a HelloRetryRequest and a ServerHello, so the library emits a second JA4S value that the per-stream vector does not hold.
