# JA4

**JA4 fingerprints one TLS client hello.** The value describes how the client offered to
negotiate, so two connections from one client library produce one value.

**JA4 is the one method of this library that FoxIO licenses under BSD 3-Clause.** Every
other method carries the FoxIO License 1.1 terms that the licensing page states.

## The value

**One JA4 value holds three parts, and one underscore separates each pair of parts.** R1 of
`docs/specs/foxio/JA4.md` holds the reading, and the image example is
`t13d1516h2_acb858a92679_e5627efa2ab1`.

| Part | What it holds | Rules |
|---|---|---|
| a | The protocol character, the TLS version, the server-name character, the cipher-suite count, the extension count and two ALPN characters. | R2 to R19 |
| b | A truncated hash of the cipher-suite list, sorted. | R20 to R24 |
| c | A truncated hash of the extension list and the signature-algorithm list. | R25 to R31 |

### Part a

**The protocol character is `t` for TCP and `q` for QUIC.** R2 holds the image label. R3
records that a DTLS client hello produces `d`, and the image states no such rule.

**The TLS version is two characters, and it reads the highest value of the
`supported_versions` extension.** R7 and R8 hold the reading. R6 states that an unmapped
version writes `00`.

**The server-name character is `d` when the client sent a server name, and `i` when it did
not.** R9 holds it.

**The cipher-suite count and the extension count each take two characters, and each one
caps at `99`.** R10 to R15 hold the two counts. **Neither count reads a GREASE value.**
RFC 8701 defines GREASE. **The extension count includes the server-name extension and the
ALPN extension**, and part c excludes both from its list under R26.

**The two ALPN characters are the first character and the last character of the first ALPN
value.** R16 holds it, and R17 states that a client with no ALPN value writes `00`.

### Part b and part c

**Each hash is a SHA-256 truncated to twelve characters.** R23 holds the width, and the
image states `Truncated` and no length.
**A list writes each value as four lowercase hex characters, and a comma separates each
pair.** R21 and R22 hold the form.

**The cipher-suite list of part b is sorted, and the extension list of part c is sorted.**
The signature-algorithm list of part c keeps the packet order, and R28 holds that
difference. **An empty list writes the zero sentinel `000000000000`**, under R24 and R30.

## What this library emits

`JA4Fingerprinter` produces the value. `NewJA4` builds one, and `ProcessPacket` reads one
packet. `ComputeJA4` reads one packet and returns one value, for a caller that holds no
connection state.

**One TLS client hello over TCP produces one result, and one QUIC initial packet produces
one result.** The QUIC path reassembles the CRYPTO frames of the client hello before it
reads the message, so a client hello that spans several packets reaches one value.

**The result carries four forms of the fingerprint.**

| Field | What it holds |
|---|---|
| `Fingerprint` | The JA4 value. |
| `Raw` | `JA4_r`, the unhashed form with the sorted lists. |
| `OriginalOrder` | `JA4_o`, the hashed form with the packet order. |
| `RawOriginalOrder` | `JA4_ro`, the unhashed form with the packet order. |

**The `Type` field holds `ja4`.**

## Two questions that the FoxIO implementations split on

**The one-character ALPN value.** R18 records four different answers across the FoxIO
implementations. **The non-ASCII first ALPN byte.** R19 records three.

**The maintainer ruled the `JA4_o` zero sentinel on 2026-08-12, in issue #287.** Where the
sorted extension string is empty, this library follows the reference Python.
`computeJA4OriginalOrder` in `ja4.go` holds the ruling.

## Where the register records a difference

`testdata/deviations.json` holds 48 entries under each of the keys `JA4`, `JA4_r`, `JA4_o`
and `JA4_ro`, measured on this branch. **Every one of the 192 sits under ruling `#42`**, and
each one records one reason:

> The FoxIO Python implementation reads no QUIC handshake, so its expected-output file omits the stream.

**So the difference describes the reference vector set, and it describes no defect of this
library.**
