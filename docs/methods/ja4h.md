# JA4H

**JA4H fingerprints one HTTP request.** The value describes the shape of the request, and
it reads no header value except the cookie fields.

## The value

**One JA4H value holds four parts, and three underscores separate them.** R1 of
`docs/specs/foxio/JA4H.md` holds the reading, and the image example is
`ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74`.

| Part | What it holds | Rules |
|---|---|---|
| a | The method code, the HTTP version, the cookie character, the referer character, the header count and four Accept-Language characters. | R3 to R17 |
| b | A truncated hash of the header names, in wire order. | R18 to R20 |
| c | A truncated hash of the cookie field names, sorted. | R21 and R22 |
| d | A truncated hash of the cookie `name=value` pairs, sorted. | R23 and R24 |

### Part a

**The method code takes two characters, and the HTTP version takes two characters.** R3 and
R5 hold the two fields. **The cookie character is `c` when the request carries a cookie,
and the referer character is `r` when it carries a referer.** R6 and R7 hold the two, and
each one writes `n` otherwise.

**The header count takes two characters, and it counts no `Cookie` header and no `Referer`
header.** R8 quotes the FoxIO text specification:

> 2 digit number of headers, not counting Cookie and Referer. For 3 headers the value is "03".

R9 quotes the cap:

> If there are more than 99, the output is 99.

**The count also excludes an HTTP/2 pseudo-header**, under R11, and the image states no
such rule.

**The four Accept-Language characters read the primary value, which is the text before the
first comma.** R12 and R13 hold it. **The field drops a hyphen and it lowercases a capital
letter**, under R14. **A value shorter than four characters pads with a trailing `0`**,
under R15, and a request with no such header writes `0000` under R16.

### Part b, part c and part d

**Each hash is a SHA-256 truncated to twelve characters**, under R26, and a comma separates
each pair of list values under R25.

**Part b reads header names alone, and it reads no header value.** R20 holds it, and R18
states that the list keeps the wire order.

**Part c and part d each sort their list.** R22 holds part c, and R23 quotes the image
label of part d: `Truncated SHA256 hash of Cookie Fields + Values, sorted`. **R24 holds the
entry form of part d**, which writes the field name, then `=`, then the value.
**A request that
carries no cookie writes `000000000000` in part c and in part d**, under R27, and the image
states no such rule.

## What this library emits

`JA4HFingerprinter` produces the value. `NewJA4H` builds one, and `ProcessPacket` reads
one packet. `ComputeJA4H` reads one packet and returns one value.

**One complete HTTP request produces one result.** The fingerprinter reads a request that
one packet carries, and it reassembles a request that spans several TCP segments.
**The maintainer ruled the emission point at issue #455**, and `parser.HTTPMessageIsComplete`
holds the rule: the value lands when the request is complete, and not when the header block
ends.

**The result carries three forms of the fingerprint.**

| Field | What it holds |
|---|---|
| `Fingerprint` | The JA4H value. |
| `Raw` | `JA4H_r`, the unhashed form with the sorted cookie lists. |
| `RawOriginalOrder` | `JA4H_ro`, the unhashed form with the wire-order cookie lists. |

**The `Type` field holds `ja4h`.**

## Three questions that the FoxIO implementations split on

**The method code of an unusual method.** R3 and R4 record four different answers. The
Wireshark dissector holds a table of 43 methods, the Zeek package holds a table of nine,
and the reference Python lowercases the first two characters of any method.

**The non-alphabetic Accept-Language character.** R17 records two answers.

**Part b of a request that carries no header.** **The maintainer holds this question, and
issue #527 records it.** The four FoxIO implementations split two against two, read on
2026-08-14 at the pinned commit. The reference Python and the Wireshark dissector each
hash the empty string and write `e3b0c44298fc`. The reference Rust and the Zeek package
each write the zero sentinel `000000000000`.

**This library writes the zero sentinel today.** `computeJA4HFromRequest` in `ja4h.go`
calls `parser.TruncatedHash`, which returns `000000000000` for the empty string.
**The question stays open until the maintainer rules it**, and
`docs/audit/ja4h-deviation-cluster.md` holds each reading with its evidence.

## Where the register records a difference

`testdata/deviations.json` holds 36 entries under `JA4H.1`, 103 under `JA4H_r.1` and 109
under `JA4H_ro.1`, measured on this branch. Two rulings cover them.

**Ruling `#441` records a capability decline.**

> #467 records ruling #441, and the library reads TCP alone as testdata/foxio/reference/python/ja4.py:514 does, so this SSDP request over UDP produces no value.

**Ruling `#285` records a disagreement between the two FoxIO vector sets.**

> The two FoxIO vector sets disagree on the JA4H shape, and the maintainer ruled on 2026-08-12 that this library follows the per-stream set.
