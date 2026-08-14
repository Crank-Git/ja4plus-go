# JA4H: HTTP Client Fingerprint

This page transcribes the FoxIO image that specifies JA4H. **This page records what each
source states, and it decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | [`technical_details/JA4H.png`](https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4H.png) |
| SHA-256 | `08592925d1371d64bf42eeed90506dddf30e4451ba062485ae437abe6c556b80` |
| Image title | `JA4H: HTTP Client Fingerprint` |
| License mark on the image | `Patent Pending` and `FoxIO License 1.1` |
| Text file at the pin | `technical_details/JA4H.md`, 278 bytes |

**This page reproduces no image.** Follow the link above to read it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `python/ja4h.py:13` as line 13 of
`testdata/foxio/reference/python/ja4h.py`. `docs/specs/foxio/README.md` states the rule,
and it names each path that the rule does not cover.

**`technical_details/JA4H.md` builds no fingerprint.** It holds one section, and that
section states the header count rule. R8 below cites it. Every other rule comes from the
image or from a reference implementation.

## What the image states

The image carries one example value. It is verbatim here, and this page rewords no part of
it.

```txt
JA4H=ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74
```

The image labels the four parts `JA4H_a`, `JA4H_b`, `JA4H_c` and `JA4H_d`.

| Part | Value in the image |
|---|---|
| `JA4H_a` | `ge20cr13enus` |
| `JA4H_b` | `974ebe531c03` |
| `JA4H_c` | `b66fa821d02c` |
| `JA4H_d` | `e97928733c74` |

## The rules

- **R1** — One JA4H value holds four parts. One underscore separates each pair of parts.
  The image states this rule, and its example value shows three underscores.
  `python/ja4h.py:77` corroborates.

- **R2** — JA4H fingerprints one HTTP request. The image title states `HTTP Client
  Fingerprint`, and `technical_details/JA4H.md:5` states `JA4H fingerprints the HTTP
  client based on each HTTP request.`.

- **R3** — Part a opens with two characters that name the HTTP method. The image states
  `HTTP Method, GET = “ge”, PUT = “pu”, POST = “po”, etc`. `python/ja4h.py:10`
  corroborates, and `zeek/ja4h/main.zeek:113` corroborates.

- **R4** — **Reference split.** The references derive the two method characters three
  ways, and the three disagree on a method the image does not name.
  - `python/ja4h.py:10` takes the first two characters of the method and lowers their
    case, for every method. `PROPFIND` produces `pr`.
  - `wireshark/source/packet-ja4.c:1087` holds a table of 43 methods whose codes are not
    always the first two characters. `PROPFIND` produces `pf`, and
    `wireshark/source/packet-ja4.c:1104` gives `MKCOL` the code `ml`.
  - `zeek/ja4h/main.zeek:112` holds a table of 9 methods.
  - An unknown method also splits them. `wireshark/source/packet-ja4.c:1138` writes `00`,
    `zeek/ja4h/main.zeek:131` writes nothing, and `python/ja4h.py:10` writes the first two
    characters.

- **R5** — Part a carries a 2-character HTTP version. The image states `HTTP Version, 2.0
  = “20”, 1.1 = “11”`. `python/ja4h.py:32` corroborates, and `zeek/ja4h/main.zeek:135`
  corroborates.

- **R6** — Part a carries one cookie character. The image states `Cookie, if there’s a
  Cookie “c”, if no Cookie “n”`. `python/ja4h.py:18` corroborates, and
  `zeek/ja4h/main.zeek:151` corroborates.

- **R7** — Part a carries one referer character. The image states `Referer, if there’s a
  Referer “r” if no Referer “n”`. `python/ja4h.py:26` corroborates, and
  `zeek/ja4h/main.zeek:156` corroborates.

- **R8** — Part a carries the count of HTTP headers, in 2 characters. The image states
  `Number of HTTP Headers (ignoring Cookie and Referer)`, and
  `technical_details/JA4H.md:9` states `2 digit number of headers, not counting Cookie and
  Referer. For 3 headers the value is "03".`. `python/ja4h.py:55` corroborates.

- **R9** — A header count above 99 produces `99`. **The image alone states no such rule.**
  `technical_details/JA4H.md:10` states `If there are more than 99, the output is 99.`,
  `python/ja4h.py:55` corroborates, and `zeek/ja4h/main.zeek:161` corroborates.

- **R10** — The header count holds no Cookie header and no Referer header. The image
  states it, `python/ja4h.py:49` corroborates, and
  `wireshark/source/packet-ja4.c:1204` corroborates.

- **R11** — The header count holds no HTTP/2 pseudo-header. **The image alone states no
  such rule.** `python/ja4h.py:49` corroborates by removing a name that opens with a
  colon.

- **R12** — Part a ends with four Accept-Language characters. The image states `First 4
  characters of primary Accept-Language (0000 if no Accept-Language)`.
  `python/ja4h.py:14` corroborates.

- **R13** — The Accept-Language value is the primary value, which is the value before the
  first comma. `python/ja4h.py:13` corroborates, and `zeek/ja4h/main.zeek:96`
  corroborates.

- **R14** — The Accept-Language characters carry no hyphen and no upper-case character.
  **The image alone states no such rule.** `python/ja4h.py:13` corroborates, and
  `zeek/ja4h/main.zeek:97` corroborates.

- **R15** — An Accept-Language value shorter than four characters gains trailing `0`
  characters. **The image alone states no such rule.** `python/ja4h.py:15` corroborates,
  and `wireshark/source/packet-ja4.c:498` corroborates.

- **R16** — No Accept-Language header produces `0000`. The image states it, and
  `python/ja4h.py:75` corroborates.

- **R17** — **Reference split.** A non-alphabetic character inside the Accept-Language
  value produces two different results.
  - `wireshark/source/packet-ja4.c:488` writes the two hexadecimal characters of the byte,
    and it counts them as two of the four characters.
  - `python/ja4h.py:13` keeps the character, and it removes only a hyphen and a semicolon.

- **R18** — Part b is a SHA-256 hash of the header names. The image states `Truncated
  SHA256 hash of Headers, in the order they appear`. `python/ja4h.py:76` corroborates.

- **R19** — The header name list keeps the order of the request, and no sort applies to
  it. The image states `in the order they appear`, and
  `wireshark/source/packet-ja4.c:1208` corroborates by appending in dissection order.

- **R20** — The header name list holds no header value. `python/ja4h.py:47` corroborates
  by keeping the text before the first colon.

- **R21** — Part c is a SHA-256 hash of the cookie field names. The image states
  `Truncated SHA256 hash of Cookie Fields, sorted`. `python/ja4h.py:72` corroborates.

- **R22** — The cookie field name list is sorted. The image states `sorted`,
  `python/ja4h.py:68` corroborates, and `zeek/ja4h/main.zeek:175` corroborates.

- **R23** — Part d is a SHA-256 hash of the cookie field names and their values. The image
  states `Truncated SHA256 hash of Cookie Fields + Values, sorted`.
  `python/ja4h.py:73` corroborates.

- **R24** — Each entry of the part d list holds the field name, then `=`, then the value.
  **The image alone states no such rule.** `wireshark/source/packet-ja4.c:531`
  corroborates, and `zeek/ja4h/main.zeek:86` corroborates.

- **R25** — A comma separates each pair of entries in every JA4H list.
  `python/common.py:127` corroborates, and `wireshark/source/packet-ja4.c:530`
  corroborates.

- **R26** — A hash part holds the first 12 characters of the SHA-256 hash. The image
  states `Truncated`, and it states no length. `python/common.py:127` corroborates, and
  `wireshark/source/packet-ja4.c:639` corroborates with the format `%12.12s`.

- **R27** — A request that carries no cookie produces the zero sentinel `000000000000` in
  part c and in part d. **The image alone states no such rule.** `python/ja4h.py:72`
  corroborates, `python/ja4h.py:73` corroborates, and
  `wireshark/source/packet-ja4.c:637` corroborates.

- **R28** — An empty header list reaches part b as a hash, and never as the zero sentinel.
  **R18 names no sentinel, and R27 confines the sentinel to part c and to part d.** The
  hash of the empty string is `e3b0c44298fc`. **The implementations split two against
  two.** `python/ja4h.py:76` and `wireshark/source/packet-ja4.c:629-630` hash the empty
  string, and `wireshark/source/packet-ja4.c:641` writes that hash into the value.
  `rust/ja4/src/lib.rs:184` and `zeek/utils/common.zeek:64` return the sentinel. **The
  maintainer ruled the split on 2026-08-14**, and a rank 1 image rule outranks an
  implementation. **Issue #527 is the reversal path**, and the port half is
  `Crank-Git/ja4plus#612`.

## Readings this page records

A reading is a conclusion about a source. None of these carries a rule.

- **Reading 1** — **The Wireshark dissector carries a preference that removes the two zero
  sentinels of R27.** `wireshark/source/packet-ja4.c:74` declares
  `pref_omit_ja4h_zero_sections`, and `wireshark/source/packet-ja4.c:637` writes an empty
  string instead of `000000000000` when an operator sets it. The default is `false`, so
  the default output holds the zero sentinel and matches R27.

- **Reading 2** — **The Zeek package maps one HTTP version that the image does not name.**
  `zeek/ja4h/main.zeek:141` maps HTTP `3.0` to `30`. `python/ja4h.py:36` derives the same
  two characters from the version string, so the two agree without a shared table.

- **Reading 3** — **The example value of the image holds the Accept-Language value
  `enus`.** Part a is `ge20cr13enus`: `ge`, `20`, `c`, `r`, `13`, `enus`. R14 explains why
  the value holds no hyphen.
