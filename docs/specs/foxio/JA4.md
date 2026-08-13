# JA4: TLS Client Fingerprint

This page transcribes the FoxIO image that specifies JA4. **This page records what each
source states, and it decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | [`technical_details/JA4.png`](https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4.png) |
| SHA-256 | `1bd63c14b3b96c2b70bfa8e85632450c9396af9a13e274489c0cb02f2a7e9615` |
| Image title | `JA4: TLS Client Fingerprint` |
| License mark on the image | `BSD 3-Clause License` |
| Text specification at the pin | `technical_details/JA4.md`, 9153 bytes |

**This page reproduces no image.** Follow the link above to read it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `python/ja4.py:220` as line 220 of
`testdata/foxio/reference/python/ja4.py`. `docs/specs/foxio/README.md` states the rule,
and it names each path that the rule does not cover.

JA4 is the one method that holds a complete text specification at the pinned commit. The
source ranking puts the image first and the text second. A rule below cites the image
where the image states it. It cites `technical_details/JA4.md` where the image is silent.

## What the image states

The image carries one example value. It is verbatim here, and this page rewords no part of
it.

```txt
JA4=t13d1516h2_acb858a92679_e5627efa2ab1
```

The image labels the three parts `JA4_a`, `JA4_b` and `JA4_c`.

| Part | Value in the image |
|---|---|
| `JA4_a` | `t13d1516h2` |
| `JA4_b` | `acb858a92679` |
| `JA4_c` | `e5627efa2ab1` |

## The rules

- **R1** — One JA4 value holds three parts. One underscore separates each pair of parts.
  The image states this rule, and its example value shows two underscores.
  `python/ja4.py:290` corroborates.

- **R2** — Part a opens with one protocol character. The image states `Protocol, TCP = “t”
  QUIC = “q”`. `python/ja4.py:220` corroborates, and `rust/ja4/src/tls.rs:481`
  corroborates.

- **R3** — A DTLS client hello produces the protocol character `d`. **The image states no
  DTLS character.** `technical_details/JA4.md:54` states it, and
  `wireshark/source/packet-ja4.c:731` corroborates.

- **R4** — Part a carries a 2-character TLS version. The image states `TLS version, 1.2 =
  “12”, 1.3 = “13”`. `python/common.py:16` corroborates.

- **R5** — The version map holds nine values. **The image states two of them.**
  `technical_details/JA4.md:60` states the full map, and
  `wireshark/source/packet-ja4.c:76` corroborates it.

- **R6** — A version the map does not hold produces `00`. **The image alone states no
  such rule.** `technical_details/JA4.md:70` states it, `rust/ja4/src/tls.rs:535`
  corroborates, and `zeek/ja4/main.zeek:104` corroborates.

- **R7** — When the supported_versions extension is present, the version is the highest
  value that extension carries. **The image alone states no such rule.**
  `technical_details/JA4.md:58` states it, `python/ja4.py:265` corroborates, and
  `rust/ja4/src/tls.rs:559` corroborates.

- **R8** — The highest-value search of R7 skips a GREASE value. `python/common.py:154`
  corroborates, and `rust/ja4/src/tls.rs:560` corroborates.

- **R9** — Part a carries one SNI character. The image states `SNI, SNI = “d” (to domain),
  no SNI = “i” (to IP)`. `python/ja4.py:263` corroborates, and `rust/ja4/src/tls.rs:319`
  corroborates.

- **R10** — Part a carries the count of cipher suites, in 2 characters. The image states
  `Number of Cipher Suites`. `python/ja4.py:255` corroborates through
  `python/common.py:149`.

- **R11** — A cipher suite count above 99 produces `99`. **The image alone states no such
  rule.** `technical_details/JA4.md:78` states it, `python/common.py:141` corroborates,
  and `rust/ja4/src/tls.rs:325` corroborates.

- **R12** — The cipher suite count skips a GREASE value. **The image alone states no such
  rule.** `technical_details/JA4.md:78` states it, `python/common.py:140` corroborates,
  and `zeek/ja4/helpers.zeek:59` corroborates.

- **R13** — Part a carries the count of extensions, in 2 characters. The image states
  `Number of Extensions`. `python/ja4.py:229` corroborates.

- **R14** — The extension count holds the SNI extension and the ALPN extension. **The
  image alone states no such rule.** `technical_details/JA4.md:82` states it, and
  `rust/ja4/src/tls.rs:326` corroborates by counting before it removes the two.

- **R15** — The extension count skips a GREASE value. `python/ja4.py:229` corroborates,
  and `zeek/ja4/helpers.zeek:83` corroborates.

- **R16** — Part a ends with two ALPN characters. They are the first character and the
  last character of the first ALPN value. The image states `First ALPN value (00 if no
  ALPN)`. `python/ja4.py:277` corroborates, and `zeek/ja4/main.zeek:86` corroborates.

- **R17** — No ALPN extension produces `00`. The image states it, and
  `zeek/ja4/main.zeek:84` corroborates.

  **The prose also names an empty first ALPN value, and it gives the same `00`.**
  `technical_details/JA4.md:92` covers three inputs in one sentence, and this is the
  verbatim text:

  > If there is no ALPN extension, no ALPN values, or the first ALPN value is empty, then we
  > print "00" as the value in the fingerprint.

  **So a FoxIO source does state the empty case.** `docs/specs/spec.md` R9 question 1 asked
  what an empty first ALPN value writes, and the maintainer ratified `00` on 2026-08-11 from
  the two implementations alone. This prose sentence corroborates that answer.
  `internal/parser/tls.go` writes `00` for the input. Issue #50 records the reading and
  changes no line of the behaviour.

- **R18** — **Reference split.** An ALPN value of one character produces three different
  results. The image states no rule for it.
  - `technical_details/JA4.md:93` states that the one character serves as both the first
    character and the last character.
  - `zeek/ja4/main.zeek:86` produces the same two characters, because `[0]` and `[-1]`
    reach the same character.
  - `wireshark/source/packet-ja4.c:552-554` produces the same two characters. It reads the
    first character of the stored value, and it reads the character at the last index.
  - `rust/ja4/src/tls.rs:625` reads no last character, and `rust/ja4/src/tls.rs:334`
    then writes `0` in its place.
  - `python/ja4.py:276` leaves the value at one character, so part a is one character
    short.

- **R19** — **Reference split.** An ALPN value whose first byte is not an ASCII
  alphanumeric character produces four different results.
  - `technical_details/JA4.md:95` states the first and last characters of the hexadecimal
    form of the whole first ALPN value.
  - `python/ja4.py:279-280` writes `99` when the first byte is above 127.
  - `wireshark/source/packet-ja4.c:1027-1028` writes `99` when the first byte is not an
    ASCII alphanumeric character.
  - `rust/ja4/src/tls.rs:616` replaces each non-ASCII character with `9`, one character at
    a time.

  **The four results agree on two inputs, and Reading 5 states the measurement.** The two
  implementations agree on every input whose first byte and last byte fall inside
  `0x20-0x7E`. They also agree on an input whose two bytes fall outside ASCII. The FoxIO
  vector `python/test/testdata/tls-non-ascii-alpn.pcapng.json` reaches the second case, and
  it holds `99`.

  **The prose rule and the FoxIO vector contradict each other.** `technical_details/JA4.md:95`
  states the rule, and `technical_details/JA4.md:97-100` states four examples of it. The
  prose states `ad` for the first ALPN value `0xAB 0xCD`. **The prose states no example for
  `0xba 0xad`**, and its rule computes `bd` for that input. The FoxIO vector holds `99` for
  it.

  **No function of the bytes satisfies both values.** Each of the two inputs holds two bytes.
  Every byte of each input falls outside the alphanumeric ranges. So no rule that reads the
  bytes gives `ad` for one input and `99` for the other.

- **R20** — Part b is a SHA-256 hash of the cipher suite list. The image states `Truncated
  SHA256 hash of the Cipher Suites, sorted`. `python/ja4.py:255` corroborates through
  `python/common.py:149`, and `rust/ja4/src/tls.rs:362` corroborates.

- **R21** — The cipher suite list is sorted by hexadecimal value, in ascending order.
  `technical_details/JA4.md:118` states it, `python/common.py:147` corroborates, and
  `rust/ja4/src/tls.rs:338` corroborates.

- **R22** — Each list entry is a 4-character lower-case hexadecimal value, and a comma
  separates each pair. `technical_details/JA4.md:108` states it, and
  `rust/ja4/src/tls.rs:342` corroborates.

- **R23** — A hash part holds the first 12 characters of the SHA-256 hash. The image
  states `Truncated`, and it states no length. `technical_details/JA4.md:31` states 12,
  `python/common.py:127` corroborates, and `rust/ja4/src/lib.rs:188` corroborates.

- **R24** — An empty cipher suite list produces the zero sentinel `000000000000`. **The
  image alone states no such rule.** `technical_details/JA4.md:121` states it,
  `python/ja4.py:259` corroborates, and `zeek/utils/common.zeek:64` corroborates.

- **R25** — Part c is a SHA-256 hash of the extension list, then one underscore, then the
  signature algorithm list. The image states `Truncated SHA256 hash of the Extensions,
  sorted + Signature Algorithms, in the order they appear`.
  `python/ja4.py:245` corroborates.

- **R26** — The extension list of part c holds no SNI extension and no ALPN extension.
  **The image alone states no such rule.** `technical_details/JA4.md:128` states it,
  `python/common.py:145` corroborates, `rust/ja4/src/tls.rs:328` corroborates, and
  `zeek/ja4/main.zeek:141` corroborates.

- **R27** — The extension list of part c is sorted by hexadecimal value.
  `technical_details/JA4.md:139` states it, and `rust/ja4/src/tls.rs:339` corroborates.

- **R28** — The signature algorithm list keeps the order of the packet, and no sort
  applies to it. The image states `in the order they appear`, and
  `rust/ja4/src/tls.rs:344` corroborates.

- **R29** — An empty signature algorithm list ends the hashed string with no underscore.
  **The image alone states no such rule.** `technical_details/JA4.md:169` states it,
  `python/ja4.py:241` corroborates, and `rust/ja4/src/tls.rs:347` corroborates.

- **R30** — An empty extension list produces the zero sentinel `000000000000`.
  `technical_details/JA4.md:176` states it, `python/ja4.py:252` corroborates, and
  `rust/ja4/src/lib.rs:185` corroborates.

- **R31** — The signature algorithm list skips a GREASE value. **The image alone states no
  such rule.** `python/common.py:211` corroborates, and `technical_details/JA4.md:40`
  states the general GREASE rule that covers it.

## Readings this page records

A reading is a conclusion about a source. None of these carries a rule.

- **Reading 1** — **The example value in the image mixes two renderings.** The image
  labels part b `sorted`, and its part b is `acb858a92679`. The FoxIO vector
  `python/test/testdata/browsers-x509.pcapng.json:13` gives the sorted value
  `t13d1516h2_8daaf6152771_e5627efa2ab1` for the same client.
  `python/test/testdata/browsers-x509.pcapng.json:15` gives `acb858a92679` as the part b
  of `JA4_o`, which is the original-order rendering. `technical_details/JA4.md:194` and
  `technical_details/JA4.md:219` state the same two values. **The rules the image states
  are unaffected.** No implementation produces the composite value the image shows.

- **Reading 2** — **The Wireshark dissector produces no JA4 client value at the pin.**
  `wireshark/source/packet-ja4.c:1723` registers `JA4S`, `JA4X`, `JA4H`, `JA4L`, `JA4LS`,
  `JA4SSH`, `JA4T`, `JA4TS` and `JA4D`, and it registers no `JA4` field. The dissector
  therefore corroborates a JA4 rule only where it shares code with another method, as R3
  and R19 above show.

- **Reading 3** — **The image carries the mark `BSD 3-Clause License`, and every other
  image of this directory carries `Patent Pending` and `FoxIO License 1.1`.** `NOTICE`
  holds the terms. `docs/specs/features/01-licensing.md` states how this project records
  the split.

- **Reading 4** — **Two implementations read the QUIC protocol character from different
  input.** `python/ja4.py:220` reads the packet layer that carried the client hello.
  `rust/ja4/src/tls.rs:318` reads the presence of the `quic_transport_parameters`
  extension, which `rust/ja4/src/tls.rs:493` numbers 57. `zeek/ja4/main.zeek:66` reads the
  transport protocol and the service name. The three agree on every capture this project
  reads, so this page records no reference split for it.

- **Reading 5** — **Neither implementation reads the ALPN byte the packet holds, and the
  tshark text form is the cause.** This reading holds FR-parity-12 of
  `docs/specs/features/08-python-parity.md`. Both implementations read the tshark field
  `tls.handshake.extensions_alpn_str`, which carries text and not bytes.
  `python/ja4.py:270` reads it as `alpn_list`, and `rust/ja4/src/tls.rs:188` reads it
  through `first`. R18 and R19 above record the results, and this reading records why they
  differ.

  - **FoxIO Python writes `U+FFFD`.** tshark writes the Unicode replacement character for
    a byte it cannot decode, and `python/ja4.py:277` copies that character into the field.
    `python/ja4.py:279` tests `ord(alpn[0]) > 127` and therefore tests the first character
    alone, so the replacement character reaches the fingerprint from the last position.
  - **FoxIO Rust writes the `tshark` escape text.** `rust/ja4/src/tls.rs:615` reads the
    field as a character sequence, so it reads a control byte as the escape text tshark
    writes. It reads the two-byte value `h\x1f` as the five characters `h`, `\`, `x`, `1`
    and `f`. `rust/ja4/src/tls.rs:624-625` then writes the first character and the last
    character of those five, which is `hf`. `rust/ja4/src/tls.rs:638-645` holds the FoxIO
    test that asserts the replacement character maps to `9`.
  - **The measurement.** The port measured both implementations at the pinned commit
    `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, against a capture it built for the purpose.
    `Crank-Git/ja4plus#141` records the commands and the table, and
    `Crank-Git/ja4plus#162` records the maintainer ruling of 2026-08-07.
    **`U+FFFD` is no byte of the packet, and `\`, `x`, `1` and `f` are no bytes of the
    packet.** So a byte outside `0x20-0x7E` in a position other than the first reaches no
    reference value that reads the wire, and `.claude/rules/parity.md`
    `## Where a difference comes from` names that shape a proven reference defect.
