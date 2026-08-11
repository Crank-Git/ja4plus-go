# JA4S: TLS Server Response Fingerprint

This page transcribes the FoxIO image that specifies JA4S. **This page records what each
source states, and it decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory and the pinned commit.

## The source

| Fact | Value |
|---|---|
| Image | [`technical_details/JA4S.png`](https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4S.png) |
| SHA-256 | `a4d303c3c51c2862d86abd69d6dfe6d28a43e86556a91d2c1c8261fa4de15458` |
| Image title | `JA4S: TLS Server Response Fingerprint` |
| License mark on the image | `Patent Pending` and `FoxIO License 1.1` |
| Text specification at the pin | None |

**This page reproduces no image.** Follow the link above to read it.

**FoxIO publishes no text specification for JA4S at the pinned commit.** The image is the
only FoxIO prose, so a rule the image does not state comes from a reference
implementation.

## What the image states

The image carries one example value. It is verbatim here, and this page rewords no part of
it.

```txt
JA4S=t120400_c030_4e8089b08790
```

The image labels the three parts `JA4S_a`, `JA4S_b` and `JA4S_c`.

| Part | Value in the image |
|---|---|
| `JA4S_a` | `t120400` |
| `JA4S_b` | `c030` |
| `JA4S_c` | `4e8089b08790` |

## The rules

- **R1** — One JA4S value holds three parts. One underscore separates each pair of parts.
  The image states this rule, and its example value shows two underscores.
  `python/ja4.py:209` corroborates.

- **R2** — JA4S reads the TLS server hello. The image title states it, and
  `python/ja4.py:591` corroborates by selecting handshake type `2`.

- **R3** — Part a opens with one protocol character. The image states `Protocol, TCP = “t”
  QUIC = “q”`. `python/ja4.py:173` corroborates, and `rust/ja4/src/tls.rs:452`
  corroborates.

- **R4** — Part a carries a 2-character TLS version. The image states `TLS version, 1.2 =
  “12”, 1.3 = “13”`. `python/ja4.py:196` corroborates through `python/common.py:16`.

- **R5** — The JA4S version map equals the JA4 version map. **The image states two of its
  values.** `python/common.py:16` serves both methods, and
  `zeek/utils/ssl-consts.zeek:4` serves both methods.

- **R6** — When the server supported_versions extension is present, the version is the
  highest value that extension carries. **The image alone states no such rule.**
  `python/ja4.py:195` corroborates, and `zeek/ja4s/main.zeek:119` corroborates.

- **R7** — The highest-value search of R6 skips a GREASE value. `python/common.py:154`
  corroborates, and `zeek/ja4s/main.zeek:116` corroborates.

- **R8** — Part a carries the count of server extensions, in 2 characters. The image
  states `Number of Extensions`. `python/ja4.py:183` corroborates, and
  `rust/ja4/src/tls.rs:453` corroborates.

- **R9** — A server extension count above 99 produces `99`. **The image alone states no
  such rule.** `python/ja4.py:183` corroborates, `rust/ja4/src/tls.rs:453` corroborates,
  and `zeek/ja4s/main.zeek:142` corroborates.

- **R10** — **Reference split.** The server extension list treats a GREASE value two
  ways, and the count of R8 follows the same split.
  - `python/ja4.py:183` keeps a GREASE value, because `to_ja4s` applies no GREASE filter.
  - `rust/ja4/src/tls.rs:604` keeps a GREASE value, and its client function
    `rust/ja4/src/tls.rs:585` removes one.
  - `wireshark/source/packet-ja4.c:757` removes a GREASE value.
  - `zeek/ja4s/main.zeek:91` removes a GREASE value, and its own comment states
    `Will we see grease from the server?`.

- **R11** — Part a ends with two ALPN characters. The image states `ALPN Chosen (00 if no
  ALPN)`. `python/ja4.py:205` corroborates, and `zeek/ja4s/main.zeek:149` corroborates.

- **R12** — The two ALPN characters are the first character and the last character of the
  ALPN value the server chose. `rust/ja4/src/tls.rs:424` corroborates through
  `rust/ja4/src/tls.rs:615`, and `zeek/ja4s/main.zeek:149` corroborates.

- **R13** — No ALPN extension produces `00`. The image states it, and
  `python/ja4.py:198` corroborates.

- **R14** — **Reference split.** A one-character ALPN value and a non-alphanumeric ALPN
  byte split the references exactly as they split them for JA4. `docs/specs/foxio/JA4.md`
  R18 and R19 state each value, and the same code serves both methods:
  `python/ja4.py:204`, `rust/ja4/src/tls.rs:615` and
  `wireshark/source/packet-ja4.c:1027`.

- **R15** — Part b is the one cipher suite the server chose. The image states `Cipher
  Suite Chosen`. `python/ja4.py:191` corroborates, and `zeek/ja4s/main.zeek:165`
  corroborates.

- **R16** — Part b is a 4-character lower-case hexadecimal value, and no hash applies to
  it. The image example holds `c030`. `zeek/ja4s/main.zeek:165` corroborates with the
  format `%04x`, and `rust/ja4/src/tls.rs:427` corroborates.

- **R17** — The references state no one value for a server hello that names no cipher
  suite. **The image states no rule for it.** `python/ja4.py:191` writes an empty part b.
  `rust/ja4/src/tls.rs:426` returns an error and writes no JA4S value at all.

- **R18** — Part c is a SHA-256 hash of the server extension list. The image states
  `Truncated SHA256 hash of the Extensions, in the order they appear`.
  `python/ja4.py:186` corroborates.

- **R19** — The server extension list keeps the order of the packet, and no sort applies
  to it. The image states `in the order they appear`, and `rust/ja4/src/tls.rs:461`
  corroborates with the comment `Note that we are preserving the original order of
  server's TLS extensions.`.

- **R20** — The server extension list holds the SNI extension and the ALPN extension.
  **The image alone states no such rule, and the JA4 rule runs the other way.**
  `rust/ja4/src/tls.rs:604` corroborates by removing neither, and the FoxIO vector
  `python/test/testdata/browsers-x509.pcapng.json:36` shows
  `t1207h2_c02b_ff01,0000,000b,0023,0005,0010,0017`, which holds `0000` and `0010`.

- **R21** — Each list entry is a 4-character lower-case hexadecimal value, and a comma
  separates each pair. `rust/ja4/src/tls.rs:462` corroborates, and
  `wireshark/source/packet-ja4.c:761` corroborates.

- **R22** — Part c holds the first 12 characters of the SHA-256 hash. The image states
  `Truncated`, and it states no length. `python/common.py:127` corroborates, and
  `wireshark/source/packet-ja4.c:566` corroborates with the format `%12.12s`.

- **R23** — An empty server extension list produces the zero sentinel `000000000000`.
  **The image alone states no such rule.** `python/ja4.py:188` corroborates,
  `rust/ja4/src/lib.rs:185` corroborates, and `wireshark/source/packet-ja4.c:573`
  corroborates.

## Readings this page records

A reading is a conclusion about a source. None of these carries a rule.

- **Reading 1** — **The image states the parts in a different order from the value.** The
  image lists `Number of Extensions` above `ALPN Chosen`, and it lists `Cipher Suite
  Chosen` last. The value `t120400_c030_4e8089b08790` places the cipher suite in part b,
  between the two. The leader lines of the image carry the order, and the bullet list does
  not.

- **Reading 2** — **The image example holds no ALPN.** Part a of `t120400` ends with `00`,
  which R13 names. The FoxIO vector `python/test/testdata/browsers-x509.pcapng.json:35`
  holds `t1207h2_c02b_cf25e267ce22`, which ends part a with `h2` instead.

- **Reading 3** — **R10 changes a fingerprint value only on a server hello that carries a
  GREASE extension.** A server hello that carries none produces the same value under both
  halves of the split. This page measures no capture, and it records the split so that a
  later measurement has a citation to start from.
