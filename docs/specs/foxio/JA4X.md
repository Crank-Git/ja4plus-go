# JA4X: X509 Fingerprint

This page transcribes the FoxIO image that specifies JA4X. **This page records what each
source states, and it decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | [`technical_details/JA4X.png`](https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4X.png) |
| SHA-256 | `71f3bd839ca7e228da8ee69dce69de870d5ee69f3e91534356bae1a48d7f322a` |
| Image title | `JA4X: X509 Fingerprint` |
| Image subtitle | `(fingerprints how a cert is created)` |
| License mark on the image | `Patent Pending` and `FoxIO License 1.1` |
| Text specification at the pin | None |

**This page reproduces no image.** Follow the link above to read it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `python/ja4x.py:87` as line 87 of
`testdata/foxio/reference/python/ja4x.py`. `docs/specs/foxio/README.md` states the rule,
and it names each path that the rule does not cover.

**FoxIO publishes no text specification for JA4X at the pinned commit.** The image is the
only FoxIO prose, so a rule the image does not state comes from a reference
implementation.

## What the image states

The image carries one example value. It is verbatim here, and this page rewords no part of
it.

```txt
JA4X=96a6439c8f5c_96a6439c8f5c_aae71e8db6d7
```

The image labels the three parts `JA4X_a`, `JA4X_b` and `JA4X_c`.

| Part | Value in the image |
|---|---|
| `JA4X_a` | `96a6439c8f5c` |
| `JA4X_b` | `96a6439c8f5c` |
| `JA4X_c` | `aae71e8db6d7` |

The image also carries six named example values. They are verbatim here.

| Name on the image | Value on the image |
|---|---|
| `SoftEther` | `d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae` |
| `Metasploit` | `2bab15409345_2bab15409345_75f1b0fafedd` |
| `Qakbot` | `2bab15409345_af684594efb4_e3b0c44298fc` |
| `Async,Quasar,BitRAT` | `7022c563de38_7022c563de38_0147df7a0c11` |
| `Sliver, Havoc C2` | `000000000000_7c32fa18c13e_bf0f0589fc03` |
| `Sliver, Havoc C2` | `000000000000_4f24da86fad6_bf0f0589fc03` |

The image ends with one sentence, verbatim: `Combine with JA4, JARM, or other metadata
like Issuer Org to eliminate FPs`.

## The rules

- **R1** — One JA4X value holds three parts. One underscore separates each pair of parts.
  The image states this rule, and its example value shows two underscores.
  `python/ja4x.py:87` corroborates.

- **R2** — JA4X reads one X.509 certificate, and it fingerprints how that certificate was
  built. The image subtitle states `(fingerprints how a cert is created)`.
  `python/ja4x.py:12` corroborates with the comment `JA4X packets are TCP TLS packets`.

- **R3** — One certificate produces one JA4X value. **The image alone states no such
  rule.** `python/ja4x.py:88` corroborates by writing one value per certificate of the
  packet, and `wireshark/source/packet-ja4.c:1629` corroborates.

- **R4** — Part a is a hash of the issuer relative distinguished names. The image states
  `Hash of Issuer RDNs, in order`. `python/ja4x.py:105` corroborates, and
  `rust/ja4x/src/lib.rs:65` corroborates.

- **R5** — Part b is a hash of the subject relative distinguished names. The image states
  `Hash of Subject RDNs, in order`. `python/ja4x.py:105` corroborates, and
  `rust/ja4x/src/lib.rs:71` corroborates.

- **R6** — Part c is a hash of the certificate extensions. The image states `Hash of
  Extensions, in order`. `python/ja4x.py:87` corroborates, and
  `rust/ja4x/src/lib.rs:77` corroborates.

- **R7** — Each of the three lists holds object identifiers, and it holds no value. The
  image states `(does not include values)`. `rust/ja4x/src/lib.rs:68` corroborates by
  reading the attribute type and never the attribute value.

- **R8** — Each of the three lists keeps the order of the certificate, and no sort applies
  to it. The image states `in order` on all three bullets.
  `python/ja4x.py:100` corroborates, and `rust/ja4x/src/lib.rs:67` corroborates.

- **R9** — Each list entry is the hexadecimal form of the object identifier content
  octets. **The image alone states no such rule.** `python/ja4x.py:33` corroborates by
  removing the first four hexadecimal characters, which carry the ASN.1 tag and the
  length. `rust/ja4x/src/lib.rs:68` corroborates by encoding the identifier bytes.

- **R10** — A comma separates each pair of list entries. **The image alone states no such
  rule.** `python/common.py:127` corroborates, and `rust/ja4x/src/lib.rs:69`
  corroborates.

- **R11** — A hash part holds the first 12 characters of the SHA-256 hash. The image
  states `Hash`, and it states no length. `python/ja4x.py:87` corroborates, and
  `rust/ja4x/src/lib.rs:174` corroborates. `rust/ja4x/src/lib.rs:180` holds the test
  `assert_eq!(hash12("551d0f,551d25,551d11"), "aae71e8db6d7");`, and `aae71e8db6d7` is the
  part c of the image example value.

- **R12** — **Reference split.** An empty list produces two different values.
  - `rust/ja4x/src/lib.rs:171` writes the zero sentinel `000000000000`, and
    `wireshark/source/packet-ja4.c:590` writes the same value.
  - `python/ja4x.py:87` hashes the empty string, which produces `e3b0c44298fc`.

  **The image carries a value for each half of the split.** The two `Sliver, Havoc C2`
  rows open with `000000000000`, and the `Qakbot` row ends with `e3b0c44298fc`.

  **The maintainer ruled the split on 2026-08-14, and this library hashes an empty list.**
  The ruling reaches part a, part b and part c together, so no part of a JA4X value of this
  library writes `000000000000`. The deciding rule is R18 of `docs/specs/foxio/JA4H.md`,
  which states a hash of the list and names no sentinel. R28 of that page records the same
  ruling for JA4H, and #527 built the JA4H half. **Issue #582 is the reversal path of the
  JA4X half**, and the port half is `Crank-Git/ja4plus#619`.

  **The two halves above transcribe what FoxIO published, and this paragraph records what
  this library answers.** The transcription survives, because a later reader needs the
  evidence that the ruling settled.

- **R13** — The Zeek package produces no JA4X value. **The image states nothing about a
  Zeek baseline.** `zeek/ja4x/__load__.zeek:1` holds the one line `# empty`, and the
  directory holds no other file.

## Readings this page records

A reading is a conclusion about a source. None of these carries a rule.

- **Reading 1** — **`e3b0c44298fc` is the first 12 characters of the SHA-256 hash of the
  empty string.** The command `printf '' | shasum -a 256 | cut -c1-12` writes it. This
  fact is what connects the `Qakbot` row of the image to the Python half of R12.

- **Reading 2** — **Part a and part b of the image example value are equal.** A
  self-signed certificate produces equal parts, because its issuer name and its subject
  name hold the same relative distinguished names. The `SoftEther`, `Metasploit` and
  `Async,Quasar,BitRAT` rows show the same equality, and the `Qakbot` row does not.

- **Reading 3** — **The Python reference removes two object identifiers before it reports
  the issuer name and the subject name.** `python/ja4x.py:59` removes `550406` and
  `55040b`. That removal serves the `_Issuer` and `_Subject` report fields of
  `python/ja4x.py:64`, and no part of the JA4X value reads its result. This page records
  the removal so that a reader does not carry it into R4 or R5.
