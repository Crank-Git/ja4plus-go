# JA4D6 — transcription of `JA4D6.png`

This page transcribes one FoxIO image as numbered rules. **The page records what each
source states. The page decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | <https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4D6.png> |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-11 |

**This page reproduces no image.** The link above reaches it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `wireshark/source/packet-ja4.c:1537` as line 1537 of
`testdata/foxio/reference/wireshark/source/packet-ja4.c`. `docs/specs/foxio/README.md` states the rule, and it
names each path that the rule does not cover.

## Which implementations state a rule

**One reference implementation builds a JA4D6 value, and that implementation is the
Wireshark dissector.** The FoxIO Zeek package states
`JA4D6 &rarr; `ja4d.log` (awaiting Zeek DHCPv6 suppport)` at `zeek/README.md:15`, and its
`ja4d` module handles the `dhcp_message` event alone at `zeek/ja4d/main.zeek:125`. The
FoxIO Rust program and the FoxIO Python program build no DHCP fingerprint at all.

A rule on this page therefore carries one implementation citation or none. **No reference
split can exist on this page**, because two implementations cannot disagree when only one
of them produces the value.

## The rules

### The schema

- **R1** — The image titles itself `JA4D6: DHCPv6 Fingerprint`, and subtitles itself
  `(Windows 11 Example)`. The image alone states this rule.
- **R2** — The image carries the notice `Patent Pending` and the notice
  `FoxIO License 1.1`. The image alone states this rule.
- **R3** — The image holds the example value `JA4D6=solct0014nn_8-1-3-39-16-6_17-23-24-39`.
  The image alone states this rule.
- **R4** — A value holds three parts, which the image labels `a`, `b` and `c`. The image
  alone states this rule.
- **R5** — An underscore separates one part from the next part. Wireshark writes the format
  `"%s%s%c%c_%s_%s"` at `wireshark/source/packet-ja4.c:713`.

### Part a — the four concatenated fields

- **R6** — Part a holds four fields, and no delimiter separates one field from the next
  field. Wireshark writes `"%s%s%c%c"` at `wireshark/source/packet-ja4.c:713`.
- **R7** — The first field of part a holds the DHCPv6 message type, which the image labels
  `DHCPv6 Message Type`. Wireshark reads `dhcpv6.msgtype` at
  `wireshark/source/packet-ja4.c:1537`.
- **R8** — The message type is a five-character code. Wireshark holds the code table at
  `wireshark/source/packet-ja4.c:835`.

  | Type | Code | Type | Code | Type | Code |
  |---|---|---|---|---|---|
  | 1 | `solct` | 14 | `query` | 27 | `pores` |
  | 2 | `advrt` | 15 | `qrply` | 28 | `urqst` |
  | 3 | `reqst` | 16 | `qdone` | 29 | `ureqa` |
  | 4 | `confm` | 17 | `qdata` | 30 | `udone` |
  | 5 | `renew` | 18 | `rereq` | 31 | `conne` |
  | 6 | `rebnd` | 19 | `rrply` | 32 | `connr` |
  | 7 | `reply` | 20 | `v4qry` | 33 | `dconn` |
  | 8 | `relse` | 21 | `v4res` | 34 | `state` |
  | 9 | `decln` | 22 | `acqry` | 35 | `conta` |
  | 10 | `recon` | 23 | `sttls` | 36 | `arinf` |
  | 11 | `inreq` | 24 | `bdudp` | 37 | `arrep` |
  | 12 | `rlayf` | 25 | `brply` | | |
  | 13 | `rlayr` | 26 | `poreq` | | |

- **R9** — A message type that the table does not name reaches five decimal digits.
  Wireshark writes `"%05u"` at `wireshark/source/packet-ja4.c:1544`.
- **R10** — An absent message type reaches `00000`. Wireshark writes `"00000"` at
  `wireshark/source/packet-ja4.c:705`.
- **R11** — The second field of part a holds the client DUID length, which the image labels
  `Client DUID Length`. **JA4D holds the maximum message size in this position, and JA4D6
  holds a length.** Wireshark reads the length of the field `dhcpv6.duid.bytes` at
  `wireshark/source/packet-ja4.c:1547`.
- **R12** — Wireshark reads the client DUID only when the message carries DHCPv6 option 1.
  Wireshark sets `dhcpv6_option_type_1_exists` at
  `wireshark/source/packet-ja4.c:1569` and tests it at
  `wireshark/source/packet-ja4.c:1549`.
- **R13** — Wireshark reads the first client DUID of the message and ignores a later one.
  Wireshark tests `wmem_strbuf_get_len(ja4d_data.size) == 0` at
  `wireshark/source/packet-ja4.c:1548`.
- **R14** — The client DUID length holds four decimal digits. Wireshark writes `"%04d"` at
  `wireshark/source/packet-ja4.c:1552`.
- **R15** — A client DUID length above 9999 reaches `9999`. Wireshark writes `"9999"` at
  `wireshark/source/packet-ja4.c:1556`.
- **R16** — An absent client DUID length reaches `0000`. Wireshark writes `"0000"` at
  `wireshark/source/packet-ja4.c:707`.
- **R17** — The third field of part a holds `i` when the message requests one specific
  address, and `n` when it requests a new address. The image labels the field
  `Requesting specific IP (i) or New IP (n)`. Wireshark tests `dhcpv6.iata` at
  `wireshark/source/packet-ja4.c:1560`.
- **R18** — The fourth field of part a holds `d` when the message carries a domain name,
  and `n` when it carries none. The image labels the field
  `Has a Domain name (d) or No domain (n)`. Wireshark tests `dhcpv6.client_domain` at
  `wireshark/source/packet-ja4.c:1563`.

### Part b — the option list

- **R19** — Part b holds the DHCPv6 option list, which the image labels
  `DHCPv6 Options List`. Wireshark reads `dhcpv6.option.type` at
  `wireshark/source/packet-ja4.c:1566`.
- **R20** — Part b skips no option. **JA4D names four options to ignore, and JA4D6 names
  none.** Wireshark writes every option type at `wireshark/source/packet-ja4.c:1570`, and
  the JA4D branch skips four values at `wireshark/source/packet-ja4.c:1526`.
- **R21** — A hyphen separates one option from the next option. Wireshark appends `"%d-"`
  at `wireshark/source/packet-ja4.c:1571`.
- **R22** — An empty option list reaches `00`. Wireshark writes `"00"` at
  `wireshark/source/packet-ja4.c:709`.

### Part c — the option request list

- **R23** — Part c holds the DHCPv6 option request list, which the image labels
  `DHCPv6 Option Request List`. Wireshark reads `dhcpv6.requested_option_code` at
  `wireshark/source/packet-ja4.c:1574`.
- **R24** — A hyphen separates one requested option from the next requested option.
  Wireshark appends `"%d-"` at `wireshark/source/packet-ja4.c:1576`.
- **R25** — An empty option request list reaches `00`. Wireshark writes `"00"` at
  `wireshark/source/packet-ja4.c:711`.

### What the implementation adds

- **R26** — Wireshark publishes the JA4D6 value under the field name `ja4.ja4d`, and it
  registers no field named `ja4.ja4d6`. Wireshark registers `ja4.ja4d` at
  `wireshark/source/packet-ja4.c:1741` and writes the value at
  `wireshark/source/packet-ja4.c:1671`.
- **R27** — Wireshark tags the JA4D6 value with the protocol name `dhcpv6`, which
  separates it from a JA4D value. Wireshark selects the tag at
  `wireshark/source/packet-ja4.c:1667`.
