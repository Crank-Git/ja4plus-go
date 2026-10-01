# JA4D — transcription of `JA4D.png`

This page transcribes one FoxIO image as numbered rules. **The page records what each
source states. The page decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | <https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4D.png> |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-11 |

**This page reproduces no image.** The link above reaches it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `zeek/ja4d/main.zeek:113` as line 113 of
`testdata/foxio/reference/zeek/ja4d/main.zeek`. `docs/specs/foxio/README.md` states the
rule, and it names each path that the rule does not cover.

## Which implementations state a rule

Zeek and Wireshark each build a JA4D value. **The FoxIO Rust program and the FoxIO Python
program build none**, so no rule on this page cites either of them.

## The rules

### The schema

- **R1** — The image titles itself `JA4D: DHCP Fingerprint`, and subtitles itself
  `(iPhone Example)`. The image alone states this rule.
- **R2** — The image carries the notice `Patent Pending` and the notice
  `FoxIO License 1.1`. The image alone states this rule.
- **R3** — The image holds the example value
  `JA4D=reqst1500in_55-57-61-51-12_1-121-3-6-15-108-114-119-252`. The image alone states
  this rule.
- **R4** — A value holds three parts, which the image labels `a`, `b` and `c`. The image
  alone states this rule.
- **R5** — An underscore separates one part from the next part. Zeek holds
  `option delimiter: string = "_";` at `zeek/config.zeek:4` and writes it at
  `zeek/ja4d/main.zeek:115`. Wireshark writes the format `"%s%s%c%c_%s_%s"` at
  `wireshark/source/packet-ja4.c:713`.

### Part a — the four concatenated fields

- **R6** — Part a holds four fields, and no delimiter separates one field from the next
  field. Zeek concatenates them at `zeek/ja4d/main.zeek:113` and at
  `zeek/ja4d/main.zeek:114`. Wireshark writes `"%s%s%c%c"` at
  `wireshark/source/packet-ja4.c:713`.
- **R7** — The first field of part a holds the DHCP message type, which the image labels
  `DHCP Message Type`. Zeek reads `msg$m_type` at `zeek/ja4d/main.zeek:47`. Wireshark reads
  `dhcp.option.dhcp` at `wireshark/source/packet-ja4.c:1497`.
- **R8** — The message type is a five-character code. Zeek holds the code table at
  `zeek/ja4d/consts.zeek:4`. Wireshark holds the same table at
  `wireshark/source/packet-ja4.c:806`.

  | Type | Code | Type | Code |
  |---|---|---|---|
  | 1 | `disco` | 10 | `lqery` |
  | 2 | `offer` | 11 | `lunas` |
  | 3 | `reqst` | 12 | `lunkn` |
  | 4 | `decln` | 13 | `lactv` |
  | 5 | `dpack` | 14 | `blklq` |
  | 6 | `dpnak` | 15 | `lqdon` |
  | 7 | `relse` | 16 | `actlq` |
  | 8 | `infor` | 17 | `lqsta` |
  | 9 | `frenw` | 18 | `dhtls` |

- **R9** — A message type that the table does not name reaches five decimal digits. Zeek
  writes `fmt("%05d", msg$m_type)` at `zeek/ja4d/main.zeek:51`. Wireshark writes `"%05u"`
  at `wireshark/source/packet-ja4.c:1504`.
- **R10** — An absent message type reaches `00000`. Zeek writes `"00000"` at
  `zeek/ja4d/main.zeek:44`. Wireshark writes `"00000"` at
  `wireshark/source/packet-ja4.c:705`.
- **R11** — The second field of part a holds the maximum DHCP message size, which the image
  labels `Maximum DHCP Message Size`. Zeek reads `options$max_msg_size` at
  `zeek/ja4d/main.zeek:56`. Wireshark reads `dhcp.option.dhcp_max_message_size` at
  `wireshark/source/packet-ja4.c:1507`.
- **R12** — The maximum message size holds four decimal digits. Zeek writes
  `fmt("%04d", options$max_msg_size)` at `zeek/ja4d/main.zeek:60`. Wireshark writes
  `"%04d"` at `wireshark/source/packet-ja4.c:1510`.
- **R13** — A maximum message size above 9999 reaches `9999`. Zeek returns `"9999"` at
  `zeek/ja4d/main.zeek:58`. Wireshark writes `"9999"` at
  `wireshark/source/packet-ja4.c:1514`.
- **R14** — An absent maximum message size reaches `0000`. Zeek returns `"0000"` at
  `zeek/ja4d/main.zeek:62`. Wireshark writes `"0000"` at
  `wireshark/source/packet-ja4.c:707`.
- **R15** — The third field of part a holds `i` when the message requests one specific
  address, and `n` when it requests a new address. The image labels the field
  `Requesting specific IP (i) or New IP (n)`. Zeek tests `options?$addr_request` at
  `zeek/ja4d/main.zeek:66`. Wireshark tests `dhcp.option.requested_ip_address` at
  `wireshark/source/packet-ja4.c:1518`.
- **R16** — The fourth field of part a holds `d` when the message carries a domain name,
  and `n` when it carries none. The image labels the field
  `Has a Domain name (d) or No domain (n)`. Zeek tests `options?$client_fqdn` at
  `zeek/ja4d/main.zeek:73`. Wireshark tests `dhcp.fqdn.name` at
  `wireshark/source/packet-ja4.c:1521`.

### Part b — the option list

- **R17** — Part b holds the DHCP option list, which the image labels
  `DHCP Options List, ignoring options 50, 53, 81, and 255`. Zeek builds it at
  `zeek/ja4d/main.zeek:84`. Wireshark builds it at
  `wireshark/source/packet-ja4.c:1524`.
- **R18** — A hyphen separates one option from the next option. Zeek passes `"-"` at
  `zeek/ja4d/main.zeek:84`. Wireshark appends `"%d-"` at
  `wireshark/source/packet-ja4.c:1527`.
- **R19** — An empty option list reaches `00`. Zeek returns `"00"` at
  `zeek/ja4d/main.zeek:82`. Wireshark writes `"00"` at
  `wireshark/source/packet-ja4.c:709`.

### Part c — the parameter request list

- **R20** — Part c holds the DHCP parameter request list, which the image labels
  `DHCP Parameter Request List`. Zeek reads `options$param_list` at
  `zeek/ja4d/main.zeek:91`. Wireshark reads `dhcp.option.request_list_item` at
  `wireshark/source/packet-ja4.c:1530`.
- **R21** — Part c skips no value, and the image names no skip set for it. Zeek passes no
  skip set at `zeek/ja4d/main.zeek:91`. Wireshark writes every item at
  `wireshark/source/packet-ja4.c:1531`.
- **R22** — A hyphen separates one parameter from the next parameter. Zeek passes `"-"` at
  `zeek/ja4d/main.zeek:91`. Wireshark appends `"%d-"` at
  `wireshark/source/packet-ja4.c:1532`.
- **R23** — An empty parameter request list reaches `00`. Zeek returns `"00"` at
  `zeek/ja4d/main.zeek:89`. Wireshark writes `"00"` at
  `wireshark/source/packet-ja4.c:711`.

### What the implementations add

- **R24** — Zeek writes one JA4D value for each DHCP message, and it aggregates no
  conversation. Zeek holds the comment
  `# We log per DHCP message for this fingerprint instead of aggregating across a` at
  `zeek/ja4d/main.zeek:123`, and it calls `do_ja4d` at `zeek/ja4d/main.zeek:127`.

### Reference splits

- **R25** — **Reference split.** Zeek skips the four options that the image names, and
  Wireshark skips a different set. Zeek holds
  `global DHCP_SKIP_OPTIONS: set[count] = { 53, 255, 50, 81, };` at
  `zeek/ja4d/consts.zeek:25`, which matches the image label in R17. Wireshark tests
  `val != 0 && val != 53 && val != 50 && val != 81` at
  `wireshark/source/packet-ja4.c:1526`. Wireshark skips option 0, and Wireshark writes
  option 255. **Issue #130 holds the question.**
