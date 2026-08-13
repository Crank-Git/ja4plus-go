# JA4T and JA4TS — transcription of `JA4T.png`

This page transcribes one FoxIO image as numbered rules. **The page records what each
source states. The page decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the rule that
states how to read a citation.

## The source

| Fact | Value |
|---|---|
| Image | <https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4T.png> |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-11 |

**This page reproduces no image.** The link above reaches it.

A citation names a path in the FoxIO repository at the pinned commit. **Join it to
`testdata/foxio/reference/`.** Read `zeek/ja4t/main.zeek:180` as line 180 of
`testdata/foxio/reference/zeek/ja4t/main.zeek`. `docs/specs/foxio/README.md` states the
rule, and it names each path that the rule does not cover.

## What the image specifies

The image titles itself `JA4T/S: TCP Fingerprint`, so it specifies JA4TS as well as JA4T.
`docs/specs/features/11-foxio-reference.md` records the same measurement.

**FoxIO publishes no image for JA4TScan**, and `docs/specs/spec.md` `Non-goals` declines
that method.

## The rules

### The schema

- **R1** — The image titles itself `JA4T/S: TCP Fingerprint`. The image alone states this
  rule.
- **R2** — The title names the server method, so the image specifies JA4TS. The image
  alone states this rule.
- **R3** — The image holds the example value `JA4T=65535_2-1-3-1-1-4_1460_8_1-2-4-8-R6`.
  The image alone states this rule.
- **R4** — A value holds five parts, which the image labels `a` to `e`. The image alone
  states this rule.
- **R5** — An underscore separates one part from the next part. Zeek holds
  `option delimiter: string = "_";` at `zeek/config.zeek:4` and writes it at
  `zeek/ja4t/main.zeek:197`. Wireshark writes the format `"%d_%s_%02d_%02d"` at
  `wireshark/source/packet-ja4.c:670`. Rust writes the format `"{}_{}_{}_{}"` at
  `rust/ja4/src/tcp.rs:136`.

### Part a — the TCP window size

- **R6** — Part a holds the TCP window size, which the image labels `TCP Window Size`.
  Zeek reads `rph$tcp$win` at `zeek/ja4t/main.zeek:132`. Wireshark reads
  `tcp.window_size_value` at `wireshark/source/packet-ja4.c:1257`. Rust reads
  `tcp.window_size_value` at `rust/ja4/src/tcp.rs:66`.
- **R7** — Part a holds the value the packet carries, and no implementation applies the
  window scale to it. Rust holds the comment
  `// Extract window size (raw, before scaling)` at `rust/ja4/src/tcp.rs:65`. Zeek writes
  `rph$tcp$win` unchanged at `zeek/ja4t/main.zeek:196`.

### Part b — the TCP options

- **R8** — Part b holds the TCP option kinds, which the image labels
  `TCP Options (in the order they are seen)`. Zeek appends each kind at
  `zeek/ja4t/main.zeek:99`. Wireshark appends each `tcp.option_kind` at
  `wireshark/source/packet-ja4.c:1456`. Rust appends each `tcp.option_kind` at
  `rust/ja4/src/tcp.rs:70`.
- **R9** — A hyphen separates one option kind from the next kind. Zeek passes `"-"` at
  `zeek/ja4t/main.zeek:199`. Wireshark appends `"%d-"` at
  `wireshark/source/packet-ja4.c:1458`. Rust joins with `"-"` at `rust/ja4/src/tcp.rs:133`.
- **R10** — **Reference split.** Zeek writes no entry for option kind 0, and Wireshark and
  Rust write one entry for each kind 0 byte. Zeek breaks the loop before the append at
  `zeek/ja4t/main.zeek:96`, so `badcurveball.pcap` frame 1 reaches `2-1-3-1-1-8-4` in Zeek.
  Wireshark appends one entry for each `tcp.option_kind` field occurrence at
  `wireshark/source/packet-ja4.c:1456`. Rust reads that same field list at
  `rust/ja4/src/tcp.rs:70`. The same frame reaches `2-1-3-1-1-8-4-0-0` in both.
  The per-packet vector for that frame holds `65535_2-1-3-1-1-8-4-0-0_1386_6`. **Zeek is the
  single outlier, and the maintainer ruled the question on 2026-08-12. Issue #297 holds the
  ruling, and this library writes one entry for each option byte.**

### Part c — the maximum segment size

- **R11** — Part c holds the TCP maximum segment size, which the image labels
  `TCP Maximum Segment Size`. Zeek reads the option kind 2 value at
  `zeek/ja4t/main.zeek:110`. Wireshark reads `tcp.options.mss_val` at
  `wireshark/source/packet-ja4.c:1461`. Rust reads `tcp.options.mss_val` at
  `rust/ja4/src/tcp.rs:77`.

### Part d — the window scale

- **R12** — Part d holds the TCP window scale, which the image labels
  `TCP Window Scale (multiplier)`. Zeek reads the option kind 3 value at
  `zeek/ja4t/main.zeek:113`. Wireshark reads `tcp.options.wscale.shift` at
  `wireshark/source/packet-ja4.c:1464`. Rust reads `tcp.options.wscale.shift` at
  `rust/ja4/src/tcp.rs:82`.

### Part e — the retransmission timings

- **R13** — Part e holds the TCP retransmission timings, which the image labels
  `TCP Retransmission Timings (only on JA4TScan)`. The image alone states this rule.
- **R14** — The image example holds the part e value `1-2-4-8-R6`, so a hyphen separates
  one timing from the next timing. The image alone states this rule.
- **R15** — The image example ends part e with `R6`, so the letter `R` marks the reset
  value. The image alone states this rule.
- **R16** — Zeek and Wireshark write part e on JA4TS, and the image labels part e
  `only on JA4TScan`. Zeek writes it at `zeek/ja4t/main.zeek:231`, under the
  `FINGERPRINT::JA4TS_enabled` guard at `zeek/ja4t/main.zeek:212`. Wireshark writes it at
  `wireshark/source/packet-ja4.c:686`, reached from the JA4TS call at
  `wireshark/source/packet-ja4.c:1595`. **Issue #56 of Epic 8b owns this difference. This
  page rules nothing.**
- **R17** — Part e appears only when the connection carries more than one SYN-ACK. Zeek
  tests `|c$fp$ja4t$synack_delays| > 0` at `zeek/ja4t/main.zeek:229`. Wireshark tests
  `conn->syn_ack_count > 1` at `wireshark/source/packet-ja4.c:684`.
- **R18** — **Zeek writes at most ten delays, and Wireshark writes at most nine.** The two
  counts differ, and each implementation bounds a different thing.
  - **Zeek bounds the list of delays.** `zeek/ja4t/main.zeek:28` declares
    `synack_delays: vector of count &default=vector();`, and `zeek/ja4t/main.zeek:180`
    appends one delay for each SYN-ACK after the first. `zeek/ja4t/main.zeek:185` reads
    `if (|c$fp$ja4t$synack_delays| == 10) {` and returns, so the list stops at ten
    delays. Eleven SYN-ACK packets reach that bound.
  - **Wireshark bounds the array of timestamps.** `wireshark/source/packet-ja4.c:234`
    holds `#define MAX_SYN_ACK_TIMES 10`, and `wireshark/source/packet-ja4.c:1290` stores
    a timestamp only while `conn->syn_ack_count < MAX_SYN_ACK_TIMES`. So the array holds
    ten timestamps at most. `wireshark/source/packet-ja4.c:686` then reads
    `for (int i = 1; i < conn->syn_ack_count; i++)` and writes one delay for each pass,
    which is nine delays from ten timestamps.
  - **The two counts differ by one, because one delay needs two timestamps.** Zeek counts
    the delays it appends, and Wireshark counts the timestamps it stores. A reader
    reproduces each count from the two loops alone.
  - **This page records the difference, and it settles no count.** The image states no
    count, which R13 records. #369 applied ten delays on 2026-08-13, from
    `docs/specs/foxio/deleted-text-specifications.md:788`, and that ruling is provisional.
    **#369 holds the reversal path, and it also holds the reset value past the bound.**

### Which packet each method reads

- **R19** — JA4T reads the first SYN of the connection. Zeek tests
  `rph$tcp$flags != TH_SYN` at `zeek/ja4t/main.zeek:126`. Wireshark tests
  `tcp_flags == 0x02` at `wireshark/source/packet-ja4.c:1266`. Rust tests
  `is_initial_syn` at `rust/ja4/src/tcp.rs:61`.
- **R20** — JA4TS reads the first SYN-ACK of the connection. Zeek tests
  `rph$tcp$flags == (TH_SYN | TH_ACK)` at `zeek/ja4t/main.zeek:171` and stores the values
  at `zeek/ja4t/main.zeek:177`. Wireshark tests `tcp_flags == 0x012` at
  `wireshark/source/packet-ja4.c:1279`.
- **R21** — Rust writes no JA4TS value. Rust reads only the first SYN, as its doc comment
  states at `rust/ja4/src/tcp.rs:47`, and writes four parts at `rust/ja4/src/tcp.rs:136`.
- **R22** — Zeek stops the JA4TS measurement after 120 seconds. Zeek tests
  `ts - c$fp$ja4t$last_ts > 120000000` at `zeek/ja4t/main.zeek:162`. Wireshark holds no
  timeout.
- **R23** — Zeek stops the JA4TS measurement at the next packet from the originator. Zeek
  sets the threshold at `zeek/ja4t/main.zeek:138` and sets `synack_done` at
  `zeek/ja4t/main.zeek:146`. Wireshark holds no equivalent stop.

### Reference splits

- **R24** — **Reference split.** Zeek truncates each part e delay to whole seconds, and
  Wireshark rounds each delay to the nearest second. Zeek writes
  `c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;` at
  `zeek/ja4t/main.zeek:180`, and `zeek/ja4t/main.zeek:162` writes a 120-second timeout as
  `120000000`, so the units are microseconds. Wireshark writes
  `return (int64_t)(round(nstime_to_sec(&result)));` at
  `wireshark/source/packet-ja4.c:277`, and `wireshark/source/packet-ja4.c:687` calls it.
  A delay of 1.6 seconds reaches `1` in Zeek and `2` in Wireshark. **Issue #18 holds the
  ruling.**
- **R25** — **Reference split.** The same split covers the reset delay. Zeek writes
  `fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000)` at
  `zeek/ja4t/main.zeek:233`. Wireshark calls the same rounding helper at
  `wireshark/source/packet-ja4.c:694`. **Issue #18 holds the ruling.**
- **R26** — **Reference split.** Zeek and Wireshark write `00` for an empty option list,
  and Rust writes an empty field. Zeek writes `"00"` at `zeek/ja4t/main.zeek:201`.
  Wireshark writes `"00"` at `wireshark/source/packet-ja4.c:671`. Rust joins an empty
  vector at `rust/ja4/src/tcp.rs:129`, which reaches the empty string. **Issue #125 holds
  the question.**
- **R27** — **Reference split.** Zeek and Wireshark write a maximum segment size of zero as
  `00`, and Rust writes it as `0`. Zeek writes `fmt("%02d", ...)` at
  `zeek/ja4t/main.zeek:204`. Wireshark writes `"%02d"` at
  `wireshark/source/packet-ja4.c:670`. Rust writes `self.mss.unwrap_or(0)` at
  `rust/ja4/src/tcp.rs:139`. **Issue #125 holds the question.**
- **R28** — **Reference split.** Zeek and Wireshark write a window scale of zero as `00`,
  and Rust writes it as `0`. Zeek writes `"00"` at `zeek/ja4t/main.zeek:207`. Wireshark
  writes `"%02d"` at `wireshark/source/packet-ja4.c:673`. Rust writes
  `self.window_scale.unwrap_or(0)` at `rust/ja4/src/tcp.rs:140`. **Issue #125 holds the
  question.**
- **R29** — **Reference split.** Rust reads a SYN that also carries the ECN flags, and Zeek
  and Wireshark decline it. Rust tests only the SYN bit and the ACK bit at
  `rust/ja4/src/tcp.rs:146`, and its own test asserts `is_initial_syn(0xC2)` at
  `rust/ja4/src/tcp.rs:153`. Zeek requires `rph$tcp$flags != TH_SYN` to be false at
  `zeek/ja4t/main.zeek:126`. Wireshark requires `tcp_flags == 0x02` at
  `wireshark/source/packet-ja4.c:1266`. **Issue #126 holds the question.**
- **R30** — **Reference split.** Zeek reads any packet that carries the RST flag as the
  reset, and Wireshark reads only a packet whose flags equal `0x004`. Zeek tests
  `rph$tcp$flags & TH_RST != 0` at `zeek/ja4t/main.zeek:167`. Wireshark tests
  `tcp_flags == 0x004` at `wireshark/source/packet-ja4.c:1296`. A RST that also carries
  ACK reaches the two implementations differently. **Issue #126 holds the question.**
