# JA4L — transcription of `JA4L.png`

This page transcribes one FoxIO image as numbered rules. **The page records what each
source states. The page decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory and the pinned commit.

## The source

| Fact | Value |
|---|---|
| Image | <https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4L.png> |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-11 |

**This page reproduces no image.** The link above reaches it.

A citation names a file of the FoxIO repository at the pinned commit. Read
`zeek/ja4l/main.zeek:112` as line 112 of that file at that commit.

## What the image does not specify

The image titles itself `JA4L: Light Distance/Location Fingerprint`. It states one client
rule per part and it states no server rule. **No image specifies JA4LS.**
`docs/specs/features/12-ja4ls.md` builds JA4LS from the reference implementations for that
reason, and `docs/specs/features/11-foxio-reference.md` records the same measurement.

The four reference implementations each publish a JA4LS value. R25 to R28 hold those
readings.

## The rules

### The schema

- **R1** — The image titles itself `JA4L: Light Distance/Location Fingerprint`. The image
  alone states this rule.
- **R2** — The image holds the example value `JA4L=5191_42_45014`. The image alone states
  this rule.
- **R3** — A value holds three parts, which the image labels `a`, `b` and `c`. The image
  alone states this rule.
- **R4** — An underscore separates one part from the next part. Zeek holds
  `option delimiter: string = "_";` at `zeek/config.zeek:4` and writes it at
  `zeek/ja4l/main.zeek:113`. Wireshark writes the format `"%d_%d_%d"` at
  `wireshark/source/packet-ja4.c:1384`. Python writes `f"{diff}_{ttl}"` at
  `python/ja4.py:161`.

### Part a — the one-way latency

- **R5** — Part a holds the one-way TCP latency in microseconds, which the image labels
  `One-way TCP latency in µs (1ms = 1,000µs)`. Zeek computes it at
  `zeek/ja4l/main.zeek:105`. Wireshark computes it at
  `wireshark/source/packet-ja4.c:1352`. Rust computes it at
  `rust/ja4/src/time/tcp.rs:179`. Python computes it at `python/ja4.py:160`.
- **R6** — Part a is half of the measured interval, because one measurement covers a round
  trip. Zeek divides by `2.0` at `zeek/ja4l/main.zeek:105`. Wireshark divides by `2` at
  `wireshark/source/packet-ja4.c:1354`. Rust divides by `2` at
  `rust/ja4/src/time/tcp.rs:179`. Python writes `int((dt2-dt1).microseconds/2)` at
  `python/common.py:182`.
- **R7** — On a TCP connection, part a of JA4L measures the ACK against the SYN-ACK. Zeek
  writes `(c$fp$ja4l$ack - c$fp$ja4l$synack) / 2.0` at `zeek/ja4l/main.zeek:105`.
  Wireshark measures `timestamp_C` against `timestamp_B` at
  `wireshark/source/packet-ja4.c:1381`. Rust measures `t_c` against `t_b` at
  `rust/ja4/src/time/tcp.rs:179`. Python measures `C` against `B` at `python/ja4.py:160`.
- **R8** — On a QUIC connection, part a of JA4L measures the client handshake packet
  against the last server handshake packet. Zeek writes
  `(c$fp$ja4l$client_handshake - c$fp$ja4l$server_handshake) / 2.0` at
  `zeek/ja4l/main.zeek:241`. Wireshark measures `timestamp_D` against `timestamp_C` at
  `wireshark/source/packet-ja4.c:1445`. Rust measures `t_d` against `t_c` at
  `rust/ja4/src/time/udp.rs:230`. Python measures `D` against `C` at `python/ja4.py:164`.
- **R9** — Zeek writes no JA4L value when the interval is negative. Zeek returns at
  `zeek/ja4l/main.zeek:110`, and reports an error at `zeek/ja4l/main.zeek:108`.
- **R10** — Zeek states that JA4L cannot work when the packets arrive out of order. Zeek
  holds the comment `# NOTE: JA4L can not work when traffic is out of order` at
  `zeek/ja4l/main.zeek:7`.

### Part b — the observed TTL

- **R11** — Part b holds the observed TTL, which the image labels `Observed TTL`. Zeek
  writes `c$fp$ja4l$ttl_c` at `zeek/ja4l/main.zeek:114`. Wireshark writes
  `conn->client_ttl` at `wireshark/source/packet-ja4.c:1385`. Rust writes `client_ttl` at
  `rust/ja4/src/time/tcp.rs:186`. Python writes `conn['client_ttl']` at
  `python/ja4.py:159`.
- **R12** — Part b of JA4L holds the TTL of the client SYN. Zeek reads `rp$ip$ttl` in
  `new_connection` at `zeek/ja4l/main.zeek:91`. Wireshark stores `curr_ttl` on the SYN at
  `wireshark/source/packet-ja4.c:1272`. Rust reads the TTL on the SYN at
  `rust/ja4/src/time/tcp.rs:214`.
- **R13** — Part b holds the value the packet carries, and no implementation subtracts it
  from an initial TTL. Zeek writes the field unchanged at `zeek/ja4l/main.zeek:114`. Rust
  writes the field unchanged at `rust/ja4/src/time/tcp.rs:186`.

### Part c — the application handshake latency

- **R14** — Part c holds the one-way application handshake latency, which the image labels
  `One-way application handshake latency`. Zeek appends it at
  `zeek/ja4l/main.zeek:133`. Wireshark writes it at
  `wireshark/source/packet-ja4.c:1385`.
- **R15** — Part c of JA4L measures the first client data packet after the server hello.
  Zeek writes `(c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / 2.0` at
  `zeek/ja4l/main.zeek:125`. Wireshark measures `timestamp_F` against `timestamp_E` at
  `wireshark/source/packet-ja4.c:1382`.
- **R16** — Zeek waits for a packet that carries data, and skips a bare ACK. Zeek tests
  `rp$tcp$dl == 0` at `zeek/ja4l/main.zeek:119`. Wireshark tests `tcp_len > 0` at
  `wireshark/source/packet-ja4.c:1320`.

### What the image alone states

- **R17** — The image states four initial TTL groups: `Initial TTL 64   - Mac, Linux,
  Phones, IoT`, `Initial TTL 128 - Windows`, `Initial TTL 255 - Cisco, F5, Networking
  Devices`, and `Estimated Hop Count = Estimated Initial TTL - Observed TTL`. The image
  alone states this rule.
- **R18** — No reference implementation writes an estimated hop count into a JA4L value.
  Python defines `hops` at `python/ja4.py:140` and calls it nowhere in that file. That
  definition holds `initial_ttl = 54` at `python/ja4.py:142`, and the image states 64.
- **R19** — The image states the distance formula `D = jc/p`, where `D = Distance`,
  `j = JA4L_a (or delta between JA4L_a and JA4L_c in the case of VPNs)`,
  `c = Speed of light per µs in fiber (0.128 miles or 0.206 km per µs)` and
  `p = Propagation delay factor`. The image alone states this rule.
- **R20** — The image states one propagation delay factor per hop count. The image alone
  states this rule.

  | Hop Count | Propagation Delay Factor |
  |---|---|
  | `<=21` | `1.5` |
  | `22` | `1.6` |
  | `23` | `1.7` |
  | `24` | `1.8` |
  | `25` | `1.9` |
  | `>=26` | `2.0` |

- **R21** — The image states the worked example `5191x0.128/1.6 = 415 miles (distance of
  VPN exit node from server)`, `45014-5191 = 39823µs (delta between client and VPN exit
  node)` and `39823x0.128/1.6 = 3,185 miles (distance of client from VPN exit node)`. The
  image alone states this rule.
- **R22** — No reference implementation computes a distance. The image states the formula
  for a reader, and Zeek, Wireshark, Rust and Python each write only the parts that R5, R11
  and R14 name. Zeek writes the whole value at `zeek/ja4l/main.zeek:112`.

### What the implementations add

- **R23** — Zeek and Wireshark publish a JA4L delta value that the image does not state.
  Zeek writes `ja4l_delta` at `zeek/ja4l/main.zeek:269`. Wireshark registers
  `ja4.ja4l_delta` at `wireshark/source/packet-ja4.c:1734` and writes it at
  `wireshark/source/packet-ja4.c:1391`.
- **R24** — The JA4L delta is the ratio of the application handshake interval to the
  transport handshake interval. Zeek writes
  `(c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / client_denom` at
  `zeek/ja4l/main.zeek:269`. Wireshark writes `(double)latency2.nsecs / (double)latency.nsecs`
  at `wireshark/source/packet-ja4.c:1389`.

### What each implementation states about JA4LS

**No image specifies JA4LS.** These rules record the implementations, and they replace no
image.

- **R25** — Every reference implementation publishes a JA4LS value. Zeek writes `ja4ls` at
  `zeek/ja4l/main.zeek:60`. Wireshark registers `ja4.ja4ls` at
  `wireshark/source/packet-ja4.c:1735`. Rust writes `ja4l_s` at `rust/ja4/src/time.rs:21`.
  Python writes `JA4L-S` at `python/ja4.py:157`.
- **R26** — Part a of JA4LS measures the SYN-ACK against the SYN on a TCP connection. Zeek
  writes `(c$fp$ja4l$synack - c$fp$ja4l$syn) / 2.0` at `zeek/ja4l/main.zeek:151`.
  Wireshark measures `timestamp_B` against `timestamp_A` at
  `wireshark/source/packet-ja4.c:1369`. Rust measures `t_b` against `t_a` at
  `rust/ja4/src/time/tcp.rs:182`. Python measures `A` against `B` at `python/ja4.py:155`.
- **R27** — Part b of JA4LS holds the TTL of the server SYN-ACK. Zeek reads it at
  `zeek/ja4l/main.zeek:145`. Wireshark stores `conn->server_ttl` at
  `wireshark/source/packet-ja4.c:1286`. Rust reads the TTL on the SYN-ACK at
  `rust/ja4/src/time/tcp.rs:215`.
- **R28** — Part c of JA4LS measures the server hello against the client hello. Zeek writes
  `(c$fp$ja4l$server_hello - c$fp$ja4l$client_hello) / 2.0` at `zeek/ja4l/main.zeek:184`.
  Wireshark measures `timestamp_E` against `timestamp_D` at
  `wireshark/source/packet-ja4.c:1370`.

### Reference splits

- **R29** — **Reference split.** Zeek and Wireshark write three parts, and Rust and Python
  write two parts. Zeek appends part c at `zeek/ja4l/main.zeek:133`. Wireshark writes three
  parts at `wireshark/source/packet-ja4.c:1383`. Rust writes two parts at
  `rust/ja4/src/time/tcp.rs:186`. Python writes two parts at `python/ja4.py:161`.
  **Issue #127 holds the question.**
- **R30** — **Reference split.** Wireshark writes the literal `tcp` in the third position
  on an HTTP connection, and Zeek writes no such marker. Wireshark writes the format
  `"%d_%d_tcp"` at `wireshark/source/packet-ja4.c:1348` and at
  `wireshark/source/packet-ja4.c:1354`. Zeek writes part c only as a latency, at
  `zeek/ja4l/main.zeek:133`. **Issue #127 holds the question.**
- **R31** — **Reference split.** The four implementations write three different third parts
  on a QUIC connection. Zeek writes `"q"` at `zeek/ja4l/main.zeek:233` and at
  `zeek/ja4l/main.zeek:252`. Wireshark writes the format `"%d_%d_quic"` at
  `wireshark/source/packet-ja4.c:1441` and at `wireshark/source/packet-ja4.c:1447`. Rust
  writes no marker at `rust/ja4/src/time/udp.rs:237`. Python writes no marker at
  `python/ja4.py:165`. **Issue #127 holds the question.**
- **R32** — **Reference split.** Zeek and Rust read the IPv6 hop limit as the observed TTL,
  and Wireshark reads no IPv6 field. Zeek reads `rp$ip6$hlim` at `zeek/ja4l/main.zeek:93`.
  Rust reads `ipv6.hlim` at `rust/ja4/src/time.rs:66`. Wireshark reads only `ip.ttl` at
  `wireshark/source/packet-ja4.c:1218`. **Issue #128 holds the question.**
