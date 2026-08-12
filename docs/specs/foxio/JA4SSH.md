# JA4SSH — transcription of `JA4SSH.png`

This page transcribes one FoxIO image as numbered rules. **The page records what each
source states. The page decides no value.** `.claude/rules/rulings.md` states who rules.

`docs/specs/foxio/README.md` holds the inventory and the pinned commit.

## The source

| Fact | Value |
|---|---|
| Image | <https://github.com/FoxIO-LLC/ja4/blob/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details/JA4SSH.png> |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-11 |

**This page reproduces no image.** The link above reaches it.

A citation names a file of the FoxIO repository at the pinned commit. Read
`zeek/ja4ssh/main.zeek:79` as line 79 of that file at that commit.

## The rules

### The schema

- **R1** — The image titles itself `JA4SSH: SSH Traffic Fingerprint`, and subtitles itself
  `(fingerprints SSH sessions)`. The image alone states this rule.
- **R2** — The image holds the example value `JA4SSH=c36s36_c55s75_c70s0`. The image alone
  states this rule.
- **R3** — A value holds three parts, which the image labels `a`, `b` and `c`. The image
  alone states this rule.
- **R4** — Each part holds one client value and one server value. The letter `c` marks the
  client value, and the letter `s` marks the server value. Zeek writes the format
  `"c%ds%d_c%ds%d_c%ds%d"` at `zeek/ja4ssh/main.zeek:79`. Wireshark writes the same format
  at `wireshark/source/packet-ja4.c:656`. Rust writes
  `"c{mode_client}s{mode_server}_c{nr_ssh_client_packets}s{nr_ssh_server_packets}_c{nr_tcp_client_acks}s{nr_tcp_server_acks}"`
  at `rust/ja4/src/ssh.rs:288`. Python writes the same shape at `python/ja4ssh.py:152`.
- **R5** — An underscore separates one part from the next part. Zeek writes it inside the
  format at `zeek/ja4ssh/main.zeek:79`. Wireshark writes it inside the format at
  `wireshark/source/packet-ja4.c:656`.

### The window

- **R6** — The method produces one value for every 200 SSH packets, which the image labels
  `(runs every 200 SSH packets by default)`. Zeek holds
  `option ja4_ssh_packet_count = 200` at `zeek/ja4ssh/main.zeek:28`. Wireshark holds
  `#define SAMPLE_COUNT 200` at `wireshark/source/packet-ja4.c:33`. Rust defaults
  `ssh.sample_size` to `200` at `rust/ja4/src/conf.rs:61`. Python holds
  `ssh_sample_count = 200` at `python/ja4.py:439`.
- **R7** — The window counts SSH packets, and it counts no bare ACK. Zeek counts the two
  payload vectors at `zeek/ja4ssh/main.zeek:140`. Wireshark counts a packet that carries
  `ssh.direction` at `wireshark/source/packet-ja4.c:1472`. Rust counts the two SSH packet
  counters at `rust/ja4/src/ssh.rs:35`. Python counts a packet that carries SSH at
  `python/ja4ssh.py:99`.
- **R8** — The counters reset after each window. Zeek clears them at
  `zeek/ja4ssh/main.zeek:88`. Wireshark clears them at
  `wireshark/source/packet-ja4.c:1485`.
- **R9** — Zeek, Wireshark and Rust each write one value for an open window at the end of
  the connection. Zeek writes it at `zeek/ja4ssh/main.zeek:162`. Wireshark writes it on a
  FIN+ACK packet at `wireshark/source/packet-ja4.c:1402`. Rust writes it at
  `rust/ja4/src/ssh.rs:52`.

### Part a — the mode of the packet length

- **R10** — Part a holds the mode of the client packet length and the mode of the server
  packet length, which the image labels `Mode of Client Packet Length` and
  `Mode of Server Packet Length`. Zeek computes it at `zeek/ja4ssh/main.zeek:80`.
  Wireshark computes it at `wireshark/source/packet-ja4.c:656`. Rust computes it at
  `rust/ja4/src/ssh.rs:284`. Python computes it at `python/ja4ssh.py:146`.
- **R11** — The mode reads the TCP payload length. Zeek reads `rp$tcp$dl` at
  `zeek/ja4ssh/main.zeek:127`. Wireshark reads `tcp_len` at
  `wireshark/source/packet-ja4.c:1477`. Rust reads `tcp.len` at `rust/ja4/src/ssh.rs:235`.
- **R12** — Where two lengths appear the same number of times, the smaller length is the
  mode. Zeek tests `freq == max && idx < mode` at `zeek/ja4ssh/main.zeek:69`. Wireshark
  tests `pkt_len < max_mode` at `wireshark/source/packet-ja4.c:410`. Rust calls
  `min_key_with_max_value` at `rust/ja4/src/ssh.rs:284`. Python writes
  `min(k for k, v in counts.items() if v == max_count)` at `python/ja4ssh.py:54`. The image
  states no tie rule.
- **R13** — The mode is `0` when the side sent no SSH packet. Zeek defaults `mode` to `0`
  at `zeek/ja4ssh/main.zeek:63`. Wireshark defaults `max_mode` to `0` at
  `wireshark/source/packet-ja4.c:400`. Rust writes `unwrap_or(0)` at
  `rust/ja4/src/ssh.rs:284`. Python returns `0` at `python/ja4ssh.py:51`.

### Part b — the SSH packet counts

- **R14** — Part b holds the count of SSH packets from each side, which the image labels
  `SSH packets sent from client` and `SSH packets sent from server`. Zeek writes the two
  vector lengths at `zeek/ja4ssh/main.zeek:82`. Wireshark writes `conn->client_pkts` and
  `conn->server_pkts` at `wireshark/source/packet-ja4.c:657`. Rust writes
  `nr_ssh_client_packets` and `nr_ssh_server_packets` at `rust/ja4/src/ssh.rs:288`. Python
  writes `client_packets` and `server_packets` at `python/ja4ssh.py:152`.

### Part c — the bare ACK counts

- **R15** — Part c holds the count of bare ACKs from each side, which the image labels
  `Bare ACKs sent from client` and `Bare ACKs sent from server`. Zeek writes `orig_ack` and
  `resp_ack` at `zeek/ja4ssh/main.zeek:84`. Wireshark writes `conn->tcp_client_acks` and
  `conn->tcp_server_acks` at `wireshark/source/packet-ja4.c:658`. Rust writes
  `nr_tcp_client_acks` and `nr_tcp_server_acks` at `rust/ja4/src/ssh.rs:288`.
- **R16** — A bare ACK is a packet whose TCP flags equal `0x10` and whose payload is empty.
  Zeek tests `rp$tcp$dl == 0` and `rp$tcp$flags == 0x10` at
  `zeek/ja4ssh/main.zeek:122-123`.
  Wireshark tests `(tcp_flags == 0x010) && (tcp_len == 0)` at
  `wireshark/source/packet-ja4.c:1302`. Rust holds
  `const BARE_ACK_FLAG: &str = "0x0010";` at `rust/ja4/src/ssh.rs:228`. Python tests
  `flags == 0x0010 and tcp_len == 0` at `python/ja4ssh.py:112`.
- **R17** — The image states that the initiating side sends the bare ACKs, and it writes
  `Bare ACKs are sent from the initiating side (eg. side doing the typing)`. The image
  alone states this rule.

### The worked examples

- **R18** — The image holds the example `Interactive SSH Session = c36s36_c51s80_c69s0`,
  and it explains the value as `Padded to 36 (minimum length over chacha20-poly1305), all
  ACKs from client`. The image alone states this rule.
- **R19** — The image holds the example `Reverse SSH Session = c76s76_c71s59_c0s70`, and it
  explains the value as `Double Padded to 76, all ACKs from server`. The image alone states
  this rule.
- **R20** — The image holds the example
  `WinSCP File Transfer to Client = c112s1460_c0s179_c21s0`, and it explains the value as
  `Max window from server 1460, all ACKs from client`. The image alone states this rule.

### What the implementations add

- **R21** — Rust writes no value when neither side sent an SSH packet. Rust returns `None`
  at `rust/ja4/src/ssh.rs:273`, under the comment
  `// This doesn't seem to be an *SSH* TCP stream after all.` at
  `rust/ja4/src/ssh.rs:272`.
- **R22** — Zeek writes a value only for a connection that carries an SSH version exchange.
  Zeek sets `is_ssh` in `ssh_client_version` at `zeek/ja4ssh/main.zeek:146` and tests it at
  `zeek/ja4ssh/main.zeek:161`.

### Reference splits

- **R23** — **Reference split.** Wireshark and Python decide the bare ACK side from the TCP
  port 22, and Zeek and Rust decide it from the connection direction. Wireshark tests
  `dstport == 22` at `wireshark/source/packet-ja4.c:1303` and `srcport == 22` at
  `wireshark/source/packet-ja4.c:1306`. Python tests the same two ports at
  `python/ja4ssh.py:113` and `python/ja4ssh.py:115`. Zeek reads `is_orig` at
  `zeek/ja4ssh/main.zeek:119`. Rust reads the sender at `rust/ja4/src/ssh.rs:247`. An SSH
  connection on another port reaches a bare ACK count in Zeek and in Rust, and a count of
  zero in Wireshark and in Python. **Issue #129 holds the question.**
