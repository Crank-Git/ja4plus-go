# The FoxIO Zeek package

This page records the reading of the FoxIO Zeek package. It states what the package
computes, what it does not compute, and which values this project declines to treat as a
reference value.

**This project read the package at FoxIO commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.** `testdata/foxio.pin` holds the same commit.
Read the package at <https://github.com/FoxIO-LLC/ja4/tree/main/zeek>.

Every claim below cites a file and a line, in the form `zeek/<file>:<line>`. The path is
relative to the root of the FoxIO repository, and never to the `zeek/` directory. **Join
it to `testdata/foxio/reference/`.** Read `zeek/ja4l/main.zeek:112` as line 112 of
`testdata/foxio/reference/zeek/ja4l/main.zeek`. `docs/specs/foxio/README.md` states the
rule, and it names each path that the rule does not cover.

**A transcription records, and it never decides.** This page states what the Zeek package
holds. A ruling belongs to the maintainer, and `.claude/rules/rulings.md` states where a
ruling lands.

## The rank of a Zeek value

`.claude/rules/rulings.md` ranks a Zeek baseline fourth. A FoxIO image decides the schema.
A FoxIO reference implementation decides the behaviour that the image leaves silent. **A
Zeek value is not a reference value for every method**, and this page names each exception.

## What the package computes

The package writes each fingerprint into the log of the protocol it reads. `zeek/README.md`
lines 6 to 16 state the mapping, and the table below cites the line that assembles each
value.

| Method | Log | Field | Where the package assembles the value |
|---|---|---|---|
| JA4 | `ssl.log` | `ja4` | `zeek/ja4/main.zeek:155` |
| JA4 raw | `ssl.log` | `ja4_r` | `zeek/ja4/main.zeek:162` |
| JA4 original order | `ssl.log` | `ja4_o` | `zeek/ja4/main.zeek:177` |
| JA4 raw, original order | `ssl.log` | `ja4_ro` | `zeek/ja4/main.zeek:184` |
| JA4S | `ssl.log` | `ja4s` | `zeek/ja4s/main.zeek:171` |
| JA4H | `http.log` | `ja4h` | `zeek/ja4h/main.zeek:208` |
| JA4L | `conn.log` | `ja4l` | `zeek/ja4l/main.zeek:112` |
| JA4LS | `conn.log` | `ja4ls` | `zeek/ja4l/main.zeek:158` |
| JA4T | `conn.log` | `ja4t` | `zeek/ja4t/main.zeek:196` |
| JA4TS | `conn.log` | `ja4ts` | `zeek/ja4t/main.zeek:214` |
| JA4SSH | `ja4ssh.log` | `ja4ssh` | `zeek/ja4ssh/main.zeek:79` |
| JA4D | `ja4d.log` | `ja4d` | `zeek/ja4d/main.zeek:113` |

`zeek/config.zeek:4` sets the part delimiter: `option delimiter: string = "_";`.
`zeek/config.zeek:7` to `zeek/config.zeek:26` hold one switch per method.

`zeek/utils/common.zeek:63` holds the shared hash function. It returns `000000000000` for
an empty input, at `zeek/utils/common.zeek:65`. It truncates the SHA-256 digest to 12
characters, at `zeek/utils/common.zeek:69`.

## What the package does not compute

| Method | Evidence |
|---|---|
| JA4X | `zeek/ja4x/__load__.zeek:1` holds one line, `# empty`. `zeek/config.zeek:24` sets `option JA4X_enabled:   bool = F;`. `zeek/README.md:16` states `(awaiting Zeek object support)`. |
| JA4D6 | The package holds no module for it. `zeek/README.md:15` states `(awaiting Zeek DHCPv6 suppport)`. |
| JA4TScan | The package holds no module for it, and FoxIO publishes no material for it. |

**Read a missing method as no evidence, and never as a value of zero.** For JA4X and JA4D6
the Zeek package states nothing, so it corroborates nothing.

## The values this project declines

### JA4L and JA4LS

`docs/specs/features/11-foxio-reference.md` states that a Zeek baseline is not a reference
value for every method, and it names JA4L and JA4LS. The reading below holds the evidence.

1. **Zeek writes a third component into `ja4l`.** `zeek/ja4l/main.zeek:132` and
   `zeek/ja4l/main.zeek:133` append `(first_client_data - server_hello) / 2` to the value
   that `zeek/ja4l/main.zeek:112` already built. The deleted specification states two
   components: `JA4L-C = {(C - B) / 2}_Client TTL`, at `JA4L.md:19`.
2. **Zeek writes a third component into `ja4ls`.** `zeek/ja4l/main.zeek:191` and
   `zeek/ja4l/main.zeek:192` append `(server_hello - client_hello) / 2`. `JA4L.md:20`
   states `JA4L-S = {(B - A) / 2}_Server TTL`.
3. **Zeek appends `q` for QUIC.** `zeek/ja4l/main.zeek:233` appends `"q"` to `ja4ls`, and
   `zeek/ja4l/main.zeek:252` appends `"q"` to `ja4l`. `JA4L.md:36` and `JA4L.md:37` state
   the QUIC formula, and they state no such marker.
4. **Zeek writes two fields that no FoxIO method defines.**
   `zeek/ja4l/main.zeek:269` writes `ja4l_delta`, and `zeek/ja4l/main.zeek:274` writes
   `ja4ls_delta`. Each field holds a ratio of two durations, and it is not a fingerprint.
5. **Zeek states its own limit.** `zeek/ja4l/main.zeek:7` states
   `# NOTE: JA4L can not work when traffic is out of order`, and
   `zeek/ja4l/main.zeek:10` states
   `# NOTE: Zeek JA4L does not attempt to handle duplicate packets.`

`docs/specs/foxio/deleted-text-specifications.md` holds the `JA4L.md` text. The image
`JA4L.png` decides the JA4L schema, and the deleted text corroborates it.
`docs/specs/features/11-foxio-reference.md` states that no image specifies JA4LS, so the
deleted text is the primary source for the JA4LS schema.

### The two Zeek latency ratios

This project declines `ja4l_delta` and `ja4ls_delta` as a reference value for any method.
FoxIO defines no method that emits either field. `zeek/ja4l/main.zeek:269` and
`zeek/ja4l/main.zeek:274` write them with the format `%.1f`.

### The Zeek JA4TS delay

**This project declines the Zeek JA4TS delay.** Zeek truncates each delay to a whole
second. This project rounds each delay to the nearest whole second, half away from zero.

1. **Zeek truncates the SYN-ACK delay.** `zeek/ja4t/main.zeek:180` holds
   `c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;`. The
   operator `/` on two `count` values of microseconds discards the remainder.
   `zeek/ja4t/main.zeek:162` writes the 120-second timeout as `120000000`, which states the
   unit.
2. **Zeek truncates the reset delay.** `zeek/ja4t/main.zeek:233` holds
   `c$conn$ja4ts += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000);`.
3. **Wireshark rounds.** `wireshark/source/packet-ja4.c:277` holds
   `return (int64_t)(round(nstime_to_sec(&result)));`. `wireshark/source/packet-ja4.c:694`
   calls the same function for the reset delay.
4. **The deleted text corroborates Wireshark.** `JA4T.md:86` holds this sentence:

> To find the delay between them we start with the timestamp of the first SYNACK and subtract it from the next SYNACK, rounding the result to the nearest whole number in seconds.

A delay of 1.6 seconds reaches `1` in Zeek and `2` in Wireshark.

**This reading adopts the port's ruling, and it is not a ruling of this project.** The
Python port settled the question first. `docs/specs/foxio/JA4T.md` in `Crank-Git/ja4plus`,
at commit `21299645366591331eb93155355b65a76a3729f3`, holds R12 rule 2, and that rule
states the same three readings. `.claude/rules/parity.md` rule 2 states that the port
decides where FoxIO specifies nothing and where this project shipped no name. `JA4T.png`
labels part `e` as `TCP Retransmission Timings (only on JA4TScan)` and states no rounding
rule, so the rank-1 image is silent.

**Reverse this reading in the port, and never here alone.** Epic 8b builds JA4TS part e,
and it consumes the reading.

## Per-method readings

Each reading below records what the Zeek package holds. None of them decides a value.

### JA4

- `zeek/ja4/main.zeek:141` and `zeek/ja4/main.zeek:142` remove the server-name extension
  and the ALPN extension from the sorted extension list.
- `zeek/ja4/main.zeek:100` counts every extension, and it keeps the two the hash list
  drops.
- `zeek/ja4/main.zeek:90` and `zeek/ja4/main.zeek:97` cap each count at `99`.
- `zeek/ja4/main.zeek:86` builds the ALPN characters from the first ALPN value.
- `zeek/ja4/main.zeek:104` sets the version to `00` when the version map holds no entry.
  `zeek/ja4/main.zeek:103` holds this comment:

```
# TODO - Investigate zeek bug returning invalid versions (testing\tls-bad-version.pcapng)
```

### JA4S

- `zeek/ja4s/main.zeek:166` keeps the server extension order, and it sorts nothing.
- `zeek/ja4s/main.zeek:91` drops a GREASE extension code.
- `zeek/ja4s/main.zeek:123` takes the highest non-GREASE value of the supported-versions
  extension.
- `zeek/ja4s/main.zeek:105` reads the first server ALPN value.
  `zeek/ja4s/main.zeek:103` states that the module assumes one server ALPN value.

### JA4H

- `zeek/ja4h/main.zeek:92` builds `header_names` without the cookie header and without the
  referer header. The `b` hash reads that list, at `zeek/ja4h/main.zeek:194`.
- `zeek/ja4h/main.zeek:80` builds `header_names_o` from every header.
  `zeek/ja4h/main.zeek:193` formats that list, and `zeek/ja4h/main.zeek:210` writes it into
  the `ja4h_ro` value. **The two lists differ**, so the Zeek `ja4h_ro` value holds the
  cookie header and the referer header.
- `zeek/ja4h/main.zeek:112` to `zeek/ja4h/main.zeek:122` map nine HTTP methods.
- `zeek/ja4h/main.zeek:96` and `zeek/ja4h/main.zeek:97` take the primary language, and they
  remove each hyphen.
- `zeek/ja4h/main.zeek:175` and `zeek/ja4h/main.zeek:182` sort the cookie names and the
  cookie values with `strcmp`.

### JA4T and JA4TS

- `zeek/ja4t/main.zeek:126` reads the SYN packet only when the TCP flags equal `TH_SYN`
  exactly. A SYN packet that carries an ECN flag reaches no fingerprint.
- `zeek/ja4t/main.zeek:201` writes `00` for an empty TCP option list, and
  `zeek/ja4t/main.zeek:207` writes `00` for a window scale of zero.
- `zeek/ja4t/main.zeek:185` stops at ten retransmission delays, and
  `zeek/ja4t/main.zeek:162` stops 120 seconds after the last SYN-ACK. `JA4T.md:106` states
  the same two limits.
- `zeek/ja4t/main.zeek:232` appends the reset delay only when the delay list holds at least
  one value.
- `zeek/ja4t/main.zeek:66` returns an empty option set when the link layer is not Ethernet.

### JA4SSH

- `zeek/ja4ssh/main.zeek:28` sets the sample size: `option ja4_ssh_packet_count = 200;`.
- `zeek/ja4ssh/main.zeek:79` builds the value with the format
  `"c%ds%d_c%ds%d_c%ds%d"`.
- `zeek/ja4ssh/main.zeek:69` breaks a tie in the packet-length mode toward the lower
  value.
- `zeek/ja4ssh/main.zeek:123` counts an acknowledgment packet only when the TCP flags
  equal `0x10` exactly.
- `zeek/ja4ssh/main.zeek:161` writes a final value at the end of the connection, and that
  value can hold fewer than 200 packets.

### JA4D

- `zeek/ja4d/main.zeek:113` to `zeek/ja4d/main.zeek:118` assemble the value.
- `zeek/ja4d/main.zeek:84` removes each option in `DHCP_SKIP_OPTIONS` from the option list.
- `zeek/ja4d/main.zeek:82` and `zeek/ja4d/main.zeek:89` write `00` for an empty list.
- `zeek/ja4d/main.zeek:125` writes one value per DHCP message, and it aggregates no
  conversation.

### A shared list helper

`zeek/utils/common.zeek:30` appends the delimiter when the index is lower than the last
index. The function also holds a `skip` set, at `zeek/utils/common.zeek:26`. **When the
skipped value is the last value, the output keeps a trailing delimiter.**
`zeek/ja4d/main.zeek:84` is the one call that passes a `skip` set.

## Where the Zeek package is silent

- The package states no rule for JA4X, for JA4D6 and for JA4TScan.
- The package states no rule for a JA4LS value that a QUIC connection produces from the
  server side alone. `zeek/ja4l/main.zeek:229` builds the QUIC `ja4ls` value from the two
  initial packets.
- The package states no raw variant for JA4L, for JA4T, for JA4TS, for JA4SSH and for
  JA4D. `zeek/config.zeek` holds a `_raw` switch for JA4, for JA4S and for JA4H only.

## How to reproduce the reading

```
git clone https://github.com/FoxIO-LLC/ja4.git
cd ja4
git checkout 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8
```

Then read each file this page cites.
