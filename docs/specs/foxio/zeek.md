# The FoxIO Zeek package

This page records the reading of the FoxIO Zeek package. It states what the package
computes, what it does not compute, and which values this project declines to treat as a
reference value.

**This project read the package at FoxIO commit
`16b96d95c220762cf658f67d678cda2aac95c81e`.** `testdata/foxio.pin` holds the same commit. FoxIO replaced the script package with a compiled plugin after `27f0cbf9`, so the plugin code sits under `zeek/src/` and each remaining script sits under `zeek/scripts/fingerprints/`.
Read the package at <https://github.com/FoxIO-LLC/ja4/tree/main/zeek>.

Every claim below cites a file and a line, in the form `zeek/<file>:<line>`. The path is
relative to the root of the FoxIO repository, and never to the `zeek/` directory. **Join
it to `testdata/foxio/reference/`.** Read `zeek/scripts/fingerprints/ja4l/main.zeek:113` as line 113 of
`testdata/foxio/reference/zeek/scripts/fingerprints/ja4l/main.zeek`. `docs/specs/foxio/README.md` states the
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
lines 9 to 24 state the mapping, and the table below cites the line that assembles each
value.

| Method | Log | Field | Where the package assembles the value |
|---|---|---|---|
| JA4 | `ssl.log` | `ja4` | `zeek/src/ja4.cc:212-214` |
| JA4 raw | `ssl.log` | `ja4_r` | `zeek/src/ja4.cc:219-221` |
| JA4 original order | `ssl.log` | `ja4_o` | `zeek/src/ja4.cc:232-233` |
| JA4 raw, original order | `ssl.log` | `ja4_ro` | `zeek/src/ja4.cc:237-238` |
| JA4S | `ssl.log` | `ja4s` | `zeek/src/ja4s.cc:97` |
| JA4H | `http.log` | `ja4h` | `zeek/src/ja4h.cc:69` |
| JA4L | `conn.log` | `ja4l` | `zeek/scripts/fingerprints/ja4l/main.zeek:113` |
| JA4LS | `conn.log` | `ja4ls` | `zeek/scripts/fingerprints/ja4l/main.zeek:157` |
| JA4T | `conn.log` | `ja4t` | `zeek/scripts/fingerprints/ja4t/main.zeek:132` |
| JA4TS | `conn.log` | `ja4ts` | `zeek/scripts/fingerprints/ja4t/main.zeek:150` |
| JA4SSH | `ja4ssh.log` | `ja4ssh` | `zeek/src/ja4ssh.cc:66-72` |
| JA4D | `ja4d.log` | `ja4d` | `zeek/scripts/fingerprints/ja4d/main.zeek:106` |

`zeek/scripts/fingerprints/config.zeek:4` sets the part delimiter: `option delimiter: string = "_";`.
`zeek/scripts/fingerprints/config.zeek:7` to `zeek/scripts/fingerprints/config.zeek:24` hold one switch per method.

`zeek/scripts/fingerprints/utils/common.zeek:63` holds the shared hash function. It returns `000000000000` for
an empty input, at `zeek/scripts/fingerprints/utils/common.zeek:65`. It truncates the SHA-256 digest to 12
characters, at `zeek/scripts/fingerprints/utils/common.zeek:69`.

## What the package does not compute

| Method | Evidence |
|---|---|
| JA4X | `zeek/scripts/fingerprints/ja4x/__load__.zeek:1` holds one line, `# empty (awaiting Zeek object support)`. `zeek/scripts/fingerprints/config.zeek:26` sets `option JA4X_enabled:   bool = F;`. `zeek/README.md:24` states `(awaiting Zeek object support)`. |
| JA4D6 | The package holds no module for it. `zeek/README.md:23` states `(awaiting Zeek DHCPv6 suppport)`. |
| JA4TScan | The package holds no module for it, and FoxIO publishes no material for it. |

**Read a missing method as no evidence, and never as a value of zero.** For JA4X and JA4D6
the Zeek package states nothing, so it corroborates nothing.

## The values this project declines

### JA4L and JA4LS

`docs/specs/features/11-foxio-reference.md` states that a Zeek baseline is not a reference
value for every method, and it names JA4L and JA4LS. The reading below holds the evidence.

1. **Zeek writes a third component into `ja4l`.** `zeek/scripts/fingerprints/ja4l/main.zeek:133` and
   `zeek/scripts/fingerprints/ja4l/main.zeek:134` append `(first_client_data - server_hello) / 2` to the value
   that `zeek/scripts/fingerprints/ja4l/main.zeek:113` already built. The deleted specification states two
   components: `JA4L-C = {(C - B) / 2}_Client TTL`, at `JA4L.md:19`.
2. **Zeek writes a third component into `ja4ls`.** `zeek/scripts/fingerprints/ja4l/main.zeek:190` and
   `zeek/scripts/fingerprints/ja4l/main.zeek:191` append `(server_hello - client_hello) / 2`. `JA4L.md:20`
   states `JA4L-S = {(B - A) / 2}_Server TTL`.
3. **Zeek appends `q` for QUIC.** `zeek/scripts/fingerprints/ja4l/main.zeek:232` appends `"q"` to `ja4ls`, and
   `zeek/scripts/fingerprints/ja4l/main.zeek:251` appends `"q"` to `ja4l`. `JA4L.md:36` and `JA4L.md:37` state
   the QUIC formula, and they state no such marker.
4. **Zeek writes two fields that no FoxIO method defines.**
   `zeek/scripts/fingerprints/ja4l/main.zeek:268` writes `ja4l_delta`, and `zeek/scripts/fingerprints/ja4l/main.zeek:273` writes
   `ja4ls_delta`. Each field holds a ratio of two durations, and it is not a fingerprint.
5. **Zeek states its own limit.** `zeek/scripts/fingerprints/ja4l/main.zeek:7` states
   `# NOTE: JA4L can not work when traffic is out of order`. The script at the pin holds
   no note about duplicate packets, and the script at `27f0cbf9` held one.

`docs/specs/foxio/deleted-text-specifications.md` holds the `JA4L.md` text. The image
`JA4L.png` decides the JA4L schema, and the deleted text corroborates it.
`docs/specs/features/11-foxio-reference.md` states that no image specifies JA4LS, so the
deleted text is the primary source for the JA4LS schema.

### The two Zeek latency ratios

This project declines `ja4l_delta` and `ja4ls_delta` as a reference value for any method.
FoxIO defines no method that emits either field. `zeek/scripts/fingerprints/ja4l/main.zeek:268` and
`zeek/scripts/fingerprints/ja4l/main.zeek:273` write them with the format `%.1f`.

### The Zeek JA4TS delay

**This project declines the Zeek JA4TS delay.** Zeek truncates each delay to a whole
second. This project rounds each delay to the nearest whole second, half away from zero.

1. **Zeek truncates the SYN-ACK delay.** `zeek/scripts/fingerprints/ja4t/main.zeek:114` holds
   `c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;`. The
   operator `/` on two `count` values of microseconds discards the remainder.
   `zeek/scripts/fingerprints/ja4t/main.zeek:96` writes the 120-second timeout as `120000000`, which states the
   unit.
2. **Zeek truncates the reset delay.** `zeek/scripts/fingerprints/ja4t/main.zeek:169` holds
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

- `zeek/src/ja4.cc:198` and `zeek/src/ja4.cc:198` remove the server-name extension
  and the ALPN extension from the sorted extension list.
- `zeek/src/ja4.cc:71` counts every extension, and it keeps the two the hash list
  drops.
- `zeek/src/ja4.cc:59` and `zeek/src/ja4.cc:68` cap each count at `99`.
- `zeek/src/ja4.cc:77-80` builds the ALPN characters from the first ALPN value.
- `zeek/src/ja4.cc:43` sets the version to `00` when the version map holds no entry. The
  script at `27f0cbf9` held a `TODO` comment about invalid versions there, and the plugin at
  the pin holds no such comment.

### JA4S

- `zeek/src/ja4s.cc:92` keeps the server extension order, and it sorts nothing.
- `zeek/scripts/fingerprints/ja4s/helpers.zeek:39` drops a GREASE extension code.
- `zeek/scripts/fingerprints/ja4s/helpers.zeek:69` takes the highest non-GREASE value of the supported-versions
  extension.
- `zeek/scripts/fingerprints/ja4s/helpers.zeek:51` reads the first server ALPN value, so
  the module assumes one server ALPN value.

### JA4H

- `zeek/scripts/fingerprints/ja4h/main.zeek:91` builds `header_names` without the cookie header and without the
  referer header. The `b` hash reads that list, at `zeek/src/ja4h.cc:54`.
- `zeek/scripts/fingerprints/ja4h/main.zeek:79` builds `header_names_o` from every header.
  `zeek/src/ja4h.cc:53` formats that list, and `zeek/src/ja4h.cc:71` writes it into
  the `ja4h_ro` value. **The two lists differ**, so the Zeek `ja4h_ro` value holds the
  cookie header and the referer header.
- `zeek/scripts/fingerprints/ja4h/main.zeek:111` to `zeek/scripts/fingerprints/ja4h/main.zeek:121` map nine HTTP methods.
- `zeek/scripts/fingerprints/ja4h/main.zeek:95` and `zeek/scripts/fingerprints/ja4h/main.zeek:96` take the primary language, and they
  remove each hyphen.
- `zeek/src/ja4h.cc:58` and `zeek/src/ja4h.cc:64` sort the cookie names and the
  cookie values with `std::sort`, which compares the bytes.

### JA4T and JA4TS

- `zeek/scripts/fingerprints/ja4t/main.zeek:64` reads the SYN packet only when the TCP flags equal `TH_SYN`
  exactly. A SYN packet that carries an ECN flag reaches no fingerprint.
- `zeek/scripts/fingerprints/ja4t/main.zeek:137` writes `00` for an empty TCP option list, and
  `zeek/scripts/fingerprints/ja4t/main.zeek:143` writes `00` for a window scale of zero.
- `zeek/scripts/fingerprints/ja4t/main.zeek:119` stops at ten retransmission delays, and
  `zeek/scripts/fingerprints/ja4t/main.zeek:96` stops 120 seconds after the last SYN-ACK. `JA4T.md:106` states
  the same two limits.
- `zeek/scripts/fingerprints/ja4t/main.zeek:168` appends the reset delay only when the delay list holds at least
  one value.
- `zeek/scripts/fingerprints/ja4t/main.zeek:49` returns an empty option set when the link layer is not Ethernet.

### JA4SSH

- `zeek/scripts/fingerprints/ja4ssh/main.zeek:24` sets the sample size: `option ja4_ssh_packet_count = 200;`.
- `zeek/src/ja4ssh.cc:66-72` builds the value with the format
  `"c%ds%d_c%ds%d_c%ds%d"`.
- `zeek/src/ja4ssh.cc:35` breaks a tie in the packet-length mode toward the lower
  value.
- `zeek/scripts/fingerprints/ja4ssh/main.zeek:76` counts an acknowledgment packet only when the TCP flags
  equal `0x10` exactly.
- `zeek/scripts/fingerprints/ja4ssh/main.zeek:102` writes a final value at the end of the connection, and that
  value can hold fewer than 200 packets.

### JA4D

- `zeek/scripts/fingerprints/ja4d/main.zeek:106` to `zeek/scripts/fingerprints/ja4d/main.zeek:111` assemble the value.
- `zeek/scripts/fingerprints/ja4d/main.zeek:77` removes each option in `DHCP_SKIP_OPTIONS` from the option list.
- `zeek/scripts/fingerprints/ja4d/main.zeek:75` and `zeek/scripts/fingerprints/ja4d/main.zeek:82` write `00` for an empty list.
- `zeek/scripts/fingerprints/ja4d/main.zeek:118` writes one value per DHCP message, and it aggregates no
  conversation.

### A shared list helper

`zeek/scripts/fingerprints/utils/common.zeek:30` appends the delimiter when the index is lower than the last
index. The function also holds a `skip` set, at `zeek/scripts/fingerprints/utils/common.zeek:26`. **When the
skipped value is the last value, the output keeps a trailing delimiter.**
`zeek/scripts/fingerprints/ja4d/main.zeek:77` is the one call that passes a `skip` set.

## Where the Zeek package is silent

- The package states no rule for JA4X, for JA4D6 and for JA4TScan.
- The package states no rule for a JA4LS value that a QUIC connection produces from the
  server side alone. `zeek/scripts/fingerprints/ja4l/main.zeek:228` builds the QUIC `ja4ls` value from the two
  initial packets.
- The package states no raw variant for JA4L, for JA4T, for JA4TS, for JA4SSH and for
  JA4D. `zeek/scripts/fingerprints/config.zeek` holds a `_raw` switch for JA4, for JA4S and for JA4H only.

## How to reproduce the reading

```
git clone https://github.com/FoxIO-LLC/ja4.git
cd ja4
git checkout 16b96d95c220762cf658f67d678cda2aac95c81e
```

Then read each file this page cites.
