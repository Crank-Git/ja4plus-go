# Why the per-packet vectors publish no JA4L key for ten more captures

**This page answers the four questions of #543.** #376 read why the Wireshark per-packet
generator publishes no JA4L key for `CVE-2018-6794.pcap`, and
`docs/audit/per-packet-ja4l-absence.md` holds that reading. **This page reads the other
thirty uncovered values**, and it edits no line of that page.

**This page changes no behavior, and it moves no fingerprint value.** It writes no entry of
`testdata/deviations.json`, and it writes no `.go` file.

**Every citation of the corpus reads the pinned commit**
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. `testdata/foxio.pin` holds it.

**Every count of this page comes from one conformance run on 2026-08-14**, against
`issue/543-thirty-uncovered-per-packet-values` at `6b47541`, which is
`origin/batch/536-value-moving-repairs` at that time. **A sibling of this batch moves JA4L
values, so a later run can report other counts.**

## The four answers, in one table

| N | The question | The answer |
|---|---|---|
| 1 | Is the cluster one cause or several? | **Four causes.** Every one of the thirty falls into one of four groups, and each group names one condition of the dissector. |
| 2 | Which line bars the emission? | `wireshark/source/packet-ja4.c:1324` for group A, `wireshark/source/packet-ja4.c:1266` and `wireshark/source/packet-ja4.c:1279` for group B, and `wireshark/source/packet-ja4.c:1364` for group C and group D. |
| 3 | Does each group earn a value decline, and under which ruling? | **Ruling #196 reaches none of the thirty.** Group A declines under ruling #128, and group C and group D decline under ruling #127. **Group B needs one answer from the maintainer.** |
| 4 | Do the FoxIO implementations disagree? | **Yes, in every group, and the maintainer has already ruled three of the four splits.** `## The one question for the maintainer` below states the fourth. |

## The re-measurement

**The run of 2026-08-14 reports thirty unaccepted uncovered per-packet JA4L and JA4LS
values, and six accepted ones.** The plan of #543 predicts those two numbers, and the run
holds them.

| What | #376 measured on 2026-08-14 | The run of 2026-08-14 on this branch |
|---|---|---|
| Uncovered per-packet JA4L and JA4LS values | 36 | **36** |
| Of those, accepted by the register | 0 | **6** |
| Of those, unaccepted | 36 | **30** |
| Captures that hold the unaccepted ones | 10 | **10** |

**The six accepted ones are the six values of `CVE-2018-6794.pcap` that #376 explained.**
The register now holds them under ruling #196, and this page reads none of them.

### The ten files are eight captures

**Two pairs of the ten files hold identical bytes.** A reader who counts causes must count
captures, and not files.

| Pair | MD5 of each file |
|---|---|
| `testdata/foxio/pcap/ipv6.pcapng` and `testdata/foxio/pcap/tls-alpn-h2.pcap` | `8b180a35e9e6396c52c24a6ef48d3aea` |
| `testdata/foxio/pcap/sshv1.pcap` and `testdata/foxio/pcap/v6.pcap` | `7e6fa5da2e409b57c0937ea3328c4a21` |

**So the thirty values sit on ten corpus files, which are eight distinct captures.** Six of
the thirty repeat another six exactly.

### The thirty values

| Key | `ours` | Group |
|---|---|---|
| `gre-erspan-vxlan.pcap/2/JA4LS.1` | `997_64` | D |
| `gre-erspan-vxlan.pcap/3/JA4L.1` | `953_64` | D |
| `gre-sample.pcap/12/JA4LS.1` | `22952_236` | B |
| `gre-sample.pcap/13/JA4L.1` | `36_255` | B |
| `gre-sample.pcap/14/JA4L.1` | `26150_255` | B |
| `http-empty-useragent.pcap/2/JA4LS.1` | `26_64` | A |
| `http-empty-useragent.pcap/3/JA4L.1` | `5_64` | A |
| `http-empty-useragent.pcap/4/JA4L.1` | `10_64` | A |
| `http-empty-useragent.pcap/5/JA4L.1` | `177863_64` | A |
| `http1-with-cookies.pcapng/2/JA4LS.1` | `64_64` | C |
| `http1-with-cookies.pcapng/3/JA4L.1` | `14_64` | C |
| `http1-with-cookies.pcapng/4/JA4L.1` | `20_64` | C |
| `ipv6.pcapng/2/JA4LS.1` | `18861_59` | A |
| `ipv6.pcapng/3/JA4L.1` | `35_64` | A |
| `ipv6.pcapng/4/JA4L.1` | `3911_64` | A |
| `macos_tcp_flags.pcap/2/JA4LS.1` | `17255_63` | B |
| `macos_tcp_flags.pcap/3/JA4L.1` | `62_64` | B |
| `macos_tcp_flags.pcap/4/JA4L.1` | `393_64` | B |
| `socks4-https.pcap/2/JA4LS.1` | `40155_52` | C |
| `socks4-https.pcap/3/JA4L.1` | `119349_126` | C |
| `socks4-https.pcap/4/JA4L.1` | `119433_126` | C |
| `sshv1.pcap/17/JA4LS.1` | `28494_61` | A |
| `sshv1.pcap/18/JA4L.1` | `271_64` | A |
| `sshv1.pcap/19/JA4L.1` | `39940_64` | A |
| `tls-alpn-h2.pcap/2/JA4LS.1` | `18861_59` | A |
| `tls-alpn-h2.pcap/3/JA4L.1` | `35_64` | A |
| `tls-alpn-h2.pcap/4/JA4L.1` | `3911_64` | A |
| `v6.pcap/17/JA4LS.1` | `28494_61` | A |
| `v6.pcap/18/JA4L.1` | `271_64` | A |
| `v6.pcap/19/JA4L.1` | `39940_64` | A |

| Group | Values | Captures |
|---|---|---|
| A — the dissector reads no IPv6 hop limit | 16 | 5 files, 3 distinct captures |
| B — the SYN carries the ECN flags | 6 | 2 |
| C — the connection reaches no fourth application packet | 6 | 2 |
| D — the one capture whose fourth measurement point is an HTTP response | 2 | 1 |

## The chain that the dissector runs on a TCP connection

**Every group names one condition of one chain, so this section states the chain once.**

The dissector fills four points before it writes a TCP JA4L value.

1. `wireshark/source/packet-ja4.c:1266` tests `tcp_flags == 0x02`. That branch fills
   `conn->client_port`, `conn->server_port`, `conn->client_ttl` and `conn->timestamp_A`.
2. `wireshark/source/packet-ja4.c:1279` tests `tcp_flags == 0x012`. That branch fills
   `conn->server_ttl` and `conn->timestamp_B`.
3. `wireshark/source/packet-ja4.c:1302` and `wireshark/source/packet-ja4.c:1311` fill
   `conn->timestamp_C` from a bare ACK that holds the relative sequence number `1` and the
   relative acknowledgment number `1`.
4. `wireshark/source/packet-ja4.c:1320` opens the emission block for a packet that carries
   a payload, and `wireshark/source/packet-ja4.c:1324` tests
   `conn->server_ttl && conn->client_ttl`.

Inside the block the dissector fills three more points from packets that carry a payload.

- `wireshark/source/packet-ja4.c:1325` fills `conn->timestamp_D` from the first client
  packet.
- `wireshark/source/packet-ja4.c:1339` fills `conn->timestamp_E` from the first server
  packet after `D`.
- `wireshark/source/packet-ja4.c:1362` fills `conn->timestamp_F` from the first client
  packet after `E`.

**The dissector holds exactly two emission sites for a TCP connection, and each one writes
part c.**

- `wireshark/source/packet-ja4.c:1345` tests `if (is_http)`, and it writes the value on the
  packet that fills `E`. It writes the literal `tcp` in the third position.
- `wireshark/source/packet-ja4.c:1368` tests `if (!is_http)`, and it writes the value on the
  packet that fills `F`. It writes the interval `E` to `D` in the third position of JA4LS,
  and the interval `F` to `E` in the third position of JA4L. It also writes
  `ja4.ja4l_delta` and `ja4.ja4ls_delta`.

`wireshark/source/packet-ja4.c:1334` computes `is_http` from
`proto_find_first_finfo(tree, proto_http)` on the packet that the dissector reads.

**So the dissector publishes a TCP JA4L value only where it can compute part c.** That
sentence is the whole reason that group C and group D reach no key.

### The control case that proves the chain

`badcurveball.pcap` runs the chain to the end, and its vector file records each step.

| Frame | Direction | `tcp.flags` | `tcp.len` | Point |
|---|---|---|---|---|
| 1 | Client to server | `0x0002` | 0 | `A` |
| 2 | Server to client | `0x0012` | 0 | `B` |
| 3 | Client to server | `0x0010` | 0 | `C` |
| 4 | Client to server | `0x0018` | 517 | `D` |
| 6 | Server to client | `0x0010` | 1374 | `E` |
| 9 | Client to server | `0x0018` | 7 | `F` |

`testdata/foxio/wireshark/badcurveball.pcap.json` holds `ja4.ja4l`, `ja4.ja4l_delta`,
`ja4.ja4ls` and `ja4.ja4ls_delta` on frame 9, and it holds no one of the four on any other
frame. **The emission sits on the packet that fills `F`, which is
`wireshark/source/packet-ja4.c:1368`.**

**A tunnel does not break the chain.** `tcpdump-geneve.pcap` carries the layer list
`eth:ethertype:ip:udp:geneve:eth:ethertype:ip:tcp`, so it holds a UDP layer and a second IP
layer before the TCP layer. `testdata/foxio/wireshark/tcpdump-geneve.pcap.json` holds
`ja4.ja4l` on frame 13, which is the packet that fills `F`. **So a nested layer changes
nothing about the field walk**, and no group of this page names a tunnel as a cause.

## Group A — the dissector reads no IPv6 hop limit

**16 values, on 5 files that hold 3 distinct captures.**
`http-empty-useragent.pcap`, `ipv6.pcapng`, `tls-alpn-h2.pcap`, `sshv1.pcap` and
`v6.pcap`.

`wireshark/source/packet-ja4.c:1218` states the one line that fills `curr_ttl`:

```c
            if (strcmp(field->hfinfo->abbrev, "ip.ttl") == 0) {
```

**The file names no IPv6 field on any line.** `grep -c ipv6` over
`testdata/foxio/reference/wireshark/source/packet-ja4.c` reports `0`, and a
case-insensitive search for `hlim`, `hop_limit` and `hoplimit` reports nothing.

`wireshark/source/packet-ja4.c:1272` writes `conn->client_ttl = curr_ttl;` and
`wireshark/source/packet-ja4.c:1286` writes `conn->server_ttl = curr_ttl;`. **On an IPv6
packet each one stores `0`**, so `wireshark/source/packet-ja4.c:1324` fails on every packet
of the connection.

### A published FoxIO value proves the reading

`chrome-cloudflare-quic-with-secrets.pcapng` carries IPv6 on all 83 of its frames, and it
carries QUIC. **The QUIC emission site tests no time-to-live, so it publishes the stored
value.** `testdata/foxio/wireshark/chrome-cloudflare-quic-with-secrets.pcapng.json` holds
this on frame 52:

```
"ja4.ja4l": ["264_0_quic"]
"ja4.ja4ls": ["9285_0_quic"]
```

**Part b reads `0` in both values.** That is `curr_ttl` on an IPv6 packet, and it is the
FoxIO dissector's own published output.

### The corpus corroborates the reading

**15 vector files of `testdata/foxio/wireshark/` hold a `ja4.ja4l` key.** 14 of the 15 carry
zero IPv6 frames. The one that carries IPv6 is
`chrome-cloudflare-quic-with-secrets.pcapng`, and it reaches the QUIC site above rather than
the TCP site.

### The other three implementations read the hop limit

- Python maps `'ttl': 'hlim'` for an IPv6 packet at `python/ja4.py:59`.
- Zeek reads `rp$ip6$hlim` at `zeek/ja4l/main.zeek:93` and at `zeek/ja4l/main.zeek:147`.
- Rust reads `ipv6.hlim` at `rust/ja4/src/time.rs:66`.

`docs/specs/foxio/JA4L.md` R32 records the same split, and it names issue #128.

### Ruling #128 settles group A

**The maintainer ruled #128 on 2026-08-11**, and the second comment of that issue states the
answer:

> **Read the IPv6 hop limit as the observed TTL, and write JA4L over IPv6.**

The reading of 2026-08-12 on the same issue names the lines of the tree that carry the
ruling, and it closes with one sentence that this page acts on:

> **The ruling reaches no durable record.**

**So the 16 values of group A earn a value decline under ruling #128**, and those entries
are the durable record that `.claude/rules/rulings.md` `## Where a ruling is recorded`
asks for. **This page writes none of them.**

## Group B — the SYN carries the ECN flags, and the dissector tests for equality

**6 values, on 2 captures.** `gre-sample.pcap` and `macos_tcp_flags.pcap`.

`wireshark/source/packet-ja4.c:1266` tests `tcp_flags == 0x02`, and
`wireshark/source/packet-ja4.c:1279` tests `tcp_flags == 0x012`. **Each test is an
equality**, so a flag byte that carries one more bit reaches neither branch.

| Capture | Frame | `tcp.flags` | What the dissector reads it as |
|---|---|---|---|
| `gre-sample.pcap` | 11 | `0x00c2` | Nothing. `0x00c2` is SYN with ECE and CWR. |
| `gre-sample.pcap` | 12 | `0x0052` | Nothing. `0x0052` is SYN-ACK with ECE. |
| `macos_tcp_flags.pcap` | 1 | `0x00c2` | Nothing. |
| `macos_tcp_flags.pcap` | 2 | `0x0052` | Nothing. |

**So `conn->client_port`, `conn->server_port`, `conn->client_ttl`, `conn->server_ttl`,
`conn->timestamp_A` and `conn->timestamp_B` never fill.**
`wireshark/source/packet-ja4.c:1324` bars every emission, and `packet_from_client` at
`wireshark/source/packet-ja4.c:419` and `packet_from_server` at
`wireshark/source/packet-ja4.c:424` each return false because both port fields hold `0`.

### The corpus corroborates the reading

**JA4T reads `wireshark/source/packet-ja4.c:1266` and JA4TS reads
`wireshark/source/packet-ja4.c:1279`, so the two methods fail with JA4L.**
`testdata/foxio/wireshark/gre-sample.pcap.json` holds `ja4.ja4ssh` and no other JA4 key.
`testdata/foxio/wireshark/macos_tcp_flags.pcap.json` holds `ja4.ja4s` and `ja4.ja4s_r` and
no other JA4 key. **Neither file holds `ja4.ja4t` or `ja4.ja4ts`.**

**The worker of #126 measured the same two captures on 2026-08-13**, and it recorded them as
the only two captures of the corpus that carry an ECN-marked SYN. That measurement and this
one agree.

### The other three implementations test the bit

- Python tests `(flags & TCP_FLAGS['SYN']) and not (flags & TCP_FLAGS['ACK'])` at
  `python/ja4.py:563`, and `(flags & TCP_FLAGS['SYN']) and (flags & TCP_FLAGS['ACK'])` at
  `python/ja4.py:567`.
- Zeek tests `(rp$tcp$flags & TH_SYN) == 0 || (rp$tcp$flags & TH_ACK) == TH_ACK` at
  `zeek/ja4l/main.zeek:84`.
- Rust reads `tcp.flags.ack` and `tcp.flags.syn` as separate fields at
  `rust/ja4/src/time/tcp.rs:211` and `rust/ja4/src/time/tcp.rs:212`.

**The FoxIO reference Python publishes a JA4L value for both captures.**
`testdata/foxio/python/gre-sample.pcap.json` holds `JA4L-S` as `22952_236` and `JA4L-C` as
`26150_255`. `testdata/foxio/python/macos_tcp_flags.pcap.json` holds `JA4L-S` as
`17255_63` and `JA4L-C` as `393_64`.

**So three FoxIO implementations write a JA4L value for a connection that opens with an
ECN-marked SYN, and the Wireshark dissector writes none.** `## The one question for the
maintainer` below states the question this raises.

## Group C — the connection reaches no fourth application packet

**6 values, on 2 captures.** `http1-with-cookies.pcapng` and `socks4-https.pcap`.

**Each capture fills `C`, `D` and `E`, and neither one fills `F`.**
`wireshark/source/packet-ja4.c:1362` needs a client packet that carries a payload after the
packet that fills `E`, and no such packet exists. **`is_http` is false on the packet that
fills `E` in each capture**, so `wireshark/source/packet-ja4.c:1345` writes nothing and
`wireshark/source/packet-ja4.c:1368` is the only remaining site.

| Capture | `C` | `D` | `E` | The layer list of the `E` packet | Client packets after `E` |
|---|---|---|---|---|---|
| `http1-with-cookies.pcapng` | frame 3 | frame 5 | frame 7 | `null:ip:tcp` | frames 8, 10 and 11, and each holds `tcp.len` 0 |
| `socks4-https.pcap` | frame 3 | frame 4 | frame 6 | `eth:ethertype:ip:tcp:data` | frames 10, 11 and 15, and each holds `tcp.len` 0 |

**Each capture is short, and this page read every frame of each one.**
`http1-with-cookies.pcapng` holds 12 TCP frames and `socks4-https.pcap` holds 16.

## Group D — the one capture whose fourth measurement point is an HTTP response

**2 values, on 1 capture.** `gre-erspan-vxlan.pcap`.

The capture fills `C` at frame 3, `D` at frame 4 and `E` at frame 5. **Frame 5 carries the
layer list `eth:ethertype:ip:gre:erspan:eth:ethertype:ip:udp:vxlan:eth:ethertype:ip:tcp:http:data`**,
so it carries the `http` protocol and `wireshark/source/packet-ja4.c:1345` decides the
outcome. `testdata/foxio/wireshark/gre-erspan-vxlan.pcap.json` holds `ja4.ja4t` on frame 1,
`ja4.ja4ts` on frame 2 and the three JA4H keys on frame 4, and it holds no JA4L key on any
frame.

**Two candidate readings explain the absent key, and this page separates them no further.**

1. **`is_http` is false on frame 5.** Then `wireshark/source/packet-ja4.c:1345` writes
   nothing, and `wireshark/source/packet-ja4.c:1362` needs a client packet with a payload
   after frame 5. Frame 6 and frame 7 each hold `tcp.len` 0, so no such packet exists and
   the capture joins group C.
2. **`is_http` is true on frame 5, and `wireshark/source/packet-ja4.c:1345` runs.** Then the
   dissector writes a value that the vector file does not hold, and the vector file is
   incomplete.

**This page prefers candidate 1**, because candidate 2 requires the FoxIO generator to drop
a value that it asked for. `wireshark/test/generate-output-files.sh:17` requests
`-e ja4.ja4l`.

**One measurement supports candidate 1 and falsifies neither.**
`wireshark/source/packet-ja4.c:1345` writes `ja4.ja4l` and `ja4.ja4ls` and it writes no
`ja4.ja4l_delta` and no `ja4.ja4ls_delta`. `wireshark/source/packet-ja4.c:1368` writes all
four. **14 vector files hold a TCP `ja4.ja4l` key, and every one of the 14 also holds
`ja4.ja4l_delta`.** So no TCP value of the corpus comes from
`wireshark/source/packet-ja4.c:1345`.

**The measurement that separates the two candidates builds the FoxIO Wireshark plugin at the
pinned commit and runs it on `gre-erspan-vxlan.pcap`. This page runs no such build.**

## Ruling #196 reaches none of the thirty

**#376 proved that each of the thirty reaches the dissector's point `C`.** Ruling #196
settles which packet fills point `C`, and `docs/specs/foxio/JA4L.md` R33 records that split.
**A value that reaches point `C` is barred by a later condition**, so the reason text of the
41 entries under ruling #196 is false for every one of the thirty. That reason reads:

> The maintainer ruled in issue #196 on 2026-08-12 that part a reads the Python measurement point, and `wireshark/source/packet-ja4.c:1302` bars the Wireshark value here.

`wireshark/source/packet-ja4.c:1302` bars no value of the thirty.

## Ruling #127 settles group C and group D

**The dissector writes a TCP JA4L value on one packet alone, and that packet supplies part
c.** `## The chain that the dissector runs on a TCP connection` above states the two
emission sites, and each one computes part c.

**Ruling #127 declines part c.** `docs/specs/foxio/JA4L.md` R29 records the split: Zeek and
Wireshark write three parts, and Rust and FoxIO's Python write two. **The maintainer
confirmed ruling #127 on 2026-08-12 under #247**, and round 25 of the `## Changelog` of
`docs/specs/spec.md` records it.

**So this project writes a two-part value at point `C`, and it waits for no application
packet.** `python/ja4.py:572` calls `calculate_ja4_latency` on the packet that fills point
`C`, and `python/ja4.py:161` writes two parts. The library follows that rule.

**Group C and group D name captures where the dissector reaches no part c packet.** The two
implementations therefore write a value on no common frame, and the vector file names no
key at all. **The 8 values of the two groups earn a value decline under ruling #127**, and
this page writes none of them.

## The one question for the maintainer

**Does the bit test that ruling #126 states for JA4T also reach JA4L?**

**The maintainer ruled #126 on 2026-08-13**, and the ruling comment states the answer for
JA4T:

> **JA4T reads any SYN whose ACK bit is clear.** That is candidate 1, and it is the Rust reading.

**`wireshark/source/packet-ja4.c:1266` is one line, and JA4T and JA4L both read it.**
`docs/specs/foxio/JA4T.md` R29 records the split for JA4T and names issue #126.
**`docs/specs/foxio/JA4L.md` records no rule for the JA4L half of the same line.** So the
register cannot cite a ruling for the six values of group B without an answer here.

**Three candidate answers, each with the yield this run measures.**

| N | The answer | What the register writes | Yield |
|---|---|---|---|
| 1 | The ruling reaches JA4L, because the line and the reference split are the same. | 6 entries under ruling #126, and `docs/specs/foxio/JA4L.md` gains one rule that records the JA4L half. | 6 values move from unaccepted uncovered to accepted uncovered. |
| 2 | The ruling names JA4T alone, and the JA4L half is a fresh question. | Nothing, until the maintainer rules the fresh question. | 0. |
| 3 | The six decline under ruling #127 alone. | 6 entries under ruling #127, and `docs/specs/foxio/JA4L.md` gains no rule. | 6 values move from unaccepted uncovered to accepted uncovered. |

**Candidate 3 rests on one measurement, and this page states it.** Once the dissector reads
the ECN-marked SYN, each capture of group B reaches a part c packet, so the dissector would
publish a three-part value on a frame that the library does not write.

| Capture | `C` | `D` | `E` | `F` | The frame the dissector would publish on |
|---|---|---|---|---|---|
| `gre-sample.pcap` | 13 | 16 | 19 | 22 | 22 |
| `macos_tcp_flags.pcap` | 3 | 4 | 6 | 12 | 12 |

**So candidate 1 and candidate 3 reach the same six values and cite different rulings.**
Candidate 1 records the reference split of the SYN flags for JA4L, and candidate 3 records
the part count alone. **This page recommends no one of the three**, because
`.claude/rules/rulings.md` `## Stop conditions` reserves a reference split to the
maintainer.

## Twenty of the thirty equal a FoxIO reference Python value

**The FoxIO reference Python publishes a JA4L value for every one of the ten files**, and
each published value equals one value of the thirty exactly.

| Capture | Python `JA4L-S` | The library key that holds it | Python `JA4L-C` | The library key that holds it |
|---|---|---|---|---|
| `gre-erspan-vxlan.pcap` | `997_64` | `/2/JA4LS.1` | `953_64` | `/3/JA4L.1` |
| `gre-sample.pcap` | `22952_236` | `/12/JA4LS.1` | `26150_255` | `/14/JA4L.1` |
| `http-empty-useragent.pcap` | `26_64` | `/2/JA4LS.1` | `177863_64` | `/5/JA4L.1` |
| `http1-with-cookies.pcapng` | `64_64` | `/2/JA4LS.1` | `20_64` | `/4/JA4L.1` |
| `ipv6.pcapng` | `18861_59` | `/2/JA4LS.1` | `3911_64` | `/4/JA4L.1` |
| `macos_tcp_flags.pcap` | `17255_63` | `/2/JA4LS.1` | `393_64` | `/4/JA4L.1` |
| `socks4-https.pcap` | `40155_52` | `/2/JA4LS.1` | `119433_126` | `/4/JA4L.1` |
| `sshv1.pcap` | `28494_61` | `/17/JA4LS.1` | `39940_64` | `/19/JA4L.1` |
| `tls-alpn-h2.pcap` | `18861_59` | `/2/JA4LS.1` | `3911_64` | `/4/JA4L.1` |
| `v6.pcap` | `28494_61` | `/17/JA4LS.1` | `39940_64` | `/19/JA4L.1` |

**Ten of ten JA4LS values match, and ten of ten last JA4L values match.** So 20 of the
thirty carry a value that a FoxIO implementation publishes, and the per-packet vector set
names no key for them.

**The other ten are an earlier JA4L emission of the same connection.** They are
`gre-sample.pcap/13`, `http-empty-useragent.pcap/3`, `http-empty-useragent.pcap/4`,
`http1-with-cookies.pcapng/3`, `ipv6.pcapng/3`, `macos_tcp_flags.pcap/3`,
`socks4-https.pcap/3`, `sshv1.pcap/18`, `tls-alpn-h2.pcap/3` and `v6.pcap/18`.

**Python moves point `C` after it fills it, and it recomputes the value on each move.**
`docs/specs/foxio/JA4L.md` R33 records that reading. **Python keeps the last value in one
per-stream record, and the per-packet set of this project records each move on its own
frame.** So the earlier values are visible here and invisible in the FoxIO per-stream file.

**This shape is not new, and no capture of this page is special.** `badcurveball.pcap`
carries a `ja4.ja4l` key and the same shape: the run reports
`badcurveball.pcap/2/JA4LS.1`, `badcurveball.pcap/3/JA4L.1` and
`badcurveball.pcap/4/JA4L.1` from the library, and the register accepts only the third of
them.

## The eight conformance figures

**This page moves no value, so the figures before and after are equal.**

| Figure | Before | After |
|---|---|---|
| Matches | 1753 | 1753 |
| Deviations the register does not hold | 273 | 273 |
| Accepted deviations | 580 | 580 |
| Register keys | 606 | 606 |
| Unaccepted uncovered values | 178 | 178 |
| Accepted uncovered values | 26 | 26 |
| Stale entries | 0 | 0 |
| Orphan entries | 0 | 0 |

`580 + 26 = 606` holds before and after.

## What this reading does not answer

- **Whether `wireshark/source/packet-ja4.c:1345` ever publishes a value.** No TCP vector
  file of the corpus holds the shape that branch writes.
  `## Group D — the one capture whose fourth measurement point is an HTTP response` above
  names the measurement that would settle it.
- **Why `gre-erspan-vxlan.pcap` reaches one JA4L value where two frames meet the Python
  condition.** Frame 3 and frame 4 each hold the relative sequence number `1` and the
  relative acknowledgment number `1`, and the run reports one JA4L value. Every other
  capture of this page reports one value for each such frame. **`ja4l.go` decides that
  count**, and `docs/audit/ja4l-deviation-cluster.md` reads that file.
- **Whether the per-packet set should record every move of point `C`.** Ten of the thirty
  come from that choice, and so do unaccepted deviations on captures this page does not
  read. **That is a question about this project and never about a FoxIO source.**
- **Whether ruling #128 and ruling #127 reach a durable record.** The reading of 2026-08-12
  on #128 states that the ruling reaches none of the three places that
  `.claude/rules/rulings.md` names. This page writes no entry, so it changes nothing there.
