# Why the per-packet vectors publish no JA4L key for two captures

**This page answers the four questions of #376.** The issue names two captures,
`CVE-2018-6794.pcap` and `tls-handshake.pcapng`. It asks why the Wireshark per-packet
generator publishes no JA4L key for them.

**This page changes no behavior, and it moves no fingerprint value.** It writes no entry of
`testdata/deviations.json`. #502 owns that file in batch #530, and
`## Answer 4 — the split, and the ruling that settles it` below states what an entry holds.

**Every citation of the corpus reads the pinned commit**
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. `testdata/foxio.pin` holds it.

**Every count of this page comes from one conformance run on 2026-08-14**, against
`origin/batch/530-ruled-entries-and-readings` at `5c2f852`.

## The four answers, in one table

| N | The question | The answer |
|---|---|---|
| 1 | Why does the generator publish no JA4L key for the two captures? | **Two different causes.** Neither capture reaches the dissector's client measurement point `C`. |
| 2 | Does the per-stream reason reach the per-packet set? | **No.** `python/ja4.py:340` states a fact about one program, and the generator is another program. |
| 3 | Does the port compare a per-packet JA4L value for these captures? | **No.** The port compares JA4TS, JA4D and JA4D6 against the per-packet set, and no other method. |
| 4 | Do the FoxIO implementations disagree? | **Yes, and the maintainer already ruled it.** Ruling #196 of 2026-08-12 settles it, so this page reaches no stop condition. |

## Answer 1 — the two causes

### The generator requests the field, so no filter of the generator removes it

`wireshark/test/generate-output-files.sh:17` requests `-e ja4.ja4l`, and
`wireshark/test/generate-output-files.sh:19` requests `-e ja4.ja4ls`. The script names one
field list for every capture, and it names no capture-specific option.

**So the absent key records an absent value, and never an absent request.** The dissector
produces nothing for these two captures.

**The corpus corroborates the reading.** 15 of the 37 files of `testdata/foxio/wireshark/`
hold a `"ja4.ja4l"` key, and the two captures of this page hold none.

### The dissector writes JA4L on one condition chain

`wireshark/source/packet-ja4.c:1320` guards every JA4L emission of a TCP connection:

```c
if ((tcp_len > 0) && !nstime_is_zero(&conn->timestamp_C)) {
```

`wireshark/source/packet-ja4.c:1324` guards it a second time:

```c
if (conn->server_ttl && conn->client_ttl) {
```

**`wireshark/source/packet-ja4.c:1313` is the only line of the TCP path that fills
`timestamp_C`.** `wireshark/source/packet-ja4.c:1429` fills it on the QUIC path, and both
captures of this page carry TCP.

The dissector fills `timestamp_C` under two conditions. `wireshark/source/packet-ja4.c:1302`
states the first:

```c
if ((tcp_flags == 0x010) && (tcp_len == 0)) {
```

`wireshark/source/packet-ja4.c:1311` and `wireshark/source/packet-ja4.c:1312` state the
second:

```c
if ((packet_time != NULL) && (nstime_is_zero(&conn->timestamp_C)) &&
    (seq == 1) && (ack == 1)) {
```

**So the dissector fills point `C` from a bare ACK that acknowledges one byte, and from
nothing else.** `docs/specs/foxio/JA4L.md` R33 records the same reading.

### `tls-handshake.pcapng` holds no TCP handshake

**The capture starts inside each connection.** Frame 1 is a client packet that carries 517
bytes of payload, and it holds the relative sequence number `1`.

A measurement of the capture reports the counts:

| What | Count |
|---|---|
| Frames | 193 |
| Packets whose `tcp.flags` equals `0x02` | 0 |
| Packets whose `tcp.flags` equals `0x12` | 0 |

**The capture holds no SYN and no SYN-ACK, so four fields never fill.**
`wireshark/source/packet-ja4.c:1274` fills `timestamp_A` from a SYN, and
`wireshark/source/packet-ja4.c:1272` fills `client_ttl` from the same packet.
`wireshark/source/packet-ja4.c:1288` fills `timestamp_B` from a SYN-ACK, and
`wireshark/source/packet-ja4.c:1286` fills `server_ttl` from the same packet.

**The guard of `wireshark/source/packet-ja4.c:1324` therefore fails on every packet**, and
the guard of `wireshark/source/packet-ja4.c:1320` fails before it.

**The corpus corroborates the reading.** `testdata/foxio/wireshark/tls-handshake.pcapng.json`
holds no `"ja4.ja4t"` key and no `"ja4.ja4ts"` key. Each of those two methods also needs a
handshake packet.

**This library produces no JA4L value for this capture either.** `clientPoint` in `ja4l.go`
reads `conn.timestamps["B"]` and returns `nil` when the SYN-ACK never arrived. **So the
capture reaches no comparison, and it reaches no uncovered value.**
`## The re-measurement` below states the count.

### `CVE-2018-6794.pcap` holds the handshake, and the client ACK acknowledges 87 bytes

**The capture holds three connections, and each one repeats one pattern.** The table reads
stream 0, and `tshark` supplies the relative sequence numbers.

| Frame | Direction | `tcp.flags` | `tcp.len` | `tcp.seq` | `tcp.ack` |
|---|---|---|---|---|---|
| 1 | Client to server | `0x0002` | 0 | 0 | 0 |
| 2 | Server to client | `0x0012` | 0 | 0 | 1 |
| 3 | Server to client | `0x0018` | 85 | 1 | 1 |
| 4 | Server to client | `0x0011` | 0 | 86 | 1 |
| 5 | Client to server | `0x0010` | 0 | 1 | 87 |

**The server sends its whole response and its FIN before the client acknowledges
anything.** So the client's first bare ACK, frame 5, acknowledges 87 bytes.

**Frame 5 is the one packet of the stream that passes
`wireshark/source/packet-ja4.c:1302`, and it fails
`wireshark/source/packet-ja4.c:1312`**, because `ack` reads `87` and the condition needs
`1`. **`timestamp_C` therefore stays zero, and the guard of
`wireshark/source/packet-ja4.c:1320` bars every emission.**

**Frame 3 holds the relative sequence number `1` and the relative acknowledgment number
`1`, and `wireshark/source/packet-ja4.c:1302` bars it**, because `tcp_len` reads `85`.

Stream 1 and stream 2 repeat the pattern. Frame 14 and frame 23 are the two other bare
ACKs, and each one holds the relative sequence number `1` and the relative acknowledgment
number `87`.

**A measurement over the whole capture reports zero packets that meet the dissector's
condition.** The filter
`tcp.flags==0x10 and tcp.len==0 and tcp.seq==1 and tcp.ack==1` matches no frame of
`CVE-2018-6794.pcap`.

**This library fills the point from frame 3, and the ruling of #196 states why.**
`clientPoint` in `ja4l.go` follows `python/ja4.py:570`, which sets no condition on the
payload length.

## Answer 2 — the per-stream reason does not reach the per-packet set

**`python/ja4.py:340` states a fact about the FoxIO reference Python, and it states nothing
about the Wireshark dissector.** The line reads:

```python
        delete_keys(['JA4L-S', 'JA4L-C'], final)
```

`python/ja4.py:339` states the condition that reaches it:

```python
    if 'ja4l' not in output_types:
```

**`output_types` is an option of one program.** The generating run named another method, so
the reference Python deleted the two keys from the per-stream file. **The reference computed
the value and then declined to print it.**

**Three facts separate that reason from the per-packet set.**

1. **The two sets come from two programs.** The per-stream set comes from `python/ja4.py`,
   and the per-packet set comes from `tshark` with the JA4 dissector.
2. **The dissector holds no `output_types` filter.** No line of
   `wireshark/source/packet-ja4.c` reads an option that selects a method.
3. **The generator asks for the field.**
   `wireshark/test/generate-output-files.sh:17` names `-e ja4.ja4l`.

**So the two absences have opposite shapes.** The per-stream absence records a value the
reference computed and suppressed. **The per-packet absence records a value the reference
never computed.**

**A register entry must therefore state a different reason for each set.** The eight
entries of ruling #361 in `testdata/deviations.json` state the per-stream reason, and each
one names `python/ja4.py:340`. **No one of the eight describes a per-packet value.**

## Answer 3 — the port

**The port compares no per-packet JA4L value.** `tests/foxio_vectors/wireshark_expected/`
holds the port's copy of the per-packet set, and three test files read that directory at tag
`v1.1.0`: `tests/test_foxio_wireshark_ja4ts.py`, `tests/test_ja4d_foxio.py` and
`tests/test_ja4d6_foxio.py`. **They cover JA4TS, JA4D and JA4D6, and no other method.**

**The port's copy of the per-packet set holds 26 files, and this repository's copy holds
35.** `tests/foxio_vectors/wireshark_expected/CVE-2018-6794.pcap.json` matches this
repository's copy, and it holds no JA4L key. **The port holds no per-packet file for
`tls-handshake.pcapng`.**

**The port's register holds 21 JA4L entries across six captures, and five of them record the
absence of a key.** `tests/foxio_deviations.json` at `v1.1.0` holds the 21, and the six
captures are `CVE-2018-6794.pcap`, `chrome-cloudflare-quic-with-secrets.pcapng`,
`https-connect.pcap`, `ssh2.pcapng`, `tls-handshake.pcapng` and `tls3.pcapng`.

**The five that record the absence sit on three captures**, and each one is per-stream. They
are `CVE-2018-6794.pcap/JA4L-C`, `CVE-2018-6794.pcap/JA4L-S`, `https-connect.pcap/JA4L-C`,
`https-connect.pcap/JA4L-S` and `tls-handshake.pcapng/JA4L-S`. **The port's issue #272
decided that decline on 2026-08-08.** Each of the five quotes the per-stream reason of
Answer 2 above.

**The other 16 entries state a different cause, and this page reads none of them.** No one
of the 16 records the absence of a key.

**So the port answers the per-stream question, and it asks no per-packet question.** This
repository compares a per-packet set that the port does not, so this reading has no other
half in the port.

**Two disagreements between the port and this repository are recorded here, and this page
repairs neither.** A repair belongs to the port.

1. **The port's cause text cites the wrong line.** It states
   `` `python/ja4.py:339` runs `delete_keys(['JA4L-S','JA4L-C'], final)` ``. Line 339 holds
   the `if` statement, and line 340 holds the call. **This repository cites 340**, in the
   eight entries of ruling #361.
2. **One sentence of the port's `docs/specs/foxio/JA4L.md` is falsified by the port's own
   tag.** The page states that
   `tests/foxio_vectors/wireshark_expected/` `holds two files today, and neither carries a
   JA4L key`. **At `v1.1.0` that directory holds 26 files, and 15 of them carry a
   `ja4.ja4l` key.**

## Answer 4 — the split, and the ruling that settles it

**The FoxIO implementations disagree about the client measurement point, and that
disagreement is the whole cause of Answer 1.** `docs/specs/foxio/JA4L.md` R33 records the
split. Python fills point `C` from any packet that carries `ACK` and no `SYN` with the
relative numbers `1` and `1`, at `python/ja4.py:570`. Wireshark adds `tcp_len == 0`, at
`wireshark/source/packet-ja4.c:1302`.

**The maintainer ruled that split on 2026-08-12, and #196 holds the ruling.** Round 15 of
the `## Changelog` of `docs/specs/spec.md` records it. The ruling follows Python, and it
states its own cost:

> **The ruling knowingly gives up the per-packet vector.**

**So this page reaches no stop condition.** `.claude/rules/rulings.md` `## Stop conditions`
reserves a reference split to the maintainer, and the maintainer already ruled this one.
**This page needs no new ruling, and it applies no delegation.**

### The six values of `CVE-2018-6794.pcap` fall under ruling #196

**The register already holds 35 per-packet JA4L entries under ruling #196**, and each one
records the same divergence. Each one carries an empty `theirs`, because the dissector
publishes no value on the frame this library writes. The entry
`badcurveball.pcap/4/JA4L.1` is one of the 35, and its reason reads:

> The maintainer ruled in issue #196 on 2026-08-12 that part a reads the Python measurement point, so the library reports part a on this frame.

**The six values of `CVE-2018-6794.pcap` differ from those 35 in one way alone, and the
difference is a classification of the harness and never a cause.**

- For `badcurveball.pcap` the vector file names a `"ja4.ja4l"` key on another frame, so the
  run reports a **deviation**.
- For `CVE-2018-6794.pcap` the vector file names no `"ja4.ja4l"` key at all, so the run
  reports an **uncovered value**.

**#361 built the machinery that makes an uncovered value registrable**, and ruling #196
predates it. **That is why the six sit outside the register while their 35 siblings sit
inside it.**

**So the six values earn a value decline under ruling #196, and this page writes none.** An
entry states a per-packet reason, and never the per-stream reason of ruling #361. The
reason names `wireshark/source/packet-ja4.c:1302`, because that line is why the dissector
publishes no key for this capture.

| Key | `ours` |
|---|---|
| `CVE-2018-6794.pcap/2/JA4LS.1` | `2219_255` |
| `CVE-2018-6794.pcap/3/JA4L.1` | `1_128` |
| `CVE-2018-6794.pcap/11/JA4LS.1` | `1513_255` |
| `CVE-2018-6794.pcap/12/JA4L.1` | `1_128` |
| `CVE-2018-6794.pcap/20/JA4LS.1` | `1948_255` |
| `CVE-2018-6794.pcap/21/JA4L.1` | `1_128` |

**`tls-handshake.pcapng` earns no entry**, because the run reaches no value for it.

## The re-measurement

**#376 states that 24 uncovered per-packet JA4L and JA4LS values sit on the two captures.
The run of 2026-08-14 disagrees with that sentence on the count and on the captures.**
**This page reports the disagreement, and it repairs no text of the issue.**

| What | #376 states | The run of 2026-08-14 reports |
|---|---|---|
| Uncovered per-packet JA4L and JA4LS values | 24 | **36** |
| Captures that hold them | 2 | **11** |
| Values on `CVE-2018-6794.pcap` | Part of the 24 | **6** |
| Values on `tls-handshake.pcapng` | Part of the 24 | **0** |

**None of the 36 is accepted.** The run reports 20 accepted uncovered values, and no one of
them is a per-packet JA4L or JA4LS value. **12 of the 20 name JA4X or JA4X_r on
`socks4-https.pcap`, and the other 8 are the per-stream JA4L entries of ruling #361.**

**Eleven captures hold the 36, and the table names each one.**

| Capture | JA4L | JA4LS |
|---|---|---|
| `CVE-2018-6794.pcap` | 3 | 3 |
| `gre-erspan-vxlan.pcap` | 1 | 1 |
| `gre-sample.pcap` | 2 | 1 |
| `http-empty-useragent.pcap` | 3 | 1 |
| `http1-with-cookies.pcapng` | 2 | 1 |
| `ipv6.pcapng` | 2 | 1 |
| `macos_tcp_flags.pcap` | 2 | 1 |
| `socks4-https.pcap` | 2 | 1 |
| `sshv1.pcap` | 2 | 1 |
| `tls-alpn-h2.pcap` | 2 | 1 |
| `v6.pcap` | 2 | 1 |

**`CVE-2018-6794.pcap` is the only one of the eleven whose cause this page reads.** A probe
of the dissector's point `C` condition separates it from the other ten.

| Capture | Packets that meet the point `C` condition |
|---|---|
| `CVE-2018-6794.pcap` | **0** |
| Each of the other ten | 1 or more |

**So the other ten reach point `C`, and their JA4L absence has another cause.**
`## What this reading does not answer` below states that the cause is unread.

**The per-stream set is a separate count, and the register already accepts it.** The run
reports six uncovered per-stream JA4L values under a stream number, and two more under an
endpoint key. The eight entries of ruling #361 accept all eight.

## The eight conformance figures

**This page moves no value, so the figures before and after are equal.**

| Figure | Before | After |
|---|---|---|
| Matches | 1753 | 1753 |
| Deviations the register does not hold | 276 | 276 |
| Accepted deviations | 577 | 577 |
| Register keys | 597 | 597 |
| Unaccepted uncovered values | 184 | 184 |
| Accepted uncovered values | 20 | 20 |
| Stale entries | 0 | 0 |
| Orphan entries | 0 | 0 |

## What this reading does not answer

- **Why the other ten captures publish no JA4L key.** Each one reaches point `C`, so the
  cause sits later in the condition chain of
  `wireshark/source/packet-ja4.c:1320` to `wireshark/source/packet-ja4.c:1394`. #376 names
  two captures, and this page reads those two.
- **Whether the 30 values of the other ten captures earn a decline.** The cause is unread,
  and `.claude/rules/rulings.md` bars a decline of an unexplained value.
- **Why #361 measured 24.** That measurement is not reproducible from this branch, and this
  page repairs no text of #376.
- **Whether the FoxIO dissector intends the `tcp_len == 0` condition.** FoxIO publishes no
  text specification of the point `C` rule, and `docs/specs/foxio/JA4L.md` R33 records the
  four implementations without one.
