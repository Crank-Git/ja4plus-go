# The JA4L and JA4LS deviation cluster

This page reads the JA4L and JA4LS deviations that `testdata/deviations.json` does not
hold. **The page records what each source states, and it decides no value.** It changes no
code and it moves no fingerprint. **The maintainer rules, and the page records each
ruling.**

Issue #443 produced it, under Epic #441. `.claude/rules/rulings.md` states who rules.

**The maintainer ruled cause 3 on 2026-08-14, and issue #528 holds that ruling.**
`## Cause 3 — the QUIC client measurement point, and a reference split` below records the
ruling, the re-measurement and the three register entries it wrote.

## The measurement

Every number of this section and of causes 1, 2, 4 and 5 comes from one run of
`make conformance` on `issue/443-ja4l-deviation-cluster` on 2026-08-13, with the corpus
present at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

**Each count below reads a tree that no branch holds today.** The run of 2026-08-13 reported
635 deviations of the whole corpus, and the base of this ruling reports 273 on 2026-08-14.
`### The ruling of 2026-08-14` under cause 3 states the re-measured figures, and it names
the command that measured them.

**Cause 6 below carries its own base, and `### The measurement of this section` states it.**
#449 added that cause on a later branch, so a number of cause 6 reads against another run.

| Measure | Count |
|---|---|
| Deviations of the whole corpus | 635 |
| **JA4L and JA4LS deviations the register does not hold** | **177** |
| JA4LS and `JA4L-S` | 95 |
| JA4L and `JA4L-C` | 82 |
| In the per-packet vector set | 175 |
| In the per-stream vector set | 2 |

**The cluster holds 177 deviations, and Epic #441 states 175.** The 175 counts the
per-packet set alone. Two per-stream deviations sit outside that count, because each one
carries a key of the form `JA4L-S` rather than `JA4LS.1`:

- `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S`
- `tls3.pcapng/25/JA4L-S`

The split of 95 against 82 holds for the count of 177.

## The shape of the cluster

**156 of the 177 deviations sit in 75 groups where part a and part b already agree.** One
group holds one capture, one method and one pair of values. In each group the library
writes the same latency and the same time-to-live that the vector writes. Two things
differ: the frame that carries the value, and part c.

`badcurveball.pcap` states the shape in two rows.

| Key | The vector holds | The library produces |
|---|---|---|
| `badcurveball.pcap/3/JA4L.1` | (none) | `2177_64` |
| `badcurveball.pcap/9/JA4L.1` | `2177_64_114797` | (none) |

**One difference produces two deviations.** The suite reports the library value as a value
the vector does not hold, and the vector value as a value the library does not produce.

**Every vector pair of JA4L and JA4LS lands on one frame.** On `badcurveball.pcap` both
sit on frame 9, on `https-connect.pcap` both sit on frame 8, and on `https3-301-get.pcap`
both sit on frame 10. The library writes the two values on two different earlier frames.

## Cause 1 — the emission frame and part c on a TCP connection

**This cause holds 149 of the 177 deviations.**

### Where the library stands

`ja4l.go:183` emits `JA4L-S` on the SYN-ACK frame. `ja4l.go:319` emits `JA4L-C` on the
frame that fills the client measurement point. `ja4l.go:483` writes two parts:

```go
	fingerprint := fmt.Sprintf("%s=%d_%d", label, latencyUS, ttl)
```

### Where the reference stands

`wireshark/source/packet-ja4.c:1362-1394` emits both values on one frame, and that frame is
the one that fills `timestamp_F`. Wireshark writes three parts for each value:

```c
                                    wmem_strbuf_append_printf(
                                        display, "%d_%d_%d", latency.nsecs / 2 / 1000, conn->server_ttl,
                                        latency2.nsecs / 2 / 1000
                                    );
```

`timestamp_F` is the first client application packet after `timestamp_E`, and
`timestamp_E` is the first server application packet after `timestamp_D`. **Part c is not
computable on the frame where this library writes a value, because both of the library's
frames come before `timestamp_D`.** So the frame and the part count are one cause and not
two.

### The count this cause closes

A candidate change adopted the Wireshark rule on the TCP path. It moved the emission to the
`timestamp_F` frame, and it wrote three parts. The candidate was reverted with
`git checkout -- .`, and it ships in no commit.

| Measure | Before | After |
|---|---|---|
| **JA4L and JA4LS deviations of this cluster** | **177** | **128** |
| In the per-packet set | 175 | 28 |
| In the per-stream set | 2 | 100 |
| Deviations of the whole corpus | 635 | 586 |
| Matches of the whole corpus | 1658 | 1629 |
| Per-packet matches | 555 | 624 |
| Per-stream matches | 1103 | 1005 |
| Stale register entries | 0 | 2 |
| Orphan register entries | 0 | 41 |

**The candidate closes 149 deviations of this cluster, and it opens 100.** It opens 98
per-stream deviations, because the per-stream set holds two parts and names a different
frame.

**28 per-packet deviations remain, and 27 of them carry the marker `quic`.** Causes 2, 3
and 4 below hold those 27. **One TCP deviation remains**, and
`## The unattributed deviation` below names it.

### Does the change move a value the register already accepts

**Yes. It orphans 41 register entries and it makes 2 stale.** `.claude/rules/parity.md`
states that a register entry whose comparison now matches fails the conformance suite, so
the register needs the same change.

### Do the FoxIO implementations agree

**No. This is a reference split, and `docs/specs/foxio/JA4L.md` R29 already records it.**
Zeek appends part c at `zeek/ja4l/main.zeek:133`, and Wireshark writes three parts at
`wireshark/source/packet-ja4.c:1383`. Rust writes two parts at
`rust/ja4/src/time/tcp.rs:186`, and Python writes two parts at `python/ja4.py:161`.

**The two FoxIO vector sets carry the two answers.** Wireshark produces the per-packet set,
and Python produces the per-stream set. `docs/specs/foxio/JA4L.md` R35 states the
consequence: **`One library value reaches one set, so the two sets cannot both match.`**

### Does the port carry the same gap

**Yes, and the port settled it.** `ja4plus/fingerprinters/ja4l.py:482` writes two parts:

```python
    return "JA4L-C={}_{}".format(_one_way_latency(timestamps["B"], timestamps["C"]), ttls["client"])
```

The port holds no measurement point named `D`, `E` or `F` on a TCP connection. The port's
`docs/specs/foxio/JA4L.md:149-151` records its ruling:

> **#225 settled this rule on 2026-08-08. `ja4plus` writes two timing parts.** The rule keeps
> the vector fallback, and it now states the reason rather than an open question. Two FoxIO
> implementations write three parts and two write two parts.

**A change here without the port opens a parity difference.**

### The cost

The change adds three measurement points and one emission path to the TCP branch of
`ja4l.go`, and it rewrites 43 register entries.

### This cause is the maintainer's

**Ruling #127 declines part c on a TCP connection, and the maintainer ruled the question on
2026-08-12.** Round 15 of the `## Changelog` of `docs/specs/spec.md` follows the per-stream
set where the two sets disagree, and it states that the ruling knowingly gives up the
per-packet vector.

**So the 149 deviations are the recorded price of two rulings, and they are not a defect.**
This page reverses no ruling, and it recommends none. The measurement prices the ruling, so
that the maintainer reads the cost against a number rather than against an estimate.

## Cause 2 — the JA4L-S emission frame on a QUIC connection

**This cause holds 16 deviations, in 8 pairs.**

`ja4l.go:381` emits `JA4L-S` on the frame that fills point B.
`wireshark/source/packet-ja4.c:1432-1451` emits both `ja4ls` and `ja4l` on the frame that
fills `timestamp_D`.

**The value is identical, and the frame differs.** Four pairs state the shape.

| Capture | The library frame | The vector frame | The value |
|---|---|---|---|
| `ssh2.pcapng` | 1042 | 1046 | `16192_57_quic` |
| `ssh2.pcapng` | 1140 | 1147 | `5389_57_quic` |
| `tls3.pcapng` | 144 | 147 | `4213_59_quic` |
| `tls3.pcapng` | 293 | 297 | `3051_57_quic` |

### The count this cause closes

A second candidate moved the `JA4L-S` emission of `processUDP` to the point D frame, and it
was reverted with `git checkout -- .`.

| Measure | Before | After |
|---|---|---|
| **Deviations of this cluster** | **177** | **162** |
| Matches of the whole corpus | 1658 | 1664 |
| Per-stream deviations | 82 | 82 |
| Orphan register entries | 0 | 20 |
| Stale register entries | 0 | 1 |

**The candidate closes 15, and it opens none.** The per-stream set does not move, because
that set names a stream rather than a frame.

**The shape above attributes 16 deviations to this cause, and the candidate closes 15.**
One pair carries a second difference, so a change of the frame alone does not close it.
**The measured count is 15, and the attributed count is 16.**

**The change orphans 20 register entries.** Every accepted QUIC `JA4L-S` entry names the
old frame.

**The four implementations agree on the frame.** Zeek writes the client value at
`zeek/ja4l/main.zeek:248` inside the branch that fills `client_handshake`, and Rust reaches
`Done` at `rust/ja4/src/time/udp.rs:185-202` on the client handshake packet. The port emits
the server value earlier, at `ja4plus/fingerprinters/ja4l.py:549-551`, so **the port carries
this gap too.**

The cost is one moved emission point in `processUDP`, and the register needs the 8 keys
rewritten.

## Cause 3 — the QUIC client measurement point, and a reference split

**This cause holds 4 deviations, and it is a reference split that no page records.** That
sentence reads the run of 2026-08-13. **The maintainer ruled the split on 2026-08-14**, and
`### The ruling of 2026-08-14` below states the re-measured count.

`ja4l.go:394-399` moves point C to the last server handshake packet:

```go
	if _, ok := conn.timestamps["B"]; ok {
		if _, ok := conn.timestamps["D"]; !ok && !isClient {
			conn.timestamps["C"] = ts
			return nil, nil
		}
	}
```

**Wireshark pins point C to the first server handshake packet.**
`wireshark/source/packet-ja4.c:1426-1430` states it:

```c
                if (fvalue_get_uinteger(get_value_ptr(field)) == 2) {
                    if ((packet_time != NULL) && (srcport == 443) &&
                        (nstime_is_zero(&conn->timestamp_C))) {
                        nstime_copy(&conn->timestamp_C, packet_time);
                    }
```

**The comment above that code states the opposite of the code.**
`wireshark/source/packet-ja4.c:1425` reads
`// QUIC handshake packets, keep updating C until D is found`, and
`nstime_is_zero(&conn->timestamp_C)` bars every update after the first.

The other three implementations move the point.

- Python returns early only once `D` is present. `python/common.py:109-112`:

  ```python
      # special requirement for ja4c when the C timestamp needs to be the
      # the last before D
      if field == 'C' and 'D' in cache[stream]:
          return
  ```

- Rust assigns on every server handshake packet, at `rust/ja4/src/time/udp.rs:181-184`:

  ```rust
                  Timestamp::ServerHandshake(t_c) => {
                      self.t_c = t_c;
                      self.into()
                  }
  ```

- Zeek assigns on every server packet until the client handshake fills, at
  `zeek/ja4l/main.zeek:254`: `c$fp$ja4l$server_handshake = get_current_packet_timestamp();`

**So three implementations take the last server handshake packet and one takes the first.**
The library follows the three. A first point produces a longer interval, and every measured
row agrees with that direction.

| Key | The vector holds | The library produces |
|---|---|---|
| `tls3.pcapng/147/JA4L.1` | `90_128_quic` | `59_128_quic` |
| `tls3.pcapng/153/JA4L.1` | `101_128_quic` | `40_128_quic` |
| `tls3.pcapng/167/JA4L.1` | `81_128_quic` | `59_128_quic` |
| `tls3.pcapng/312/JA4L.1` | `83_128_quic` | `45_128_quic` |

**`docs/specs/foxio/JA4L.md` R8 does not record this split.** R8 states that part a of JA4L
measures the client handshake packet against the last server handshake packet, and it cites
`wireshark/source/packet-ja4.c:1445` for Wireshark. Line 1445 reads the two points, line
1428 guards point C, and line 1429 fills it. **The citation is right about the subtraction
and silent about the point.**

**This is a stop condition.** `.claude/rules/rulings.md` reserves a reference split to the
maintainer, and this page picks no answer. The two candidate answers are:

1. **The last server handshake packet.** Python, Rust and Zeek write it. The library writes
   it today, and the per-stream vector set carries it.
2. **The first server handshake packet.** Wireshark writes it, and the per-packet vector set
   carries it.

The port writes answer 1, at `ja4plus/fingerprinters/ja4l.py`, so **the port carries the
same difference from Wireshark.** A change here needs the same change there.

The cost of answer 2 is one guard in `processUDP`. The cost of answer 1 is nothing, because
the library writes it today.

### The count answer 2 closes

A third candidate added the guard that fills point C once, and it was reverted with
`git checkout -- .`.

| Measure | Before | After |
|---|---|---|
| **Deviations of this cluster** | **177** | **174** |
| Matches of the whole corpus | 1658 | 1661 |
| Per-stream deviations | 82 | 82 |
| Orphan register entries | 0 | 0 |
| Stale register entries | 0 | 0 |

**The candidate closes 3, and it costs nothing.** It opens no deviation, it moves no
per-stream value, and it leaves every register entry in place. **It is the cheapest change
of this reading, and it is still a reference split that the maintainer rules.**

**The three sentences above read the run of 2026-08-13, and the register has grown since
it.** `#### The candidate makes five register entries stale` below states the cost of the
same candidate on 2026-08-14.

**The shape above attributes 4 deviations to this cause, and the candidate closes 3.**
`tls3.pcapng/153/JA4L.1` still reads `the two values differ`, so that row carries a second
difference.

### The ruling of 2026-08-14

**The maintainer ruled answer 1 on 2026-08-14.** JA4L point C is the last QUIC server
handshake packet. Comment 5294398628 of issue #528 holds the ruling, and issue #528 is the
reversal path.

**The library keeps the packet it reads today, so no line of `ja4l.go` changes.** The
register gains one entry for each per-packet comparison that the point C reading alone
holds.

#### The re-measurement

Issue #528 ran `make corpus` and then `make conformance` on
`issue/528-ja4l-point-c-last-packet` on 2026-08-14, with the base
`origin/batch/555-session-15-rulings` at `05a7566` and the corpus at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

| Measure | Before the entries | After the entries |
|---|---|---|
| Matches | 1753 | 1753 |
| Deviations the register does not hold | 273 | 270 |
| Accepted deviations | 580 | 583 |
| Register keys | 606 | 609 |
| Unaccepted uncovered values | 178 | 178 |
| Accepted uncovered values | 26 | 26 |
| Stale register entries | 0 | 0 |
| Orphan register entries | 0 | 0 |

**The identity holds on each side: `580 + 26 = 606`, and `583 + 26 = 609`.**

#### The count of this ruling is 3, and the count above is 4

**The figure of 4 comes from the run of 2026-08-13, and it is not the count this ruling
writes.** Issue #528 re-ran the candidate of `### The count answer 2 closes` above against
the base of 2026-08-14, and it measured a different set.

**Five per-packet comparisons move when point C reads the first server handshake packet,
and the ruling alone holds three of them.**

| Key | The vector holds | The library produces | The candidate produces | The register |
|---|---|---|---|---|
| `tls3.pcapng/147/JA4L.1` | `90_128_quic` | `59_128_quic` | `90_128_quic` | One entry under ruling #528. |
| `tls3.pcapng/167/JA4L.1` | `81_128_quic` | `59_128_quic` | `81_128_quic` | One entry under ruling #528. |
| `tls3.pcapng/312/JA4L.1` | `83_128_quic` | `45_128_quic` | `83_128_quic` | One entry under ruling #528. |
| `tls3.pcapng/153/JA4L.1` | `101_128_quic` | `40_128_quic` | `71_128_quic` | No entry. |
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` | `264_0_quic` | `113_64_quic` | `264_64_quic` | No entry. |

**The last two rows carry a second difference, so ruling #528 alone does not hold either
one.** `tls3.pcapng/153/JA4L.1` reads `71_128_quic` under the candidate, and the vector holds
`101_128_quic`. No reading of this page states that remainder.

Part a of `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` agrees exactly under the
candidate. The time-to-live `0` of that vector stays open under cause 4.

**An entry that named ruling #528 for either row would accept a difference the ruling does
not decide.**

**The row of `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` is new.** The run of
2026-08-13 attributed that comparison to cause 4 alone. The re-measurement moves its part a
from `113` to `264`. **So cause 3 and cause 4 both reach that one comparison.**

#### The candidate makes five register entries stale

**This section prices answer 2, and the maintainer ruled answer 1.** **The ruling itself
costs no register entry**, because the library keeps the value it produces today.

**Answer 2 is no longer cost-free, and the run of 2026-08-13 reported that it was.** The
candidate makes five per-stream entries stale, because each one records the value the
library produces under answer 1.

| Comparison | Recorded | The candidate produces |
|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-C` | `113_64_quic` | `264_64_quic` |
| `tls3.pcapng/21/JA4L-C` | `59_128_quic` | `90_128_quic` |
| `tls3.pcapng/23/JA4L-C` | `40_128_quic` | `71_128_quic` |
| `tls3.pcapng/24/JA4L-C` | `59_128_quic` | `81_128_quic` |
| `tls3.pcapng/28/JA4L-C` | `45_128_quic` | `83_128_quic` |

**A reversal of ruling #528 therefore rewrites those five entries and removes the three
entries of this ruling.** `.claude/rules/parity.md` states that a register entry whose
comparison now matches fails the conformance suite.

**The candidate ships in no commit.** Issue #528 restored `ja4l.go` with `cp` from a copy it
took before the edit, and `git status` reports the file unchanged.

#### The port needs no change

`ja4plus/fingerprinters/ja4l.py:591-594` at tag `v1.1.0` takes the last server handshake
packet, as this library does. **This ruling makes the two repositories agree, and it opens
no issue of the port.**

## Cause 4 — the time-to-live of a second QUIC connection on one four-tuple

**This cause holds 3 deviations, all on `chrome-cloudflare-quic-with-secrets.pcapng`.**

| Key | The vector holds | The library produces |
|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/48/JA4LS.1` | (none) | `9285_56_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4LS.1` | `9285_0_quic` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` | `264_0_quic` | `113_64_quic` |

**The vector writes the time-to-live `0` on the second connection of the stream, and the
library writes the observed value.** The latency `9285` agrees exactly, so cause 2 covers
the frame of the first row and the second row, and the time-to-live is a separate
difference.

**#229 names the nearest reading, and it does not reach this value.** #229 states that a
QUIC connection which reuses one four-tuple keeps the measurement points of the first
connection, and it states
`No corpus capture reuses a four-tuple, so a closure carries a test that builds the separating packet sequence`.
**This stream reuses one four-tuple, so that sentence of #229 is wrong for this capture.**
The reading of #229 needs the correction, and this page records it.

**A vector that writes `0` for an observed time-to-live describes the capture rather than
the connection.** `.claude/rules/parity.md` `## Where a difference comes from` names that
shape a proven reference defect, and it reserves the decline to the maintainer. **This page
declines nothing.**

## Cause 6 — the coalesced QUIC datagram, and a second reference split

**This cause holds 2 deviations of the count of 177, and it holds 4 on the base of this
reading.** #449 produced it, under batch #536.

**The two counts differ because #443 measured the cluster before #447 landed.** #443 left
the two `JA4L` rows unattributed, and this section holds them now.
`## The unattributed deviation` below records that move. #447 then moved the QUIC `JA4L-S`
emission to the point D frame, and two `JA4LS` rows joined the two `JA4L` rows. **This
section states the reading that #443 asked for, and it decides no value.**

### The measurement of this section

**Every number of this section comes from one run of `make conformance` on
`issue/449-coalesced-quic-datagram`**, forked from `batch/536-value-moving-repairs` at the
merge of batch #530. The corpus is present at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. **The base of this section is not the base of
`## The measurement` above**, so no count of this section adds to a count of that table.

### Where the library stands

`IsQUICHandshakePacket` in `internal/parser/quic.go` reads `payload[0]`, which is the first
byte of the first QUIC packet of a datagram. `processUDP` in `ja4l.go` is the sole caller on
the client point path.

**RFC 9000 Section 12.2 lets one datagram carry more than one QUIC packet.** A server
datagram that coalesces an Initial packet and a Handshake packet therefore fills point B,
and it fills no point C. The connection then fills no point D, and the library publishes no
`JA4L` value and no `JA4L-S` value for it.

**The point B branch of `processUDP` returns after it fills point B**, so one datagram
reaches one point today. A repair needs the walk and the fall-through together.

### The four rows

| Key | The vector holds | The library produces |
|---|---|---|
| `ssh2.pcapng/1046/JA4L.1` | `279_128_quic` | (none) |
| `ssh2.pcapng/1046/JA4LS.1` | `16192_57_quic` | (none) |
| `tls3.pcapng/297/JA4L.1` | `271_128_quic` | (none) |
| `tls3.pcapng/297/JA4LS.1` | `3051_57_quic` | (none) |

**Each row reproduces on the base of this section.** The per-stream set adds one row:
`ssh2.pcapng/33/JA4L-S` reads `the vector holds a value the library does not produce`.

### The count this cause closes

A candidate walked every QUIC packet of a datagram, and it was reverted with
`git checkout -- internal/parser/quic.go ja4l.go docs/audit/conformance.md`.

| Measure | Before | After |
|---|---|---|
| Matches of the whole corpus | 1753 | **1757** |
| Deviations the register does not hold | 273 | **271** |
| Accepted deviations | 580 | 580 |
| Register keys | 600 | 600 |
| Unaccepted uncovered values | 184 | 184 |
| Accepted uncovered values | 20 | 20 |
| Stale register entries | 0 | 0 |
| Orphan register entries | 0 | 0 |
| Per-packet deviations | 229 | **225** |
| Per-stream deviations | 44 | **46** |

**The candidate closes 4 per-packet deviations, and it opens 2 per-stream deviations.** It
writes no register entry, and it makes no entry stale or orphan.

**The two opened rows are the reason this cause reaches the maintainer.**

| Key | The vector holds | The candidate produces |
|---|---|---|
| `ssh2.pcapng/33/JA4L-C` | (none) | `279_128_quic` |
| `tls3.pcapng/25/JA4L-C` | (none) | `271_128_quic` |

**One per-stream row changes shape rather than state.** `ssh2.pcapng/33/JA4L-S` reads
`the two values differ` after the candidate: the vector holds `16192_57` and the candidate
produces `16192_57_quic`. **The latency and the time-to-live agree exactly, and part c is
the whole difference.**

**`CHANGELOG.md` holds a guard that reads the two moved counts.**
`TestTheChangelogPreambleStatesTheCountsTheTreeProduces` failed under the candidate, and it
named 1753 and 273. That is the one test of the suite that the candidate reddened.

### Do the FoxIO implementations agree

**No. Two read every QUIC packet of a datagram, and two read the first packet alone.**

**Wireshark reads every packet.** `wireshark/source/packet-ja4.c:969` walks every field of
the frame:

```c
        for (unsigned item_idx = 0; item_idx < items->len; item_idx++) {
```

`wireshark/source/packet-ja4.c:1408` matches each `quic.long.packet_type` field of that
walk, and a coalesced datagram carries one such field for each QUIC packet:

```c
            if (strcmp(field->hfinfo->abbrev, "quic.long.packet_type") == 0) {
```

**FoxIO's Python reads the first packet alone.** `python/ja4.py:403-404` drops every QUIC
layer after the first:

```python
            if isinstance(quic, list):
                quic = quic[0]
```

**Rust reads the first packet alone.** `rust/ja4/src/time/udp.rs:258` takes the first `quic`
protocol of the packet, and `rust/ja4/src/time/udp.rs:278` takes the first field of it:

```rust
        let Ok(packet_type) = quic.first("quic.long.packet_type") else {
```

`rust/ja4/src/pcap.rs:123` states what `first` returns:

```rust
    /// Returns the [value] of the first field ([`rtshark::Metadata`]) with the given name.
```

**The Zeek reading is incomplete.** `zeek/ja4l/main.zeek:237` hooks one event for each QUIC
Handshake packet:

```zeek
event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
```

**Zeek raises that event, and Zeek's QUIC analyzer is not in the corpus.** So this page
states no answer for Zeek, and it counts 2 against 2 at worst and 3 against 2 at best.

### The vector sets carry the disagreement

**The per-stream set is FoxIO's Python output, and it holds no client value for either
connection.** `testdata/foxio/python/ssh2.pcapng.json` holds `"JA4L-S": "16192_57"` for
stream 33 and no `JA4L-C`. `testdata/foxio/python/tls3.pcapng.json` holds
`"JA4L-S": "3583_57"` for stream 25 and no `JA4L-C`.

**Every other QUIC stream of `tls3.pcapng` holds both values.** Streams 21, 22, 23, 24 and
28 each hold a `JA4L-C`, and none of those five carries a coalesced server datagram. **So
the absence names the coalesced datagram, and it names no other property of the capture.**

**The per-packet set is Wireshark's output, and it holds both values.** The four rows above
state them.

### This cause is the maintainer's

**`.claude/rules/rulings.md` `## Stop conditions` names a disagreement of the FoxIO
implementations, and it reserves that question to the maintainer.** This page picks no
answer. The two candidate answers are:

1. **Read every QUIC packet of a datagram.** Wireshark writes it. The per-packet vector set
   carries it. The measurement above states the cost: it closes 4 and it opens 2.
2. **Read the first QUIC packet of a datagram.** FoxIO's Python and Rust write it, and the
   library writes it today. The per-stream vector set carries it. The cost is nothing,
   because the library writes it today.

**Cause 3 above splits 3 against 1 the other way, and the library follows the three there.**
A reader who rules answer 1 here rules against the Python and the Rust of one method, and
the library then follows Wireshark on this question and the three on cause 3.

### Does the port carry the same gap

**Yes.** `ja4plus/fingerprinters/ja4l.py:558` calls `long_header_packet_type` once for one
datagram, and `ja4plus/utils/quic_utils.py:64` reads `udp_payload[0]`. **The port therefore
writes answer 2**, and a ruling for answer 1 is a change in both repositories.
`Crank-Git/ja4plus#613` holds the other half.

## Cause 7 — the seconds component of the Wireshark delta

**This cause holds the one deviation that no other cause explains.** Issue #652 measured it
on 2026-08-15, and this section holds the reading. **The reading decides no value.**

| Key | The vector holds | The library produces |
|---|---|---|
| `browsers-x509.pcapng/128/JA4LS.1` | `2948_229_14055` | (none) |

### Ruling #127 covers the deviation, and it is not the whole reason

**Ruling #127 declines part c on a TCP connection.** The maintainer ruled it on 2026-08-12,
re-ruled the same question as #247 on the same day, and kept it on 2026-08-15. So the
library writes two parts on a TCP connection, and `emitResult` in `ja4l.go` writes them on
the SYN-ACK frame. **The library therefore produces `2948_229` on frame 121**, and the
conformance suite reports that value as a second deviation of the pair that
`## The shape of the cluster` above describes.

**Cause 1 above prices a reversal of ruling #127, and its candidate left this row open.**
`### The count this cause closes` records the measurement: the candidate closes 149
deviations, and one TCP deviation remains. **This section states why that one row survives a
reversal.**

### Part c of the vector discards a whole second

`wireshark/source/packet-ja4.c:1371-1374` writes the three parts:

```c
                                    wmem_strbuf_append_printf(
                                        display, "%d_%d_%d", latency.nsecs / 2 / 1000, conn->server_ttl,
                                        latency2.nsecs / 2 / 1000
                                    );
```

**`nsecs` is the sub-second field of `nstime_t`, and it is never the whole interval.** The
Wireshark core at `v4.6.0` defines the type:

```c
typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;
```

`wireshark/source/packet-ja4.c:1370` fills `latency2` with
`nstime_delta(&latency2, &conn->timestamp_E, &conn->timestamp_D)`, and the dissector reads
`latency2.nsecs` alone. **So an interval of one second or more loses its whole-second
part.**

### The measurement

**`browsers-x509.pcapng` stream 2 is the one TCP connection of the corpus whose interval
crosses one second.** The frames below come from the capture at the pinned commit.

| Point | Frame | Timestamp |
|---|---|---|
| A | 120 | `1691545934.646949000` |
| B | 121 | `1691545934.652846000` |
| D | 123 | `1691545934.653341000` |
| E | 125 | `1691545935.681451000` |

**The interval `E - D` is 1028110000 nanoseconds.** It normalizes to `secs=1` and
`nsecs=28110000`.

| Reading | Arithmetic | Result |
|---|---|---|
| The whole interval | `1028110000 / 2 / 1000` | `514055` |
| **The `nsecs` field alone** | `28110000 / 2 / 1000` | **`14055`** |

**The published vector holds `14055`**, so the vector reads the `nsecs` field.

**The corpus corroborates the reading with a second published field.**
`testdata/foxio/wireshark/browsers-x509.pcapng.json` holds `ja4.ja4ls_delta` `4.8` on frame
128. `wireshark/source/packet-ja4.c:1377` computes that ratio as
`latency2.nsecs / latency.nsecs`. The `nsecs` reading gives `28110000 / 5897000`, which is
4.767 and rounds to `4.8`. The whole-interval reading gives `1028110000 / 5897000`, which
is 174.3. **So FoxIO's own delta field states which interval the dissector read.**

### Why the JA4L value of the same frame closes and the JA4LS value does not

`ja4.ja4l` on frame 128 holds `78_128_150466`. Its part c reads `F - E`, which is 300932000
nanoseconds. **That interval stays below one second, so both readings give `150466`.** The
cause 1 candidate therefore closes the JA4L row of frame 128 and it leaves the JA4LS row
open.

### This is the defect that #253 records, in a second implementation

**#253 records the same defect class in FoxIO's reference Python.**
`python/common.py:182` holds `return int((dt2-dt1).microseconds/2)`, and
`timedelta.microseconds` is the sub-second field. #253 states the question it leaves open:

> **Whether any corpus capture holds a latency above one second is the question this issue leaves open**, and it decides whether the defect reaches a published vector.

**This measurement answers that question. One capture holds such an interval, and the
defect reaches a published vector.** The vector is a Wireshark vector rather than a Python
vector, so the answer names the dissector.

**`## What #253 and #249 explain` below reads part a of every JA4L value, and it reads no
part c.** That section states that no interval of the cluster crosses one second, and the
sentence holds for part a alone. **The `E - D` interval of part c crosses one second.**

### Do the FoxIO implementations agree

**No.** The Wireshark dissector discards the whole-second part, and no other implementation
does.

| Implementation | What it reads | Evidence |
|---|---|---|
| Wireshark | The `nsecs` field of the delta. | `wireshark/source/packet-ja4.c:1373` |
| Zeek | The whole timestamp, in microseconds. | `zeek/ja4l/main.zeek:72`, `zeek/ja4l/main.zeek:125` |
| FoxIO's reference Python | The `microseconds` field of the delta. | `python/common.py:182` |

`zeek/ja4l/main.zeek:72` returns `cp$ts_sec * 1000000.0 + cp$ts_usec`, so the Zeek package
keeps the whole interval. **FoxIO's reference Python carries the same defect as Wireshark**,
and #253 holds that reading.

### Does the port carry the same gap

**Yes.** The port writes two parts on a TCP connection, so it produces no part c at all.
`ja4plus/fingerprinters/ja4l.py:482` at the tag `v1.1.0` writes the client value with two
parts, and `:447` and `:467` write the server value with two parts. `_one_way_latency` at
`ja4plus/fingerprinters/ja4l.py:348` returns `int((end - start) / LATENCY_DIVISOR)` over
whole microsecond timestamps, so the port discards no second.

**A reversal of ruling #127 therefore reaches both repositories**, and this row needs a
second decision after that reversal.

### This cause is the maintainer's

**`.claude/rules/parity.md` `## Where a difference comes from` names a proven reference
defect, and it reserves the decision to the maintainer.** This section records the
measurement, and it recommends no change.

**The decision is not needed while ruling #127 stands.** Ruling #127 gives the library two
parts on a TCP connection, so no part c of the library can reach this vector. **The decision
is needed only if the maintainer reverses ruling #127.** The reversal then asks one further
question: does the library reproduce the seconds truncation of the dissector, or does it
write the whole interval and decline this vector?

## What #253 and #249 explain

**#253 explains no deviation of this cluster.** It reads that FoxIO's reference Python
computes `int((dt2-dt1).microseconds/2)` at `python/common.py:182`, which truncates every
interval above one second and turns a negative interval into a large positive one. **The
second half of #253 is now measured: the cluster holds one candidate.**
`chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S` reads `10990_56` in the
per-stream set, and the per-packet set reads `9285` for the same connection. Both values
sit below one second, so the truncation of #253 does not reach either one. **No part a of
this cluster crosses one second.**

**That sentence reads part a alone, and #652 measured a part c that crosses one second.**
`## Cause 7 — the seconds component of the Wireshark delta` above holds the measurement:
the `E - D` interval of `browsers-x509.pcapng` stream 2 is 1028110000 nanoseconds, and the
published vector holds the sub-second part of it. **So one value of this cluster does carry
the signature of #253**, in the Wireshark dissector rather than in FoxIO's reference
Python.

**#249 is explained in part, and one half stays open.** #249 asks why the server latency of
the second QUIC connection on one stream differs by 1705 microseconds when the client
latency agrees. The measurement adds one fact that #249 does not hold: **the per-packet
vector agrees with the library and the per-stream vector does not.**

| Source | The value for that connection |
|---|---|
| The per-stream vector set | `10990_56` |
| **The per-packet vector set** | **`9285_0_quic`** |
| **This library** | **`9285_56_quic`** |

**So the two FoxIO vector sets disagree with each other on the latency, and this library
matches Wireshark on it.** #249 reads the per-stream value alone, and it concludes that
nothing explains the difference. The per-packet value explains the latency: Wireshark and
this library read one pair of points, and Python reads another. **The time-to-live `0` of
the per-packet value stays unexplained, and cause 4 above holds it.**

`tls3.pcapng/25/JA4L-S` carries the same shape. The per-stream vector reads `3583_57` and
the library reads `3051_57_quic`, and the per-packet set reads `3051_57_quic` on frame 297.
**So the second per-stream deviation of this cluster has the same reading as #249.**

## The whole attribution

| Cause | Attributed | Measured close | Cost | Who decides |
|---|---|---|---|---|
| 1 — the TCP emission frame and part c | 149 | **149** | Opens 100. Orphans 41 entries. | The maintainer. Ruling #127 holds it. |
| 2 — the QUIC `JA4L-S` emission frame | 16 | **15** | Opens none. Orphans 20 entries. | An engineer. The four implementations agree. |
| 3 — the QUIC client measurement point | 4 | **3** | **The ruling costs nothing.** Answer 2 cost nothing on 2026-08-13, and it costs 5 stale entries on 2026-08-14. | **Ruled on 2026-08-14. Issue #528 holds it.** |
| 4 — the time-to-live of a reused four-tuple | 3 | Not measured. The vector writes `0`. | — | The maintainer. A reference defect. |
| 5 — the two vector sets disagree | 2 | Not measured. Each set holds a different value. | — | The maintainer. #249 holds it. |
| 6 — the coalesced QUIC datagram | 2 | **4**, on a later base. Opens 2. | None. | The maintainer. A reference split, 2 against 2. |
| 7 — the seconds component of the Wireshark delta | 1 | Not measured. Ruling #127 bars a candidate. | — | The maintainer. A proven reference defect. |
| **Total** | **177** | | | |

**Four causes carry a measured count, and each one was measured on its own.** Cause 3 is
the cheapest: it closes 3, it opens none, and it leaves the register whole. Cause 2 closes
15 and rewrites 20 register entries. Cause 1 closes 149 and opens 100. Cause 6 closes 4 and
opens 2.

**The four counts do not add.** Causes 1, 2 and 3 each ran against the base of
`## The measurement` above. **Cause 6 ran against a later base**, which #447 had already
moved, so its count of 4 counts two rows that the base of this page does not hold. A reader
who buys two causes measures the pair.

**Every deviation of the cluster reaches a cause.**

## The last deviation, and where its reading lives

`browsers-x509.pcapng/128/JA4LS.1` was unattributed until 2026-08-15, and
`## Cause 7 — the seconds component of the Wireshark delta` above now holds its reading.
**#443 produced no reading for it, and #652 measured it.**

| Key | The vector holds | The library produces | Which cause holds it |
|---|---|---|---|
| `browsers-x509.pcapng/128/JA4LS.1` | `2948_229_14055` | (none) | Cause 7, and ruling #127 beside it. |

**Two causes reach this one row, and cause 1 alone does not close it.** Ruling #127 declines
part c on a TCP connection, so the library writes `2948_229` on frame 121. **Part c of the
vector also discards a whole second**, so the cause 1 candidate leaves the row open.

**#443 listed two more rows here, and cause 6 above now holds them.**
`ssh2.pcapng/1046/JA4L.1` and `tls3.pcapng/297/JA4L.1` each read
`the vector holds a value the library does not produce`, and #449 states why.

## What this page does not state

- **It recommends no change.** **The maintainer ruled cause 3 on 2026-08-14**, and causes
  1, 4, 5, 6 and 7 each stay with the maintainer.
- **It measured causes 1, 2, 3 and 6.** Causes 4 and 5 carry no measured count, because
  each one needs a ruling before a candidate exists. **Cause 7 carries no measured count
  either**, because ruling #127 bars the candidate that would produce one.
- **It measured each cause on its own.** It measured no pair of causes together, so the
  four counts do not add. **Causes 1, 2 and 3 ran against one base, and cause 6 ran against
  a later base.** `### The measurement of this section` states the base of cause 6.
- **It ran no Python.** The port was read as text. `.claude/rules/parity.md` states the rule.
- **The reading of #443 writes no register entry.** **Issue #528 wrote three entries under
  the ruling of 2026-08-14**, and `### The ruling of 2026-08-14` above names each one.
- **It states no count for the JA4H cluster.** #442 reads that cluster.
