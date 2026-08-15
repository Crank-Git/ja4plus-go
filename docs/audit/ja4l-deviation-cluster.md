# The JA4L and JA4LS deviation cluster

This page reads the JA4L and JA4LS deviations that `testdata/deviations.json` does not
hold. **The page records what each source states, and it decides no value.** It changes no
code and it moves no fingerprint. **The maintainer rules, and the page records each
ruling.**

Issue #443 produced it, under Epic #441. `.claude/rules/rulings.md` states who rules.

**The maintainer ruled cause 3 on 2026-08-14, and issue #528 holds that ruling.**
`## Cause 3 — the QUIC client measurement point, and a reference split` below records the
ruling, the re-measurement and the three register entries it wrote.

**The maintainer kept ruling #127 on 2026-08-15 UTC, so cause 1 is settled.** Comment
5299851784 of issue #441 holds the decline of the reversal. The register round on
`issue/682-ruling-127-register-entries` wrote the entries that record the price. Issue #127
is the reversal path.

**The maintainer ruled causes 4, 5 and 6 on 2026-08-15 UTC.** Issue #229 holds cause 4,
issue #249 holds cause 5 and issue #449 holds cause 6. Batch #668 wrote the seven register
entries that the three rulings produce. **The cause 5 decline is provisional**, because
`Crank-Git/ja4plus#622` asks which FoxIO vector set is authoritative for JA4L timing and
that question is open. **Each section below states its ruling, its re-measurement and its
reversal path.**

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
`## Cause 7 — the seconds component of the Wireshark delta` below names it. **Cause 7
states why that row survives this candidate**, so the candidate closes 149 of 150 TCP rows.

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

#### The maintainer kept ruling #127 on 2026-08-15, and the register now records the price

**The maintainer declined the reversal on 2026-08-15 UTC**, in comment 5299851784 of issue
#441. Issue #127 is the reversal path, and the ruling stays reversible.

**The register round on `issue/682-ruling-127-register-entries` wrote one entry for each
comparison the ruling reaches.** The library
keeps the two parts it writes today, so no line of `ja4l.go` changes.
`.claude/rules/rulings.md` `## Where a ruling is recorded` states the rule the entries
satisfy: a ruling that a vector reaches carries an entry in `testdata/deviations.json`.

**The round enumerated the set from one live run, and never from this page.**
`docs/audit/conformance.md` truncates each deviation group to three rows, so no document of
this repository ever held the list. `make conformance` runs `go test -tags conformance -v`.
`conformanceRecordComparison` in `conformance_test.go` then writes one log line for every
unaccepted deviation. **The round read the list from that output** on
`issue/682-ruling-127-register-entries`, with the corpus at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

| Measure | Before the entries | After the entries |
|---|---|---|
| Matches | 1754 | **1754** |
| Deviations the register does not hold | 247 | **97** |
| Accepted deviations | 605 | **755** |
| Register keys | 637 | **787** |
| Unaccepted uncovered values | 175 | 175 |
| Accepted uncovered values | 32 | 32 |
| Stale register entries | 0 | 0 |
| Orphan register entries | 0 | 0 |

**The match count does not move**, because a decline moves a comparison from unaccepted to
accepted and it moves no output. **The identity holds on each side**: `605 + 32 = 637`, and
`755 + 32 = 787`.

**The run reports 150 newly accepted per-packet comparisons, and this cause holds 149 of
them.** The 150th is `tls3.pcapng/153/JA4L.1`, and
`### The count of this ruling is 3, and the count above is 4` under cause 3 states why no
reading explains it. **The entry of that row says so, and it claims no cause.**

**Issue #652 already declined `browsers-x509.pcapng/128/JA4LS.1`**, at `5d3a650`, so the
round did not re-enter it. **A duplicate key fails the conformance suite**, and
`TestTheRegisterHoldsEachKeyOnce` in `deviations_test.go` holds that rule.

#### The 149 rows hold two shapes, and the second one is not a pair

`## The shape of the cluster` above states the pair: one difference produces two deviations.
The suite reports the library value as a value the vector does not hold. It reports the
vector value as a value the library does not produce. **138 of the 149 rows form 69 such
pairs.** One more row, `browsers-x509.pcapng/121/JA4LS.1`, pairs with the cause 7 row that
issue #652 already declined.

**The remaining 10 rows carry a library value that the reference publishes nowhere.** Each
one reads `the library produces a value the vector does not hold`. No vector row of the
capture holds the same part a and part b on any frame.

| Key | The library produces | The reference publishes |
|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/2/JA4LS.1` | `5749_56` | (nothing for that connection) |
| `chrome-cloudflare-quic-with-secrets.pcapng/3/JA4L.1` | `30_64` | (nothing for that connection) |
| `latest.pcapng/111/JA4LS.1` | `3915_57` | (nothing for that connection) |
| `latest.pcapng/112/JA4L.1` | `32_128` | (nothing for that connection) |
| `ssh2.pcapng/370/JA4LS.1` | `6252_58` | (nothing for that connection) |
| `ssh2.pcapng/371/JA4L.1` | `45_128` | (nothing for that connection) |
| `ssh2.pcapng/954/JA4LS.1` | `4272_58` | (nothing for that connection) |
| `ssh2.pcapng/955/JA4L.1` | `50_128` | (nothing for that connection) |
| `tls3.pcapng/76/JA4LS.1` | `3181_57` | (nothing for that connection) |
| `tls3.pcapng/77/JA4L.1` | `14_128` | (nothing for that connection) |

**The emission frame explains the shape, and it is the same cause.**
`wireshark/source/packet-ja4.c:1362-1394` writes on the `timestamp_F` frame alone, so a
connection that never fills `timestamp_F` reaches no Wireshark value at all. **This library
writes on the SYN-ACK frame and on the client measurement point.** Each of those frames
comes before `timestamp_D`, so the connection reaches a library value.

**The measurement that settles the attribution is the candidate of
`### The count this cause closes` above: it closes 149.** That figure equals the 149 rows of
this ruling, so every row of both shapes falls to the same change.

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
| `tls3.pcapng/153/JA4L.1` | `101_128_quic` | `40_128_quic` | `71_128_quic` | One entry under ruling #127, and its reason states that no reading explains the difference. |
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` | `264_0_quic` | `113_64_quic` | `264_64_quic` | No entry under ruling #528. Ruling #229 holds it. |

**The last two rows carry a second difference, so ruling #528 alone does not hold either
one.** `tls3.pcapng/153/JA4L.1` reads `71_128_quic` under the candidate, and the vector holds
`101_128_quic`. No reading of this page states that remainder.

Part a of `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` agrees exactly under the
candidate. The time-to-live `0` of that vector reaches cause 4, and the maintainer ruled
cause 4 on 2026-08-15 UTC.

**An entry that named ruling #528 for either row would accept a difference the ruling does
not decide.**

**`tls3.pcapng/153/JA4L.1` now carries one entry, and it names ruling #127 rather than
ruling #528.** The register round on `issue/682-ruling-127-register-entries` wrote it on
2026-08-15 UTC. Its reason states two facts.

1. **Ruling #127 decides no part of this difference.** The ruling decides the part count on
   a TCP connection and the `quic` marker on a QUIC connection, and both sides of this
   comparison already agree on each of those.
2. **No reading of this page explains the remainder that ruling #528 leaves.** The table
   above states that remainder: the candidate of ruling #528 produces `71_128_quic`, and
   the vector holds `101_128_quic`.

**The entry therefore claims no cause.** It is the one entry of that round that this page
does not attribute.
**Issue #127 is its reversal path**, and a later reading that explains the remainder moves
the entry to the ruling that does decide it.

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

**This cause held 3 deviations on 2026-08-13, and it holds 2 today.** Every one sits on
`chrome-cloudflare-quic-with-secrets.pcapng`. **The maintainer ruled the cause on
2026-08-15 UTC**, and `### The ruling of 2026-08-15` below states the ruling and the two
register entries it wrote.

### The reading of 2026-08-13

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
shape a proven reference defect, and it reserved the decline to the maintainer.

### The re-measurement of 2026-08-15

**The first two rows above are one row today, so this cause holds 2 deviations.** #447
moved the QUIC `JA4LS` emission to the point D frame, so the library writes its `JA4LS`
value on frame 52 rather than on frame 48. **The frame difference of cause 2 closed, and
the time-to-live difference stayed.**

| Key | The vector holds | The library produces |
|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4LS.1` | `9285_0_quic` | `9285_56_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` | `264_0_quic` | `113_64_quic` |

**The run reports no deviation on frame 48.** Two runs of `make conformance` on
`batch/668-route-and-declines` produced both rows above, on 2026-08-15 UTC, with the corpus
present at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.
`docs/audit/conformance.md` holds each row.

### The ruling of 2026-08-15

**The maintainer ruled on 2026-08-15 UTC that this library writes the observed
time-to-live.** Comment 5299851633 of issue #229 holds the ruling, and issue #229 is the
reversal path. The ruling states the reason:

> **A time-to-live of `0` on a second connection over one four-tuple describes the capture, and it does not describe the connection.**

**The library keeps the value it produces today, so no line of `ja4l.go` changes.** #229
wrote one entry in `testdata/deviations.json` for each row of the table above, and the run
reports both comparisons as accepted.

## Cause 6 — the coalesced QUIC datagram, and a second reference split

**This cause holds 2 deviations of the count of 177, and it holds 4 on the base of this
reading.** #449 produced it, under batch #536.

**The two counts differ because #443 measured the cluster before #447 landed.** #443 left
the two `JA4L` rows unattributed, and this section holds them now.
`## The last deviation, and where its reading lives` below records that move. #447 then
moved the QUIC `JA4L-S`
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

**Each row reproduces on the base of this section.** The per-stream set adds two rows, and
each one reads `the vector holds a value the library does not produce`.

| Key | The vector holds | The library produces |
|---|---|---|
| `ssh2.pcapng/33/JA4L-S` | `16192_57` | (none) |
| `tls3.pcapng/25/JA4L-S` | `3583_57` | (none) |

**This page named one of the two rows until 2026-08-15.** #449 measured the pair, and batch
#668 records both here. `### Where the library stands` above states the mechanism that
empties each one: the connection fills no point D, so the library publishes no `JA4L-S`
value for it.

**The two rows are not exact analogues, and #675 measured the difference on 2026-08-15.**
`### The reading of #675` below states it. `ssh2.pcapng/33/JA4L-S` carries one difference
from the reference, and `tls3.pcapng/25/JA4L-S` carries two.

**`tls3.pcapng/25/JA4L-S` is one of the two per-stream deviations of the count of 177**, and
`## The measurement` above names it. Cause 5 held it until 2026-08-15, and
`## What #253 and #249 explain` below states why it moved.

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

### The ruling of 2026-08-15

**The maintainer ruled answer 2 on 2026-08-15 UTC.** The library reads the first QUIC packet
of a coalesced datagram. Comment 5299851551 of issue #449 holds the ruling, and issue #449
is the reversal path.

**The library keeps the packet it reads today, so no line of `internal/parser/quic.go` and
no line of `ja4l.go` changes.** #449 wrote 4 entries in `testdata/deviations.json`, one for
each row of `### The four rows` above, and the run reports all four as accepted.

**The ruling reaches the four per-packet rows, and it reaches neither per-stream row.** Both
sides of a per-stream comparison read the first QUIC packet alone, because FoxIO's Python
produces the per-stream set and `python/ja4.py:403-404` drops every QUIC layer after the
first. **So the ruled rule cannot produce the per-stream difference**, and a decline there
would hide the fall-through of `processUDP` behind a ruling that does not reach it.
**Issue #675 holds that fall-through.**

### The reading of #675

**#675 read the two per-stream rows on 2026-08-15, and it names the fall-through.** It
writes no register entry, and it changes no line of `ja4l.go`.

**The measured yield is 2, and it is not attributed.** One run of `make conformance` on
`issue/675-processudp-per-stream-ja4ls` reports 1754 matches, 247 deviations, 605 accepted
deviations and 637 register keys. Two comparisons of the whole corpus read
`the vector holds a value the library does not produce` for a per-stream `JA4L-S` key.
**They are the two rows of `### The four rows` above.**

#### The emission point is not the difference

**The reference computes the QUIC server value inside its point D branch, and the library
does the same.** `python/ja4.py:585-587` calls `calculate_ja4_latency` only when
`cache_update` fills point `D`:

```python
                if x['packet_type'] == '2' and x['dstport'] == '443':
                    if (cache_update(x, 'D', x['timestamp'], STREAM)):
                        calculate_ja4_latency(x, 'quic', STREAM) 
```

**`calculate_ja4_latency` then writes the server value from point A and point B alone.**
`python/ja4.py:154-157` reads no point C and no point D:

```python
            if 'B' in conn and 'A' in conn:
                diff = epoch_diff(conn['A'], conn['B'])
                ttl = conn['server_ttl']
                cache_update(x, 'JA4L-S',  f"{diff}_{ttl}", STREAM)
```

**The client value needs point C and point D**, at `python/ja4.py:162-164`. So a connection
that fills point D and no point C reaches one value and not two, which is what each vector
holds.

#### The fall-through: the library gates point D on point C

**The reference fills point D on a client Handshake packet, and it reads no point C.**
`python/ja4.py:585` tests the packet type and the destination port, and nothing else.

**`processUDP` in `ja4l.go` fills point D only when point C is present.** Its point D branch
opens with a test of `conn.timestamps["C"]`. A connection with no point C therefore reaches
the end of the method, and it returns no result. **That test is the fall-through, and it is
the whole cause of `ssh2.pcapng/33/JA4L-S`.**

**#447 created these two rows, and the fall-through was harmless before it.** The library
published the QUIC server value on the frame that fills point B until #447, so a connection
that never fills point D still reached a value. `## Cause 2 — the JA4L-S emission frame on a
QUIC connection` above records that behavior, and it names `16192_57_quic` on frame 1042 of
`ssh2.pcapng`. **That is the same connection this section reads.** #447 moved the emission to
the point D frame, and the point C gate then emptied both rows.

**Point C stays empty for a lawful reason, and the reference agrees with the library
there.** `IsQUICHandshakePacket` in `internal/parser/quic.go` reads `payload[0]`, so a
coalesced datagram that leads with an Initial packet fills no point C. The reference reads
the first QUIC packet alone as well, and neither vector holds a `JA4L-C` value for these two
streams. **So `IsQUICHandshakePacket` empties point C, and it produces no deviation.** The
ruling of 2026-08-15 keeps that behavior, and #675 does not change it.

#### One cause, and one second difference on one row

**A probe ran `JA4LFingerprinter` over each capture on 2026-08-15 and read the connection
state.** Exactly one connection of each capture reaches point A and point B and no further.

| Capture | Connection | Points | Server TTL | `(B-A)/2` | The vector holds |
|---|---|---|---|---|---|
| `ssh2.pcapng` | `142.251.32.74:443` and `172.16.225.48:51810` | A and B | 57 | 16192 | `16192_57` |
| `tls3.pcapng` | `104.21.234.234:443` and `192.168.1.169:61884` | A and B | 57 | 3051 | `3583_57` |

**`ssh2.pcapng/33` carries one difference.** The library already holds the value the vector
states, and the fall-through above is the only reason it publishes nothing.

**`tls3.pcapng/25` carries a second difference, and the fall-through does not reach it.**
The library reads point B at the first server Initial packet, and the reference reads it at
the Initial packet that carries the ServerHello. `python/ja4.py:580-581` states the
reference rule:

```python
                if x['packet_type'] == '0' and 'type' in x and x['type'] == '2':
                    cache_update(x, 'B', x['timestamp'], STREAM) 
```

**`python/common.py:101` names `B` among the fields the reference never updates**, so the
first Initial packet that carries a ServerHello fixes the point.

**The probe read the packet sequence of that connection.** The server sends two Initial
packets, 6102 µs and 7166 µs after the client Initial packet. Half of each delay is 3051 and
3583. **The library takes the first, and the vector holds the second.** So the reference
reads a ServerHello in the second Initial packet and not in the first.

**That second difference is a reference split, and it belongs to the maintainer.** The
per-packet set holds `3051_57_quic` for `tls3.pcapng/297/JA4LS.1`, which is the first server
Initial packet. So Wireshark reads the first packet and FoxIO's Python reads the ServerHello
packet. `.claude/rules/rulings.md` `## Stop conditions` reserves that question. **Issue #686
holds it, and #675 rules nothing.**

#### The port does not carry this gap

**The port publishes the QUIC server value at point B, and never at point D.**
`ja4plus/fingerprinters/ja4l.py:547-550` of tag `v1.1.0` fills the point and returns the
value in one step:

```python
    timestamps["B"] = now
    conn["ttls"]["server"] = ttl
    return "JA4L-S={}_{}_{}".format(
        _one_way_latency(timestamps["A"], timestamps["B"]), ttl, QUIC_MARKER
```

**So the fall-through of `processUDP` has no analogue in the port.** The port reaches a
server value on a connection that fills no point C and no point D, and this library does
not.

**The port also reads the reference point B rule.** `ja4plus/fingerprinters/ja4l.py:543` of
tag `v1.1.0` returns until `server_hello_is_complete` holds, so the port takes the Initial
packet that carries the ServerHello.

**This section states what the port's code does, and it states no value the port produces.**
`.claude/rules/parity.md` `## Never run the port from a test` bars a run.
`ja4plus/fingerprinters/ja4l.py:538` of tag `v1.1.0` gates point B on a decryption, and this
reading did not measure that decryption.

**`### Does the port carry the same gap` above answers a different question.** It reads the
coalesced datagram, and the port carries that reading. This section reads the emission point
and the point B rule, and the port carries neither gap.

#### Why no register entry cites ruling #449

**Both sides of a per-stream comparison read the first QUIC packet of a datagram**, so the
ruled rule produces no difference between them. A decline that cites #449 would state a
false cause, and it would hide the fall-through above. **#675 therefore writes no entry in
`testdata/deviations.json`.**

#### A repair moves a fingerprint value

**A repair of the fall-through is not a documentation change, and #675 builds none of it.**
`.claude/rules/rulings.md` `## Stop conditions` and the body of #675 each bar it. Three
values move.

- **`ssh2.pcapng/33/JA4L-S` changes state, and it does not close.** The library would
  publish `16192_57_quic`, and the vector holds `16192_57`. The row reads
  `the two values differ` after the repair.
- **`tls3.pcapng/25/JA4L-S` changes state, and the second difference survives.** The library
  would publish `3051_57_quic`, and the vector holds `3583_57`.
- **The per-packet set gains a `JA4LS.1` value on each of the two captures.** A point D that
  fills without point C emits on a frame that publishes nothing today.

**`CHANGELOG.md` holds a guard that reads the match count and the deviation count.**
`### The count this cause closes` above records that the candidate of #449 reddened it.

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
the SYN-ACK frame. **The library therefore produces `2948_229` on frame 121.** The conformance suite reports
that value as a second deviation. `## The shape of the cluster` above describes that pair.

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
| Zeek | The whole timestamp, in microseconds. | `zeek/ja4l/main.zeek:74`, `zeek/ja4l/main.zeek:125` |
| FoxIO's reference Python | The `microseconds` field of the delta. | `python/common.py:182` |

`zeek/ja4l/main.zeek:74` returns `cp$ts_sec * 1000000.0 + cp$ts_usec`, so the Zeek package
keeps the whole interval. **FoxIO's reference Python carries the same defect as Wireshark**,
and #253 holds that reading.

### Does the port carry the same gap

**Yes.** The port writes two parts on a TCP connection, so it produces no part c at all.
`ja4plus/fingerprinters/ja4l.py:482` at the tag `v1.1.0` writes the client value with two
parts, and `:446` and `:466` write the server value with two parts.
`ja4plus/fingerprinters/ja4l.py:358` returns `int((end - start) / LATENCY_DIVISOR)` over
whole microsecond timestamps, so `_one_way_latency` discards no second.

**A reversal of ruling #127 therefore reaches both repositories**, and this row needs a
second decision after that reversal.

### This cause is the maintainer's

**`.claude/rules/parity.md` `## Where a difference comes from` names a proven reference
defect, and it reserves the decision to the maintainer.** This section records the
measurement, and it recommends no change.

**The decision is not needed while ruling #127 stands.** Ruling #127 gives the library two
parts on a TCP connection, so no part c of the library can reach this vector. **The decision
is needed only if the maintainer reverses ruling #127.** The reversal then asks one further
question, and it holds two answers.

1. The library reproduces the seconds truncation of the dissector.
2. The library writes the whole interval, and it declines this vector.

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
this library read one pair of points, and Python reads another. **Cause 4 above holds the
time-to-live `0` of the per-packet value, and the maintainer ruled cause 4 on 2026-08-15
UTC.**

**The maintainer ruled the latency question on 2026-08-15 UTC.** This library keeps the
value it produces, and this project declines the disagreement between the two vector sets.
Comment 5299851698 of issue #249 holds the ruling. #249 wrote one entry in
`testdata/deviations.json` for `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S`,
and the run reports that comparison as accepted.

**The decline is provisional.** `Crank-Git/ja4plus#622` asks which FoxIO vector set is
authoritative for JA4L timing, and that question is open. **The maintainer ruled on
2026-08-15 UTC that v1.0.0 ships with it open**, and the release records the divergence as
a known cross-implementation difference: this library writes `9285_56_quic` and the port
writes `10990_56_quic` for that connection. **The reversal path is issue #249 and
`Crank-Git/ja4plus#622`.**

**`tls3.pcapng/25/JA4L-S` does not carry that shape, and an earlier sentence of this page
stated that it does.** Batch #668 re-measured the row on 2026-08-15 UTC, and the library
produces no value there at all.

| Source | The value for that connection |
|---|---|
| The per-stream vector set | `3583_57` |
| The per-packet vector set, on frame 297 | `3051_57_quic` |
| **This library** | **(none)** |

Two runs of `make conformance` on `batch/668-route-and-declines` report
`the vector holds a value the library does not produce` for the per-stream row, with the
corpus present at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.
`testdata/foxio/python/tls3.pcapng.json` holds `"JA4L-S": "3583_57"` for stream 25 and no
`JA4L-C`, and `testdata/foxio/wireshark/tls3.pcapng.json` holds `ja4.ja4ls`
`3051_57_quic` on frame 297.

**A row where the library produces nothing matches neither vector set, so the reading of
#249 does not reach it.** #249 reads a connection where the two sets disagree and the
library matches one of them. **`## Cause 6 — the coalesced QUIC datagram, and a second
reference split` above holds this row**, together with its analogue
`ssh2.pcapng/33/JA4L-S`. Issue #675 holds the fall-through of `processUDP` that empties
each one.

**So cause 5 holds one per-stream deviation, and it held two until 2026-08-15.**

## The whole attribution

| Cause | Attributed | Measured close | Cost | Who decides |
|---|---|---|---|---|
| 1 — the TCP emission frame and part c | 149 | **149** | Opens 100. Orphans 41 entries. | **Kept on 2026-08-15 UTC. Ruling #127 holds it, and the register round wrote 149 entries.** |
| 2 — the QUIC `JA4L-S` emission frame | 16 | **15** | Opens none. Orphans 20 entries. | An engineer. The four implementations agree. |
| 3 — the QUIC client measurement point | 4 | **3** | **The ruling costs nothing.** Answer 2 cost nothing on 2026-08-13, and it costs 5 stale entries on 2026-08-14. | **Ruled on 2026-08-14. Issue #528 holds it.** |
| 4 — the time-to-live of a reused four-tuple | 3 | Not measured. The vector writes `0`. | 2 register entries. | **Ruled on 2026-08-15 UTC. Issue #229 holds it.** |
| 5 — the two vector sets disagree | 1 | Not measured. Each set holds a different value. | 1 register entry. | **Ruled on 2026-08-15 UTC. Issue #249 holds it. Provisional.** |
| 6 — the coalesced QUIC datagram | 3 | **4**, on a later base. Opens 2. | 4 register entries. | **Ruled on 2026-08-15 UTC. Issue #449 holds it.** |
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

**The `Attributed` column reads the base of `## The measurement` above, and the `Cost`
column reads the tree of 2026-08-15 UTC.** The two columns therefore name two moments, and
a reader adds no figure across them. **Batch #668 moved one attributed row on 2026-08-15
UTC**, from cause 5 to cause 6. `tls3.pcapng/25/JA4L-S` is that row, and
`## What #253 and #249 explain` above states the measurement that moved it. **The total of
177 does not change**, because the move takes one row from one cause and gives it to
another.

**Cause 4 states 3 in the `Attributed` column and it holds 2 today.**
`### The re-measurement of 2026-08-15` above states the reason: #447 collapsed two rows of
the 2026-08-13 reading into one comparison on frame 52.

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

- **It recommends no change.** **The maintainer ruled cause 3 on 2026-08-14, and causes 1,
  4, 5 and 6 on 2026-08-15 UTC.** Cause 7 stays with the maintainer, and the decision it
  needs arises only if the maintainer reverses ruling #127.
- **It measured causes 1, 2, 3 and 6.** Causes 4 and 5 carry no measured count, because
  each one needs a ruling before a candidate exists. **Cause 7 carries no measured count
  either**, because ruling #127 bars the candidate that would produce one.
- **It measured each cause on its own.** It measured no pair of causes together, so the
  four counts do not add. **Causes 1, 2 and 3 ran against one base, and cause 6 ran against
  a later base.** `### The measurement of this section` states the base of cause 6.
- **It ran no Python.** The port was read as text. `.claude/rules/parity.md` states the rule.
- **The reading of #443 writes no register entry.** **Issue #528 wrote three entries under
  the ruling of 2026-08-14**, and `### The ruling of 2026-08-14` above names each one.
  **Batch #668 wrote seven more on 2026-08-15 UTC**, under the rulings of #229, #249 and
  #449. The register held 630 keys before that batch and it holds 637 after it, measured on
  2026-08-15 UTC. **The register round on `issue/682-ruling-127-register-entries` then
  wrote 150 more under ruling #127 on 2026-08-15 UTC**, and the register holds 787 keys
  after it.
  `#### The maintainer kept ruling #127 on 2026-08-15, and the register now records the price`
  under cause 1 above holds that measurement.
- **It states no count for the JA4H cluster.** #442 reads that cluster.
