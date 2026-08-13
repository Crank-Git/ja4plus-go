# The JA4L and JA4LS deviation cluster

This page reads the JA4L and JA4LS deviations that `testdata/deviations.json` does not
hold. **The page records what each source states, and it decides no value.** It changes no
code, it moves no fingerprint, and it adds no register entry.

Issue #443 produced it, under Epic #441. `.claude/rules/rulings.md` states who rules.

## The measurement

Every number on this page comes from one run of `make conformance` on
`issue/443-ja4l-deviation-cluster`, with the corpus present at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

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

**The candidate closes 149 deviations of this cluster, and it opens 100.** It closes every
TCP deviation of the per-packet set. It opens 98 per-stream deviations, because the
per-stream set holds two parts and names a different frame.

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

**This page measured no count for this cause on its own.** The candidate of cause 1 touched
the TCP path alone, so these 16 deviations stand in the before column and in the after
column. A separate candidate measures this cause, and #443 built none.

**The four implementations agree on the frame.** Zeek writes the client value at
`zeek/ja4l/main.zeek:248` inside the branch that fills `client_handshake`, and Rust reaches
`Done` at `rust/ja4/src/time/udp.rs:185-197` on the client handshake packet. The port emits
the server value earlier, at `ja4plus/fingerprinters/ja4l.py:549-551`, so **the port carries
this gap too.**

The cost is one moved emission point in `processUDP`, and the register needs the 8 keys
rewritten.

## Cause 3 — the QUIC client measurement point, and a reference split

**This cause holds 4 deviations, and it is a reference split that no page records.**

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

- Python returns early only once `D` is present. `python/common.py:108-111`:

  ```python
      # special requirement for ja4c when the C timestamp needs to be the
      # the last before D
      if field == 'C' and 'D' in cache[stream]:
          return
  ```

- Rust assigns on every server handshake packet, at `rust/ja4/src/time/udp.rs:181-183`:

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
`wireshark/source/packet-ja4.c:1445` for Wireshark. Line 1445 reads the two points, and
line 1428 fills point C. **The citation is right about the subtraction and silent about the
point.**

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

## What #253 and #249 explain

**#253 explains no deviation of this cluster.** It reads that FoxIO's reference Python
computes `int((dt2-dt1).microseconds/2)` at `python/common.py:182`, which truncates every
interval above one second and turns a negative interval into a large positive one. **The
second half of #253 is now measured: the cluster holds one candidate.**
`chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S` reads `10990_56` in the
per-stream set, and the per-packet set reads `9285` for the same connection. Both values
sit below one second, so the truncation of #253 does not reach either one. **No JA4L
interval of this cluster crosses one second, and no value of this cluster carries the
signature of #253.**

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

| Cause | Deviations | Measured | Who decides |
|---|---|---|---|
| 1 — the TCP emission frame and part c | 149 | **Yes. 177 falls to 128, and the per-stream set gains 98.** | The maintainer. Ruling #127 holds it. |
| 2 — the QUIC `JA4L-S` emission frame | 16 | No. #443 built no candidate for it. | An engineer. The four implementations agree. |
| 3 — the QUIC client measurement point | 4 | No. #443 built no candidate for it. | The maintainer. A reference split, 3 against 1. |
| 4 — the time-to-live of a reused four-tuple | 3 | No. The vector writes `0`. | The maintainer. A reference defect. |
| 5 — the two vector sets disagree | 2 | No. Each set holds a different value. | The maintainer. #249 holds it. |
| Unattributed | 3 | — | — |
| **Total** | **177** | | |

**Every deviation of the cluster reaches a cause, except three.**

## The three unattributed deviations

| Key | The vector holds | The library produces | Why it stays open |
|---|---|---|---|
| `ssh2.pcapng/1046/JA4L.1` | `279_128_quic` | (none) | The library writes no client value for the connection, and no cause above states why. |
| `tls3.pcapng/297/JA4L.1` | `271_128_quic` | (none) | The same shape as the row above. |
| `browsers-x509.pcapng/128/JA4LS.1` | `2948_229_14055` | (none) | Three numeric parts on a TCP connection, and the candidate of cause 1 did not close it. |

**Each one needs a separate reading, and #443 produced none.**

## What this page does not state

- **It recommends no change.** Causes 1, 3, 4 and 5 each reach the maintainer.
- **It measured cause 1 alone.** Causes 2, 3 and 4 carry no measured count.
- **It ran no Python.** The port was read as text. `.claude/rules/parity.md` states the rule.
- **It writes no register entry**, and `testdata/deviations.json` is unchanged.
- **It states no count for the JA4H cluster.** #442 reads that cluster.
