# The JA4T, JA4TS, JA4SSH and JA4S deviation clusters

This page is a reading. **It moves no fingerprint value, and it adds no register entry.**
Issue #459 produced it, under Epic #441.

It reads every JA4T, JA4TS, JA4SSH, JA4S and JA4S_r deviation that
`testdata/deviations.json` does not hold. It names one cause for each one. It states the
count each cause reaches, measured against the corpus at the pin of `testdata/foxio.pin`.

**Two runs of `make conformance` produced the counts of this page, and each figure below
names its run.** Both runs read the corpus at
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, in one worktree, on 2026-08-13.

- **The first run produced every count that #459 wrote.** It read the batch #478 branch
  before #467 sub-merged. It reports 1680 matches, 475 deviations, 450 accepted deviations
  and 470 register keys.
- **The second run reads the branch head, and #486 produced it.** #467 added 108 register
  entries between the two runs. The second run reports 1680 matches, 367 deviations, 558
  accepted deviations and 578 register keys.

**Every five-method count of this page holds at both runs.** Each of the 108 entries names a
`JA4H`, `JA4H_r` or `JA4H_ro` key. **No entry of the 108 names one of the five methods.**

The second run reports each of these.

- The same 67 deviations that the register does not hold.
- The same split of 31, 6, 16, 7 and 7 over the five methods.
- The same twelve captures.

**A whole-run figure therefore names its run, and a five-method figure holds at both.**

**Neither run above describes the tree today.** The Epic #441 batch merged after both of them,
and it moved every count. **`## The merged tree of the Epic #441 batch, 2026-08-14` below states
every re-measured figure**, and it names the run that measured each one. **A reader who carries
1680, 367, 558 or 578 forward from this preamble reads a stale figure.**

**#486 changes no byte of `testdata/deviations.json`, and it changes no Go file.**

**This page builds no candidate change, and #459 bars a Go edit.** So the count each cause
closes carries one of three labels.

- A **proved** count reads the vector alone. The value the vector holds on the deviating
  frame is byte-identical to a value that the library already produces. The vector already
  accepts that value on another frame of the same capture.
- An **attributed** count names the deviations one cause holds. The page then states what a
  candidate change must still measure. **Never read an attributed count as a proved one.**
- A **register** count is zero. The cause needs an entry in `testdata/deviations.json`, and
  it needs no code change.

**The `## Terms` table of `docs/specs/spec.md` declines the word `yield`**, because the
`emit` row names it as a synonym. So this page writes `the count it closes`.

## The gate condition

**`make conformance` exits 2 on `dev`, and Epic #441 owns that exit.** This page reports no
green gate. **Each of the two runs above exits 2.** The first run reports 475 deviations that
the register does not hold, and the second run reports 367.

**The green `conformance` check of a pull request is no conformance gate while Epic #441 is
open.** `.github/workflows/ci.yml:187` runs `make conformance 2>&1 | tee conformance.log ||
status=$?`, and it never exits on that status. `.github/workflows/ci.yml:200` fails the job on
a `--- FAIL:` line that does not name `TestConformance`. **So a green check reports that the
suite ran and that nothing but a deviation failed.** Round 47 of the `## Changelog` of
`docs/specs/spec.md` records the same mechanism.

## The merged tree of the Epic #441 batch, 2026-08-14

**One run of `make conformance` on `issue/512-epic-441-round` at `74c8827` produced every
figure of this section.** That run reads the corpus at
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, and `74c8827` is the head of
`origin/epic/441-deviation-fixes` after the last member sub-merged. **The run rewrote no byte
of `docs/audit/conformance.md`**, so the tracked report already described that head. **The run
exits 2.**

**Every count below this section names a run of 2026-08-13.** The Epic #441 batch then closed
34 of the 67 with a code change, and it accepted 16 more in the register.

| Count | The first run | The second run | The merged tree |
|---|---|---|---|
| matches | 1680 | 1680 | 1753 |
| deviations the register does not hold | 475 | 367 | 278 |
| accepted deviations | 450 | 558 | 575 |
| register keys | 470 | 578 | 595 |

**The Epic #441 batch closed 73 comparisons and opened 1.** So the 1680 of each run above holds
for batch #478, and never for this batch. `1680 + 73 = 1753`, and `575 + 20 = 595`.

**The merged tree reports 17 deviations that name one of the five methods**, against 67 in
each run above. 15 sit in the per-packet set and 2 sit in the per-stream set.

| Method | Each run of 2026-08-13 | The merged tree | Cause |
|---|---|---|---|
| JA4T | 31 | 0 | 1 |
| JA4TS | 6 | 3 | 2 |
| JA4SSH | 16 | 0 | 3, 4 and 5 |
| JA4S | 7 | 7 | 6 and 7 |
| JA4S_r | 7 | 7 | 6 and 7 |
| **Total** | **67** | **17** | |

| Cause | What closed it | Deviations of 2026-08-13 | The merged tree |
|---|---|---|---|
| 1 | #494, `ecc2fa1`. A code change. | 31 | 0 |
| 2 | #495, `d637e66`. A code change on 3 of the 6. | 6 | 3 |
| 3 | #484, `1d632a7`. 12 register declines. | 12 | 0 |
| 4 | #484, `1d632a7`. 2 register declines under the #491 ruling. | 2 | 0 |
| 5 | #484, `1d632a7`. 2 register declines. | 2 | 0 |
| 6 | **Nothing. No issue of this batch built it.** | 12 | 12 |
| 7 | **Nothing. #496 answered the question, and no member wrote the 2 entries.** | 2 | 2 |
| **Total** | | **67** | **17** |

**The 3 that remain of cause 2 are the three client resets of `https3-301-get.pcap`.**
FR-parity-44 of `docs/specs/features/08-python-parity.md` declines a reset that the client
sent, and **#502 holds that question**. #495 measured each frame, and
`## Cause 2 — the library returns no JA4TS value on a reset of a connection that holds one SYN-ACK`
below states the reading.

**#495 also opened one comparison, and the register accepts it.** The run reports
`browsers-x509.pcapng/119/JA4TS.1` as an accepted deviation under ruling #503. Frame 119 is a
server reset that carries ACK, and FR-parity-42 states that this library reads the reset bit
alone. **The old guard hid that difference on that frame.**

**The register holds 87 entries that name one of the five methods**, against 70 at each run
above.

| Method | Entries | Ruling |
|---|---|---|
| JA4S | 28 | #42 |
| JA4S_r | 28 | #42 |
| JA4SSH | 14 | #484 |
| JA4S | 5 | #387 |
| JA4S_r | 5 | #387 |
| JA4SSH | 4 | #223 |
| JA4SSH | 2 | #491 |
| JA4TS | 1 | #503 |

**The register still holds no entry that names JA4T.**

## The measurement

Each run reads 38 captures, 3 of them not applicable, and 268 per-stream entries.

| Count | The first run | The second run |
|---|---|---|
| matches | 1680 | 1680 |
| deviations the register does not hold | 475 | 367 |
| accepted deviations | 450 | 558 |
| register keys | 470 | 578 |

**The matches hold at 1680 across both runs**, so no member of batch #478 moved a
fingerprint value. **`475 - 367 = 108` and `558 - 450 = 108`**, so the fall in the
unaccepted count equals the rise in the accepted count.

**67 deviations name JA4T, JA4TS, JA4SSH, JA4S or JA4S_r, in each run.** 61 sit in the
per-packet set and 6 sit in the per-stream set.

### The count per method

**Epic #441 measured 65 on 2026-08-13, before batch #421 and before #438.** Each run of this
page measures 67. **The JA4S pair is the one row that moves**: the epic recorded 12, and each
run records 14. The JA4T pair holds at 37 and JA4SSH holds at 16.

| Method | Epic #441, 2026-08-13 | Each run | Cause |
|---|---|---|---|
| JA4T | 37 for the pair | 31 | 1 |
| JA4TS | | 6 | 2 |
| JA4SSH | 16 | 16 | 3, 4 and 5 |
| JA4S | 12 for the pair | 7 | 6 and 7 |
| JA4S_r | | 7 | 6 and 7 |
| **Total** | **65** | **67** | |

**Nobody schedules work from a reading that gives one number for five methods.** So the
table above is the form that Epic #441 reads. **Epic #421 changed JA4SSH behavior, so the
JA4SSH figure of the epic is stale by construction.** The two figures agree at 16, and that
agreement is a measurement rather than a carried number.

### The count per capture

| Capture | Count | Methods |
|---|---|---|
| `ssh2.pcapng` | 38 | JA4T 31, JA4TS 2, JA4S 2, JA4S_r 2, JA4SSH 1 |
| `latest.pcapng` | 4 | JA4S 2, JA4S_r 2 |
| `ssh-r.pcap` | 4 | JA4SSH 4 |
| `sshv1.pcap` | 4 | JA4SSH 4 |
| `v6.pcap` | 4 | JA4SSH 4 |
| `browsers-x509.pcapng` | 3 | JA4TS 1, JA4S 1, JA4S_r 1 |
| `https3-301-get.pcap` | 3 | JA4TS 3 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 2 | JA4S 1, JA4S_r 1 |
| `tls-handshake.pcapng` | 2 | JA4S 1, JA4S_r 1 |
| `gre-sample.pcap` | 1 | JA4SSH 1 |
| `ssh-scp-1050.pcap` | 1 | JA4SSH 1 |
| `ssh.pcapng` | 1 | JA4SSH 1 |

**Twelve captures hold the 67**, and the rows above sum to 67.

### What the register holds today

**The register holds 70 entries that name one of the five methods.** The register holds 470
entries at the first run and 578 at the branch head, and **the count of 70 holds at both**.
It holds no entry that names JA4T, and no entry that names JA4TS.

**The merged tree of the Epic #441 batch reads 87 and 595**, and it holds one JA4TS entry.
`## The merged tree of the Epic #441 batch, 2026-08-14` above holds that table.

| Method | Entries | Ruling |
|---|---|---|
| JA4S | 28 | #42 |
| JA4S_r | 28 | #42 |
| JA4S | 5 | #387 |
| JA4S_r | 5 | #387 |
| JA4SSH | 4 | #223 |

## The seven causes, and the count each one reaches

| N | Cause | Deviations | Count it closes | Label |
|---|---|---|---|---|
| 1 | The library reads no TCP header that an ICMP error message quotes. | 31 | 31 | Proved |
| 2 | The library returns no JA4TS value on a reset of a connection that holds one SYN-ACK. | 6 | 3 | Proved |
| 3 | The library clears the window at the first FIN+ACK packet, and the dissector clears none. | 12 | 12 | Attributed |
| 4 | The library counts a server segment that the `tshark` SSH dissector does not label. | 2 | 0 | Register |
| 5 | The library publishes the last open window, and the Python reference publishes none. | 2 | 0 | Register |
| 6 | The library reads no TLS record that spans more than one TCP segment. | 12 | 0 | Attributed |
| 7 | The library reads the second QUIC connection, and the Python reference publishes no value for it. | 2 | 0 | Register |

**The seven causes attribute all 67.** 31 + 6 + 12 + 2 + 2 + 12 + 2 = 67.

**The Epic #441 batch repaired two cells of the `Count it closes` column, and each repair
carries a measurement.** **Cause 2 read 6, and #495 measured 3.** 3 of the 6 frames are client
resets, FR-parity-44 declines a client reset, and #502 holds that question. **Cause 4 read 2
and the label read `Attributed`, and the maintainer ruled the question at #491 on 2026-08-14.**
The answer is a register decline and no code change, so the count is 0 and the label is
`Register`. `### The reference is not unanimous, and the maintainer ruled this cause` below
states the reading.

**Cause 3 and cause 4 compose**, and neither one closes the six deviations of `sshv1.pcap`
and `v6.pcap` on its own. **Cause 4, cause 5 and cause 7 each need a register entry and no code
change.** The maintainer ruled cause 4 that way at #491 on 2026-08-14, and the row above read
`Attributed` before that ruling.
**Cause 6 opens about as many per-stream deviations as it closes**, and its section states
the measurement.

---

## Cause 1 — the library reads no TCP header that an ICMP error message quotes

**31 deviations, all in `ssh2.pcapng`, and all 31 close.** Every one reads
`the vector holds a value the library does not produce`, and every one names JA4T.

Each of the 31 frames carries the protocol stack `eth:ethertype:ip:icmp:ip:tcp`. Frame 19 is
the worked example. It is an ICMP `Destination unreachable (3)` message of code 13, from
`10.128.128.128` to `172.16.225.48`, and it quotes the TCP SYN that frame 18 carries.

```
ssh2.pcapng/19/JA4T.1  expected: "64240_2-1-3-1-1-4_1460_8"  produced: ""
```

**The library read the outer layer list, and the quoted header sits inside the ICMP
payload.** `GetTCPLayer` of `internal/parser/packet.go` walks the layers that `gopacket`
decodes, and `ProcessPacket` of `ja4t.go` returned at once when that walk found no TCP layer.
**#494 built the change at `ecc2fa1`**, and `ProcessPacket` now calls `QuotedTCPHeader` of
`internal/parser/` before it decides. **Every sentence of this section that reads in the present
tense describes the tree before that change.**
`gopacket` decodes no IP layer and no TCP layer inside an ICMP payload, so the walk finds
none.

**The dissector reads the whole protocol tree, so it reaches the quoted header.**
`wireshark/source/packet-ja4.c:1261` matches the field abbreviation `tcp.flags` anywhere in
the tree, and `wireshark/source/packet-ja4.c:1266` sets `syn = 1` for the flag byte `0x02`.
`wireshark/source/packet-ja4.c:1583-1584` then writes `hf_ja4t` for that frame.

### The count is proved

**The vector holds one JA4T value for the 31 deviating frames, and it is
`64240_2-1-3-1-1-4_1460_8`.** The vector holds that same value on 43 of the 44 frames of the
capture that the library already matches. The quoted header is a copy of the client SYN
header, so a read of the quoted header produces the value the vector holds. **The count it
closes is 31.**

### This cause holds a reference split, and the maintainer rules it

**Split T1 — whether a TCP header that an ICMP error message quotes produces a JA4T value.**

**The maintainer ruled split T1 on 2026-08-14, and the answer is candidate answer 1.** #484 is
the reversal path. #494 built the change at `ecc2fa1`, `internal/parser/icmp_quoted.go` holds
the decode path, and `ja4t_icmp_quoted_test.go` holds the rule.

- **The Wireshark dissector produces one.** `wireshark/source/packet-ja4.c:1261` and
  `wireshark/source/packet-ja4.c:1266` state the mechanism, and the per-packet vector holds
  31 such values in `ssh2.pcapng`.
- **The Rust reference produces none.** `rust/ja4/src/tcp.rs:59` reads
  `tcp.first("tcp.flags")`, which reads a top-level `tcp` object of the `tshark` JSON. A
  measurement of frame 19 records the layer keys of that JSON as
  `['frame', 'eth', 'ip', 'icmp']`, so the object carries no top-level `tcp` key.
- **Zeek produces none.** `zeek/ja4t/main.zeek:126` reads `rph$tcp`, which is the TCP header
  of the raw packet.
- **The Python reference produces none.** It computes no JA4T value at all. `python/ja4.py`
  holds no JA4T branch.

**The candidate answers.**

1. The library reads a TCP header that an ICMP error message quotes, as the dissector does.
2. The library reads the outer TCP header alone, as it did before `ecc2fa1`, and as Zeek and the
   Rust reference do. **The maintainer declined this answer.**
3. The library reads the quoted header, and the conformance suite excludes the value from
   the per-stream comparison.

**This reading picks none.** `.claude/rules/rulings.md` `## Stop conditions` names the first
stop condition, and the maintainer rules it.

- **The port carries the same gap.** `ja4plus/fingerprinters/ja4t.py:153` holds
  `if not packet.haslayer(TCP): return None`, and `ja4plus/fingerprinters/ja4t.py:156` holds
  `tcp = packet[TCP]`. `scapy` decodes a quoted header as `IPerror` and `TCPerror`, so
  `haslayer(TCP)` reports false. **No file of `ja4plus/` names ICMP.** **A change here that
  the port does not make opens a parity difference on 31 values.**
- **No register entry closes.** The register holds no JA4T entry.
- **The cost is one decode path.** The library reads the ICMP payload as an IP packet, and it
  bounds every length field of that payload. **The payload is untrusted input**, and
  `CLAUDE.md` states the bound rule.

---

## Cause 2 — the library returns no JA4TS value on a reset of a connection that holds one SYN-ACK

**6 deviations, and this page predicted that all 6 close.** `https3-301-get.pcap` holds 3,
`ssh2.pcapng` holds 2 and `browsers-x509.pcapng` holds 1. Every one reads
`the vector holds a value the library does not produce`.

**#495 built the change, and it measured 3.** The 3 of `ssh2.pcapng` and
`browsers-x509.pcapng` close. **The 3 of `https3-301-get.pcap` are client resets, FR-parity-44
declines a client reset, and #502 holds that question.** `ja4tsConnKey` of `ja4ts.go` names the
server first, so a client reset reverses the key and finds no connection. **#495 also opened
`browsers-x509.pcapng/119/JA4TS.1`**, and the register accepts it under ruling #503.

Every one of the 6 frames carries the TCP reset flag and no other flag.

```
https3-301-get.pcap/20/JA4TS.1  expected: "14240_2-4-8-1-3_1436_10"  produced: ""
```

**The library held a reset branch, and a guard closed it.** `ProcessPacket` of `ja4ts.go`
calls `resetResults` for a packet that carries the reset flag. `resetResults` returned nil
when the connection held fewer than two SYN-ACK times. Each of the 6 connections holds one
SYN-ACK, so the guard returned nil. **#495 built the change at `d637e66`**, and `resetResults`
now returns nil only where the connection key reaches no entry. **Every sentence of this section
that reads in the present tense describes the tree before that change.**

**The dissector publishes the stored four-part value, and the delay list is a separate
branch.** `wireshark/source/packet-ja4.c:1295-1299` sets `syn = 3` for the flag byte `0x004`.
`wireshark/source/packet-ja4.c:1599-1608` then copies the window size, the maximum segment
size, the window scale and the option list from the stored connection state, and it writes
`hf_ja4ts`. `wireshark/source/packet-ja4.c:684` guards the delay list and the reset letter on
`conn->syn_ack_count > 1`, and **the four-part value sits outside that guard**.

### The count is proved

`https3-301-get.pcap` holds one JA4TS value, `14240_2-4-8-1-3_1436_10`. The vector holds it
on frame 2, which is the SYN-ACK, and the library matches that frame. The vector holds the
same string on frames 20, 21 and 23, which are the three reset frames. The same identity
holds for `ssh2.pcapng` and for `browsers-x509.pcapng`. **This page read the count it closes as
6, and #495 measured 3.** The identity holds for each of the 6, and the reset direction decides
which 3 close.

**One condition of the identity.** `wireshark/source/packet-ja4.c:1604-1606` appends the
stored option list to the option list of the reset packet. Each of the 6 reset packets
carries no TCP option, so the two lists agree. **A reset packet that carries an option
produces a different string**, and no capture of the corpus reaches that input.

### This cause holds a reference split, and the maintainer rules it

**Split T2 — whether a reset of a connection with one SYN-ACK produces a JA4TS value.**

**The maintainer ruled split T2 on 2026-08-14, and the answer is candidate answer 1.** #484 is
the reversal path. #495 built the change at `d637e66`, and the ruling falsified FR-parity-43 of
`docs/specs/features/08-python-parity.md`. **The Epic #441 documentation round amended that
requirement**, and it added FR-parity-43a for the reset that reaches no stored connection.

- **The Wireshark dissector produces one**, in the four-part form. The two citations above
  state the mechanism.
- **Zeek produces none.** `zeek/ja4t/main.zeek:228-233` appends the reset letter inside the
  delay branch, and it writes one value for each connection at
  `connection_state_remove`. It names no frame.
- **The Python reference produces none.** It computes no JA4TS value at all.

**The candidate answers.**

1. The library publishes the stored four-part value on a reset, as the dissector does.
2. The library returns no value for such a reset, as it did before `d637e66`. **The maintainer
   declined this answer.**
3. The library publishes the value in the per-packet comparison alone.

**This reading picks none.**

**This cause re-opens no part of #369.** `.claude/rules/rulings.md`
`### Every delegated decision of session 9` records that #369 settled the JA4TS part e count
at ten delays, and `ja4ts.go` records the ruling that the library reads the eleventh SYN-ACK
time for the reset delay. **Both hold, and this cause asks a different question**: whether a
reset produces the four-part value where no delay exists.

- **The port carries the same gap, and by the same guard.**
  `ja4plus/fingerprinters/ja4ts.py:341-342` calls `_reset_value` for a reset packet, and
  `ja4plus/fingerprinters/ja4ts.py:183` returns nothing until the connection holds two
  SYN-ACK times. `ja4plus/fingerprinters/ja4ts.py:189` then writes the five-part form
  `f"{self.prefixes[key]}_{delays}-R{_delay_seconds(now, stamps[-1])}"`. **A change here that
  the port does not make opens a parity difference on 6 values.**
- **No register entry closes.** The register holds no JA4TS entry.
- **The cost is one guard.** `resetResults` of `ja4ts.go` writes the stored prefix where the
  connection holds fewer than two SYN-ACK times.
- **One doc comment of the tree needed a repair, and the repair landed.** The doc comment of
  `resetResults` in `ja4ts.go` stated that both FoxIO implementations nest the reset branch
  inside the delay branch. **That reading holds for the reset letter and not for the
  four-part value**, and `wireshark/source/packet-ja4.c:1599-1608` writes the four-part value
  outside the delay branch. **This page repaired no file that #459 does not own**, so it
  reported the comment. **Round 45 of the `## Changelog` of `docs/specs/spec.md` repaired the
  comment, in this same batch.** The merged comment reads
  `Neither branch reaches the four-part value, and each implementation writes that value`
  and `above the branch. So a connection with one SYN-ACK still reaches a JA4TS value.` #486
  read the merged comment and recorded this repair.

---

## Cause 3 — the library clears the window at the first FIN+ACK packet, and the dissector clears none

**12 deviations. 10 sit in the per-packet set and 2 sit in the per-stream set.**

The per-packet 10 are `gre-sample.pcap` 1, `ssh-r.pcap` 3, `sshv1.pcap` 3 and `v6.pcap` 3.
Every one reads `the vector holds a value the library does not produce`. Each frame carries
the FIN flag and the ACK flag, on a connection that holds port 22.

```
ssh-r.pcap/339/JA4SSH.1  expected: "c48s21_c6s5_c4s5"  produced: ""
```

`ssh-r.pcap` frame 335 and frame 339 are the two FIN+ACK packets of one connection. The
library matches frame 335 and produces nothing on frame 339.

**The library starts a new window at every emission.** `emitSSHWindow` of `ja4ssh.go` clears
`clientSizes`, `serverSizes`, `clientACKs` and `serverACKs` after it builds the value. It
reports false for a window that holds no SSH packet. So the second FIN+ACK packet reaches an
empty window, and the library returns nothing.

**The dissector clears nothing on the FIN+ACK path.**
`wireshark/source/packet-ja4.c:1399-1403` writes `hf_ja4ssh` for a frame whose flag byte is
`0x011` on port 22, and it clears no counter. `wireshark/source/packet-ja4.c:1485-1491`
clears the counters, and that code sits inside the 200-packet branch alone.

**The dissector keeps counting between the two FIN+ACK packets.** The vector holds
`c76s76_c66s65_c9s51` on `ssh-r.pcap` frame 1826 and `c76s76_c66s65_c9s52` on frame 1831. The
last part rises by one, so a candidate change that republishes a frozen value produces the
wrong string on frame 1831.

The per-stream 2 are `ssh-r.pcap/0/JA4SSH.2` and `ssh2.pcapng/14/JA4SSH.2`. Both read
`the two values differ`, and both expect a value whose part b is `c0s0`.

```
ssh-r.pcap/0/JA4SSH.2  expected: "c64s64_c0s0_c0s1"  produced: "c64s64_c33s48_c41s2"
```

**The Python reference reaches the same second emission through a different path.**
`python/ja4.py:555-556` calls `finalize_ja4ssh` for a packet that carries the FIN flag and
the ACK flag, and `python/ja4.py:374-376` computes the value and deletes the cache entry. A
later packet of the connection opens a new entry, and the second FIN+ACK packet then emits a
window whose packet counts are zero.

### The count is attributed, and a candidate change must measure three things

**12 is the count this cause holds.** A candidate change that emits at every FIN+ACK packet
and clears no counter must still measure each of these.

1. **Whether the value matches on `ssh-r.pcap` frame 1831.** The vector holds a value that
   differs from the value of frame 1826, so the candidate must keep counting between the two.
2. **Whether the six deviations of `sshv1.pcap` and `v6.pcap` close.** They close only where
   cause 4 closes too, because the library produces the wrong value on the first FIN+ACK
   packet of those two captures. **The `## Cause 4` section states that composition.**
3. **Whether the change closes a register entry.** The register holds 4 JA4SSH entries under
   ruling #223, at `ssh-r.pcap/1/JA4SSH.1`, `ssh-r.pcap/2/JA4SSH.1`,
   `ssh-scp-1050.pcap/0/JA4SSH.3` and `ssh-scp-1050.pcap/0/JA4SSH.4`. A change that adds a
   per-stream value renumbers the values that follow it, so an entry can become stale.
   **`.claude/rules/parity.md` `## Every ruling carries a register entry or a test` states
   that a closed deviation left in the file fails the suite.**

### This cause reaches a maintainer ruling

**The transcription states that the counters reset, and the dissector's FIN+ACK path does
not reset them.** `docs/specs/foxio/JA4SSH.md` R8 states
`The counters reset after each window.`, and it cites `zeek/ja4ssh/main.zeek:88` and
`wireshark/source/packet-ja4.c:1485`. `docs/specs/foxio/JA4SSH.md` R9 states
`Zeek, Wireshark and Rust each write one value for an open window at the end of the
connection.`, and it cites `wireshark/source/packet-ja4.c:1402` for Wireshark.

**R9 states one value, and the dissector writes one value for each FIN+ACK packet of the
connection.** A TCP close carries two FIN+ACK packets, so the dissector writes two.

**The candidate answers.**

1. The library writes one value for each FIN+ACK packet, and it clears no counter on that
   path.
2. The library writes one value at the first FIN+ACK packet, as it does today, and as R9
   states.
3. The library writes one value for each FIN+ACK packet in the per-packet comparison alone.

**The maintainer ruled this question on 2026-08-14, and the answer is candidate answer 2.** The
library keeps the behavior it holds today. `testdata/deviations.json` records 12 declines under
ruling #484, and #484 wrote every one at `1d632a7`. **#484 is the reversal path.**

**This reading picks none.** **The question is whether a published FoxIO value contradicts a
published FoxIO rule**, which `.claude/rules/rulings.md`
`### The narrow delegation of 2026-08-12` reserves to a delegated ruling or to the
maintainer. **Narrow condition 2 fails**, because the dissector's FIN+ACK path departs from
R8. So this reading records the evidence and decides nothing.

- **The port carries the same behavior as this library.**
  `ja4plus/fingerprinters/ja4ssh.py:439-442` clears the two packet lists and the two ACK
  counters inside `_close_window`, and `ja4plus/fingerprinters/ja4ssh.py:422-424` then
  returns nothing for the next call. The docstring at
  `ja4plus/fingerprinters/ja4ssh.py:416-420` states that
  "the second FIN packet of a close finds the window the first FIN packet emptied."
  **A change here that the port does not make opens a parity difference on 12 values.**
- **The cost is one branch and one risk.** The emission path keeps the counters for a FIN+ACK
  packet and clears them for a 200-packet boundary. **A connection that never closes then
  holds a window that no rule clears**, and `.claude/rules/concurrency.md` `## Rules`
  states that a new state map has a removal path.

---

## Cause 4 — the library counts a server segment that the `tshark` SSH dissector does not label

**2 deviations, in `sshv1.pcap` and `v6.pcap`.** Both read `the two values differ`, and both
name the first FIN+ACK frame of the connection. **This page read both as closing with a code
change, and the maintainer ruled on 2026-08-14 that both close with a register decline.**
`### The reference is not unanimous, and the maintainer ruled this cause` below states the
ruling.

```
sshv1.pcap/72/JA4SSH.1  expected: "c20s12_c18s21_c10s1"  produced: "c20s20_c18s25_c10s1"
```

**Part b and part a of the server side differ, and the client side agrees.** The library
counts 25 server packets and the vector counts 21. The library reports the server mode as 20
and the vector reports 12.

**The count of 21 is the count of `ssh.direction` fields.** `tshark` labels 25 server
segments of `sshv1.pcap` with a positive TCP payload length. It writes `ssh.direction` for 21
of them. Frame 63 and frame 65 carry the `ssh` protocol and no `ssh.direction` field. Frame
68 and frame 70 carry no `ssh` protocol at all.

**The reference counts the labeled packet.** `docs/specs/foxio/JA4SSH.md` R7 states
`The window counts SSH packets, and it counts no bare ACK.`, and it cites
`wireshark/source/packet-ja4.c:1472` for the `ssh.direction` count.
`wireshark/source/packet-ja4.c:1469-1470` reads the field, and
`wireshark/source/packet-ja4.c:1471` increments `conn->pkts`.

**The library counts a completed segment of a connection whose banner it read.**
`ProcessPacket` of `ja4ssh.go` appends the completed lengths where the payload passes
`IsSSHPacket`, **or where the connection holds a client banner or a server banner**. The
banner test opens the count for every later segment, including the four the dissector does
not label.

**The mode follows from the count.** The 21 labeled server segments hold six lengths of 12
and six lengths of 20. `docs/specs/foxio/JA4SSH.md` R12 states that the smaller length wins a
tie, so the mode is 12. The four extra segments add one more length of 20, so the library
reads seven of 20 against six of 12, and its mode is 20. **`mode` of `ja4ssh.go` already
holds the tie rule of R12**, so the tie rule needs no change.

### The reference is not unanimous, and the maintainer ruled this cause

**The heading of this section read `The reference agrees, so this cause needs no ruling`, and
that sentence is false.** #491 measured the reference on 2026-08-14, and the Epic #441
documentation round repaired the heading and this section.

**The reference is not unanimous on `sshv1.pcap`.** Only the Wireshark plugin publishes
`c20s12_c18s21_c10s1`. `testdata/foxio/wireshark/sshv1.pcap.json` holds that value.
`testdata/foxio/python/sshv1.pcap.json` holds one stream entry with `ssh_extras` and no JA4SSH
value. **The corpus holds no Zeek vector and no Rust vector for that capture.** So row 1 of
`.claude/rules/parity.md` `## Where a difference comes from` does not govern this cause. **The
paragraph this round replaced stated that it does.**

**The maintainer ruled the question at #491 on 2026-08-14, under row 3 of that same table.** Row
3 names a reference that holds a proven defect. **The server count of 21 describes the capture
rather than the connection.** `tshark` reaches 21 because it stalled its own reassembly. It
reassembles 480 bytes across frame 63 and frame 65, and its own framing asks for 484. **So 4
bytes stay pending, and frame 68 and frame 70 reach no SSH dissection.** **Frame 70 holds 20
bytes, and it opens `00000009`.** That is one whole SSHv1 message under the arithmetic
`4 + (8 - length % 8) + length`. **The same dissector applies that arithmetic to the four
messages of frame 63.** **So a rule that frames SSH consistently produces the server count 25
and the mode 20, and it never produces the mode 12.**

**The answer is a register decline and no code change.** `testdata/deviations.json` holds
`sshv1.pcap/72/JA4SSH.1` and `v6.pcap/72/JA4SSH.1` under ruling #491, and #484 wrote both
entries at `1d632a7`. **#491 is the reversal path**, and `Crank-Git/ja4plus#608` holds the port
half.

**The three sentences below hold for a candidate change that this cause no longer needs.** Each
implementation counts a packet that the SSH dissector labels. Zeek counts the payload vectors at
`zeek/ja4ssh/main.zeek:140`. Rust counts the SSH packet counters at `rust/ja4/src/ssh.rs:35`.
Python counts a packet whose protocol list holds `ssh` at `python/ja4ssh.py:99`. **None of the
three publishes a value for `sshv1.pcap`**, which is why they settle nothing here.

**One fact a later issue needs.** **The library labels no frame that `tshark` leaves unlabeled,
in any of the nine SSH captures.** The two agree exactly on `ssh.pcapng` (318), `ssh2.pcapng`
(318), `ssh-r.pcap` (1223), `ssh-scp-1050.pcap` (853) and `gre-sample.pcap` (8). The library
adds 4 frames on `sshv1.pcap` and on `v6.pcap`, and 3 frames on `ssh2-malformed.pcap` and on
`ssh2-moloch-crash.pcap`. **Any later issue that changes the JA4SSH packet selection re-measures
those five agreements.** A change that closes this cause can open a deviation on a capture that
matches today.

### The count it closes is 0, and this cause composes with cause 3

**2 is the count of deviations this cause holds on its own, and the count it closes is 0.** The
maintainer ruled a register decline, so no code change closes either one. It also decides the
value of the six `sshv1.pcap` and `v6.pcap` deviations of cause 3, because a republished window
republishes whatever the count holds. **Neither cause closes those six on its own.**

- **The port carries the same gap.** `ja4plus/fingerprinters/ja4ssh.py:247-248` holds
  `if completed and (is_ssh_packet(payload) or conn["client_id"] or conn["server_id"]):`,
  which is the same banner test. **A change here that the port does not make opens a parity
  difference.**
- **A register entry can close.** The register holds `ssh-r.pcap/1/JA4SSH.1` under ruling
  #223, whose `ours` value is `c48s21_c6s5_c4s5` and whose `theirs` value is
  `c64s64_c6s5_c4s5`. The two differ in part a alone. **A change to the packet selection can
  move part a**, so a candidate change measures the register before it lands.
- **The cost is one test.** The library reads a rule that reproduces the `ssh.direction`
  label. **No FoxIO source states that rule in words.** So the candidate change needs a
  measurement across every SSH capture of the corpus, and never one capture.

---

## Cause 5 — the library publishes the last open window, and the Python reference publishes none

**2 deviations, both in the per-stream set, and neither one closes with a code change.**

```
ssh.pcapng/0/JA4SSH.2  expected: ""  produced: "c36s52_c42s76_c0s0"
```

`ssh-scp-1050.pcap/0/JA4SSH.5` is the second one. Both read
`the library produces a value the vector does not hold`.

**The library publishes the window that a connection holds open when the packet source
ends.** `CloseOpenWindows` of `ja4ssh.go` is that rule, and its doc comment cites
`rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164`. **The transcription states
the same rule.** `docs/specs/foxio/JA4SSH.md` R9 states
`Zeek, Wireshark and Rust each write one value for an open window at the end of the
connection.`

**The Python reference publishes no such value.** `python/ja4.py:610` holds the call as a
comment: `#finalize_ja4ssh() if 'ja4ssh' in output_types else None`. So the per-stream vector
holds the last window only where a FIN+ACK packet reaches
`python/ja4.py:556`. `ssh.pcapng` sends no such packet on the connection, and
`ssh-scp-1050.pcap` ends with a window that no FIN+ACK packet closes.

### This cause needs a register entry, and it needs no code change

**The library follows R9 and three FoxIO implementations, and the fourth publishes nothing.**
The port's issues #105, #199 and #214 hold the ruling, and `CloseOpenWindows` of `ja4ssh.go`
names all three. **So the difference is a decline of a Python reference limit, and
`testdata/deviations.json` is the place that records it.**

- **The port holds the same behavior as this library.**
  `ja4plus/fingerprinters/ja4ssh.py:439-442` clears the window at each emission, and the port
  publishes the last window under its own issues #105, #199 and #214. **No parity difference
  opens.**
- **The register needs 2 new entries**, and this page writes none. **#484 wrote both at
  `1d632a7` on 2026-08-14**, under ruling #484. They are `ssh-scp-1050.pcap/0/JA4SSH.5` and
  `ssh.pcapng/0/JA4SSH.2`. The sentence this round replaced named #467 as the owner of
  `testdata/deviations.json`, and #467 is a member of batch #478.
- **The two entries are `capability: false`**, because the library produces a value and the
  vector holds none.
- **The count depended on cause 3, and the cause 3 ruling released it.** A change that closes
  cause 3 renumbers the per-stream values of these two captures. **The maintainer ruled cause 3
  as a register decline on 2026-08-14**, so no code change renumbers either capture and the two
  entries needed no wait.

---

## Cause 6 — the library reads no TLS record that spans more than one TCP segment

**12 deviations, on 6 frames, and each frame carries one JA4S key and one JA4S_r key.** Every
one reads `the vector holds a value the library does not produce`.

| Capture | Frame | TCP stream | Segments | Record length |
|---|---|---|---|---|
| `tls-handshake.pcapng` | 151 | 43 | 3 | 3950 |
| `latest.pcapng` | 163 | 9 | 5 | 7136 |
| `latest.pcapng` | 197 | 10 | 5 | 7136 |
| `ssh2.pcapng` | 237 | 11 | 5 | 6291 |
| `ssh2.pcapng` | 259 | 12 | 5 | 7031 |
| `browsers-x509.pcapng` | 8 | 0 | 3 | 5942 |

```
tls-handshake.pcapng/151/JA4S.1  expected: "t120400_c030_4e8089b08790"  produced: ""
```

Each of the 6 frames holds the handshake type list `2,11,22,12,14`, so one TLS record carries
the ServerHello, the Certificate, the ServerKeyExchange and the ServerHelloDone. The TCP
payload of the frame is shorter than the record, so the record spans 3 segments or 5
segments.

**The library reads one segment.** `ProcessPacket` of `ja4s.go` calls
`parser.GetTCPPayload`, which returns the payload of one packet. `GetTCPPayload` of
`internal/parser/packet.go` reads `tcp.Payload` and nothing else. **The library holds no TCP
reassembler on the JA4S path.**

**The library produces no value on any frame of those 6 streams.** The per-packet set reports
no surplus JA4S value in those captures, so the first segment produces none either.

**The parser is not the cause.** The library matches 83 of the 84 `ja4.ja4s` frames of
`tls-handshake.pcapng`.

### The count is attributed, and a candidate change opens about as many deviations as it closes

**The per-stream vector holds no JA4S key for any of the 6 streams.** A measurement of the
six per-stream entries records the JA4S key list as empty for every one.

| Capture | Stream | Per-stream entry | JA4S keys |
|---|---|---|---|
| `tls-handshake.pcapng` | 43 | present | none |
| `latest.pcapng` | 9 | present | none |
| `latest.pcapng` | 10 | present | none |
| `ssh2.pcapng` | 11 | present | none |
| `ssh2.pcapng` | 12 | present | none |
| `browsers-x509.pcapng` | 0 | present | none |

**So a candidate change closes 12 per-packet deviations and opens about 12 per-stream
deviations**, one JA4S key and one JA4S_r key for each of the 6 streams. **So the cause closes about nothing without a register
entry**, and the shape is the shape of cause 4 of
`docs/audit/ja4h-deviation-cluster.md`.

**This page states about 12 and not 12**, because it builds no candidate change. The exact
count depends on how the conformance suite keys a per-stream JA4S value that the vector omits.

- **The FoxIO implementations disagree, and the disagreement is a limit rather than a rule.**
  The Wireshark dissector publishes the value on the frame that completes the record. The
  Python reference publishes none, and `python/ja4.py:591` holds the branch
  `if x['hl'] == 'tls' and x.get('type') == '2':`. **The highest layer of each of the 6 frames
  is `ocsp` or `x509ce`, and never `tls`.** **This page does not determine the reference's own
  reason**, and the `## What this reading does not answer` section states why.
- **The port carries the same gap.** `ja4plus/utils/tls_utils.py:44` reads
  `raw_data = bytes(packet[Raw])`, and `ja4plus/utils/tls_utils.py:90-93` declines a hello
  that a segment cuts. The port holds a `TCPStreamReassembler` at
  `ja4plus/utils/tcp_stream.py`, and `ja4plus/fingerprinters/ja4s.py` imports it never.
  **A change here that the port does not make opens a parity difference on 12 values.**
- **No register entry closes.** The register holds 33 JA4S entries and 33 JA4S_r entries. 28
  of each name ruling #42, which declines a QUIC stream the Python reference omits. 5 of each
  name ruling #387, which declines a second value that a HelloRetryRequest produces. **No
  entry names one of the 6 streams above.**
- **The cost is one reassembler and about 12 register entries.** The library already holds a
  TCP reassembler for JA4H and for JA4X, so the work reuses it.

---

## Cause 7 — the library reads the second QUIC connection, and the Python reference publishes no value for it

**2 deviations, both in `chrome-cloudflare-quic-with-secrets.pcapng`, and neither one closes
with a code change.**

```
chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S
    expected: ""  produced: "q130200_1301_234ea6891581"
```

`0:50280/JA4S_r` is the second one. Both read
`the library produces a value the vector does not hold`.

**The capture holds two connections to one server.** `0:57098` is a TCP connection, and the
per-stream vector holds `"JA4S": "t130200_1301_234ea6891581"` for it. The library matches
that value. `0:50280` is a QUIC connection, and the per-stream vector holds `JA4L-S` and
`JA4L-C` for it and no TLS-derived key.

**The library publishes six values for `0:50280` that the vector does not hold**: JA4, JA4_r,
JA4_o, JA4_ro, JA4S and JA4S_r. **This page owns the JA4S pair, and Epic #441 owns the other
four.**

### This cause needs a register entry, and it needs no code change

**Ruling #42 already declines 56 keys of this shape.** Each one reads
`The FoxIO Python implementation reads no QUIC handshake, so its expected-output file omits
the stream.` The two keys above carry no entry, and the key form differs: a ruling #42 key
reads `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4S`, and this key reads
`chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S`.

- **The port holds the behavior, so no parity difference opens.**
  `ja4plus/fingerprinters/ja4s.py:82-87` reads a QUIC Initial packet, and
  `ja4plus/fingerprinters/ja4s.py:154-157` collects CRYPTO fragments until the ServerHello is
  complete. `ja4plus/fingerprinters/ja4s.py:266` writes the proto character `q`.
- **The register needs 2 new entries**, and this page writes none. The sentence this round
  replaced named #467 as the owner of `testdata/deviations.json`, and #467 is a member of batch
  #478. **No member of the Epic #441 batch wrote either entry**, so the merged tree still reports
  both comparisons as deviations.
- **A reader answers one question before anybody writes those entries, and #496 answered it.**
  The `## What this reading does not answer` section states the question and the answer.

---

## What this reading does not answer

- **Which frame supplies the library's JA4S value for `0:50280`. #496 answered this on
  2026-08-14, and the answer is frame 49 of that connection.** The run reports
  `chrome-cloudflare-quic-with-secrets.pcapng frame 48: cipher: message authentication failed`
  and the same line for frame 49. Frame 49 is the one frame of that connection that carries a
  ServerHello. **A value that the library derives from another connection is a different
  question from a value that the reference omits**, and the two need different register
  entries. The two values of the connection share the cipher `1301` and the extension hash
  `234ea6891581` with the values of `0:57098`, and two connections to one server can send one
  ServerHello. **`docs/audit/quic-ja4s-frame-source.md` holds the measurement.** A
  `JA4SFingerprinter` that read frame 47 and frame 49 alone produced the whole value. **That
  fingerprinter reports no error on either frame.** **Both error lines belong to
  `JA4Fingerprinter`**, because `Processor.ProcessPacket` joins the errors of every
  fingerprinter and an error line of the run names none. **#501 closed both lines** at
  `74c8827`, and neither one was a deviation.
- **Why the Python reference publishes no JA4S for the 6 reassembled streams of cause 6.**
  `python/ja4.py:591` names the highest layer, and the highest layer of each frame is `ocsp`
  or `x509ce`. `python/ja4.py:430-431` reads the first element of a handshake type list, and
  that element is `2`. **The two facts do not compose into one reason**, and this page runs
  the reference never.
- **The exact per-stream cost of cause 6.** The page states about 12, and it builds no
  candidate change.
- **Whether cause 4 moves the value of a register entry.** The `## Cause 4` section names the
  entry and the risk, and no measurement settles it. **The cause 4 ruling of 2026-08-14 needs no
  code change**, so no change of this batch reached that risk. **A later issue that changes the
  JA4SSH packet selection still reaches it.**
- **Split T1 and split T2. The maintainer ruled both on 2026-08-14**, and #484 is the reversal
  path of each one. #494 built split T1 and #495 built split T2.
- **The FIN+ACK question of cause 3. The maintainer ruled it on 2026-08-14**, and the answer is
  candidate answer 2. The library keeps the behavior it holds today, and the register records 12
  declines under ruling #484.
- **Whether FR-parity-44 declines a client reset correctly.** #495 measured that 3 of the 6
  frames of cause 2 are client resets, and **#502 holds that question**. A reversal of
  FR-parity-44 closes those 3.

## What this reading measured with `tshark`

**This page reads packet headers with `tshark`, and it reads no fingerprint value from
it.** Every fingerprint value of this page comes from the FoxIO vector at the pinned commit,
or from the conformance run. `tshark` supplied the TCP flags, the protocol list, the
reassembly counts and the `ssh.direction` labels. **A reader who repeats a measurement with a
later `tshark` can read a different protocol list**, and the FoxIO vector does not move.
