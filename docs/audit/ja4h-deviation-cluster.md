# The JA4H deviation cluster

This page is a reading. **It moves no fingerprint value.** Issue #442 produced it, under
Epic #441.

**#442 added no register entry, and #467 added 108 of them for cause 4.**
`### The maintainer ruled split S1 on 2026-08-13` below states the ruling those entries
record.

It reads every JA4H, JA4H_r and JA4H_ro deviation that `testdata/deviations.json` does not
hold. It names one cause for each one. It states the count each cause closes, measured
against the corpus at the pin of `testdata/foxio.pin`.

**Every count of the reading comes from a run of `make conformance` in one worktree, on
2026-08-13, against the corpus at `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.** Each
candidate change was built, measured, and then reverted with `git checkout -- .`. **No
commit of #442 holds a Go file.**

**Two sections below carry a count that a later run measured, and each one names its own
run.** #465 measured `## Two causes are closed since this reading` against the batch #457
head. #467 measured `### The maintainer ruled split S1 on 2026-08-13` against the
batch #478 head.

## Two causes are closed since this reading

**#446 closed cause 3, and #462 closed cause 2.** This section states what the library does
today. **Each cause section below keeps the count that #442 measured**, because that count
is the record that earned the change.

| Cause | Who closed it | What the library does today |
|---|---|---|
| 2 | #462, under the maintainer ruling of 2026-08-13 on #455 | `ProcessPacket` of `ja4h.go` produces the value at the packet that completes the request. `HTTPMessageIsComplete` of `internal/parser/http.go` holds the gate. |
| 3 | #446 | `segmentCarriesNoNewRequest` of `ja4h.go` reads the consumed sequence range, so a repeated segment produces no second value. |

**Cause 1 is open, and #441 owns it.** **The maintainer ruled split S1
of cause 4 on 2026-08-13**, and #467 recorded that ruling in `testdata/deviations.json`.
**The library produces no value for an SSDP request over UDP**, so cause 4 moves no
fingerprint value.

**#527 closed cause 5 on 2026-08-14.** The maintainer ruled rule 5b on the same day, and
`### The maintainer ruled rule 5b on 2026-08-14` below states the ruling and the
measurement. **The library reads a request path that holds a space, and JA4H part b hashes
an empty header list.**

**#446 landed in batch #421, and #462 landed in batch #457.** So the two changes reach
`docs/audit/conformance.md` in two different measurements.

**#462 moved the per-packet set alone, and it moved no per-stream count.** The per-packet
counts read as follows.

- The matches rise from 561 to 577.
- The deviations that the register does not hold fall from 508 to 412.
- The accepted deviations rise from 143 to 175.

**96 deviations become 48 comparisons**, because each frame pair of cause 2 holds one value.
**16 of the 48 are matches, and 32 are accepted deviations.** The register grows from 438
keys to 470.

## The measurement

The suite reports 635 deviations that the register does not hold. **337 of them name JA4H,
JA4H_r or JA4H_ro.** The register held 459 entries on the day of the run. The run accepted
419 of them. 108 of the accepted entries named a JA4H form. **#465 re-measured all three
against the tree of that run**, at commit `dbbad89`.

| Direction | Count |
|---|---|
| `the vector holds a value the library does not produce` | 239 |
| `the library produces a value the vector does not hold` | 98 |

**Eight captures hold the 337.**

| Capture | Count |
|---|---|
| `http1.pcapng` | 96 |
| `ssh2.pcapng` | 87 |
| `http2-with-cookies.pcapng` | 75 |
| `CVE-2018-6794.pcap` | 50 |
| `tls3.pcapng` | 12 |
| `latest.pcapng` | 9 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 5 |
| `gre-erspan-vxlan.pcap` | 3 |

**The project manager measured 335 on the same corpus, and this run measures 337.** The
per-capture counts of the two runs agree in every row, so the two runs differ by two
deviations that neither run attributes to a capture difference. This page reports what this
run measured.

**Three deviation keys name one request.** The per-packet set publishes JA4H, JA4H_r and
JA4H_ro for one frame, so one cause that reaches one frame closes three keys. **95 frames
of the per-packet set and 26 occurrences of the per-stream set carry the 337.**

## The five causes, and the count each one closes

| N | Cause | Deviations | Count it closes, measured |
|---|---|---|---|
| 1 | The library reads no HTTP/2 request and no HTTP/3 request. | 80 | Not measured. The section states why. |
| 2 | The library emitted at the frame that ends the header block. **#462 closed it.** | 96 | 64 |
| 3 | The library emitted a second value for a repeated TCP segment. **#446 closed it.** | 50 | 50 |
| 4 | The library reads no HTTP request over UDP. | 108 | The candidate opens 36 more deviations than it closes. |
| 5 | The request line parser rejects a path that holds a space. | 3 | 1 |

**The five causes attribute all 337.** 80 + 96 + 50 + 108 + 3 = 337.

**Ruling #285 holds 106 of the 337, behind cause 2, cause 4 and cause 5.** The
`## Ruling #285 sits behind three causes` section states each one.

---

## Cause 1 — the library reads no HTTP/2 request and no HTTP/3 request

**80 deviations.** `http2-with-cookies.pcapng` holds 75 and
`chrome-cloudflare-quic-with-secrets.pcapng` holds 5. Every one reads
`the vector holds a value the library does not produce`.

**The library holds no HTTP/2 decoder.** `ProcessPacket` of `ja4h.go` reads the TCP payload
and passes it to `parser.ParseHTTPRequest`. That function reads a request line of the form
`<method> <path> HTTP/<digit>.<digit>`, at `requestLineRe` of `internal/parser/http.go`. An HTTP/2 request
carries no such line, because it carries HPACK header blocks.

**The reference reads both.** `testdata/foxio/reference/wireshark/source/packet-ja4.c:1152`
sets the version to `20` when the frame holds `http2.headers.method`, and
`packet-ja4.c:1197` reads `http2.header.name` for the header list.

**The frames are encrypted.** Frame 15 of `http2-with-cookies.pcapng` is a TLS record on TCP
port 443, and the vector holds `ge20cn19enus_cb83bf27b7a9_c7713052b7e4_348cad68b6fb` for it.
So this cause holds three separate pieces of work: read the decryption secret, decrypt the
TLS record, and decode the HPACK header block. `chrome-cloudflare-quic-with-secrets.pcapng`
adds QUIC and QPACK.

**This page measures no count for cause 1.** A candidate change costs a TLS record decryptor,
an HPACK decoder and a QPACK decoder, which no reading builds to take one measurement. **The
80 deviations are attributed by exclusion**: every one of the two captures' JA4H deviations
reads `the vector holds a value the library does not produce`, and every value the vector
names holds the version code `20`, which `packet-ja4.c:1152` writes for an HTTP/2 request
alone. **One frame was read byte by byte, and it is frame 15 of `http2-with-cookies.pcapng`.**

- **The FoxIO implementations agree.** The Wireshark dissector computes the value at
  `packet-ja4.c:1197`. The Python reference computes it at
  `testdata/foxio/reference/python/ja4.py:519-520`, which reads the `http2` layer.
- **The port carries the same gap.** `Crank-Git/ja4plus` holds no HPACK decoder, and its
  `ja4plus/fingerprinters/ja4h.py:111` reads `packet[TCP]` and `packet[Raw]` alone.
- **No register entry closes.** No register entry names a JA4H value of
  `http2-with-cookies.pcapng` or of `chrome-cloudflare-quic-with-secrets.pcapng`.
- **The cost is high.** A TLS decryptor, an HPACK decoder and a QPACK decoder are three new
  subsystems, and each one reads untrusted input.

---

## Cause 2 — the library emitted at the frame that ends the header block

**#462 closed this cause.** The `## Two causes are closed since this reading` section above
states what the library does today. **This section keeps the reading that earned the
change.**

**96 deviations, all in `http1.pcapng`, and 64 of them close.** 48 read
`the library produces a value the vector does not hold` and 48 read the reverse. The two
sets pair frame by frame, and each pair holds one value.

```
http1.pcapng/1/JA4H.1  expected: ""  produced: "po11nn050000_530ceba2075f_000000000000_000000000000"
http1.pcapng/2/JA4H.1  expected: "po11nn050000_530ceba2075f_000000000000_000000000000"  produced: ""
```

**The value agrees, and the frame number differs by one.** Frame 1 holds the request line,
the whole header block, and the first 1460 bytes of a 6419-byte body. Frame 2 holds the rest
of that body.

**The library emitted when the header block ended, and #462 ended that rule.**
`ParseHTTPRequest` of `internal/parser/http.go` returned nil until `headerBlockEnd` found the
empty line, and `ProcessPacket` of `ja4h.go` then emitted on that frame. **Today
`HTTPMessageIsComplete` of `internal/parser/http.go` holds the value until the payload after
the header block reaches the byte count that `Content-Length` names.**

**The reference emits when the body ends.** `packet-ja4.c:1634` guards the emission on
`http_req != -100`, which the dissector sets at `packet-ja4.c:1149` when the frame carries
`http.request.method`.

**The Wireshark HTTP dissector is not in this corpus, so this page reads its behavior from
the vector.** `testdata/foxio/wireshark/http1.pcapng.json` names frame 2 and names no frame 1,
and frame 2 holds no request line. So the dissector exposed `http.request.method` on the
frame that completes the reassembled request. **A reader who needs the dissector's own rule
must read the Wireshark source, which the pin does not hold.**

**The measurement.** A candidate change held the value until the payload after the header
block reached the byte count that `Content-Length` names. The JA4H count moved from 337 to
273, and the total moved from 635 to 571.

**32 deviations remain in `http1.pcapng` after that change, and every one of them is ruling
#285.** The frames now agree, so the difference that remains is the trailing underscore of
the raw forms:

```
http1.pcapng/15/JA4H_r.1  expected: "po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length__"
                          produced: "po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_"
```

**Those 32 keys need 32 new register entries under ruling #285.** The register already holds
80 entries for `http1.pcapng`, and every one of them names ruling #285. Each existing key
names a frame that this change does not move, so the change closes no accepted deviation.
The measurement confirms it: the accepted count held at 419.

**#462 wrote those 32 entries**, and the register grew from 438 keys to 470.

- **The FoxIO implementations agree that the value is one per request.** They differ on the
  frame, and only the per-packet set names a frame at all.
- **The port carries the same gap, and #462 opened a parity difference.**
  `ja4plus/fingerprinters/ja4h.py:149-166` reads
  `header_block_end(stream_data)` and emits at once. **`Crank-Git/ja4plus#607` carries the
  port half**, and the `## Parity with ja4plus` section of `docs/specs/spec.md` holds the row.
- **The cost is one guard.** The fingerprinter reads `Content-Length` and holds the value
  until the payload reaches that byte count.

**One risk the reading names and does not settle.** A request whose sender never completes
the body reaches no emission under that guard. The library emitted such a request when this
reading was written.

**The maintainer settled that risk on 2026-08-13, and the answer is the strict gate.** A
request whose body never completes reaches no value. **No vector separates the two answers**,
so `ja4h_body_gate_test.go` records the ruling, and
`TestJA4H_ProducesNoValueForARequestWhoseBodyNeverCompletes` holds it.

---

## Cause 3 — the library emitted a second value for a repeated TCP segment

**#446 closed this cause.** The `## Two causes are closed since this reading` section above
states what the library does today. **This section keeps the reading that earned the
change.**

**50 deviations, all in `CVE-2018-6794.pcap`, and all 50 close.** 30 are per-packet and 20
are per-stream. Every one reads `the library produces a value the vector does not hold`.

Frame 6 and frame 15 of that capture carry the same bytes on the same four-tuple:

```
GET / HTTP/1.1\r\nHost: 192.168.235.136:8089\r\nConnection: keep-alive\r\n...
```

**The vector holds frame 6 and frame 16 alone.** `testdata/foxio/wireshark/CVE-2018-6794.pcap.json`
publishes `ja4.ja4h` for those two frames, and for no other frame of the capture. The
per-stream vector `testdata/foxio/python/CVE-2018-6794.pcap.json` publishes one entry for
stream 0 and one for stream 1.

**The library held no record of the segment it read.** `ProcessPacket` of `ja4h.go` added
every segment to the reassembler, and it removed the stream after each emission. Nothing held
the sequence number that the fingerprinter had already read, so the repeat produced a second
value. **`segmentCarriesNoNewRequest` of `ja4h.go` now holds that sequence range**, and
`rememberTheConsumedRequest` of the same file writes it.

**The reference reads the frame once.** The Python reference writes one value for each stream
at `testdata/foxio/reference/python/common.py:117`, which overwrites the cache entry, so the
per-stream vector holds one entry for each stream.

**The Wireshark HTTP dissector is not in this corpus, so this page reads its behavior from
the vector.** `packet-ja4.c:1634` fires only when the frame carries `http.request.method`, and
the vector names frame 6 and frame 16 alone. So the dissector exposed no such field for the
repeat. **A reader who needs the dissector's own rule must read the Wireshark source, which
the pin does not hold.**

**The measurement.** A candidate change held the sequence number of each emitted segment and
returned no value for a repeat. The JA4H count moved from 337 to 287, and the total moved
from 635 to 585. **No other capture moved, and the accepted count held at 419.**

- **The FoxIO implementations agree.** Neither one publishes a second value for the repeat.
- **The port does not carry this gap. It already holds the guard.**
  `ja4plus/fingerprinters/ja4h.py:172-221` holds a `consumed_seq` state table, and
  `ja4plus/fingerprinters/ja4h.py:130` reads it before the reassembler. **This library was
  behind the port on one rule, and #446 closed that parity difference.**
- **No register entry closes.** The register holds 4 JA4H entries for this capture, and each
  one names ruling #285. **The sentence read `4 entries for this capture` until #465**, and
  the capture reaches 10 entries. The other 6 name JA4L or JA4LS under ruling #361, and this
  page reads no JA4L deviation.
- **The cost is one bounded state table.** The fingerprinter holds the consumed sequence range
  of each stream. `.claude/rules/concurrency.md` requires a removal path, so the entry belongs
  in `CleanupConnection` and in `Reset`, and the table needs the bound that
  `ja4hMaxStreams` already states for the reassembler.

---

## Cause 4 — the library reads no HTTP request over UDP

**108 deviations. `ssh2.pcapng` holds 87, `tls3.pcapng` holds 12 and `latest.pcapng` holds
9.** Every one reads `the vector holds a value the library does not produce`.

**Every one of the 108 is an SSDP request over UDP port 1900.** Frame 15 of `ssh2.pcapng`
holds:

```
M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nUSER-AGENT: Microsoft Edge/114.0.1823.67 Windows\r\n\r\n
```

The per-packet vector holds `ms11nn050000_2ba00a982a15_000000000000_000000000000` for it.

**87 JA4H deviations in a capture named for SSH are 87 SSDP requests.** The capture holds
1391 frames, and the SSDP traffic sits beside the SSH traffic.

**The library reads TCP alone.** `ProcessPacket` of `ja4h.go` returns at once when the packet
holds no TCP layer.

### The maintainer ruled split S1 on 2026-08-13

**The library reads an HTTP request over TCP alone.** The ruling is at comment 5286085639
of issue #441. It follows the FoxIO Python reference, so the library produces no JA4H value
for an SSDP request over UDP.

**#467 recorded the ruling in `testdata/deviations.json`.** A ruling that a vector reaches
carries a register entry, and `.claude/rules/rulings.md` `## Where a ruling is recorded`
states that rule. **Each entry is a capability decline**, because the library declines a
capability and it produces no different value.

**#467 re-measured the count against the batch #478 head, and it did not adopt the 108 of
this page.** The two counts agree.

| What #467 measured | Count |
|---|---|
| Unaccepted per-packet JA4H deviations in `ssh2.pcapng`, `tls3.pcapng` and `latest.pcapng` | 108 |
| Frames that carry them | 36 |
| Register entries #467 added | 108 |

**Every one of the 36 frames is UDP port 1900.** `tshark` reports IP protocol `17` and the
protocol column `SSDP` for each one, and it reports no TCP port. **No frame of any other
capture in this cluster is SSDP.**

**The run counts moved as the ruling predicts.**

| Count | Before | After |
|---|---|---|
| Matches | 1680 | 1680 |
| Deviations the register does not hold | 475 | 367 |
| Accepted deviations | 450 | 558 |
| Register keys the run reaches | 470 | 578 |

**The fall of 108 equals the rise of 108, and the matches hold at 1680.** So the change
moves no fingerprint value.

**The reversal path is issue #441.** A reversal reads the UDP payload, and it needs a
matching change in the port. `### The measurement` below states the cost.

**Split S1 — whether an HTTP request over UDP produces a JA4H value.**

- **The Wireshark dissector produces one.** `packet-ja4.c:1229`, `packet-ja4.c:1236` and
  `packet-ja4.c:1243` read `udp.srcport`, `udp.dstport` and `udp.stream`, and
  `packet-ja4.c:136-138` names the three fields. The per-packet vector holds 36 SSDP values
  across the three captures.
- **The Python reference produces none.** `testdata/foxio/reference/python/ja4.py:514` opens
  `if 'tcp' in x['protos']:`, and `ja4.py:518` reads the HTTP layer inside that branch.
  `ja4.py:530` is the one UDP branch, and it reads QUIC. The per-stream vectors of
  `ssh2.pcapng` hold two JA4H entries, and both name TCP port 80.

**The candidate answers.**

1. The library reads an HTTP request over UDP, as the dissector does.
2. The library reads an HTTP request over TCP alone, as the Python reference and the port do.
3. The library reads an HTTP request over UDP, and the conformance suite excludes the value
   from the per-stream comparison.

**This reading picked none**, because `.claude/rules/rulings.md` `## Stop conditions` names
the first stop condition. **The maintainer picked answer 2 on 2026-08-13.**

**Split S2 — the two-letter method code.**

- **The Wireshark dissector reads a table.** `packet-ja4.c:1087-1131` maps a method name to a
  code. `packet-ja4.c:1108` holds `{"M-SEARCH",          "ms"}`, `packet-ja4.c:1104` holds
  `{"MKCOL",             "ml"}` and `packet-ja4.c:1114` holds
  `{"PROPFIND",          "pf"}`. `packet-ja4.c:1138` states the fallback: `"00"`.
- **The Python reference reads the first two characters.**
  `testdata/foxio/reference/python/ja4h.py:10` holds `return method.lower()[:2]`, which
  answers `m-` for `M-SEARCH`, `mk` for `MKCOL` and `pr` for `PROPFIND`.
- **The library follows the Python reference.** `ja4hPartA` of `ja4h.go` reads the first two
  characters.
- **The port follows the Python reference too**, at
  `ja4plus/fingerprinters/ja4h.py:403`, and the port's issue #219 records that ruling.

**The candidate answers.**

1. The library reads the dissector's table.
2. The library reads the first two characters, as it does today.
3. The library reads the table for the per-packet comparison alone.

**This reading picks none, and the ruling of split S1 makes split S2 unreachable.**
`M-SEARCH` reaches this library only through an SSDP request over UDP, and the ruling
produces no value for one. **No vector separates the two rules on a TCP request**, because
every method that both vector sets reach is `GET`, `POST` or `HEAD`, and the two rules agree
on all three.

**So the library keeps the first-two-characters rule**, which the Python reference states
and which ruling #219 of the port already records.

**Split S2 becomes live again only if the maintainer reverses the ruling of split S1.** A
reversal reopens the question, and issue #441 is the reversal path.

### The measurement

A candidate change read the UDP payload and adopted the dissector's method table. **The JA4H
count moved from 337 to 373, so the candidate opens 36 more deviations than it closes.**

| Set | Before | After |
|---|---|---|
| per-packet, `the vector holds a value the library does not produce` | 108 | 0 |
| per-packet, `the two values differ` | 0 | 72 |
| per-stream, `the library produces a value the vector does not hold` | 0 | 72 |

**The 36 base JA4H values agree exactly after the change.** The 72 per-packet differences
that remain are ruling #285, and each one is a trailing underscore of a raw form:

```
latest.pcapng/172/JA4H_r.1  expected: "ms11nn040000_HOST,MAN,MX,ST__"
                            produced: "ms11nn040000_HOST,MAN,MX,ST_"
```

**The 72 new per-stream deviations are split S1 itself.** The per-stream vector holds no SSDP
entry, so every SSDP value the library produces reads as a surplus value against that set.

- **No register entry closes.** The accepted count held at 419.
- **The port carries the same behavior, and the port matches the Python reference.**
  `ja4plus/fingerprinters/ja4h.py:111` reads `packet.haslayer(TCP)`. **A change here that the
  port does not make opens a parity difference on 36 values.**
- **The cost is a UDP read path, a method table, and a conformance exclusion or 72 register
  entries.** The count of register entries depends on how the maintainer rules split S1.

---

## Cause 5 — the request line parser rejects a path that holds a space

**#527 closed this cause on 2026-08-14, and
`### The maintainer ruled rule 5b on 2026-08-14` below states the result.** The rest of
this section is the reading that earned the change, and it states the tree before the
change.

**3 deviations, all in `gre-erspan-vxlan.pcap`, and 1 of them closes.** #527 re-measured
that count on 2026-08-14, and the run still reports 3. Frame 4 holds:

```
GET /Hello Arkime HTTP/1.0\r\n\r\n
```

The per-packet vector holds `ge10nn000000_e3b0c44298fc_000000000000_000000000000` for it.

**Two separate rules keep the library from that value.**

**Rule 5a — the path group reads no space.** `requestLineRe` of `internal/parser/http.go` holds
`(\S+)` for the path, so the match reads `/Hello`, then needs `HTTP/1.0` and finds `Arkime`.
`ParseHTTPRequest` returns nil.

**Rule 5b — part b writes the zero sentinel for an empty header list.**
`computeJA4HFromRequest` of `ja4h.go` calls
`parser.TruncatedHash`, and `TruncatedHash` of `internal/parser/hash.go` returns `000000000000` for the
empty string. **The Python reference hashes the empty string.**
`testdata/foxio/reference/python/common.py:127` holds
`return sha256(','.join(values).encode('utf8')).hexdigest()[:12]`, and that value is
`e3b0c44298fc`. **Two other FoxIO implementations write the zero sentinel instead**, and
`### Rule 5b needs a ruling` below states each reading.

**The measurement.** A candidate change that relaxed the path group alone moved the JA4H count
from 337 to 337, and it closed nothing. It produced
`ge10nn000000_000000000000_000000000000_000000000000` against the expected
`ge10nn000000_e3b0c44298fc_000000000000_000000000000`. **A second candidate change that also
hashed the empty header list moved the count from 337 to 336.** The two rules therefore
compose, and neither one closes a deviation on its own.

**The 2 deviations that remain are ruling #285.** The two raw forms hold
`ge10nn000000__` against the expected `ge10nn000000___`.

- **The FoxIO implementations split on rule 5b.** An earlier draft of this page stated that
  they agree, and it read two of the four. `### Rule 5b needs a ruling` below states each
  reading, and #527 holds the question.
- **The port carries both gaps.** `ja4plus/utils/http_utils.py:31-34` holds the same `(\S+)`
  path group. **A change here that the port does not make opens a parity difference.**
- **No register entry closes.** The accepted count held at 419.
- **The cost of rule 5a is one regular expression, and the cost of rule 5b is one call
  site.** **Rule 5b reaches every JA4H value whose header list is empty, so it needs a wider
  measurement than one capture before anybody builds it.**

### Rule 5b needs a ruling

**The maintainer ruled rule 5b on 2026-08-14, so this section is the reading that earned
the ruling and never a statement of the tree today.**
`### The maintainer ruled rule 5b on 2026-08-14` below states the ruling, and it states
each sentence of this section that the ruling supersedes. **The split is real history, and
this page keeps it.**

**The four FoxIO implementations split two against two.** #527 read each one on 2026-08-14,
at the pin `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

| Implementation | Part b of an empty header list | Evidence |
|---|---|---|
| Python | `e3b0c44298fc` | `testdata/foxio/reference/python/ja4h.py:72` and `testdata/foxio/reference/python/common.py:127` |
| Wireshark | `e3b0c44298fc` | `testdata/foxio/reference/wireshark/source/packet-ja4.c:628` and `:641` |
| Rust | `000000000000` | `testdata/foxio/reference/rust/ja4/src/http.rs:202` and `testdata/foxio/reference/rust/ja4/src/lib.rs:184` |
| Zeek | `000000000000` | `testdata/foxio/reference/zeek/ja4h/main.zeek:195` and `testdata/foxio/reference/zeek/utils/common.zeek:64` |

**Python and Wireshark hash the header string under no guard.**
`testdata/foxio/reference/python/ja4h.py:72` holds `headers = sha_encode(x['headers'])`.
`testdata/foxio/reference/wireshark/source/packet-ja4.c:641` writes `hash1` directly, and
it reserves `zero_hash` for part c and part d alone.

**Rust and Zeek return the zero sentinel for the empty string.**
`testdata/foxio/reference/rust/ja4/src/lib.rs:184` holds `if s.is_empty() {`, and the next
line returns `"000000000000".to_owned()`.
`testdata/foxio/reference/zeek/utils/common.zeek:64` holds `if (input == "") {`, and the
next line returns `"000000000000"`.

**Each of the two guards reaches part b, and neither one reaches part b in a published
vector.** `testdata/foxio/reference/rust/ja4/src/http.rs:202` calls `hash12` on the joined
header list, and an empty list joins to the empty string. **No Rust snapshot reads a header
count of `00`**, so no published Rust value exercises the guard.

**R18 of `docs/specs/foxio/JA4H.md` is a rank 1 image rule, and it names no sentinel.** It
states `Truncated SHA256 hash of Headers, in the order they appear`. **R27 confines the zero
sentinel to part c and part d.** So the image agrees with Python and with Wireshark.

**One vector of the corpus exercises the question, and the Wireshark dissector produced
it.** `testdata/foxio/wireshark/gre-erspan-vxlan.pcap.json` holds
`ge10nn000000_e3b0c44298fc_000000000000_000000000000` at frame 4. **That vector is the
output of one party to the split**, so it corroborates the image rather than deciding the
question on its own.

**The corpus holds 215 JA4H values, and 1 of them reads a header count of `00`.** No vector
of the corpus writes `000000000000` in part b. Measured on 2026-08-14.

**This project already records the same question for another method, and it records it as a
reference split.** **R12 of `docs/specs/foxio/JA4X.md` states
`**R12** — **Reference split.** An empty list produces two different values.`** It names
`rust/ja4x/src/lib.rs:171` and `wireshark/source/packet-ja4.c:590` for the sentinel, and
`python/ja4x.py:87` for the hash. **So the empty list question is open for JA4X today**, and
rule 5b asks it for part b of JA4H.

**One difference separates the two.** The JA4X image carries a value for each half of the
split, and R12 records both. **The JA4H image names a hash at R18, and it confines the
sentinel to part c and part d at R27.** So the JA4H evidence leans one way and the JA4X
evidence leans neither way.

**Two stop conditions of `.claude/rules/rulings.md` fire together.** The implementations
disagree with each other, and the image disagrees with two of them. **The maintainer rules
rule 5b, and no session builds it first.** A ruling lands in this repository and in
`Crank-Git/ja4plus` together, under `.claude/rules/parity.md`.

**A repair of rule 5b changes no line of `internal/parser/hash.go`.** `TruncatedHash` serves
nine call sites outside part b, in `ja4.go`, in `ja4s.go`, in `ja4x.go` and in the two
cookie parts of `computeJA4HFromRequest`. **R27 holds the sentinel for part c and part d**,
and **R12 of `docs/specs/foxio/JA4X.md` holds the sentinel for JA4X**. The doc comment of
`computeJA4XWithRaw` in `ja4x.go` cites R12 and it names the same reliance. So a change to
the shared function moves a JA4 value, a JA4S value and a JA4X value.

**Rule 5a alone opens a deviation rather than closing one.** The path group repair makes
`ParseHTTPRequest` return a request for frame 4, and part b then writes `000000000000`
against the expected `e3b0c44298fc`. **So no session builds rule 5a before the maintainer
rules rule 5b.**

### The maintainer ruled rule 5b on 2026-08-14

**JA4H part b hashes an empty header list to `e3b0c44298fc`, and it writes no zero
sentinel.** The ruling comment is comment 5294404252 of #527, and **issue #527 is the
reversal path**. The port half is `Crank-Git/ja4plus#612`, and
`ja4plus/fingerprinters/ja4h.py:480` at tag `v1.1.0` writes the sentinel that the ruling
reverses.

**The deciding fact is R18 of `docs/specs/foxio/JA4H.md`.** It is a rank 1 image rule, it
states `Truncated SHA256 hash of Headers, in the order they appear`, and it names no
sentinel. **R27 confines the sentinel to part c and to part d.**
`.claude/rules/rulings.md` `## The source ranking` places an image above every
implementation, so the image outranks the four references of the table above.

**#527 built rule 5a and rule 5b together**, because the two rules close one comparison
only when both hold.

**Three sentences of `### Rule 5b needs a ruling` above no longer state the tree.** This
section states each one.

| The sentence above | What the tree holds today |
|---|---|
| `The maintainer rules rule 5b, and no session builds it first.` | The maintainer ruled it on 2026-08-14, and #527 built it. |
| `So no session builds rule 5a before the maintainer rules rule 5b.` | #527 built rule 5a in the same change. |
| The sentence that states that a repair of rule 5b changes no line of `internal/parser/hash.go`. | The repair adds `TruncatedHashNoSentinel` to that file, and it changes no call site outside JA4H part b. |

**The repair keeps `TruncatedHash` unchanged, so it moves no JA4 value, no JA4S value and
no JA4X value.** `TruncatedHashNoSentinel` of `internal/parser/hash.go` hashes the empty
string, `TruncatedHash` calls it for a non-empty input, and `computeJA4HFromRequest` of
`ja4h.go` is the one caller of the new function.
`TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed` of
`ja4h_empty_header_list_test.go` names every call site of the root package, and it fails
when a later change adds one.

**Rule 5a reads the path group.** `requestLineRe` of `internal/parser/http.go` now holds a
lazy group of any character in place of the non-space group. The group is lazy, so a first
line that holds two version tokens reaches the earlier one, as the non-space group did.

**Rule 5a also tightened each separator of that expression, and the self-review of #527
earned the change.** A separator of `\s` reads a line ending, so the match crossed into the
second line of the payload and read a request line that no line holds. **The payload
`SSH-2.0-OpenSSH_9.6\r\n/a HTTP/1.1\r\n` matched before 2026-08-14**, under the non-space
path group and the `\s` separator. `ja4l.go` reads `IsHTTPRequest` to pick a measurement
point, so that match moves a JA4L value. Each separator now reads a space or a horizontal
tab. **The change moves no value of the corpus**: the run above is byte-identical with the
separator and without it, so no capture of the corpus holds such a payload.
`TestTheRequestLineReadsNoSecondLine` of `ja4h_empty_header_list_test.go` holds the rule,
and `TestTheRequestLineReadsASpaceAndATabAsASeparator` holds the separator set.

#### The measurement

**`make corpus` and then `make conformance`, on `issue/527-ja4h-hash-empty-header-list`,
base `origin/batch/555-session-15-rulings` at `2d675e7`, corpus at
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, on 2026-08-14.**

| Measure | Before | After |
|---|---|---|
| Matches | 1753 | 1754 |
| Deviations the register does not hold | 270 | 267 |
| Accepted deviations | 583 | 585 |
| Unaccepted uncovered values | 172 | 175 |
| Accepted uncovered values | 32 | 32 |
| Register keys | 615 | 617 |
| Stale register entries | 0 | 0 |
| Orphan register entries | 0 | 0 |

`585 + 32 = 617` holds.

**One fingerprint value moved, and one capture holds it.**
`gre-erspan-vxlan.pcap/4/JA4H.1` reached no value before the change, and it now matches
`ge10nn000000_e3b0c44298fc_000000000000_000000000000`.

**The two raw forms of the same frame became reachable, and #527 wrote a register entry for
each one under ruling #285.** Each entry holds `ge10nn000000__` against
`ge10nn000000___`, which is the one trailing underscore that #285 settles. **The reading
above predicted both entries.**

**Rule 5a also opened three uncovered values, and the reading above predicted none of
them.** The per-stream vector file `testdata/foxio/python/gre-erspan-vxlan.pcap.json`
holds `JA4L-S` and `JA4L-C` for stream 0, and it holds no JA4H key. The library now
produces `gre-erspan-vxlan.pcap/0/JA4H`, `/JA4H_r` and `/JA4H_ro` for that stream, so the
per-stream unaccepted uncovered count rises from 144 to 147. **The JA4H value of the
stream equals the per-packet vector of frame 4**, so the three uncovered values record a
coverage difference of the FoxIO Python harness and never a value disagreement. **#527
wrote no register entry for them**, because the register records an accepted difference
from a FoxIO value and no FoxIO value exists here.

---

## Ruling #285 sits behind three causes

**The maintainer ruled #285 on 2026-08-12, and the register records it.** The entry states:

> The two FoxIO vector sets disagree on the JA4H shape, and the maintainer ruled on
> 2026-08-12 that this library follows the per-stream set.

**So the trailing underscore is settled, and it is not an open question.** The register holds
142 entries for it today. **The count read 108 until #462**, which wrote the 32 entries that
cause 2 predicted. **#527 wrote the last 2 on 2026-08-14**, when the ruling of rule 5b made
frame 4 of `gre-erspan-vxlan.pcap` reach a value.

**#285 no longer names every JA4H entry of the register.** #467 added 108 entries under
ruling #441, so the register holds 250 JA4H entries across the two rulings.

**Three causes hide a #285 difference behind a larger one.** A frame that produces no value at
all reports one deviation, and the same frame reports the #285 difference once it produces a
value.

| Cause | #285 deviations it reveals |
|---|---|
| 2 | 32 |
| 4 | 72 |
| 5 | 2 |

**Each one needs a new register entry, and no one of them needs a new ruling.** A change that
closes cause 2 therefore closes 64 deviations and adds 32 register entries.

**The 72 of cause 4 stay unreachable under the ruling of split S1.** The library produces no
value for an SSDP request over UDP, so no frame of cause 4 reveals a #285 difference. **A
reversal of that ruling reaches them.**

---

## What this reading does not answer

- **The count each candidate for cause 1 closes.** The section states the reason.
- **The two-deviation difference between this run and the project manager's run.** Both runs
  read the same corpus and the same pin, and the per-capture counts agree.
- **Whether rule 5b moves a value outside `gre-erspan-vxlan.pcap` in a capture the corpus
  does not hold.** #527 answered the corpus half on 2026-08-14: the whole-corpus run moves
  one comparison, and `gre-erspan-vxlan.pcap` holds it. **The corpus holds 215 JA4H values,
  and 1 of them reads a header count of `00`.** The rule reaches every empty header list
  outside the corpus, and no measurement bounds that set.
- **Whether the maintainer confirms the ruling of split S1.** The maintainer ruled it on
  2026-08-13, and issue #441 is the reversal path.
- **Split S2.** The ruling of split S1 makes it unreachable, and a reversal makes it live
  again.
