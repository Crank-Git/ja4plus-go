# The JA4X deviation cluster

This page is a reading. **It moves no fingerprint value, and it adds no register entry.**
Issue #458 produced it, under Epic #441.

It reads every JA4X and JA4X_r deviation that `testdata/deviations.json` does not hold. It
names one cause for each one. It states the count each cause closes, measured against the
corpus at the pin of `testdata/foxio.pin`.

**Every JA4X count of this page comes from one run of `go test -tags conformance -count=1
-v ./...` in one worktree, on 2026-08-13.** That run reads the corpus at
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. **It read the batch #478 branch before #467
sub-merged.** It reports 1680 matches, 475 deviations, 450 accepted deviations and 470
register keys. **No commit of #458 holds a Go file, and no commit of #458 changes
`testdata/deviations.json`.**

**#467 then added 108 register entries, and batch #478 re-measured the four whole-run
counts at the branch head.** A second run of `make conformance` on 2026-08-13 reports 1680
matches, 367 deviations, 558 accepted deviations and 578 register keys. **Every JA4X count
of this page holds at the branch head**, because each of the 108 entries names a JA4H key.
The second run reports 50 JA4X and JA4X_r deviations that the register does not hold. It
reports the same six captures, and the same 34 and 16 split. **So a whole-run figure of this
page names the first run, and a JA4X figure names both runs.**

**`make conformance` exits 2, and Epic #441 owns that exit.** Step 4 of the
`## A change is done when` list of `CLAUDE.md` is unmeetable today. This page reports no
green gate.

**Neither run above describes the tree today, and every count of this page outside the next
section names a run of 2026-08-13.** The Epic #441 batch merged after both runs, and it closed
39 of the 50. **`## The merged tree of the Epic #441 batch, 2026-08-14` below states every
re-measured figure**, and it names the run that measured each one. **A reader who carries 1680,
475, 367, 558 or 578 forward from this preamble reads a stale figure.**

## The merged tree of the Epic #441 batch, 2026-08-14

**One run of `make conformance` on `issue/512-epic-441-round` at `74c8827` produced every
figure of this section.** That run reads the corpus at
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, and `74c8827` is the head of
`origin/epic/441-deviation-fixes` after the last member sub-merged. **The run rewrote no byte
of `docs/audit/conformance.md`**, so the tracked report already described that head.

**The run reports 1753 matches, 278 deviations that the register does not hold, 575 accepted
deviations and 595 register keys.** It reports 184 unaccepted uncovered values, 20 accepted
uncovered values, 0 stale register entries and 0 orphan register entries. **`575 + 20 = 595`,
so the accepted comparison count equals the register key count.**

| Cause | The member that built it | Deviations of 2026-08-13 | The merged tree |
|---|---|---|---|
| 1 | #489, `91a289d` | 36 | 0 |
| 2 | **None. #492 left this batch.** | 11 | 11 |
| 3 | #490, `8347afd` | 3 | 0 |
| **Total** | | **50** | **11** |

**The 11 that remain are the 11 of cause 2, and the run names the same two captures.**
`http2-with-cookies.pcapng` holds 9 and
`chrome-cloudflare-quic-with-secrets.pcapng` holds 2. **So the cause 2 attribution of this
page holds against the merged tree**, and the two closed causes reached the counts they
predicted. **The ship-partial comment of #441 dated 2026-08-14 states why #492 left the
batch.**

## The measurement

**The first run reports 475 deviations that the register does not hold, and the second run
reports 367. 50 of them name JA4X or JA4X_r in each run.** **Epic #441 measured 50 on
2026-08-13, before batch #421 and before #438.** This page re-measured the number rather
than adopt it, and the three measurements agree.

**Each table of this section carries a second count column, and the Epic #441 batch produced
it.** `## The merged tree of the Epic #441 batch, 2026-08-14` above names the run.

| Key kind | 2026-08-13 | The merged tree |
|---|---|---|
| `JA4X` | 34 | 8 |
| `JA4X_r` | 16 | 3 |

| Direction | 2026-08-13 | The merged tree |
|---|---|---|
| `the vector holds a value the library does not produce` | 47 | 11 |
| `the two values differ` | 3 | 0 |

**The `the two values differ` row reads 0, and this page keeps the row.** A row that states a
measured 0 separates a direction that no deviation reaches from a direction that nobody
measured. **Every remaining JA4X deviation reads
`the vector holds a value the library does not produce`.**

**Six captures hold the 50, and two of the six hold the 11.**

| Capture | Per-stream | Per-packet | Total | The merged tree |
|---|---|---|---|---|
| `tls-handshake.pcapng` | 6 | 12 | 18 | 0 |
| `socks-https-example.pcap` | 4 | 8 | 12 | 0 |
| `http2-with-cookies.pcapng` | 3 | 6 | 9 | 9 |
| `latest.pcapng` | 2 | 4 | 6 | 0 |
| `badcurveball.pcap` | 1 | 2 | 3 | 0 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 2 | 0 | 2 | 2 |

**The per-packet set publishes JA4X and JA4X_r for one frame, and the per-stream set
publishes JA4X alone.** So one certificate that the library misses costs two per-packet keys
and one per-stream key.

### How this page reads the library output without a candidate change

**The run states the produced value of every deviating key, and a key that reports no
deviation holds the value the vector names.** So the produced list of each stream is
readable from the run alone. `tls-handshake.pcapng` stream 40 is the worked example. The
vector holds three values. The run reports a deviation at occurrence 2 and at occurrence 3,
and none at occurrence 1. **So the library produced two values, and the second one is the
value the vector names at occurrence 3.**

## The three causes, and the count each one closes

| N | Cause | Deviations | Count it closes, measured |
|---|---|---|---|
| 1 | The certificate set names no stream, so a certificate that two live streams carry reaches one value. | 36 | 36 |
| 2 | The library reads no encrypted TLS 1.3 handshake record. | 11 | 11 |
| 3 | The Go certificate parser refuses a key that names explicit elliptic curve parameters. | 3 | 3 |

**The three causes attribute all 50.** 36 + 11 + 3 = 50.

**No cause of this page reaches a maintainer ruling.**
`## No cause reaches a maintainer ruling` below states the evidence for each one.

---

## Cause 1 — the certificate set names no stream

**36 deviations.** `tls-handshake.pcapng` holds 18, `socks-https-example.pcap` holds 12 and
`latest.pcapng` holds 6. **All 36 close.**

**#489 built the change, and it sub-merged at `91a289d` on 2026-08-14. The merged tree reports
0 of the 36.**

**`findCertificatesInStream` of `ja4x.go` reads `processedCerts` before it writes a value,
and it skips a certificate the set holds.** The key of that set is the SHA-256 hash of the
certificate, and it names no stream. `CleanupConnection` of `ja4x.go` removes the hashes of
one closed connection, so a certificate that two live streams carry reaches one value.

### The measurement

**One command extracts every certificate of a capture, keyed by stream and by hash.**
`tshark -r <capture> -Y tls.handshake.certificate -T fields -e tcp.stream -e frame.number -e
tls.handshake.certificate` writes the DER bytes of each certificate. `tls-handshake.pcapng`
reads as follows, at tshark 4.6.7, where each hash is the first 16 characters of the SHA-256
of the DER bytes.

```
stream 5 frame 19 cert 1 5a754ee8dcc036d3 NEW
stream 5 frame 19 cert 2 b676ffa3179e8812 NEW
stream 33 frame 112 cert 1 a1ac71dd8fdaeb4a NEW
stream 33 frame 112 cert 2 52274c57ce4dee3b NEW
stream 34 frame 130 cert 1 a1ac71dd8fdaeb4a REPEAT of stream 33
stream 34 frame 130 cert 2 52274c57ce4dee3b REPEAT of stream 33
stream 40 frame 136 cert 1 0745bd123ae1b6ef NEW
stream 40 frame 136 cert 2 52274c57ce4dee3b REPEAT of stream 33
stream 40 frame 136 cert 3 4348a0e9444c78cb NEW
stream 43 frame 151 cert 1 b8e1471ceac15a0b NEW
stream 43 frame 151 cert 2 c1ad7778796d20bc NEW
stream 46 frame 165 cert 1 70910f466baf9508 NEW
stream 46 frame 165 cert 2 52274c57ce4dee3b REPEAT of stream 33
stream 46 frame 165 cert 3 4348a0e9444c78cb REPEAT of stream 40
```

**The repeat table predicts every deviation of the capture, certificate by certificate.**

| Stream | Certificates the set suppresses | What the run reports |
|---|---|---|
| 33 | none | No deviation. |
| 34 | 1 and 2 | Occurrence 1 and occurrence 2 hold no produced value. |
| 40 | 2 | Occurrence 2 differs, and occurrence 3 holds no produced value. |
| 46 | 2 and 3 | Occurrence 2 and occurrence 3 hold no produced value. |

Stream 40 is the case that separates this cause from any other. The run reports:

```
per-stream deviation tls-handshake.pcapng/40/JA4X.2: the two values differ
      expected: "7d5dbb3783b4_a373a9f83c6b_a83ffcd6e6c2"
      produced: "7d5dbb3783b4_7d5dbb3783b4_f269f029c206"
per-stream deviation tls-handshake.pcapng/40/JA4X.3: the vector holds a value the library does not produce
      expected: "7d5dbb3783b4_7d5dbb3783b4_f269f029c206"
      produced: ""
```

**The produced value of occurrence 2 is the expected value of occurrence 3.** The library
skipped the middle certificate and moved the third one up one place.

The other two captures read the same way.

```
socks-https-example.pcap: stream 0 holds 2 new certificates, and stream 2 and stream 4 repeat both.
latest.pcapng: stream 9 holds 2 new certificates, and stream 10 repeats both.
```

### The count it closes

**All 36 close, and each closed key becomes a match.** Each suppressed certificate already
produces the value the vector names, on the stream that carried it first. Stream 33 of
`tls-handshake.pcapng` matches at occurrence 1 and at occurrence 2, and stream 34 carries the
same two certificates. Stream 0 of `socks-https-example.pcap` matches at both occurrences,
and stream 2 and stream 4 carry the same two certificates. Stream 9 of `latest.pcapng`
matches at both occurrences, and stream 10 carries the same two certificates.

**The change closes no accepted deviation.** The register holds 12 JA4X entries, and every
one names `socks4-https.pcap` under ruling #375. That capture holds one stream, so no
certificate of it repeats on a second stream.

**The change raises the count of unaccepted uncovered values by 11.** The per-stream vector
set publishes no JA4X_r key, so every per-stream JA4X_r value the library produces reads as
an uncovered value. The run of 2026-08-13 reports 47 unaccepted uncovered JA4X keys, and this
page predicted that the change takes that count to 58. **#489 built the change, and the merged
tree reads 59.** #490 adds `badcurveball.pcap/0/JA4X_r.2` on top of the 11 that #489 adds, so
the 58 of the prediction and the 59 of the measurement differ by one.
`## The merged tree of the Epic #441 batch, 2026-08-14` above names the run.
**An uncovered value fails no gate.** `conformanceReportTotals` of
`conformance_test.go` fails the run on a deviation count above zero, and it logs the
uncovered counts.

The rise reads stream by stream. `tls-handshake.pcapng` stream 34 gains 2, stream 40 gains 1
and stream 46 gains 2. `socks-https-example.pcap` stream 2 gains 2 and stream 4 gains 2.
`latest.pcapng` stream 10 gains 2. **The count of uncovered keys of one stream equals the
count of certificates the library produces on it**, and the run holds that identity for every
stream of the six captures.

### The evidence, the port and the cost

- **The three FoxIO implementations agree, and none of them holds a certificate cache.**
  `testdata/foxio/reference/python/ja4x.py:14` states
  `# JA4X does not use any caching from common.py`, and
  `testdata/foxio/reference/python/ja4.py:348` states
  `# JA4X works on the packet rather than a cache entry`.
  `testdata/foxio/reference/wireshark/source/packet-ja4.c:1620` opens
  `if (handshake_type == 11) {`, and `:1628` and `:1629` write one JA4X_r value and one JA4X
  value for each certificate of the message.
  `testdata/foxio/reference/rust/ja4/src/tls.rs:86` reads
  `for hexdump in tls.values("tls.handshake.certificate") {`, and `:93` pushes one record for
  each certificate.
- **Zeek publishes no JA4X.** `testdata/foxio/reference/zeek/ja4x/__load__.zeek:1` holds
  `# empty`.
- **So this difference is row 1 of `.claude/rules/parity.md`
  `## Where a difference comes from`.** The reference is unanimous and this project differs.
  **The action is a change to the code, and the register gains nothing.**
- **The port does not carry this gap, and it holds the repair.**
  `ja4plus/fingerprinters/ja4x.py:341` reads
  `key = (stream_id, hashlib.sha256(cert_bytes).hexdigest())`, and `:326` states
  `FoxIO computes one JA4X value for each certificate on each stream, and its`.
  **This library is behind the port on one rule, and a change here closes a parity
  difference.** **This reading read the port at the tag `v1.1.0`, which
  `.claude/rules/parity.md` names.** `ja4plus/fingerprinters/ja4x.py` is byte-identical at
  `v1.1.0` and at the checkout `9e4c578` on this machine.
- **The cost is one key.** The certificate set takes the stream name beside the certificate
  hash. `certsByStream` of `ja4x.go` already indexes the set by stream, so
  `CleanupConnection` needs the new key shape and no new table.
  `.claude/rules/concurrency.md` requires a removal path, and `Reset` and
  `CleanupConnection` already hold one.

---

## Cause 2 — the library reads no encrypted TLS 1.3 handshake record

**11 deviations.** `http2-with-cookies.pcapng` holds 9 and
`chrome-cloudflare-quic-with-secrets.pcapng` holds 2. Every one reads
`the vector holds a value the library does not produce`.

**#492 builds this cause, and #492 left the Epic #441 batch on 2026-08-14. The merged tree
reports all 11.** The ship-partial comment of #441 of that date states the three parts the
work needs, and it states that #492 reaches #171, Epic 10 and the port together.

**`findCertificatesInStream` of `ja4x.go` reads the first byte of each TLS record, and it
skips a byte that is not `parser.TLSRecordTypeHandshake`.**
`internal/parser/tls.go:10` holds `TLSRecordTypeHandshake  = 0x16`. **A TLS 1.3 server
writes the Certificate message inside a record whose type byte is `0x17`**, so the reader
walks past it.

### The measurement

Frame 10 of `http2-with-cookies.pcapng` reads as follows, at tshark 4.6.7.

```
    TLSv1.3 Record Layer: Handshake Protocol: Multiple Handshake Messages
        Opaque Type: Application Data (23)
        ...
        Handshake Protocol: Certificate
            Handshake Type: Certificate (11)
```

The record type byte is 23, and the certificate sits behind the record protection. tshark
reads the certificate because the capture holds the decryption secrets.

**Two frames of `chrome-cloudflare-quic-with-secrets.pcapng` carry a certificate, and each
one adds a layer.**

```
8	eth:ethertype:ipv6:tcp:tls	23	22	8,25,15,20
51	eth:ethertype:ipv6:udp:quic:tls			25,15,20
```

Frame 8 sits in a protected TLS record on TCP stream 0, and handshake type 25 is the
compressed certificate of RFC 8879. Frame 51 carries the same message inside a QUIC CRYPTO
frame, and QUIC holds no TLS record layer. **The vector key names TCP stream 0**, at
`chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.1`, so the deviation belongs to
frame 8.

**Two captures of the corpus hold a protected certificate frame, and no third one does.**
One command over all 38 captures counts a certificate frame whose record carries an opaque
type: `http2-with-cookies.pcapng` reports one, and
`chrome-cloudflare-quic-with-secrets.pcapng` reports one. **So a change that reads the
protected record opens no surplus value anywhere else in the corpus.**

### The count it closes

**All 11 close, and the two captures carry two grades of evidence.**

**The 9 of `http2-with-cookies.pcapng` close on a direct reading.** The tshark of this
measurement extracts the three certificates of frame 10 from the same bytes the library
reads, so a reader that reaches the plaintext produces the three values the vector names.

**The 2 of `chrome-cloudflare-quic-with-secrets.pcapng` close on the vector alone.** The
tshark of this measurement reports the compressed message and no certificate inside it, so
this page reads the two expected values from the vector file and it extracts no certificate.
**A reader that also decompresses the message produces them**, and this page measures no
capture that proves it.

**The change closes no accepted deviation.** No register entry names a JA4X key of either
capture.

**The change raises the count of unaccepted uncovered values by 5**, for the same reason that
cause 1 does. `http2-with-cookies.pcapng` stream 0 gains 3, and
`chrome-cloudflare-quic-with-secrets.pcapng` stream `0:57098` gains 2.

### The evidence, the port and the cost

- **The FoxIO implementations agree, and each one reads the plaintext that tshark
  supplies.** `testdata/foxio/reference/rust/ja4/src/tls.rs:86` reads
  `tls.values("tls.handshake.certificate")`, and
  `testdata/foxio/reference/python/ja4.py:517` reads the `x509af` layer of the tshark output.
  **Neither one decrypts anything of its own.**
- **The port carries the same gap.** `ja4plus/fingerprinters/ja4x.py:166-167` returns at once
  for a packet that holds no TCP layer and no `Raw` layer, and `:279-280` breaks the scan on
  a byte that is not `TLS_HANDSHAKE_CONTENT_TYPE`, which `:26` sets to `0x16`. **A change
  here that the port does not make opens a parity difference on 11 values.**
- **The cost is high, and the library already holds part of it.** `types.go` exports
  `ParseKeyLog`, `ReadKeyLogFromCapture`, `KeyLog.Secret` and `DecryptQUICPacket`, so the key
  material and one decryptor exist. **A TLS record decryptor for TCP does not.** The JA4X
  fingerprinter reads the TCP payload and it reads no key log, so the work holds three parts:
  a key log that reaches the fingerprinter, a TLS 1.3 record decryptor, and a reader for the
  compressed certificate of RFC 8879.
- **`chrome-cloudflare-quic-with-secrets.pcapng` needs the third part, and
  `http2-with-cookies.pcapng` does not.** Frame 10 of the second capture holds handshake type
  11, and frame 8 of the first holds handshake type 25.

---

## Cause 3 — the Go certificate parser refuses explicit elliptic curve parameters

**3 deviations, all in `badcurveball.pcap`, and all 3 close.** One is per-stream and two are
per-packet. Every one reads `the vector holds a value the library does not produce`.

**#490 built the change, and it sub-merged at `8347afd` on 2026-08-14. The merged tree reports
0 of the 3.**

```
per-packet deviation badcurveball.pcap/7/JA4X.2: the vector holds a value the library does not produce
      expected: "2e9214a636bc_2e9214a636bc_795797892f9c"
      produced: ""
```

**Frame 7 holds two certificates in one cleartext TLS 1.2 Certificate message, and the
library produces a value for the first one alone.** The repeat table of cause 1 reports both
certificates as new, so cause 1 does not reach this capture.

### The measurement

**The two certificates differ in one field, and that field decides the outcome.**

| Certificate | Public key parameters | What `openssl x509 -text` prints |
|---|---|---|
| 1 | A named curve | `ASN1 OID: secp384r1` and `NIST CURVE: P-384` |
| 2 | Explicit parameters | `Field Type: prime-field` and `Prime:` |

`openssl asn1parse` reads the AlgorithmIdentifier of certificate 2 as follows.

```
  225:d=4  hl=2 l=   7 prim: OBJECT            :id-ecPublicKey
  234:d=4  hl=4 l= 343 cons: SEQUENCE
```

**The parameters field is a SEQUENCE, and it is no object identifier.**

**`ja4xParts` of `ja4x.go` calls `x509.ParseCertificate`, and that function returns an error
for certificate 2.** At Go 1.26.5, `crypto/x509/parser.go:285` opens the ECDSA branch,
`:286` reads the parameters, and `:289` returns
`errors.New("x509: invalid ECDSA parameters")` when the parameters hold no object identifier.
`crypto/x509/parser.go:1011` calls that reader from the certificate parser, and it returns
the error, so the whole certificate parse fails. `ja4xParts` then answers false, and
`computeJA4XWithRaw` of `ja4x.go` returns two empty strings.

**The certificate is readable, and the key is the one part the fingerprint never uses.**
JA4X reads the issuer identifiers, the subject identifiers and the extension identifiers.
`openssl x509` reads all three from certificate 2, and the public key blocks none of them.

### The count it closes

**All 3 close.** The expected value `2e9214a636bc_2e9214a636bc_795797892f9c` names an issuer
list and a subject list that are equal, which is the self-signed certificate that
`openssl x509` prints as `Issuer: C=HR, ST=Zagreb, O=INFIGO IS, CN=INFIGO` and
`Subject: C=HR, ST=Zagreb, O=INFIGO IS, CN=INFIGO`.

**The change closes no accepted deviation.** No register entry names a JA4X key of
`badcurveball.pcap`.

**The change raises the count of unaccepted uncovered values by 1.** Stream 0 of
`badcurveball.pcap` holds one uncovered JA4X_r key today, and it gains a second one.

### The evidence, the port and the cost

- **The FoxIO implementations agree, and each one produces a value for certificate 2.** The
  per-stream vector `testdata/foxio/python/badcurveball.pcap.json` holds `JA4X.2`, and the
  per-packet vector holds `JA4X.2` and `JA4X_r.2` for frame 7. **The Wireshark x509 dissector
  and the `x509_parser` crate each read the certificate structure, and neither one validates
  the curve.**
- **So this difference is row 1 of `.claude/rules/parity.md`
  `## Where a difference comes from`.** The reference is unanimous and this project differs.
- **The port does not carry this gap.** `ja4plus/fingerprinters/ja4x.py:487` calls
  `x509.load_der_x509_certificate(cert_data, default_backend())`, and `cryptography` reads
  the certificate. A read of the same DER bytes in the port's environment reports four issuer
  identifiers, four subject identifiers and three extensions. **This library is behind the
  port, and a change here closes a parity difference on 3 values.**
- **The cost is a reader that does not parse the public key.** `crypto/x509` refuses the
  certificate as a whole, so the fix reads the three identifier lists from the ASN.1
  structure. **`internal/parser/` already holds the X.509 decoding of this project**, so the
  new reader belongs there. **Every packet is untrusted input**, so the reader bounds each
  length field before it slices.
- **The certificate of this capture is the CVE-2020-0601 shape**, and a reader of it never
  validates a signature. JA4X reads identifiers, so the reader needs no trust decision.

---

## The uncovered JA4X values

**The run of 2026-08-13 reports 192 uncovered values, and 59 of them name a JA4X key.** **The
merged tree reports 204 uncovered values, and 71 of them name a JA4X key.** An uncovered value
is a value the library produces for which the vector file names no key.

| Category | All methods, 2026-08-13 | JA4X keys, 2026-08-13 | All methods, merged | JA4X keys, merged |
|---|---|---|---|---|
| unaccepted | 172 | 47 | 184 | 59 |
| accepted | 20 | 12 | 20 | 12 |

**45 of the 47 unaccepted keys name `JA4X_r`, and 2 name `JA4X`.** **The merged tree reads 57
of the 59 as `JA4X_r`, and the same 2 as `JA4X`.** Every unaccepted JA4X key of each run
belongs to the per-stream set. The per-stream vector set publishes JA4X alone, because
`testdata/foxio/reference/python/ja4x.py:87` writes the key `JA4X.{idx+1}` and no raw key.
**So that rule accounts for the 45 and for the 57, and it accounts for neither of the 2.**

**The 2 are `https-connect.pcap/0/JA4X` and `https-connect.pcap/0/JA4X.2`.**
`testdata/foxio/python/https-connect.pcap.json` holds one stream entry, and that entry names
`JA4H` and `JA4H_ro` and no JA4X key at all. **So the reference publishes no JA4X value for
that capture, and the library publishes two.** **That is a disagreement about coverage, and
it is no disagreement about a value.** `## No cause reaches a maintainer ruling` below
states the same reading for `chrome-cloudflare-quic-with-secrets.pcapng`. **Batch #478
measured the 45 and the 2**, and
the sentence this round replaced read `Every one of the 47 unaccepted keys names JA4X_r`.

**The 12 accepted keys hold the 12 JA4X register entries, and each one names
`socks4-https.pcap` under ruling #375.** Six are per-stream and six are per-packet.

**This page opens no question about them**, because an uncovered value is neither a match nor
a deviation, and `conformanceReportTotals` of `conformance_test.go` fails no run for one.
Each of the three causes raises the count, and the three sections above state each rise.

## No cause reaches a maintainer ruling

`.claude/rules/rulings.md` `## Stop conditions` names five conditions. **This page reads all
three causes against them, and no cause meets one.**

| Cause | The FoxIO implementations | The reading |
|---|---|---|
| 1 | Python, Wireshark and Rust each write one value for each certificate, and none holds a cache. | The reference is unanimous. |
| 2 | Python and Rust each read the plaintext that tshark supplies. | The reference is unanimous. |
| 3 | Both vector sets publish the value, and no implementation validates the curve. | The reference is unanimous. |

**So each cause is row 1 of `.claude/rules/parity.md` `## Where a difference comes from`.**
The action is a change to the code, and the register gains nothing. **This page names no
reference split, and it invents no rule.**

**Two facts sit beside the causes, and neither one is a split.**

- **The two FoxIO vector sets disagree on
  `chrome-cloudflare-quic-with-secrets.pcapng`.** The per-stream file holds `JA4X.1` and
  `JA4X.2` for stream `0:57098`, and the per-packet file holds no JA4X key at all. **The
  disagreement is about coverage and not about a value**, so it settles nothing and it
  blocks nothing.
- **The per-stream vector set publishes no JA4X_r key**, which the
  `## The uncovered JA4X values` section above states.

## The sentence this page reported, and the round that repaired it

**The `JA4XFingerprinter` row of the fingerprinter state table in `docs/specs/spec.md` read
`guarded by mu`, and `ja4x.go` holds no such field.** **#458 owns no file of `docs/specs/`,
so this page reported the sentence and repaired nothing.** The sentence states no behavior,
so `CLAUDE.md` sent it to the batch documentation round rather than to a new issue.

**The repair landed in this same batch, and round 45 of the `## Changelog` of
`docs/specs/spec.md` carried it.** The merged row names five fields: `reassembler`,
`processedCerts`, `certsByStream`, `streamBytes` and `lastCleanup`. **The merged row names
no mutex.** `.claude/rules/concurrency.md` bars a mutex in a fingerprinter, and no other row
of that table names one. #486 read the merged row and recorded this repair.

**This page is a reading and it is no audit**, so it reports a sentence where an audit
reports a finding.

## What this reading does not answer

- **The count that each cause closes under a candidate change.** #458 writes no Go file, so no
  candidate change was built and no second conformance run measured one. **Each count above
  reads the run output, the vector files and the certificate bytes**, and the
  `### How this page reads the library output without a candidate change` section states the
  method. **A fix issue re-measures the count it closes with a run.** #489 and #490 each did,
  and `## The merged tree of the Epic #441 batch, 2026-08-14` above states both results.
  **This page wrote the word `yield` on two lines, and the `## Terms` table of
  `docs/specs/spec.md` declines that word in the `Do not use` column of the `emit` row.** The
  Epic #441 documentation round converted both.
- **Whether a fix for cause 2 produces a value outside the corpus.** Two captures of the
  corpus hold a protected certificate frame, and one measurement over 38 captures reports
  that. A capture that no corpus holds reaches no measurement here.
- **The cost of the compressed certificate reader of RFC 8879.** The tshark of this
  measurement reports the compressed message and no certificate inside it, so this page
  reads the expected values of
  `chrome-cloudflare-quic-with-secrets.pcapng` from the vector file alone.
- **Whether the rule of the port that joins two records closes a deviation here.**
  `ja4plus/fingerprinters/ja4x.py:255` joins consecutive handshake records before it reads
  the messages, and `ja4xCertificatesInRecord` of `ja4x.go` reads one record at a time. **No
  deviation of the 50 needs that rule**, and this page measures no capture outside the corpus.
