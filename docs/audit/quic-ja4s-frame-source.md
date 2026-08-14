# The frame that supplies the JA4S value of the second QUIC connection

**This page answers one question of `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`.** That
page states the question in the first bullet of its `## What this reading does not answer`
section. The question names one connection, `0:50280` of
`chrome-cloudflare-quic-with-secrets.pcapng`. It asks which frame supplies the library's JA4S
value for that connection.

**This page changes no behavior, and it moves no fingerprint value.** #496 holds the
measurement, and #441 holds the epic. **This page writes no entry of
`testdata/deviations.json`.** #484 owns the two entries that the answer unblocks, and
`## Answer 5 — the register entry each answer implies` below states what each one holds.

**The measurement reads the corpus at the pinned commit**
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. `testdata/foxio.pin` holds it.

**Every quotation of RFC 9001 comes from <https://www.rfc-editor.org/rfc/rfc9001.html>,
retrieved 2026-08-14.**

## The five answers, in one table

| N | The question | The answer |
|---|---|---|
| 1 | Which frame supplies each part of `q130200_1301_234ea6891581`? | **Frame 49.** It supplies every part. |
| 2 | Why does the decryption of frame 48 and frame 49 fail? | **The key is wrong**, and the failure belongs to `JA4Fingerprinter`. |
| 3 | Does the value derive from a frame of `0:50280`? | **Yes.** Frame 47 and frame 49 alone produce it. |
| 4 | Is the failure a defect of this library or a limit of the capture? | **A defect of this library.** #501 holds the repair. |
| 5 | What register entry does each answer imply? | **Two entries under ruling #42.** #484 writes them. |

## Where each identifier of this page lives

**Every identifier below names code of this library, and this table names the file of each
one.** The prose then names the identifier alone.

| Identifier | File |
|---|---|
| `Processor.ProcessPacket` | `processor.go` |
| `JA4Fingerprinter` | `ja4.go` |
| `JA4SFingerprinter`, `quicDCIDs`, `computeJA4SPair` | `ja4s.go` |
| `ParseQUICServerInitial`, `DecryptQUICInitialCrypto` | `internal/parser/quic.go` |
| `DeriveInitialKeys`, `DeriveServerInitialKeys`, `deriveInitialKeysForRole` | `internal/parser/quic.go` |
| `ParseQUICInitial`, `ClientHelloFromCryptoFragments` | `internal/parser/quic.go` |
| `IsQUIC` | `internal/parser/tls.go` |

**`ParseQUICInitial` and `ClientHelloFromCryptoFragments` each set `IsQUIC` on a
ClientHello**, and answer 3 below reads that fact.

## The connection, and the five frames of the handshake start

**`tshark` supplied the table below, and it supplied no fingerprint value.** The reading of
each fingerprint value comes from the library or from the FoxIO vector.

```
$ tshark -r testdata/foxio/pcap/chrome-cloudflare-quic-with-secrets.pcapng \
    -T fields -e frame.number -e udp.srcport -e udp.dstport \
    -e quic.long.packet_type -e tls.handshake.type
```

| Frame | Sender | QUIC packet type | TLS handshake type |
|---|---|---|---|
| 47 | the client, port `50280` | `0`, an Initial packet | `1`, a ClientHello |
| 48 | the server, port `443` | `0`, an Initial packet | (none) |
| 49 | the server, port `443` | `0`, an Initial packet | `2`, a ServerHello |
| 50 | the server, port `443` | `2`, a Handshake packet | `8`, an EncryptedExtensions |
| 51 | the server, port `443` | `2`, a Handshake packet | `25`, `15`, `20` |

**Frame 49 is the one frame of this connection that carries a ServerHello.** Frames 1 through
46 carry the TCP connection at the client port `57098`, and no frame above 51 carries a
ServerHello. **Frame 56 carries two NewSessionTicket messages**, which the JA4S value reads
never.

## Answer 1 — frame 49 supplies every part of the value

**The library publishes `q130200_1301_234ea6891581` and `q130200_1301_0033,002b` for
`0:50280`.** Every part of both values reads one ServerHello, and frame 49 carries it.

| Part | Value | What frame 49 holds |
|---|---|---|
| The protocol character | `q` | The QUIC long header of the packet. `ParseQUICServerInitial` sets `IsQUIC`, and `computeJA4SPair` reads it. |
| The version | `13` | `tls.handshake.extensions.supported_version` is `0x0304`. |
| The extension count | `02` | `tls.handshake.extension.type` holds `51` and `43`. |
| The ALPN | `00` | The ServerHello names no application protocol. TLS 1.3 carries the ALPN in the EncryptedExtensions of frame 50. |
| The cipher | `1301` | `tls.handshake.ciphersuite` is `0x1301`. |
| The extension list | `0033,002b` | `51` is `0x33`, and `43` is `0x2b`, in the wire order. |
| The extension hash | `234ea6891581` | The truncated hash of `0033,002b`. |

```
$ tshark -r testdata/foxio/pcap/chrome-cloudflare-quic-with-secrets.pcapng \
    -Y "frame.number==49" -T fields -e tls.handshake.type \
    -e tls.handshake.ciphersuite -e tls.handshake.extension.type \
    -e tls.handshake.extensions.supported_version
2	0x1301	51,43	0x0304
```

**Frame 47 supplies no part of the value, and it supplies the key input that unlocks frame
49.** It carries the Destination Connection ID that the client sent first, `203f9e9f68698274`.
`JA4SFingerprinter` in `ja4s.go` holds that value in `quicDCIDs` until the server answers.

A throwaway probe named the frame of each JA4S result of the capture:

```
frame 6: ja4s 2606:4700:10::6816:826:443-2001:db8:1::1:57098 fp="t130200_1301_234ea6891581" raw="t130200_1301_0033,002b"
frame 49: ja4s 2606:4700:10::6816:826:443-2001:db8:1::1:50280 fp="q130200_1301_234ea6891581" raw="q130200_1301_0033,002b"
```

**The capture produces two JA4S results, and one frame supplies each one.**

## Answer 2 — the key is wrong, and the failure belongs to JA4

**The two error lines of the conformance run do not belong to the JA4S fingerprinter.**

```
chrome-cloudflare-quic-with-secrets.pcapng frame 48: cipher: message authentication failed
chrome-cloudflare-quic-with-secrets.pcapng frame 49: cipher: message authentication failed
```

`Processor.ProcessPacket` runs ten fingerprinters and joins their errors, so the line names no
fingerprinter. A throwaway probe ran each fingerprinter on its own:

```
frame 48: ja4 error cipher: message authentication failed
frame 49: ja4 error cipher: message authentication failed
frame 49: ja4s produced ja4s 443-50280 fp="q130200_1301_234ea6891581" raw="q130200_1301_0033,002b"
```

**`JA4SFingerprinter` reports no error on frame 48 and no error on frame 49.**
`JA4Fingerprinter` reports both.

### The two code paths read two keys

| Fingerprinter | The path it takes | The key it derives |
|---|---|---|
| `JA4SFingerprinter` | `ProcessPacket` reads `quicDCIDs`, then `ParseQUICServerInitial` calls `DeriveServerInitialKeys` with the Destination Connection ID that the client sent first. | The key that protects the packet. |
| `JA4Fingerprinter` | `ProcessPacket` calls `DecryptQUICInitialCrypto`, which reads the Destination Connection ID of the packet it holds, then calls `DeriveInitialKeys`. | A key that protects no packet of this connection. |

**A server Initial packet of this connection carries a Destination Connection ID of zero
length.** `tshark` measured the field of the three frames:

```
$ tshark -r testdata/foxio/pcap/chrome-cloudflare-quic-with-secrets.pcapng \
    -Y "frame.number==47 or frame.number==48 or frame.number==49" \
    -T fields -e frame.number -e quic.dcid -e quic.scid -e quic.scil -e quic.dcil
47	203f9e9f68698274		0	8
48		0130dfc5a047e6acd230b5c5e047ced9b0a6bbf0	20	0
49		0130dfc5a047e6acd230b5c5e047ced9b0a6bbf0	20	0
```

The library reads the same lengths:

```
frame 48: first byte cb version 00000001 dcidlen 0 payload 1200 bytes
frame 49: first byte cc version 00000001 dcidlen 0 payload 1200 bytes
```

**So `DecryptQUICInitialCrypto` derives the client role key of a Destination Connection ID of
zero length.** **One Destination Connection ID protects every Initial packet of the
connection**, and the client sent it in frame 47.

RFC 9001 Section 5.2 states which Destination Connection ID the derivation reads:

> The connection ID used with HKDF-Expand-Label is the Destination Connection ID in the Initial packet sent by the client.

It states the two labels in the same section:

> The secret used by clients to construct Initial packets uses the PRK and the label "client in" as input to the HKDF-Expand-Label function from TLS [TLS13] to produce a 32-byte secret. Packets constructed by the server use the same process with the label "server in".

`deriveInitialKeysForRole` writes each label, and `DeriveServerInitialKeys` names the server
role. `DecryptQUICInitialCrypto` calls `DeriveInitialKeys`, which names the client role.

A probe measured the three keys:

```
frame 49: DecryptQUICInitialCrypto frags=0 dcid= err=cipher: message authentication failed
client role, empty connection id: key 77946e94d6f58bf7e8140b50b1ad28d2 err <nil>
client role, client connection id: key 0f0fc413510225606e27a4286b918bbb err <nil>
server role, client connection id: key 2b7586786245af4480862013e1fa8d15 err <nil>
```

**The error names a cipher, a key or a nonce, and it is the key.** The cipher is AES-128-GCM
on both paths, because each path derives a 16-byte key and reads it through `aes.NewCipher`
and `cipher.NewGCM`. RFC 9001 Section 5.3 names `AEAD_AES_128_GCM` for an Initial packet. The
nonce derives from the same wrong secret as the key, so one fault produces both. **The `message authentication failed` text is the report of the Go
standard library**, and `aead.Open` in `DecryptQUICInitialCrypto` returns it.

**Frame 48 carries an ACK frame and no CRYPTO frame**, so `ParseQUICServerInitial` reads it,
finds no fragment and declines it without an error:

```
frame 48: ParseQUICServerInitial sh=false err=<nil>
frame 49: ParseQUICServerInitial sh=true err=<nil>
```

## Answer 3 — the value derives from frame 49 of `0:50280`

**The two values of `0:57098` and `0:50280` share the cipher `1301` and the extension hash
`234ea6891581`, and neither value reads the other connection.** A probe fed frame 47 and
frame 49 to a new `JA4SFingerprinter` that read no frame of the TCP connection:

```
frame 47: err <nil>
frame 49: err <nil>
frame 49: 443-50280 fp="q130200_1301_234ea6891581" raw="q130200_1301_0033,002b"
```

**Three facts separate the two connections.**

1. **A fingerprinter that never read frame 6 produces the whole value**, from frame 47 and
   frame 49 alone.
2. **The protocol character differs**, and one function writes it. `computeJA4SPair` writes
   `q` for `IsQUIC`, and `ParseQUICServerInitial` is the one function that sets `IsQUIC` on a
   ServerHello. `ParseQUICInitial` and `ClientHelloFromCryptoFragments` set the field of a
   ClientHello, and no JA4S value reads one. A value that read the TCP ServerHello of frame 6
   would carry `t`.
3. **The shared parts are the common parts of a TLS 1.3 ServerHello.** Cipher `0x1301` is
   `TLS_AES_128_GCM_SHA256`, and extensions `0033` and `002b` are the key share and the
   supported versions. `testdata/deviations.json` already holds
   `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4S` with the value
   `q130200_1301_234ea6891581`, on another capture and another server.

**So the shared value is a property of TLS 1.3, and never a leak between the two
connections.**

## Answer 4 — the failure is a defect of this library

**The capture supplies everything the library needs.** The Initial keys of a QUIC connection
derive from the client's Destination Connection ID. So the JA4S value of `0:50280` needs no
decryption secret. The probe of answer 3 proves it: two frames of the capture produce
the whole value.

**The defect is the derivation of `DecryptQUICInitialCrypto`, and #501 holds the repair.**
That issue states the measurement and the two candidate answers. **It moves no fingerprint
value**, because `JA4Fingerprinter` already produces the JA4 value of this connection from
frame 47 and the error reaches no result.

**The cost of the defect is a false reading, and not a wrong value.** A reader who pairs the
two error lines with the JA4S value of the same connection concludes that the JA4S
decryption fails. It does not.

## Answer 5 — the register entry each answer implies

**Answer 3 makes both entries a decline of the reference, and neither one a defect.** The
library reads the QUIC handshake of `0:50280`, and the FoxIO Python implementation does not.
The per-stream vector holds `JA4L-S` and `JA4L-C` for the connection, and it holds no
TLS-derived key.

**Ruling #42 already states that reason for 248 entries of the register.** The two entries
below carry it without a change.

```json
{
  "key": "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S",
  "capability": false,
  "ours": "q130200_1301_234ea6891581",
  "theirs": "",
  "ruling": "#42",
  "reason": "The FoxIO Python implementation reads no QUIC handshake, so its expected-output file omits the stream."
}
```

```json
{
  "key": "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S_r",
  "capability": false,
  "ours": "q130200_1301_0033,002b",
  "theirs": "",
  "ruling": "#42",
  "reason": "The FoxIO Python implementation reads no QUIC handshake, so its expected-output file omits the stream."
}
```

**This page writes neither entry.** **No member of the Epic #441 batch wrote either one**, so the
merged tree reports both comparisons as deviations. **#484 keeps the two entries, and it does not close
with this batch.**

**`docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`
`## Cause 7 — the library reads the second QUIC connection, and the Python reference publishes no value for it`
named #467 as the owner of `testdata/deviations.json`, and #467 is a member of batch #478.** **The batch
documentation round of the Epic #441 batch repaired that citation**, so the sentence above describes the
page as it read before that repair.

**No parity difference opens.** The port holds the same behavior:
`ja4plus/fingerprinters/ja4s.py:82-87` reads a QUIC Initial packet.
`ja4plus/fingerprinters/ja4s.py:147` reads the client's Destination Connection ID from the
connection, and `ja4plus/fingerprinters/ja4s.py:150` calls
`decrypt_quic_server_initial_crypto(udp_payload, client_dcid)` with it.
`ja4plus/fingerprinters/ja4s.py:154-157` collects the CRYPTO fragments until the ServerHello
is complete. The reading is of the port at the tag `v1.1.0`.

**The key form of the two entries differs from the key form of the 248.** A ruling #42 key
reads `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4S`, and each key above
reads the stream name that the FoxIO per-stream vector gives the connection. The conformance
report writes the stream name where the vector names one, and the difference names no second
question.

## What this page does not answer

- **The four JA4 keys of `0:50280`.** They are `JA4`, `JA4_r`, `JA4_o` and `JA4_ro`. **Epic
  #441 owns them**, and this page reads none of them.
- **Which of the two candidate answers of #501 the library takes.** Each one changes the
  error that one exported method returns, and #501 holds the choice.
- **Whether any other capture of the corpus reports the same error line.** This page read the
  error lines of one capture.

## One sentence this measurement falsifies

**The body of #496 states that the library produces a value while its own decryption of the
only ServerHello frame fails.** Answer 2 falsifies it. The decryption of frame 49 succeeds on
the JA4S path, and it fails on the JA4 path. **`docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`
states no such sentence**, and it pairs the two facts without a claim about the cause.

## The counts before the change and after it

**No count moves, because no line of Go changes.**

| Measure | Before | After |
|---|---|---|
| Matches | 1716 | 1716 |
| Deviations | 331 | 331 |
| Accepted deviations | 558 | 558 |
| Register keys | 578 | 578 |

**Each pair of counts is equal**, and the `make conformance` run of
`issue/496-quic-ja4s-frame-source` produced the right column.

## Every probe this measurement built

**Each probe below is a throwaway, and no commit holds one.** `probe496_test.go` held them,
and the measurement deleted that file before it opened the pull request.

| Probe | What it measured |
|---|---|
| The frame probe | The frame of every JA4S result of the capture. |
| The fingerprinter probe | The fingerprinter that reports each error line. |
| The frame reader | The header fields of frame 48 and frame 49, and the result of `ParseQUICServerInitial` on each one. |
| The key probe | The three Initial keys, and the error of `DecryptQUICInitialCrypto` on frame 49. |
| The isolation probe | The value that frame 47 and frame 49 alone produce. |
