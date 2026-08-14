---
id: conformance-gaps
feature: Conformance gap closure
epic: "Epic 5: Conformance gap closure"
status: issued
issues: [37, 38, 39, 40, 41, 42]
mockups: []
---

## Purpose

Epic 4 produces a deviation list. This feature set closes it.

The maintainer set the bar at a byte-identical match for every capture in the corpus,
with no exception. That bar decides the scope. A deviation is not excluded because it is
hard. A deviation is closed, or a named requirement records why it cannot be closed and
the maintainer accepts that record before Epic 10 releases.

Three gaps are visible before the harness runs. The corpus holds three encapsulated
captures that `tshark` decapsulates. The corpus holds one capture whose TLS secrets sit
in pcapng Decryption Secrets Blocks. The corpus holds one capture that FoxIO marks
`notest`. Each has its own requirement below.

The rest of the work is unknown until Epic 4 finishes. This feature set is sized after
the deviation list exists, not before.

## User stories

- As a library author, I want the library to produce the same fingerprint as every other
  JA4+ tool, so that a fingerprint I store is comparable with one from Wireshark or Zeek.
- As an analyst, I want a fingerprint from an encapsulated capture, so that a tunnel does
  not hide the traffic I am examining.
- As a maintainer, I want every unclosed deviation to carry a written reason, so that the
  release states the truth about coverage.

## Functional requirements

### The general rule

- **FR-gaps-1** — Each deviation in `docs/audit/conformance.md` produces one requirement
  in this file, or one closure.
- **FR-gaps-2** — Each closure adds a test that names the capture and the method.
- **FR-gaps-3** — Each closure that changes a fingerprint records the change in
  `CHANGELOG.md`.
- **FR-gaps-4** — The FoxIO reference decides every disputed result. A library test that
  disagrees with the reference is wrong.
- **FR-gaps-5** — A deviation that cannot be closed records the reason, the evidence and
  the maintainer's acceptance in `docs/audit/conformance-exclusions.md`.
- **FR-gaps-6** — `docs/audit/conformance-exclusions.md` holds no entry that the
  maintainer has not accepted by name and by date.

### Tunnel decapsulation

- **FR-gaps-7** — The parser decapsulates a GRE packet and fingerprints the inner packet.
- **FR-gaps-8** — The parser decapsulates an ERSPAN packet and fingerprints the inner
  packet.
- **FR-gaps-9** — The parser decapsulates a VXLAN packet and fingerprints the inner
  packet.
- **FR-gaps-10** — The parser decapsulates a Geneve packet and fingerprints the inner
  packet.
- **FR-gaps-11** — The parser decapsulates a nested encapsulation up to a depth of four
  layers.
- **FR-gaps-12** — The parser stops at a depth of four and returns no fingerprint beyond
  it.
- **FR-gaps-13** — `GetShardKey` returns the grouping key for an encapsulated packet, so
  it reads the inner address pair and the inner port pair.
- **FR-gaps-14** — A `FingerprintResult` for an encapsulated packet holds the reported
  key, so it holds the outer address pair and the inner port pair.
- **FR-gaps-14a** — The first packet of one connection fixes the reported key, and a later
  packet does not move it.
- **FR-gaps-14b** — A JA4L value and a JA4LS value read the time-to-live of the outer
  address layer.
- **FR-gaps-14c** — `CleanupConnection` reads the reported key, so a caller removes a
  connection with the address pair that a `FingerprintResult` carries.
- **FR-gaps-14d** — `JA4Fingerprinter` and `JA4SFingerprinter` each hold an index that pairs
  the reported key with the grouping key, so `CleanupConnection` removes a tunneled
  connection.
- **FR-gaps-14e** — `CleanupConnection` falls back to the key the caller gave, so a caller
  that names the grouping key removes the connection.

### QUIC decryption secrets

- **FR-gaps-15** — The capture reader reads a pcapng Decryption Secrets Block.
- **FR-gaps-16** — The library decrypts a QUIC packet with a secret that a Decryption
  Secrets Block supplies.
- **FR-gaps-17** — The library exports a way for a caller to supply a TLS key log, so
  that a caller who reads a capture through another reader can pass secrets.
- **FR-gaps-18** — The library produces no fingerprint from a secret when the caller
  supplies none, and returns a non-fatal error instead.

### The `notest` capture

- **FR-gaps-19** — The suite records `dtls-udp.notest.cap` as `not applicable` and names
  the FoxIO `notest` marker as the reason.
- **FR-gaps-20** — `docs/audit/conformance-exclusions.md` records that FoxIO excludes
  this capture from their own suite.

### QUIC reassembly

- **FR-gaps-21** — The library reassembles a TLS client hello that spans more than one
  QUIC CRYPTO frame.
- **FR-gaps-22** — The library reassembles a TLS client hello that spans more than one
  QUIC Initial packet.
- **FR-gaps-23** — The library bounds the accumulated fragment buffer for one QUIC
  connection, and drops the connection when the bound is exceeded.
- **FR-gaps-30** — `ReassembleCryptoFrames` drops a CRYPTO fragment that reaches past
  `MaxCryptoBufferBytes`, so every reassembly path holds one bound. FR-gaps-23 names the
  accumulated buffer of one connection, and `ParseQUICInitial` and
  `ParseQUICServerInitial` each reassemble the fragments of one datagram without that
  accumulation. Issue #168 measured an amplification of about 10000 to 1 on the second
  path.

### The hashed wire-order form

The FoxIO per-stream vector set holds a `JA4_o` value on 160 entries.
`testdata/foxio/reference/python/ja4.py:291` builds the value, and it hashes each list of
the wire-order raw form.

- **FR-gaps-24** — `FingerprintResult` holds the exported field `OriginalOrder`, which
  carries the FoxIO `JA4_o` value.
- **FR-gaps-25** — `JA4Fingerprinter` fills `OriginalOrder` with the part a of `JA4`, a
  hash of the wire-order cipher list and a hash of the wire-order extension list.
- **FR-gaps-26** — Every fingerprinter other than `JA4Fingerprinter` leaves
  `OriginalOrder` empty, because neither FoxIO vector set publishes a second `_o` key. The
  per-stream set publishes `JA4_o` alone, and the per-packet set publishes no `_o` key.
  Issue #290 scoped this requirement to the two vector sets.

### The role of a QUIC Initial packet

`DecryptQUICInitialCrypto` derives the client keys of the Destination Connection ID that the
packet holds. The server derives its own keys from the Destination Connection ID that the
client sent, and RFC 9001 Section 5.2 states that derivation input. So the derived key
authenticates no server Initial packet. **Issue #501 chose the decline, and it is the
reversal path.**

- **FR-gaps-27** — `DecryptQUICInitialCrypto` returns no error for a packet that the derived
  key does not authenticate.
- **FR-gaps-28** — `DecryptQUICInitialCrypto` returns an error for a malformed packet. A
  payload shorter than the authentication tag and a truncated CRYPTO frame each reach one.
- **FR-gaps-29** — The decline of FR-gaps-27 covers a corrupted client Initial packet.
  `crypto/cipher` reports one error value for every authentication failure, so the library
  separates a wrong role from a corrupted packet at no point.

## User flows

### An engineer closes a deviation

1. Read the deviation row in `docs/audit/conformance.md`.
2. Read the FoxIO reference behavior for that method and that capture.
3. Write a test that reads the capture and asserts the FoxIO value. The test fails.
4. Change the parser or the fingerprinter.
5. The test passes.
6. Run `make conformance`. The deviation count falls by one and no new deviation appears.

### An engineer records an exclusion

1. Read the deviation row.
2. Establish that the closure is not possible, and record the evidence.
3. Add an entry to `docs/audit/conformance-exclusions.md` with the reason and the
   evidence.
4. Ask the maintainer to accept the entry.
5. The maintainer records their name and the date in the entry.

## Screens & states

The project has no user interface. This section does not apply. The conformance report
that `features/04-conformance-harness.md` defines is the only reader-facing output.

## Behaviour rules

- A closure changes the library to match FoxIO. A closure never changes the vector.
- A closure that makes one capture match must not break another. Every closure runs the
  whole suite.
- Decapsulation applies to every method. A JA4T fingerprint from an inner SYN packet is
  as valid as one from an outer SYN packet.
- The depth limit exists because a crafted packet can nest encapsulation without a bound.
  The limit is a security control, not a convenience.
- A secret from a Decryption Secrets Block applies only to the capture that carries it.
  The library holds no secret between captures.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `internal/parser/packet.go` | Gains the decapsulation loop and the depth limit. |
| `internal/parser/tunnel.go` | New. Holds the GRE, ERSPAN, VXLAN and Geneve decoders. |
| `internal/parser/quic.go` | Gains multi-packet reassembly and the fragment bound. |
| `internal/parser/secrets.go` | New. Holds the key-log reader. |
| `capture.go` | New or changed. Reads a Decryption Secrets Block. |
| `docs/audit/conformance-exclusions.md` | New. |
| `types.go` | Gains the `OriginalOrder` field of `FingerprintResult`. |
| `ja4.go` | Gains the builder of the `JA4_o` value. |
| `CHANGELOG.md` | One entry for each changed fingerprint. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `gopacket` layer decoders | v1.1.19 | <https://pkg.go.dev/github.com/google/gopacket/layers> |
| `gopacket/pcapgo` reader | v1.1.19 | <https://pkg.go.dev/github.com/google/gopacket/pcapgo> |
| pcapng Decryption Secrets Block | Draft, block type `0x0000000A` | <https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html#name-decryption-secrets-block> |
| GRE | RFC 2784 | <https://www.rfc-editor.org/rfc/rfc2784> |
| VXLAN | RFC 7348 | <https://www.rfc-editor.org/rfc/rfc7348> |
| Geneve | RFC 8926 | <https://www.rfc-editor.org/rfc/rfc8926> |
| ERSPAN Type II and III | Cisco specification | <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03> |
| QUIC | RFC 9000, RFC 9001 | <https://www.rfc-editor.org/rfc/rfc9001> |

`gopacket` provides `layers.GRE`, `layers.VXLAN` and `layers.Geneve`. The engineer
confirms each decoder against the package documentation before use. `gopacket/pcapgo`
does not expose a Decryption Secrets Block at v1.1.19, so FR-gaps-15 either extends the
reader or reads the block directly.

## Edge cases & failures

| Case | What happens |
|---|---|
| An encapsulated packet nests five layers. | The parser stops at four and returns a non-fatal error that names the limit. |
| A GRE packet carries an unknown protocol type. | The parser returns a non-fatal error and produces no fingerprint. |
| A VXLAN packet has a truncated inner frame. | The parser returns a non-fatal error and produces no fingerprint. It does not panic. |
| A Decryption Secrets Block holds a secret for a connection that the capture does not carry. | The library ignores the secret. |
| A QUIC connection sends fragments that never complete a client hello. | The fragment buffer reaches its bound and the library drops the connection state. |
| `gopacket` at v1.1.19 cannot decode a tunnel that the corpus holds. | Epic 7 decides whether the maintained fork solves it. Risk R5 in `../spec.md` records this. |
| Closing a deviation changes a fingerprint that a released version produced. | `CHANGELOG.md` records it as a breaking behavior change under `v1.0.0`. |
| A QUIC connection sends a server Initial packet. | `DecryptQUICInitialCrypto` declines the packet, and it returns no error. |
| The Length field of a QUIC Initial packet leaves fewer bytes than the authentication tag. | `DecryptQUICInitialCrypto` returns a non-fatal error that names the tag. |

## Acceptance criteria

- [ ] `make conformance` reports zero deviations.
- [ ] `docs/audit/conformance.md` records `match` for `gre-sample.pcap`.
- [ ] `docs/audit/conformance.md` records `match` for `gre-erspan-vxlan.pcap`.
- [ ] `docs/audit/conformance.md` records `match` for `tcpdump-geneve.pcap`.
- [ ] `docs/audit/conformance.md` records `match` for
      `chrome-cloudflare-quic-with-secrets.pcapng`, or
      `docs/audit/conformance-exclusions.md` records an accepted exclusion for it.
- [ ] `docs/audit/conformance.md` records `match` for
      `quic-with-several-tls-frames.pcapng`.
- [ ] `docs/audit/conformance.md` records `not applicable` for `dtls-udp.notest.cap`, and
      names the `notest` marker.
- [ ] A test packet with five nested encapsulation layers produces a non-fatal error and
      no panic.
- [ ] Every entry in `docs/audit/conformance-exclusions.md` holds the maintainer's name
      and a date.
- [ ] `go test -race ./...` passes.
- [ ] `CHANGELOG.md` records every changed fingerprint.

## Out of scope

- This feature set does not add a method that FoxIO defines and this library does not
  implement. The non-goals in `../spec.md` record which.
- This feature set does not add live capture.
- This feature set does not change the API, except where FR-gaps-17 adds the key-log
  entry point.

## Open questions

- **Q1** — Can `gopacket` v1.1.19 read a pcapng Decryption Secrets Block, or must the
  project read the block itself? The engineer answers this before FR-gaps-15 starts, and
  records the answer in the issue.
- **Q2** — Does the deviation list hold a gap that no requirement above covers? Epic 4
  answers this. Each such gap becomes a new requirement in this file before Epic 5 starts.
