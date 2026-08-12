# Changelog

This file records every notable change to this project.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Every measurement in this section names the base of the run that produced it. Issue #42 put 150
entries into `testdata/deviations.json`, and the register held no entry before that. A run
on the current tree reports 1035 matches, 1348 deviations, 150 accepted deviations and 150
register keys. A count that an entry below states therefore differs from a fresh run.

### Added

- Four exported names, which emit the JA4SSH window that a connection holds open at the end
  of the packet source: the `WindowCloser` interface, `JA4SSHFingerprinter.CloseOpenWindows`,
  `Processor.CloseOpenWindows` and `SyncProcessor.CloseOpenWindows`. The maintainer ruled on
  2026-08-11 that the method sits on a second optional interface, so the exported
  `Fingerprinter` interface does not change and no third-party implementation breaks. A
  caller discovers the interface with a type assertion, and a stateless fingerprinter
  implements nothing. `cmd/ja4plus analyze` calls the method when the capture ends.
  `docs/specs/features/08-python-parity.md` FR-parity-29 through FR-parity-33 state the
  requirements, and the port's issues #105, #199 and #214 hold the ruling.
- Eight exported names, which read a pcapng Decryption Secrets Block and decrypt one QUIC
  packet with a TLS secret: `ErrNoSecret`, `KeyLog`, `ParseKeyLog`,
  `ReadKeyLogFromCapture`, `KeyLog.Secret`, `KeyLog.ClientRandoms`, `KeyLog.Len` and
  `DecryptQUICPacket`. The maintainer accepted the eight names on 2026-08-11, before the
  `v1.0.0` freeze. `docs/specs/features/05-conformance-gaps.md` FR-gaps-15 through
  FR-gaps-18 state the requirements, and the `Interface` register row of
  `docs/specs/spec.md` records that the port adopts these names under parity rule 2. The
  change moves no fingerprint.
- The `corpus`, `conformance`, `cover` and `fuzz` make targets.
- The FoxIO corpus pin in `testdata/foxio.pin`, and `scripts/fetch-corpus.sh`, which
  fetches the corpus at that commit. The corpus is FoxIO-licensed material, so the
  repository holds no fetched file.
- A benchmark for the processor, and one benchmark for each method.
- `data/README.md`, which names FoxIO as the source of `data/ja4plus-mapping.csv` and
  states that FoxIO License 1.1 covers that file.
- `docs/audit/license-decision.md`, which transcribes the maintainer's license decision
  and the date of each part of it.

### Fixed

- The JA4SSH window now emits at the packet count the caller names, and the threshold holds
  no upper cap. `ja4ssh.go:196-199` capped it at 10, so the library over-emitted by hundreds
  of values on one capture. The window also counts the SSH packets of the two directions
  alone, so a bare ACK no longer advances it and a window of bare ACKs produces no value.
  The HASSH trigger goes too: `ja4ssh.go:201` emitted when the two HASSH values were present
  and the window held one packet, and the port holds no such rule. `docs/specs/spec.md`
  `## Parity with ja4plus` holds the four JA4SSH rows, FR-parity-25 through FR-parity-28
  state the requirements, and the port's issues #28, #96 and #97 hold the rulings. Measured
  against `epic/48-parity-tls-latency` at `ec0f63e` with the corpus present: 1807 JA4SSH
  comparisons moved, on `gre-sample.pcap`, `ssh-r.pcap`, `ssh-scp-1050.pcap`, `ssh.pcapng`,
  `ssh2.pcapng`, `sshv1.pcap` and `v6.pcap`. The run reports 1035 matches before and after,
  3155 deviations before and 1348 after, and 150 register keys before and after. Every moved
  comparison was an extra value that the vector does not hold.
- `CleanupConnection` on JA4L now removes a tunneled connection. The method normalized the
  address pair the caller gave, and it deleted that one key. `normalizeKey` builds the
  grouping key from the inner address pair, and a `FingerprintResult` reports the outer
  pair, so the two keys never met. A caller that named the reported pair removed no
  tunneled connection, and `connections` grew without a bound. `JA4LFingerprinter` now
  holds `groupingKeys`, which reads the grouping key from the reported key. The method
  removes the connection and every index entry of it, so a caller that names either key
  leaves no state behind. `ja4plus/fingerprinters/ja4l.py:100-104` holds the same map, and
  `ja4plus/fingerprinters/ja4l.py:216` holds the same cleanup rule. Every FoxIO reference
  and the port agree, so this is a reading and not a ruling.
  `docs/specs/features/05-conformance-gaps.md` FR-gaps-14c states the rule, and issue #169
  holds the reading. JA4 and JA4S read no such index, so they remove no tunneled
  connection, and issue #193 owns that repair. The change moves no fingerprint.
- The QUIC CRYPTO stream reassembly. `ParseCryptoFrames` stepped over a PADDING frame
  alone, so a PING frame in front of the CRYPTO frames hid the whole client hello. RFC 9000
  Section 19.2 gives the PING frame no field. The library now produces a JA4 value on every
  QUIC capture of the corpus that carries a client hello. Issue #42 holds the measurement.

### Changed

- **JA4L now fills the TCP client measurement point from the packet that the Python
  reference names, and the client value of a TCP connection moves.** This is a breaking
  behaviour change under `v1.0.0`, and **the maintainer has not ruled on it.** Point `C`
  reads every packet that carries `ACK`, carries no `SYN`, and holds the relative sequence
  number `1` and the relative acknowledgement number `1`. A later such packet replaces the
  point. A packet that carries a whole HTTP request moves no point, because the reference
  keeps such a packet under a separate cache. Earlier releases read the first packet that
  carried `ACK` and no `SYN`, they tested no sequence number, and the point never moved.
  **The four FoxIO implementations disagree here, so this is a ruling and not a reading.**
  `docs/specs/foxio/JA4L.md` R33 states the four rules, and R34 states that the two FoxIO
  vector sets hold two different values for stream 0 of `badcurveball.pcap`. Python states
  the rule that this change implements, at `python/ja4.py:570`. Wireshark, Rust and Zeek
  each fill the point once and never move it. Issue #196 holds the question, and the branch
  must not merge before the maintainer rules. The conformance run reports 703 matches, 1402
  deviations and 150 accepted deviations in the per-stream set before the change, and 701
  matches, 1449 deviations and 150 accepted deviations after it. The per-packet set reports
  332 matches and 1753 deviations before the change, and 332 matches and 1788 deviations
  after it. The register key count stays at 150. The last JA4L-C value of a stream moves on
  43 comparisons across 22 captures, and it then reaches the per-stream vector value on 53
  of the 54 comparisons that the set holds. `gre-erspan-vxlan.pcap` stream 0 reaches no
  value, which issue #199 covers. **The recorded deviation count rises, because the
  per-stream harness numbers a second emission as the occurrence `JA4L-C.2` and it compares
  the first emission against the vector.** The run measured the change on
  `epic/48-parity-tls-latency` at `ec0f63e`.
- **JA4L and JA4LS now report half of the measured time, and every latency value moves.**
  This is a breaking behaviour change under `v1.0.0`. The `JA4L.png` image labels part a
  `One-way TCP latency in µs (1ms = 1,000µs)`. `docs/specs/foxio/JA4L.md` R6 states that
  part a is half of the measured time, because one measurement covers a round trip.
  Earlier releases reported the whole time between the two measurement points. Every value
  was therefore exactly twice the FoxIO vector, and JA4L matched on no capture. R6 cites
  four FoxIO reference implementations that each divide by 2. The two integer references
  truncate the half toward zero, and Go integer division truncates the same way. Every
  FoxIO reference agrees, so this is a reading and not a ruling. The conformance run
  reports 943 matches and 3247 deviations before the change. It reports 1011 matches and
  3179 deviations after it. The register key count stays at 0. On the per-stream vector
  set, JA4LS falls from 59 deviations to 3, and JA4L falls from 56 deviations to 44.
  Twenty-four captures move, and JA4LS now matches on every stream of twenty-one of them.
  The per-packet counts stay at 308 matches and 1777 deviations. A per-packet JA4L vector
  carries a third part that the library does not yet produce. Issue #166 holds the
  measurement, and the run measured the change on `batch/184-ja4l-repairs` at `f4aa6e6`.
- **JA4L now fills the two QUIC client measurement points in the reference direction, and
  the client value of a QUIC connection moves.** This is a breaking behaviour change under
  `v1.0.0`. A server Handshake packet fills point C, and a client Handshake packet fills
  point D and completes the value. Every server Handshake packet moves point C until point
  D fills, so the last one supplies the point. A long-header packet of another type fills
  neither point. Earlier releases read point C from a client packet and point D from a
  server packet, and they read every long-header type, so the library reported the client
  value on a server packet and reported no value at all on three connections of
  `tls3.pcapng`. `ja4plus/fingerprinters/ja4l.py:580-599` states both rules, and every
  FoxIO reference agrees, so this is a reading and not a ruling. The conformance run
  reports 3251 deviations before the change and 3247 after it, the match count stays at
  943, and the register key count stays at 0. Three captures move:
  `chrome-cloudflare-quic-with-secrets.pcapng`, `ssh2.pcapng` and `tls3.pcapng`. On the
  per-packet vector set, seven JA4L client values reach the packet the vector names, and
  four values that sat on a server packet go away. On the per-stream vector set,
  `tls3.pcapng` streams 22, 23 and 24 produce a JA4L-C value again, and each one is twice
  the vector value, which #166 halves. Issue #186 holds the measurement, and the run
  measured the change on `batch/184-ja4l-repairs` at `4d46f47`.
- **JA4L and JA4LS now read a UDP flow only when the flow carries QUIC, and the library
  produces no value for another UDP flow.** This is a breaking behaviour change under
  `v1.0.0`. The library reads the UDP payload for a QUIC long header, and it reads the
  direction of the flow from the UDP port 443 alone. A flow whose two ports are 443 names
  no server, so the library produces no value for it. Earlier releases timed every UDP
  flow, and they read the direction from the address that sent the first packet. An NTP
  flow therefore produced a JA4L value that the reference does not produce.
  `ja4plus/fingerprinters/ja4l.py:554-566` states the rule, and every FoxIO reference
  agrees, so this is a reading and not a ruling. The library stops producing 193 values
  across six captures of the FoxIO corpus: `gre-sample.pcap`, `latest.pcapng`,
  `ssh2.pcapng`, `sshv1.pcap`, `tls3.pcapng` and `v6.pcap`. The conformance run reports
  3441 deviations before the change and 3251 after it, and the register key count stays
  at 0. Issue #173 holds the measurement, and the run measured the change on
  `batch/184-ja4l-repairs` at `c1f13d5`.
- **A tunneled connection now carries two keys, and the fingerprint of such a connection
  moves.** This is a breaking behaviour change under `v1.0.0`. A `FingerprintResult` for a
  GRE, ERSPAN, VXLAN or Geneve packet holds the outer address pair with the inner port
  pair, and the first packet of the connection fixes that pairing. The library collects
  packets into one connection by the inner address pair and the inner port pair, and
  `GetShardKey` returns that grouping pair. A JA4L value and a JA4LS value read the
  time-to-live of the outer address layer. Earlier releases read the outer address pair
  for both keys and read the tunnel transport layer for the port pair, so a mirrored
  capture merged both directions of one session into one connection and a VXLAN packet
  reported the tunnel port 4789. The three tunneled captures of the FoxIO corpus move:
  `gre-sample.pcap`, `gre-erspan-vxlan.pcap` and `tcpdump-geneve.pcap`. The maintainer
  ruled this on 2026-08-11, and `docs/specs/spec.md` `## Changelog` row 12 records it.
- **The JA4 and JA4S QUIC branches now read the inner UDP layer of a tunneled packet.**
  The first tunnel repair reached the paths that call the parser helper. These two branches
  read the outer UDP layer directly. They reported the tunnel port, and they grouped a
  tunneled connection by the outer address pair. #170 routes both branches through the
  helper. No capture of the FoxIO corpus carries QUIC inside a tunnel, so no value moves
  and `quic_tunnel_test.go` holds the behaviour.
- The parser reads no fingerprint from a packet that nests more than four tunnel layers,
  and it returns a non-fatal error that names the limit. It returns the same result for a
  tunnel whose inner packet it does not read, such as a GRE header that names an unknown
  protocol type or a truncated inner frame. No released value moves, because no capture of
  the FoxIO corpus nests more than three tunnel layers.
- **A changed fingerprint.** The library produces the JA4 value
  `q13d0310h3_55b375c5d22e_cd85d2d88918` on `quic-with-several-tls-frames.pcapng` and on
  `quic-tls-handshake.pcapng`, and it produced none before. The FoxIO Rust implementation
  produces the same value on both captures. On
  `chrome-cloudflare-quic-with-secrets.pcapng` stream 0 the JA4 value moves from
  `q12i030000_55b375c5d22e_000000000000` to `q13d0310h3_55b375c5d22e_cd85d2d88918`, and the
  raw form moves from `q12i030000_1301,1302,1303_` to
  `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201`.
  The earlier value read a part of the client hello, so it named three cipher suites and no
  extension. A released version produced it, so this is a breaking behaviour change under
  `v1.0.0`. Issue #42 holds the measurement.
- `ClientHelloFromCryptoFragments` returns no client hello while a fragment of the
  handshake message is still missing. It parsed a part of the message before, which
  produced a fingerprint of a cipher list that the client never sent.
- The QUIC fragment buffer of one connection reaches 16384 bytes. The JA4 fingerprinter
  drops the connection state when a sender passes the bound, because an unbounded buffer is
  a memory-exhaustion path. `parser.MaxCryptoBufferBytes` holds the bound, and the port
  holds the same value.
- The license correction. The repository states two licenses, and it names which material
  each one covers. The original Go code carries the BSD 3-Clause license.
  FoxIO License 1.1 covers nine of the methods that this project implements, and that
  license permits non-commercial use only. `NOTICE` names those nine methods, and it holds
  the FoxIO terms. Earlier releases named the BSD 3-Clause license alone, so a commercial
  user read a permission that FoxIO does not grant. `docs/audit/license-decision.md`
  records the decision behind the correction.
- The module needs Go 1.24 or later. It needed Go 1.22 before this change, so a consumer
  on Go 1.22 or Go 1.23 must move to Go 1.24.

## [v0.3.0] - 2026-04-08

### Added

- The JA4D fingerprinter, which reads a DHCP message.
- `CleanupConnection` on the `Fingerprinter` interface. A caller removes the state of one
  connection, so a long-running monitor holds no dead entry.
- `GetShardKey` on the processor. It returns one key for both directions of a connection,
  so a sharded caller routes both directions to one processor.

### Changed

- `FingerprintResult.Type` holds a lower-case method name for every method. JA4, JA4S and
  JA4X held an upper-case value before this release.

## [v0.2.0] - 2026-04-08

### Added

- IPv6 support in every method that reads an IP header.
- QUIC detection in JA4S.
- HASSH extraction from an SSH KEXINIT message, for the client and for the server.
- TCP stream reassembly in JA4H, so an HTTP request that spans two segments produces a
  fingerprint.
- UDP and QUIC timing in JA4L, plus the distance estimate and the operating-system
  estimate.
- The `JA4_ro` raw form, which holds the original wire order.
- `InterpretJA4SSH`, which names the session type of a JA4SSH value.
- CRYPTO frame accumulation in the QUIC parser, so a ClientHello that spans two Initial
  packets produces a fingerprint. The release exports `CryptoFragment`,
  `DecryptQUICInitialCrypto` and `ClientHelloFromCryptoFragments`.

### Fixed

- JA4S hashes the extension list in wire order. It sorted the list before this release.
- JA4SSH breaks a tie in the packet-size mode on the value it reads first.
- JA4SSH produces a fingerprint on each packet after it reads both HASSH values.

## [v0.1.0] - 2026-04-06

### Added

- Package `ja4plus`, which holds the `Fingerprinter` interface and one fingerprinter per
  method.
- The JA4 fingerprinter, for a TLS ClientHello over TCP or over QUIC.
- The JA4S fingerprinter, for a TLS ServerHello.
- The JA4H fingerprinter, for an HTTP request.
- The JA4X fingerprinter, for an X.509 certificate.
- The JA4SSH fingerprinter, which produces one fingerprint for each window of SSH
  packets.
- The JA4T fingerprinter and the JA4TS fingerprinter, for a TCP SYN and for a TCP
  SYN-ACK.
- The JA4L fingerprinter, which measures the latency of a connection.
- The processor, which runs every fingerprinter over one packet.
- The fingerprint lookup, which reads the embedded FoxIO database.
- The `ja4plus` command-line program.
- Package `internal/parser`, which decodes TLS, QUIC, HTTP, SSH and X.509. It also
  detects a GREASE value and computes a truncated SHA-256 hash.
- The CI workflow and the release workflow.
- The README, which documents the interface, the command-line program and the format of
  each fingerprint.

[Unreleased]: https://github.com/Crank-Git/ja4plus-go/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/Crank-Git/ja4plus-go/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/Crank-Git/ja4plus-go/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Crank-Git/ja4plus-go/releases/tag/v0.1.0
