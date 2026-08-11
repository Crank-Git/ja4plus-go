# Changelog

This file records every notable change to this project.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `corpus`, `conformance`, `cover` and `fuzz` make targets.
- The FoxIO corpus pin in `testdata/foxio.pin`, and `scripts/fetch-corpus.sh`, which
  fetches the corpus at that commit. The corpus is FoxIO-licensed material, so the
  repository holds no fetched file.
- A benchmark for the processor, and one benchmark for each method.

### Changed

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
