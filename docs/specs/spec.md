---
name: ja4plus-go v1.0.0
slug: ja4plus-go
repo: Crank-Git/ja4plus-go
status: approved
spec_version: 2
created: 2026-08-06
approved: 2026-08-06
html_generated: 2026-08-06
branch_model: dev-and-live
features:
  - id: foundation
    file: features/00-foundation.md
  - id: licensing
    file: features/01-licensing.md
  - id: correctness-audit
    file: features/02-correctness-audit.md
  - id: concurrency
    file: features/03-concurrency.md
  - id: conformance-harness
    file: features/04-conformance-harness.md
  - id: conformance-gaps
    file: features/05-conformance-gaps.md
  - id: fuzz-testing
    file: features/06-fuzz-testing.md
  - id: supply-chain
    file: features/07-supply-chain.md
  - id: python-parity
    file: features/08-python-parity.md
  - id: database-lookup
    file: features/09-database-lookup.md
  - id: release
    file: features/10-release.md
---

# ja4plus-go v1.0.0

## Overview

`ja4plus-go` is a Go library and command-line program for JA4+ network fingerprinting.
It implements ten JA4+ methods. It reads packets through `gopacket` and returns a
fingerprint for each method that the packet matches. The library is at version `v0.3.0`.
The most recent work aligned several methods with FoxIO pull requests from May 2026.

This spec describes the work that takes the library from `v0.3.0` to `v1.0.0`. Version
`v1.0.0` is an API freeze. After the freeze, the exported names and signatures stay
stable for the whole `v1` series. A freeze is only safe when three things are true. The
implementation must match the FoxIO specification. The concurrency contract must be
explicit and correct. The license must state the terms that FoxIO applies to the JA4+
methods.

None of the three is true today. The library has no conformance test against the FoxIO
reference vectors. Nine of the ten fingerprinters hold unguarded state, and no document
states who may call them. The repository declares BSD 3-Clause and has no `LICENSE` file
at all, while FoxIO licenses nine of the ten methods under FoxIO License 1.1. This spec
closes all three gaps, adds the test gates that keep them closed, and then releases
`v1.0.0`.

The readers of this spec are the engineers and the agents who do the work. The audience
of the product is a Go developer who embeds the library in a network monitor, and a
network analyst who runs the command-line program against a capture file.

## Terms

| Term | Part of speech | Meaning in this project | Do not use |
|---|---|---|---|
| method | noun | One of the ten JA4+ fingerprint definitions, such as JA4 or JA4H. | algorithm, type, scheme |
| fingerprinter | noun | The Go type that implements one method, such as `JA4HFingerprinter`. | engine, module, handler |
| fingerprint | noun | The output string that a fingerprinter produces for a packet. | hash, signature, ID |
| processor | noun | The `Processor` type, which runs every fingerprinter over one packet. | aggregator, pipeline, dispatcher |
| capture | noun | A packet capture file in `pcap` or `pcapng` format. | trace, dump, pcap file |
| vector | noun | One expected fingerprint that FoxIO publishes for one capture. | fixture, golden file, sample |
| corpus | noun | The whole set of captures and vectors that the project tests against. | dataset, suite, test data |
| conformance | noun | The property that the library output equals the FoxIO vector exactly. | compliance, correctness, accuracy |
| deviation | noun | A recorded difference between the library output and a FoxIO vector. | mismatch, failure, exception |
| reference | noun | The FoxIO repository at the pinned commit. It decides every disputed result. | upstream, source, spec repo |
| audit | noun | A read-only review of the code that produces findings. | review, sweep, pass |
| finding | noun | One defect that the audit reports, with a file and a line. | issue, bug, problem |
| gate | noun | A CI job that fails the build when its check fails. | check, guard, step |
| contract | noun | A documented rule that a caller must obey. | guarantee, promise, invariant |
| connection | noun | One network flow, identified by a five-tuple or by a QUIC connection identifier. | session, stream, flow |
| freeze | noun | The `v1.0.0` commitment that exported names and signatures stay stable. | lock, stabilization |
| fetch | verb | To download the corpus from the reference at the pinned commit. | pull, sync, grab |
| close | verb | To change the code so that a finding or a deviation no longer exists. | fix, resolve, address |

## Goals

1. Every method produces the exact fingerprint that the FoxIO reference produces, for
   every capture in the corpus.
2. The concurrency contract is documented on every exported type, and a race test proves
   it.
3. The license files state the FoxIO terms for the nine FoxIO-licensed methods.
4. CI gates conformance, race detection, fuzz testing, vulnerability scanning, lint and
   test coverage on every pull request.
5. The library releases as `v1.0.0` with a frozen exported API.
6. The README, the package documentation and the CHANGELOG describe the released
   behaviour and nothing else.

## Non-goals

- The project does not add an eleventh method. JA4E, JA4LS, JA4SScan and JA4TScan stay
  out of scope.
- The project does not add live network capture. The library reads packets that the
  caller supplies.
- The project does not become a network monitor. `GetShardKey` and `CleanupConnection`
  exist to serve a monitor that the caller writes.
- The project does not change the Python port in this repository. A parity gap found
  here produces an issue in `Crank-Git/ja4plus`, not code in this repository.
- The project does not seek a commercial license from FoxIO as part of this work.

## Users & personas

| Persona | Who they are | What they need | What they may do |
|---|---|---|---|
| Library author | A Go developer who embeds `ja4plus-go` in a network monitor. | A stable API, a documented concurrency contract, and fingerprints that match every other JA4+ tool. | Import the module and call the exported API. |
| Analyst | A network analyst who runs `ja4plus` against a capture. | Correct output, and a fingerprint that they can search for in other tools. | Run the command-line program. |
| Maintainer | The repository owner. | CI that fails when a change breaks conformance, and a release process that needs no manual steps. | Merge, tag and release. |

## Feature map

| Feature set | Spec file | Epic | Mockups |
|---|---|---|---|
| Foundation | `features/00-foundation.md` | Epic 0: Foundation | — |
| License compliance | `features/01-licensing.md` | Epic 1: License compliance | — |
| Correctness audit | `features/02-correctness-audit.md` | Epic 2: Correctness audit | — |
| Concurrency contract | `features/03-concurrency.md` | Epic 3: Concurrency contract | — |
| Conformance harness | `features/04-conformance-harness.md` | Epic 4: Conformance harness | `mockups/01-conformance-report.html` |
| Conformance gap closure | `features/05-conformance-gaps.md` | Epic 5: Conformance gap closure | — |
| Fuzz testing | `features/06-fuzz-testing.md` | Epic 6: Fuzz testing | — |
| Supply chain and CI gates | `features/07-supply-chain.md` | Epic 7: Supply chain and CI gates | — |
| Python parity | `features/08-python-parity.md` | Epic 8: Python parity | — |
| Database lookup | `features/09-database-lookup.md` | Epic 9: Database lookup | — |
| Release | `features/10-release.md` | Epic 10: API freeze and release | `mockups/02-cli-output.html` |

## Architecture & stack

### Components

| Component | Path | Responsibility |
|---|---|---|
| Public library | `*.go` at the repository root, package `ja4plus` | One fingerprinter per method, plus `Processor` and the database lookup. |
| Parser | `internal/parser/` | Protocol decoding for TLS, QUIC, HTTP, SSH, TCP streams, X.509 and GREASE. |
| Command-line program | `cmd/ja4plus/` | Reads a capture and prints fingerprints. |
| Embedded database | `data/ja4plus-mapping.csv` | The FoxIO fingerprint-to-application mapping. |
| Corpus | `testdata/foxio/` | The fetched FoxIO captures and vectors. Not tracked in git. |

### Data flow

1. The caller reads a packet with `gopacket`.
2. The caller passes the packet to `Processor.ProcessPacket`.
3. The processor calls every fingerprinter in turn.
4. Each fingerprinter decodes the packet through `internal/parser`.
5. Each fingerprinter updates its per-connection state and returns zero or more results.
6. The processor returns the joined results and the non-fatal errors.

### Key choices

| Choice | Alternative | Why this choice wins |
|---|---|---|
| `github.com/google/gopacket` v1.1.19 | `gopacket/gopacket` fork, `google/gopacket` successor | The repository already depends on it, and the audit checks whether the fork is a better home. See `features/07-supply-chain.md`. |
| Pure-Go capture reading through `pcapgo` | `libpcap` through cgo | Commit `e32e49e` already removed the cgo dependency. A pure-Go build cross-compiles to five platforms in `release.yml`. |
| Go 1.24 as the module floor | Go 1.22, Go 1.23 | Go 1.22 has left upstream security support. A security-adjacent library at `v1.0.0` needs a supported toolchain floor. |
| Fetch the corpus at a pinned commit | Commit the corpus into the repository | The corpus is FoxIO-licensed material. A fetch avoids redistribution, and a pinned commit keeps the result reproducible. |
| A separate `SyncProcessor` wrapper | Lock every fingerprinter | The lock-free core keeps the per-packet path fast for the shard-per-goroutine design that `GetShardKey` implies. The wrapper serves callers who want safety instead of throughput. |

### Deploy target

The library has no runtime deployment. The release artifacts are the Go module on
`proxy.golang.org` and the five binaries that `.github/workflows/release.yml` attaches
to the GitHub release. `pkg.go.dev` serves the package documentation.

## Data model

The library holds no database. It holds in-memory state per connection, and one embedded
lookup table.

### `FingerprintResult`

| Field | Type | Meaning | Lifecycle |
|---|---|---|---|
| `Fingerprint` | `string` | The method output for the packet. | Created per packet. |
| `Raw` | `string` | The unhashed form, such as `JA4_r`. | Created per packet. |
| `RawOriginalOrder` | `string` | The wire-order unhashed form, `JA4_ro`. | Created per packet. Empty for methods that define no such form. |
| `Type` | `string` | The method name in lower case, such as `ja4h`. | Created per packet. |
| `SrcIP`, `DstIP` | `string` | The packet addresses. | Created per packet. |
| `SrcPort`, `DstPort` | `uint16` | The packet ports. | Created per packet. |
| `Timestamp` | `time.Time` | The packet capture time. | Created per packet. |

### Fingerprinter state

| Fingerprinter | State it holds | Keyed by | Cleared by |
|---|---|---|---|
| `JA4Fingerprinter` | `quicFragments`, `dcidToTuple`, `results` | QUIC connection identifier | `Reset`, `CleanupConnection` |
| `JA4SFingerprinter` | `quicDCIDs`, `results` | QUIC connection identifier | `Reset`, `CleanupConnection` |
| `JA4HFingerprinter` | `reassembler`, `results` | Five-tuple | `Reset`, `CleanupConnection` |
| `JA4TFingerprinter` | `results` | — | `Reset` |
| `JA4TSFingerprinter` | `results` | — | `Reset` |
| `JA4LFingerprinter` | `connections`, `results` | Five-tuple | `Reset`, `CleanupConnection` |
| `JA4XFingerprinter` | `streams`, `processedCerts`, `results`, `lastCleanup`, guarded by `mu` | Five-tuple, certificate hash | `Reset`, `CleanupConnection`, an interval sweep |
| `JA4SSHFingerprinter` | `connections`, `packetCount`, `results` | Five-tuple | `Reset`, `CleanupConnection` |
| `JA4DFingerprinter` | `results` | — | `Reset` |
| `JA4D6Fingerprinter` | `results` | — | `Reset` |

Every fingerprinter appends to `results` and never truncates it. `CleanupConnection`
does not touch `results`. `features/02-correctness-audit.md` treats this as a suspected
defect, because `CleanupConnection` exists to stop state growth in a long-running
process.

### Lookup database

`data/ja4plus-mapping.csv` maps a fingerprint to an application name, a type and a note.
The library embeds the file with `go:embed` and loads it once through `sync.Once`. The
package-level variables `lookupDB`, `dbSource` and `dbCachePath` hold the loaded state.
`features/09-database-lookup.md` covers the reload path and the remote fallback.

## Cross-cutting concerns

### Concurrency

The core fingerprinters are not safe for use from more than one goroutine. The contract
after this work is explicit: one `Processor` serves one goroutine, and the caller routes
packets to processors with `GetShardKey`. `SyncProcessor` wraps a `Processor` and serves
callers who share one instance. `features/03-concurrency.md` holds the detail.

### Error handling

A fingerprinter returns a non-fatal error rather than a panic when a packet does not
decode. `Processor.ProcessPacket` collects the errors and returns them alongside the
results. A malformed packet never terminates the caller. `features/06-fuzz-testing.md`
proves this against generated input.

### Input validation

Every packet is untrusted input. Every parser bounds-checks every length field it reads
before it slices. The fuzz targets in `features/06-fuzz-testing.md` are the enforcement.

### Logging

The library writes nothing to standard output and nothing to standard error. The
command-line program owns all output. This rule is a contract and the audit checks it.

### Performance targets

- `Processor.ProcessPacket` allocates no more per packet after this work than before it.
  `features/07-supply-chain.md` defines the benchmark that proves this.
- `SyncProcessor` adds one mutex acquisition per packet over `Processor`.
- The library holds no unbounded state for a connection that `CleanupConnection` has
  removed.

### Security posture

- The library performs no network input and no network output, except the opt-in
  database update that `features/09-database-lookup.md` covers.
- The library reads no file except the database cache path.
- `govulncheck` gates every pull request.
- `SECURITY.md` is out of scope. The README states how to report a vulnerability.

### Accessibility and internationalization

The project has no user interface. Both concerns are out of scope.

## Environments & config

The library reads no environment variable. The command-line program and the test suite
read the following.

| Name | Read by | What it does | Default |
|---|---|---|---|
| `JA4PLUS_DB_CACHE` | `lookup.go` | The path of the downloaded database cache file. | An operating-system cache directory. |
| `JA4PLUS_FOXIO_DIR` | The conformance test | The directory that holds the fetched corpus. | `testdata/foxio` |
| `JA4PLUS_FOXIO_REF` | The fetch script | The FoxIO commit to fetch. | The pinned commit in `testdata/foxio.pin` |

The project holds no secret. `release.yml` uses the GitHub-provided token only.

Seed data is the corpus. `make corpus` fetches it. `features/04-conformance-harness.md`
defines the script.

## Testing strategy

| Layer | What it covers | Command |
|---|---|---|
| Unit | One function or one fingerprinter, with a hand-built packet. | `go test ./...` |
| Race | The concurrency contract, under the race detector. | `go test -race ./...` |
| Conformance | Every method against every FoxIO vector. | `go test -tags conformance ./...` |
| Fuzz | Every parser entry point against generated input. | `go test -fuzz=Fuzz -fuzztime=60s ./internal/parser` |
| Benchmark | The per-packet path, for allocation and time. | `go test -bench=. -benchmem ./...` |

A change is done when five things are true.

1. `go build ./...` succeeds on the module floor.
2. `go test -race ./...` passes.
3. `golangci-lint run` reports nothing.
4. The conformance suite reports no new deviation.
5. Coverage does not fall below the recorded floor.

## Epics

### Epic 0: Foundation

**Goal.** Make the repository able to run every gate that the later epics add.

**Covers.** `features/00-foundation.md`

**Depends on.** Nothing.

**Exit criteria.** A fresh clone runs `make test`, `make lint`, `make bench`,
`make corpus` and `make conformance`. The `dev` branch exists. `.golangci.yml` pins the
linter set. The module floor is Go 1.24. `CLAUDE.md` and `.claude/` are tracked.

### Epic 1: License compliance

**Goal.** State the correct license terms for every part of the repository.

**Covers.** `features/01-licensing.md`

**Depends on.** Nothing. This epic runs first among the content epics, because the
release cannot ship without it.

**Exit criteria.** `LICENSE` and `NOTICE` exist. The README, the package documentation
and `data/ja4plus-mapping.csv` carry the FoxIO attribution. No document claims that the
FoxIO-licensed methods are BSD 3-Clause.

### Epic 2: Correctness audit

**Goal.** Find and close every logic defect in the library, the parser, and the
command-line program.

**Covers.** `features/02-correctness-audit.md`

**Depends on.** Epic 0.

**Exit criteria.** Every file has an audit record. Every confirmed finding is closed and
has a regression test. The findings report is committed at `docs/audit/findings.md`.

### Epic 3: Concurrency contract

**Goal.** Make the concurrency behaviour explicit, correct and tested.

**Covers.** `features/03-concurrency.md`

**Depends on.** Epic 0. Runs alongside Epic 2.

**Exit criteria.** Every exported type documents its contract. `SyncProcessor` exists. A
race test drives `SyncProcessor` from many goroutines and passes under `-race`. A second
race test proves the shard-per-goroutine pattern.

### Epic 4: Conformance harness

**Goal.** Test every method against the FoxIO reference vectors.

**Covers.** `features/04-conformance-harness.md`

**Depends on.** Epic 0.

**Exit criteria.** `make corpus` fetches the corpus at the pinned commit. The harness
reads both the per-stream vectors and the per-packet vectors. The harness reports one
row per capture and per method. The report lists every deviation.

### Epic 5: Conformance gap closure

**Goal.** Make every vector match.

**Covers.** `features/05-conformance-gaps.md`

**Depends on.** Epic 4. The deviation list that Epic 4 produces defines the work.

**Exit criteria.** The conformance suite reports no deviation for any capture in the
corpus. Tunnel decapsulation and pcapng decryption-secret reading are implemented, or a
named requirement records why a vector is unreachable and the maintainer has accepted it.

### Epic 6: Fuzz testing

**Goal.** Prove that no packet input can panic the library.

**Covers.** `features/06-fuzz-testing.md`

**Depends on.** Epic 0.

**Exit criteria.** A fuzz target exists for every parser entry point. A seed corpus
exists for each. A short fuzz run gates every pull request. A long fuzz run runs nightly.
Every crash that the fuzzer finds is closed and its input joins the seed corpus.

### Epic 7: Supply chain and CI gates

**Goal.** Make the build reproducible and the dependencies watched.

**Covers.** `features/07-supply-chain.md`

**Depends on.** Epic 0.

**Exit criteria.** `govulncheck` gates every pull request. Dependabot watches Go modules
and GitHub Actions. Every action reference is pinned. Coverage has a floor that CI
enforces. Benchmarks run in CI and report a regression.

### Epic 8: Python parity

**Goal.** Close every gap between this library and `Crank-Git/ja4plus` that applies to
Go.

**Covers.** `features/08-python-parity.md`

**Depends on.** Epic 4, because the corpus is how parity is measured.

**Exit criteria.** A parity table records every Python capability and its Go status. Each
applicable gap is closed. Each inapplicable gap records why Go does not need it.

### Epic 9: Database lookup

**Goal.** Decide and implement where the remote database lookup belongs.

**Covers.** `features/09-database-lookup.md`

**Depends on.** Epic 2.

**Exit criteria.** Network input and output sit behind an explicit boundary. The client
sets a timeout, verifies the server certificate, and bounds the response size. The
lookup table reloads after an update within the same process.

### Epic 10: API freeze and release

**Goal.** Freeze the exported API and release `v1.0.0`.

**Covers.** `features/10-release.md`

**Depends on.** Every other epic.

**Exit criteria.** The exported API is recorded in `docs/api/v1.md`. The README, the
package documentation and the CHANGELOG describe the released behaviour. The `v1.0.0`
tag builds and publishes. `pkg.go.dev` serves the documentation.

## Milestones

| Milestone | Epics | What "shippable" means |
|---|---|---|
| M1: Ready to work | Epic 0, Epic 1 | The repository runs every gate, and the license is correct. The library is safe to distribute. |
| M2: Known-correct | Epic 2, Epic 3, Epic 4 | Every defect that the audit found is closed, the concurrency contract holds, and the deviation list is known. |
| M3: Conformant | Epic 5, Epic 6 | Every FoxIO vector matches, and no generated input panics the library. |
| M4: Hardened | Epic 7, Epic 8, Epic 9 | The supply chain is watched, parity is recorded, and the network boundary is explicit. |
| M5: Released | Epic 10 | `v1.0.0` is tagged, published and documented. |

## Assumptions

1. The maintainer accepts a Go 1.24 module floor, and accepts that consumers on Go 1.22
   and Go 1.23 stay on `v0.3.0`.
2. FoxIO keeps publishing the corpus at `FoxIO-LLC/ja4`. A pinned commit protects the
   project from a move for the life of the pin.
3. The FoxIO Wireshark vectors are authoritative for JA4D and JA4D6, because the FoxIO
   Python vectors for `dhcpv6.pcap` are an empty list.
4. The maintainer wants `dev` as the integration branch and `master` as the live branch.
   `master` stays releasable at all times.
5. The maintainer will file the parity issues in `Crank-Git/ja4plus` personally. This
   project only records them.
6. A conformance failure blocks a merge. A benchmark regression warns and does not block.

## Risks & open questions

### R1 — The license split is a release blocker (resolved 2026-08-06)

FoxIO License 1.1 covers JA4S, JA4H, JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4TScan, JA4D,
JA4D6, JA4SScan, JA4E and JA4SSH. It is a non-commercial license. `LICENSE-JA4` covers
JA4 alone under BSD 3-Clause. The repository README claims BSD 3-Clause for the whole
library and links to a `LICENSE` file that does not exist.

Epic 1 implements the model that the FoxIO licensing FAQ recommends: the original Go
code stays BSD 3-Clause, and a `NOTICE` file carries the FoxIO terms. This is what
`driftnet-io/go-ja4x` does, and the FAQ names it as a good example.

**This spec is not legal advice.**

**The maintainer resolved this risk on 2026-08-06.** The dual model is sufficient for
`v1.0.0`. The project does not contact FoxIO before the release. Epic 1 records this
decision in `docs/audit/license-decision.md`, and the Epic 10 release gate is satisfied
when that record exists.

Source: <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>,
<https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4>,
<https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md>, read 2026-08-06 at commit
`27f0cbf`.

### R2 — Two vectors may be unreachable (open)

`chrome-cloudflare-quic-with-secrets.pcapng` carries TLS secrets in pcapng Decryption
Secrets Blocks. `gopacket` does not read those blocks. `dtls-udp.notest.cap` carries the
`notest` marker, which means FoxIO excludes it from their own suite.

Epic 5 treats both as named requirements with their own issues, not as exclusions. If
reading a Decryption Secrets Block proves impossible within `gopacket`, the requirement
records the reason and the maintainer accepts it before Epic 10 releases.

### R3 — Encapsulation support is unscoped until Epic 4 runs (open)

The corpus holds `gre-sample.pcap`, `gre-erspan-vxlan.pcap` and `tcpdump-geneve.pcap`.
`tshark` decapsulates all three. The library appears not to. The size of Epic 5 is not
knowable until the Epic 4 harness produces the deviation list. Epic 5 is sized after
Epic 4 finishes, not before.

### R4 — The Python port carries the same license gap (closed, out of scope)

`Crank-Git/ja4plus` ships a plain BSD 3-Clause `LICENSE` with no FoxIO notice. The same
correction applies there. This project records the finding and does not act on it.

### R5 — `gopacket` upstream is unmaintained (open)

`github.com/google/gopacket` has had no release since v1.1.19 in 2022. The community
fork is `github.com/gopacket/gopacket`. Epic 7 decides whether to migrate before the
freeze, because a dependency change after `v1.0.0` is harder.

## Changelog

| Round | Date | What changed |
|---|---|---|
| 1 | 2026-08-06 | First draft, written from the Phase 1 interview and from the FoxIO reference at commit `27f0cbf`. |
| 2 | 2026-08-06 | The maintainer approved the spec and the scaffold. R1 resolved: the dual BSD 3-Clause and FoxIO `NOTICE` model is sufficient for `v1.0.0`. The project does not contact FoxIO before the release. |
