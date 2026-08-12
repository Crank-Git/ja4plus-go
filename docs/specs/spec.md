---
name: ja4plus-go v1.0.0
slug: ja4plus-go
repo: Crank-Git/ja4plus-go
status: approved
spec_version: 3
created: 2026-08-06
approved: 2026-08-11
html_generated: 2026-08-11
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
  - id: foxio-reference
    file: features/11-foxio-reference.md
  - id: ja4ls
    file: features/12-ja4ls.md
  - id: live-capture
    file: features/13-live-capture.md
  - id: documentation
    file: features/14-documentation.md
  - id: mutation-sweep
    file: features/15-mutation-sweep.md
  - id: pre-release-validation
    file: features/16-pre-release-validation.md
---

# ja4plus-go v1.0.0

## Overview

`ja4plus-go` is a Go library and command-line program for JA4+ network fingerprinting.
FoxIO publishes the JA4+ standard. This project is an independent implementation of that
standard. The library is at version `v0.3.0`.

**FoxIO names twelve methods. This project implements eleven of them.** The twelfth is
JA4TScan. `Non-goals` holds the reason, and the reason is that FoxIO publishes no format
specification and no reference implementation for it.

**`JA4LFingerprinter` writes both JA4L and JA4LS, so ten fingerprinters carry eleven
methods.** Read the ten as a count of fingerprinters, and never as a count of methods.
The port settled this wording in its issue #387, and `features/12-ja4ls.md` builds the
eleventh method here.

This spec describes the work that takes the library from `v0.3.0` to `v1.0.0`. Version
`v1.0.0` is an API freeze. After the freeze, the exported names and signatures stay
stable for the whole `v1` series. A freeze is only safe when four things are true.

1. The implementation produces the fingerprint that the FoxIO reference produces.
2. The concurrency contract is explicit and correct.
3. The license states the terms that FoxIO applies to the JA4+ methods.
4. This project and the port produce the same fingerprint for the same packet.

None of the four is true today. The reader of this spec is an engineer or an agent who
works on `ja4plus-go`. The user of `ja4plus-go` is a Go developer who embeds the library
in a network monitor, and a network analyst who runs the command-line program.

### What round 3 of this spec changed, and why

Rounds 1 and 2 were written on 2026-08-06. **The port shipped `v1.0.0` on 2026-08-10 and
`v1.1.0` on 2026-08-11, and it recorded about thirty rulings between those dates.** Each
ruling settled a question that this project must answer the same way, and about twenty of
them end with a sentence of the form "The port must X, or the two implementations
disagree on Y". In that sentence, "the port" names this project.

Round 3 therefore reads the port first and plans this repository second. `Parity with
ja4plus` below holds the register that carries every such row. The Changelog records the
round.

## Terms

This table is the controlled vocabulary of the project. **Where a term also appears in
the port's own table, the meaning here is the same meaning.** One concept keeps one word
across both repositories, because a reader moves between them.

| Term | Part of speech | Meaning in this project | Do not use |
|---|---|---|---|
| method | noun | One named JA4+ algorithm, for example JA4 or JA4SSH. FoxIO names twelve of them, and this project implements eleven. | algorithm, type, scheme |
| method name | noun | The lower-case token that names one method, for example `ja4h`. `FingerprintResult.Type` holds one. | method key, type name, token |
| fingerprinter | noun | The Go type that implements one method or two. `JA4LFingerprinter` implements JA4L and JA4LS, so ten fingerprinters carry eleven methods. | engine, module, handler |
| fingerprint | noun | The output string of one method for one connection. | hash, signature, ID |
| processor | noun | The `Processor` type, which runs every fingerprinter over one packet. | aggregator, pipeline, dispatcher |
| capture | noun | A packet capture file in `pcap` or `pcapng` format. | trace, dump, pcap file |
| key log | noun | The list of TLS secrets of one or more connections, in the NSS key log format that `draft-ietf-tls-keylogfile` specifies. | keylog file, secrets file, SSLKEYLOGFILE |
| secret | noun | One TLS traffic secret of one connection. The library derives the QUIC packet protection keys from it. | key, key material |
| decryption secrets block | noun | The pcapng block that carries a key log inside a capture. The IETF pcapng draft states its block type. | DSB, secrets block |
| vector | noun | One FoxIO capture plus the expected-output file that FoxIO publishes for it. | fixture, golden file, sample |
| corpus | noun | The whole set of captures and vectors that the project tests against. | dataset, suite, test data |
| conformance | noun | The property that the library output equals the FoxIO vector exactly. | compliance, correctness, accuracy |
| conformance suite | noun | The test suite that compares library output against every vector. | validation tests, spec tests |
| deviation | noun | A recorded difference between the library output and a FoxIO vector. | mismatch, failure, exception |
| reference | noun | The FoxIO repository at the pinned commit. It decides every disputed fingerprint. | upstream, source, spec repo |
| reference split | noun | The state where two FoxIO implementations produce different values for one input. The reference then decides nothing, and a person decides. | disagreement, conflict |
| reading | noun | One recorded conclusion about what a source states, with the evidence that supports it. | interpretation, take, finding |
| ruling | noun | One determination the maintainer makes where no source settles the question. A ruling is the choice of a person, and a reading is a conclusion about a source. | decision, call, verdict |
| register | noun | The tracked file `testdata/deviations.json`, which holds one entry for each accepted difference from a FoxIO value. | deviation list, exception file |
| value decline | noun | One register entry that records a disagreement with a FoxIO value. An implementation change on either side could close it. The entry carries `"capability": false`. | value dispute, defect entry |
| capability decline | noun | One register entry that records a capability this project chose not to build. No implementation change closes it. The entry carries `"capability": true`. | scope decline, boundary decline |
| exclusion | noun | A capture or a stream that the conformance suite makes no comparison for. | exception, skip, ignore |
| transcription | noun | This project's own prose form of one FoxIO image, held under `docs/specs/foxio/`. | translation, copy, write-up |
| corroboration | noun | One FoxIO-authored source, other than the image, that states the same rule. | confirmation, second opinion |
| baseline | noun | One expected-output file of the FoxIO Zeek package, held under `zeek/tests/Traces/`. | golden file, expected log |
| port | noun | The Python implementation at `Crank-Git/ja4plus`. **The port's own spec uses this word for this repository. In this repository it names the Python side.** | Python version, sibling, twin |
| parity | noun | The state where this project and the port expose the same interface and produce the same fingerprint. | alignment, sync, consistency |
| audit | noun | A read-only review of the code that produces findings. | review, sweep, pass |
| finding | noun | One defect that the audit reports, with a file and a line. | issue, bug, problem |
| added file | noun | One `.go` file that a later issue adds to the repository root, to `internal/parser/` or to `cmd/ja4plus/`. No audit reads it, and `docs/audit/findings.md` names the issue that added it. | new file, unaudited file |
| gate | noun | A CI job that fails the build when its check fails. | check, guard, step |
| contract | noun | A documented rule that a caller must obey. | guarantee, promise, invariant |
| connection | noun | One network flow, identified by a five-tuple or by a QUIC connection identifier. | session, stream, flow |
| endpoint | noun | One address and one port. | host, peer, side |
| state table | noun | The map a fingerprinter uses to hold per-connection data. | cache, store, registry |
| freeze | noun | The `v1.0.0` commitment that exported names and signatures stay stable. | lock, stabilization |
| window | noun | The count of packets JA4SSH reads before it produces a fingerprint. | interval, batch, sample |
| open window | noun | One JA4SSH window that a connection holds when the packet source ends. | partial window, trailing window |
| raw form | noun | The unhashed form of a fingerprint, for example `JA4_r`. | expanded form, debug form |
| zero sentinel | noun | The literal value `000000000000` that a hash field carries when its list holds no value. | zero marker, zero hash |
| plausibility guard | noun | A check that rejects input a method reads, because its content describes no real client. | sanity check, heuristic, filter |
| hop count | noun | The count of routers a packet crossed, read as the initial time-to-live minus the observed time-to-live. | hop distance, TTL delta |
| propagation factor | noun | The JA4L divisor that the FoxIO hop-count table gives for one hop count. | propagation delay, terrain factor |
| measurement point | noun | One packet timestamp that a JA4L value measures from or to. | anchor, marker |
| protocol marker | noun | The third part that a JA4L or JA4LS value carries on a QUIC connection. Its value is `quic`. | protocol part, suffix |
| part e | noun | The fifth part of a JA4TS value. It holds the delay of each SYN-ACK after the first, in whole seconds. | retransmission part, timing part |
| object identifier | noun | One ASN.1 identifier, written as a dotted string such as `2.5.4.3`. JA4X hashes its hex form. | OID, identifier, tag |
| tunnel | noun | One connection that carries another protocol inside its payload, for example a SOCKS4 proxy connection. | proxy, wrapper, encapsulation |
| reported key | noun | The four address fields a `FingerprintResult` carries. It holds the outer address pair and the inner port pair. | output key, result key |
| grouping key | noun | The address pair and the port pair that collect packets into one connection. Both read the inner layer. | connection key, state key |
| index | noun | The map that pairs the reported key of a connection with the grouping key of it. `CleanupConnection` reads it. | lookup, reverse map, mapping |
| outer layer | noun | The address layer of the tunnel. A `FingerprintResult` reports it, and the time-to-live reads it. | tunnel header, outer header |
| inner layer | noun | The address layer of the packet the tunnel carries. The grouping key reads it. | inner header, payload header |
| monitor | noun | The `ja4plus watch` command, which reads packets from an interface until the operator stops it. | daemon, sniffer, listener |
| capture handle | noun | The object the monitor opens on one interface to read packets. | socket, listener, handle |
| capture backend | noun | The code that a build selects to open a capture handle. This project holds two. | driver, provider |
| pure-Go backend | noun | The capture backend that `pcapgo.NewEthernetHandle` provides. It builds on Linux and needs no cgo. | native backend, default backend |
| libpcap backend | noun | The capture backend that the `libpcap` build tag selects. It links libpcap through cgo and builds on macOS. | cgo backend, pcap backend |
| capture filter | noun | The Berkeley Packet Filter expression the `--bpf` option passes to the capture backend. | BPF, packet filter |
| drop count | noun | The count of packets the capture backend dropped. | loss, misses, drops |
| statistics line | noun | The one line the monitor writes to standard error to report its counts. | stats output, status line |
| stop request | noun | The flag that a termination signal sets and that the monitor reads after each packet. | shutdown flag, kill switch |
| documentation site | noun | The MkDocs site that GitHub Pages serves at `https://crank-git.github.io/ja4plus-go/`. | docs, website, manual |
| mutation | noun | One change that a sweep applies to one expression of one package under this module. The sweep runs the suite against the change and then reverts it. | mutant, tweak |
| sweep | noun | One run of the mutation tool over a named package set. It records the result of every mutation it applies. | campaign, mutation testing |
| candidate | noun | One test that no mutation of one sweep makes fail. | survivor, weak case |
| clean environment | noun | One module cache and one build tree that hold no source of this repository. `features/16-pre-release-validation.md` states the cases that build it. | fresh environment, sandbox |
| fetch | verb | To download the corpus from the reference at the pinned commit. | pull, sync, grab |
| close | verb | To change the code so that a finding or a deviation no longer exists. | fix, resolve, address |
| conform | verb | To produce the same output as the FoxIO reference. | comply, match spec |
| emit | verb | To return a fingerprint from a fingerprinter. | output, produce, yield |
| decline | verb | To choose not to reproduce a FoxIO value or not to build a capability, and to record the choice in the register. | reject, skip, ignore |

## Goals

1. Every method produces the fingerprint that the FoxIO reference produces, for every
   capture in the corpus, except where the register records a decline.
2. This project and the port produce the same fingerprint for every capture in the
   corpus, and expose the same interface where FoxIO specifies none.
3. Eleven methods are implemented. JA4LS is the eleventh.
4. The concurrency contract is documented on every exported type, and a race test proves
   it.
5. The license files state the FoxIO terms for the FoxIO-licensed methods.
6. CI gates conformance, race detection, fuzz testing, vulnerability scanning, lint and
   test coverage on every pull request.
7. The documentation site publishes to GitHub Pages on a push to the live branch.
8. The library releases as `v1.0.0` with a frozen exported API, and the release carries
   binaries for five platforms.
9. Every ruling carries a register entry or a test, and every reading cites its source.

## Non-goals

**The rule for this section is capability.** A capability that Go can achieve is in
scope. Only a capability that Go cannot achieve, or that FoxIO defines too little for any
implementation to achieve, stays out.

- **JA4TScan is out of scope, because FoxIO publishes nothing to implement.** A read of
  `FoxIO-LLC/ja4` on 2026-08-11 reports that `technical_details/` holds material for ten
  methods and holds no file for JA4TScan. FoxIO ships no Python, no Rust, no Zeek and no
  Wireshark implementation of it. The name appears in `License FAQ.md:5`, in
  `LICENSE:3` and in the FoxIO `README.md:293`, which describes it as an Active TCP
  Fingerprint Scanner. **A goal of one-to-one with FoxIO cannot be met for a method that
  FoxIO does not define**, so no amount of Go capability closes this. The ruling is
  reversible, and it reverses when FoxIO publishes a format. The port declined the same
  method for a different reason, and `Parity with ja4plus` records the difference.
- **JA4Scan carries no ruling.** `License FAQ.md:5` names `JA4Scan`, `LICENSE:3` spells
  it `JA4SScan`, and the FoxIO `README.md:293` names neither spelling. FoxIO publishes no
  format and no implementation. **This project decided nothing about it, so this section
  states no reason.** A stated reason would assert a ruling that no round holds.
- **JA4E carries no ruling, for the same cause.** `LICENSE:3` is the one FoxIO record
  that names it.
- The project does not run the port. No test in this repository builds, imports or
  executes Python. `Parity with ja4plus` rule 3 states why.
- The project does not change the port. A parity gap found here produces an issue in
  `Crank-Git/ja4plus`, and no code in this repository.
- The project does not seek a commercial license from FoxIO as part of this work.
- Wire-speed performance is out of scope. The project measures throughput and records it,
  and sets no target for `v1.0.0`.

### What round 3 moved out of this section

Round 2 held three non-goals that round 3 removes, because Go can achieve each one.

| Round 2 non-goal | Why it is now in scope | Feature set |
|---|---|---|
| "The project does not add an eleventh method. JA4E, JA4LS, JA4SScan and JA4TScan stay out of scope." | JA4LS is a defined FoxIO method with published reference values, and the port implements it. The other three stay out, and the bullets above hold the reason. | `features/12-ja4ls.md` |
| "The project does not add live network capture." | `gopacket/pcapgo` provides a pure-Go capture handle on Linux, and the `libpcap` build tag reaches macOS. | `features/13-live-capture.md` |
| "The project does not become a network monitor." | The same reason. `GetShardKey` and `CleanupConnection` now serve a monitor this project ships, as well as one the caller writes. | `features/13-live-capture.md` |

## Users & personas

| Persona | Who they are | What they need | What they may do |
|---|---|---|---|
| Library author | A Go developer who embeds `ja4plus-go` in a network monitor. | A stable API, a documented concurrency contract, and fingerprints that match every other JA4+ tool. | Import the module and call the exported API. |
| Analyst | A network analyst who runs `ja4plus` against a capture. | Correct output, and a fingerprint that they can search for in other tools. | Run the command-line program. |
| Monitor operator | An operator who runs `ja4plus watch` against a live interface. | A process that reads an interface, reports its drop count, and never exhausts memory. | Open a capture handle. This needs elevated privileges on the host. |
| Maintainer | The repository owner. | Evidence that a change broke no conformance and no parity. | Merge, tag and release. |

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
| FoxIO reference material | `features/11-foxio-reference.md` | Epic 11: FoxIO reference material | — |
| Parity with the port | `features/08-python-parity.md` | Epic 8: Parity with the port | — |
| JA4LS | `features/12-ja4ls.md` | Epic 12: JA4LS | — |
| Database lookup | `features/09-database-lookup.md` | Epic 9: Database lookup | — |
| Live capture | `features/13-live-capture.md` | Epic 13: Live capture | `mockups/03-watch-output.html` |
| Documentation site | `features/14-documentation.md` | Epic 14: Documentation site | `mockups/04-docs-site.html` |
| Mutation sweep | `features/15-mutation-sweep.md` | Epic 15: Mutation sweep | — |
| Pre-release validation | `features/16-pre-release-validation.md` | Epic 16: Pre-release validation | — |
| API freeze and release | `features/10-release.md` | Epic 10: API freeze and release | `mockups/02-cli-output.html` |

## Architecture & stack

### Components

| Component | Path | Responsibility |
|---|---|---|
| Public library | `*.go` at the repository root, package `ja4plus` | One fingerprinter per method, plus `Processor` and the database lookup. |
| Parser | `internal/parser/` | Protocol decoding for TLS, QUIC, HTTP, SSH, TCP streams, X.509 and GREASE. |
| Capture backend | `internal/capture/` | New. Opens a capture handle on one interface. Holds the pure-Go backend and the libpcap backend. |
| Command-line program | `cmd/ja4plus/` | Reads a capture or an interface, and prints fingerprints. |
| Embedded database | `data/ja4plus-mapping.csv` | The FoxIO fingerprint-to-application mapping. |
| Corpus | `testdata/foxio/` | The fetched FoxIO captures and vectors. Not tracked in git. |
| Register | `testdata/deviations.json` | Tracked. One entry per accepted difference from a FoxIO value. |
| Reference material | `docs/specs/foxio/` | Tracked. The transcriptions and the readings that every ruling cites. |
| Documentation site | `docs/`, `mkdocs.yml` | The pages GitHub Pages serves. |

### Data flow

1. The caller reads a packet with `gopacket`, or the monitor reads one from a capture
   handle.
2. The caller passes the packet to `Processor.ProcessPacket`.
3. The processor calls every fingerprinter in turn.
4. Each fingerprinter decodes the packet through `internal/parser`.
5. Each fingerprinter updates its state table and returns zero or more results.
6. The processor returns the joined results and the non-fatal errors.
7. When the packet source ends, the caller calls `Processor.CloseOpenWindows`, which
   returns the results that the open windows hold.

### Key choices

| Choice | Alternative | Why this choice wins |
|---|---|---|
| `github.com/google/gopacket` v1.1.19 | `gopacket/gopacket` fork | The repository already depends on it. `features/07-supply-chain.md` decides whether the fork is a better home before the freeze. |
| Pure-Go capture reading through `pcapgo` | `libpcap` through cgo for every build | Commit `e32e49e` removed the cgo dependency. The default build cross-compiles to five platforms with no C toolchain. |
| A `libpcap` build tag for the macOS monitor | No macOS monitor, or cgo in every build | `pcapgo/capture.go` carries the build constraint `linux,go1.9`, so the pure-Go handle reaches Linux alone. The tag keeps cgo off the default build and off every released binary. `features/13-live-capture.md` states the containment. |
| Go 1.24 as the module floor | Go 1.22, Go 1.23 | Go 1.22 has left upstream security support. `go.mod` still declares `go 1.22`, so Epic 0 moves it. |
| Fetch the corpus at a pinned commit | Commit the corpus into the repository | The corpus is FoxIO-licensed material. A fetch avoids redistribution, and a pin keeps the result reproducible. |
| A separate `SyncProcessor` wrapper | Lock every fingerprinter | The lock-free core keeps the per-packet path fast for the shard-per-goroutine design that `GetShardKey` implies. |
| MkDocs with the Material theme | Hugo, a pure-Go generator | The port publishes the same site, and a reader moves between the two. The prose pages port across with no reformatting. |
| A hand-written API reference that links to `pkg.go.dev` | A generator such as `gomarkdoc` | Go already publishes a canonical API surface at `pkg.go.dev`. A second generated copy drifts, and a drift check costs more than the pages are worth. |
| GoReleaser for the release | The hand-rolled build matrix in `release.yml` | One configuration file replaces the inline shell, and it produces the checksums, the software bill of materials and the release notes. |

Verified against <https://pkg.go.dev/github.com/google/gopacket/pcapgo> (v1.1.19),
<https://www.mkdocs.org/user-guide/configuration/> (MkDocs 1.6),
<https://squidfunk.github.io/mkdocs-material/> (Material 9.7.7) and
<https://goreleaser.com/customization/> (GoReleaser v2), retrieved 2026-08-11.

### Deploy target

The library has no runtime deployment. It produces four release artifacts.

| Artifact | Where it goes | Who publishes it |
|---|---|---|
| The Go module | `proxy.golang.org` | The `v1.0.0` tag. |
| Five platform binaries and their checksums | The GitHub release | GoReleaser, from the tag. |
| The package documentation | `pkg.go.dev` | The module proxy. |
| The documentation site | `https://crank-git.github.io/ja4plus-go/` | `.github/workflows/docs.yml`, on a push to `master`. |

## Parity with ja4plus

The port is the Python implementation at `Crank-Git/ja4plus`. It is at version `v1.1.0`.
The two implementations must not drift apart, because a user who runs both must get one
answer.

**The port's own spec holds the register that governs this section.** Its `Parity with
ja4plus-go` section carries about thirty rows, and about twenty of them end with a
sentence of the form "The port must X". In the port's vocabulary "the port" names this
repository. **Those sentences are the work list of Epic 8.**

Three rules govern parity. **These are the port's rules, adopted here without a change,
so that one rule set governs both repositories.**

1. **FoxIO decides behaviour.** Where FoxIO specifies the output, the vectors decide.
   This rule outranks the port. Where this project disagrees with a vector, this project
   is wrong.
2. **The port decides interface where this project shipped nothing.** Where FoxIO
   specifies nothing, and where this project has no exported name for the behaviour, this
   project adopts the port's choice rather than inventing a second one. **Where this
   project shipped a name first, rule 2 runs the other way and the port adopted it.** The
   register records which side each row followed.
3. **The gate is the shared vector set.** Both repositories read the same FoxIO vectors,
   pinned to the same upstream commit. **No test in this repository builds, runs or
   imports the port.** A cross-language test rig couples two repositories that move at
   different speeds, and it fails for reasons that have nothing to do with the change
   under test.

Rule 3 reverses a decision of round 2. `features/08-python-parity.md` held FR-parity-8
through FR-parity-14, which specified a test that runs the Python library over the corpus
and compares the two outputs as strings. Round 3 deletes those seven requirements.

### The register

Each row states what the port ruled, what this project does today, and what this project
must change. The **Ruling** column names the port issue that holds the ruling and the
measurement. Every ruling is reversible, and a reversal happens in both repositories or
in neither.

Rows are grouped by method. `features/08-python-parity.md` numbers each row as a
requirement and holds the acceptance criteria.

#### JA4 and JA4S

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| ALPN value for a first byte that is not alphanumeric | Not measured. | Write `99`. | 1 | #127, #141 |
| ALPN value for a byte outside `0x20-0x7E` in a position other than the first | Not measured. | Write `99`. This is a reference split. FoxIO Python writes `U+FFFD`, which is a character no packet byte holds. FoxIO Rust writes the `tshark` escape text. Neither reads the packet. | 1 | #141, #162, #522 |
| ALPN value for a first ALPN value of one byte | Not measured. | Repeat the byte and write `hh`. FoxIO Python writes `h`, which cannot fill a two-character field. FoxIO Rust writes `h0`. No vector separates them. | 1 | #141, #162, #522 |
| A structurally valid ClientHello whose body describes no real client | Produces a fingerprint. The library holds no plausibility guard. | No change. **Hold the current behaviour and add a test that a guard would fail.** The port measured 5000 random bodies: all 5000 produced a well-formed fingerprint, and a guard on the two separating conditions would move no vector and would still admit about one fabricated value in twenty-five hundred. | 1 | #338, #343 |

#### JA4L and JA4LS

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| JA4LS | Not implemented. `ja4l.go:198` sets `Type: "ja4l"` and no other value. | Implement it. `JA4LFingerprinter` writes both methods. | 1 | `features/12-ja4ls.md` |
| The client value on the return path | Not measured. | Report one client value for one connection. The port's return path repeats the value and its stored list holds one, and its issue #156 measured every candidate end-of-connection point. | 1 | #156 |
| The part count | Not measured. | Write two timing parts on a TCP connection. This is a reference split: the image and two implementations write three parts, and two implementations write two. All 114 JA4L values of the port's vector set hold two. | 1 | #225 |
| The protocol marker on a QUIC connection | Not measured. | Write `quic` as the third part of both values on a QUIC connection. **Follow the Wireshark spelling.** The Zeek package appends `q`, and the port's rule declines the Zeek spelling. Do not write the `tcp` literal that the dissector writes on an HTTP connection. | 1 | #225 |
| The server value on a retransmitted SYN-ACK | Not measured. | Emit one server value for one connection. A retransmitted SYN-ACK finds the measurement point set, and it gives no value. | 1 | #272 |
| A reference file that holds no JA4L key | Not measured. | Record five value declines. The FoxIO generating run deleted the key, so the comparison is unreachable and not failed. This row changes no fingerprint. | 1 | #200, #272 |

#### JA4SSH

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| The window threshold | `ja4ssh.go:176-180` caps the threshold at `min(packetCount, 10)`. | Emit at `packetCount`, which defaults to 200. **The port names this a defect of this repository**, and its issue #28 fixed the same defect on its own side. | 1 | #28 |
| The mode field | Not measured. | Read the mode field from the window alone. | 1 | #96 |
| A window that holds no SSH packet | Not measured. | Emit nothing. | 1 | #97 |
| The window that a connection holds open at the end of a capture | Not measured. No equivalent method exists. | Emit it. Add `CloseOpenWindows`, on every fingerprinter and on `Processor`. **The name follows the port, under rule 2.** The FoxIO references split two against two, and the maintainer followed the Rust reference and the Zeek package. Two FoxIO reference values verify the result. | 1, 2 | #105, #199, #214 |

#### JA4T and JA4TS

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| The empty option list, the absent maximum segment size and the zero window scale | `ja4t.go:68`, `ja4t.go:73` and `ja4t.go:87` write `%d` with no padding and no sentinel. | Write the two-digit form. An empty option list writes `00`, part c writes two digits, and a window scale of zero writes `00`. The Wireshark dissector and the Zeek package both write it, and the deleted `technical_details/JA4T.md` corroborates it in prose. | 1 | #215 |
| Part e of JA4TS | Not implemented. | Write part e. A connection the server answered twice or more carries the delay of each SYN-ACK after the first, in whole seconds. A connection the server answered once omits part e. | 1 | #226 |
| The JA4TS value that a RST produces | Not implemented. | Append `-R` and the delay of the RST to part e, on a connection that already holds a delay. Read part a through part d from the first SYN-ACK. **Test the RST bit rather than the whole flag byte**, so a RST that also carries ACK reaches the rule. A RST on a connection with no delay produces no value, and a client RST produces no value. | 1 | #246 |

#### JA4H, JA4X, JA4D and JA4D6

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| The JA4H method code | `ja4h.go:171-173` reads the first two characters of any method token. | **No change. Already at parity.** Keep a test that holds the reading against a constructed `PROPFIND` request and a constructed `MKCOL` request. | 1 | #219 |
| JA4X on a stream that a proxy tunnel carries | Not measured. | Read the record layer without regard to the tunnel protocol that carries it. No FoxIO implementation holds the SOCKS4 values, and the same behaviour produces the `https-connect.pcap` values that two FoxIO references do hold. | 1 | #138 |
| Subfield 2 of JA4D when a message repeats option 57 | Not measured. | Write the first Maximum DHCP Message Size, in four digits. The dissector appends each occurrence to one buffer, which gives a part a of fifteen characters where the image gives eleven. | 1 | #231 |
| JA4D on a BOOTP message that carries no option 53 | Not measured. | Emit no value. Two FoxIO references against one, and the Zeek author recorded their own doubt in a comment. | 1 | #231 |
| Subfield 1 of JA4D6 on a relay message | Not measured. | Write the outer DHCPv6 message type alone, in five characters, so part a holds eleven characters. The dissector writes both the outer and the inner type, which gives sixteen. | 1 | #271 |

#### Interface

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| Result type | `FingerprintResult` struct with 9 fields. | No change. **The port adopted this field set**, including `Timestamp`, under rule 2. | 2 | — |
| Results per packet | A slice of results. | No change. The port adopted it. | 2 | — |
| Parse failures | Returned as a second value. | No change. The port adopted it. | 2 | — |
| Shard key format | `tcp:ip:port->ip:port`. | No change. Already at parity. Keep a test that proves it. | 2 | — |
| Mapping file refresh | `db update` and `db info`. | No change. Already at parity. Keep a test that proves it. | 2 | — |
| Remote lookup | One opt-in covers the local lookup and the remote call. | **Separate the local lookup from the remote lookup**, so the remote call needs its own opt-in. The port fixed the same shape in its Epic 7. `features/09-database-lookup.md` holds the work. | 2 | — |
| `CloseOpenWindows` | No equivalent method. | Add it. The port shipped `close_open_windows` first, so rule 2 names the port's word and this project writes the Go form of it. | 2 | #214 |
| The key-log interface | `types.go` exports `ErrNoSecret`, `KeyLog`, `ParseKeyLog`, `ReadKeyLogFromCapture`, `KeyLog.Secret`, `KeyLog.ClientRandoms`, `KeyLog.Len` and `DecryptQUICPacket`. | No change here. **This project shipped the interface first**, so rule 2 runs the other way and the port adopts these eight names. The port holds no key-log interface: a code search of `Crank-Git/ja4plus` for `keylog` returns no file. This row moves no fingerprint. | 2 | `Crank-Git/ja4plus#593` |

#### License and coverage

| Item | This project today | What must change | Rule | Ruling |
|---|---|---|---|---|
| The methods the FoxIO License 1.1 covers | The README claims BSD 3-Clause for the whole library, and links to a `LICENSE` file that does not exist. | Name the methods this project implements under the license, state that FoxIO's list is wider, and cite the pinned commit. **Assert no equality with FoxIO's list.** Three FoxIO records at the pinned commit name three different sets: `License FAQ.md:5` names twelve, the FoxIO `README.md:293` names nine, and `LICENSE:3` names thirteen and spells the scanner `JA4SScan`. | — | #388, #466 |
| JA4TScan | Not implemented, and round 2 declined it as an eleventh method. | Restate the decline. **The reason changes.** The port declined it as a capability boundary, because it sends crafted packets. This project declines it because FoxIO publishes no format and no implementation. The two repositories therefore hold one outcome and two readings, and this row records that. | — | #197 |

Verified against <https://github.com/Crank-Git/ja4plus> (`docs/specs/spec.md`, retrieved
2026-08-11, default branch `dev` at `v1.1.0`).

## Data model

The library holds no database. It holds in-memory state per connection, one embedded
lookup table, and one tracked register.

### `FingerprintResult`

| Field | Type | Meaning | Lifecycle |
|---|---|---|---|
| `Fingerprint` | `string` | The method output for the packet. | Created per packet. |
| `Raw` | `string` | The unhashed form, such as `JA4_r`. | Created per packet. |
| `RawOriginalOrder` | `string` | The wire-order unhashed form, `JA4_ro`. | Created per packet. Empty for methods that define no such form. |
| `Type` | `string` | The method name in lower case, such as `ja4h`. **`JA4LFingerprinter` writes `ja4l` and `ja4ls`.** | Created per packet. |
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
| `JA4TSFingerprinter` | `connections`, `results` | Five-tuple. **New. Part e and the RST value need the first SYN-ACK of the connection.** | `Reset`, `CleanupConnection` |
| `JA4LFingerprinter` | `connections`, `results` | Five-tuple | `Reset`, `CleanupConnection` |
| `JA4XFingerprinter` | `streams`, `processedCerts`, `results`, `lastCleanup`, guarded by `mu` | Five-tuple, certificate hash | `Reset`, `CleanupConnection`, an interval sweep |
| `JA4SSHFingerprinter` | `connections`, `packetCount`, `results` | Five-tuple | `Reset`, `CleanupConnection`, `CloseOpenWindows` |
| `JA4DFingerprinter` | `results` | — | `Reset` |
| `JA4D6Fingerprinter` | `results` | — | `Reset` |

Every fingerprinter appends to `results` and never truncates it. `CleanupConnection` does
not touch `results`. `features/02-correctness-audit.md` treats this as a suspected defect,
because `CleanupConnection` exists to stop state growth in a long-running process. **The
monitor makes that defect reachable**, so `features/13-live-capture.md` depends on the
audit closing it.

### The register

`testdata/deviations.json` holds one entry for each accepted difference from a FoxIO
value. The conformance suite reads it, and a comparison that the register names is
expected to differ. **An entry that no longer differs fails the suite**, so a closed
deviation cannot sit in the file unnoticed.

| Field | Type | Constraint |
|---|---|---|
| `key` | string | The capture, the stream and the method. |
| `capability` | boolean | `true` for a capability decline, `false` for a value decline. |
| `ours` | string | The value this project produces. |
| `theirs` | string | The value the FoxIO reference publishes. |
| `ruling` | string | The port issue or the local issue that holds the ruling. |
| `reason` | string | One sentence. |

### Lookup database

`data/ja4plus-mapping.csv` maps a fingerprint to an application name, a type and a note.
The library embeds the file with `go:embed` and loads it once through `sync.Once`.
`features/09-database-lookup.md` covers the reload path and the remote fallback.

## Cross-cutting concerns

### Concurrency

The core fingerprinters are not safe for use from more than one goroutine. The contract
after this work is explicit: one `Processor` serves one goroutine, and the caller routes
packets to processors with `GetShardKey`. `SyncProcessor` wraps a `Processor` and serves
callers who share one instance. **The monitor owns one `Processor` on one goroutine**, so
it needs no lock. `features/03-concurrency.md` holds the detail.

### Error handling

A fingerprinter returns a non-fatal error rather than a panic when a packet does not
decode. `Processor.ProcessPacket` collects the errors and returns them alongside the
results. A malformed packet never terminates the caller.

### Input validation

Every packet is untrusted input. Every parser bounds-checks every length field it reads
before it slices. The fuzz targets in `features/06-fuzz-testing.md` are the enforcement.

### Logging

The library writes nothing to standard output and nothing to standard error. The
command-line program owns all output. **The statistics line is command-line output**, and
`features/13-live-capture.md` places it in `cmd/ja4plus`.

### Rulings and evidence

- **A ruling carries a register entry or a test.** A ruling that neither records is a
  ruling a later reader cannot find.
- **A reading cites its source with a file and a line.** `docs/specs/foxio/` holds the
  transcriptions that a reading cites, and `features/11-foxio-reference.md` builds them.
- **Text copied from FoxIO material is verbatim.** `.claude/rules/ste.md` bars a
  rewording of it, because a reworded quotation is no longer evidence.

### Performance targets

- `Processor.ProcessPacket` allocates no more per packet after this work than before it.
- `SyncProcessor` adds one mutex acquisition per packet over `Processor`.
- The library holds no unbounded state for a connection that `CleanupConnection` removed.
- The project records the packet throughput of one named capture on one named host, and
  sets no target.

### Security posture

- The library performs no network input and no network output, except the opt-in database
  lookup that `features/09-database-lookup.md` covers.
- **The monitor is the one component that opens an interface.** It reads packets and
  sends none. `features/13-live-capture.md` states that boundary.
- The library reads no key material outside a capture file. **It reads a pcapng
  Decryption Secrets Block, because the block is part of the capture the operator already
  holds.** `features/05-conformance-gaps.md` holds that work.
- `govulncheck` gates every pull request.

### Accessibility and internationalization

The command-line program and the monitor write plain text. The documentation site inherits
the Material theme's contrast and keyboard behaviour. No further work is in scope.

## Environments & config

The library reads no environment variable. The command-line program, the monitor and the
test suite read the following.

| Name | Read by | What it does | Default |
|---|---|---|---|
| `JA4PLUS_DB_CACHE` | `lookup.go` | The path of the downloaded database cache file. | An operating-system cache directory. |
| `JA4PLUS_DB_LOOKUP` | `cmd/ja4plus` | When set to `1`, the program allows the remote lookup. The `--lookup-remote` flag does the same. **The name follows the port, under rule 2.** | Unset. |
| `JA4PLUS_FOXIO_DIR` | The conformance suite | The directory that holds the fetched corpus. | `testdata/foxio` |
| `JA4PLUS_FOXIO_REF` | The fetch script | The FoxIO commit to fetch. | The pin in `testdata/foxio.pin` |
| `GITHUB_TOKEN` | The workflows | Provided by GitHub Actions. The documentation workflow publishes to GitHub Pages with it. | Provided. |

The project holds no secret. The release workflow and the documentation workflow use the
GitHub-provided token only.

Seed data is the corpus. `make corpus` fetches it. `features/04-conformance-harness.md`
defines the script.

## Testing strategy

| Layer | What it covers | Command |
|---|---|---|
| Unit | One function or one fingerprinter, with a hand-built packet. | `go test ./...` |
| Race | The concurrency contract, under the race detector. | `go test -race ./...` |
| Conformance | Every method against every FoxIO vector, and the register. | `go test -tags conformance ./...` |
| Ruling | Every ruling that no vector separates, against a constructed packet. | `go test -run TestRuling ./...` |
| Fuzz | Every parser entry point against generated input. | `go test -fuzz=Fuzz -fuzztime=60s ./internal/parser` |
| Benchmark | The per-packet path, for allocation and time. | `go test -bench=. -benchmem ./...` |
| Mutation | The test cases that no mutation makes fail. | `make mutate` |
| Documentation | Every internal link of the site, and every code sample. | `mkdocs build --strict` |
| Pre-release | The released binary and `go install` from a clean environment. | `make prerelease` |

A change is done when six things are true.

1. `go build ./...` succeeds on the module floor.
2. `go test -race ./...` passes.
3. `golangci-lint run` reports nothing.
4. The conformance suite reports no new deviation, and the register holds no closed entry.
5. Coverage does not fall below the recorded floor.
6. `mkdocs build --strict` succeeds when the change touches a page.

## Epics

Epics 0 through 10 keep their round 2 numbers, so an existing issue keeps its epic. Round
3 adds Epics 11 through 16. **Epic 11 runs before Epic 8**, because Epic 8 cites the
material that Epic 11 writes.

### Epic 0: Foundation

**Goal.** Make the repository able to run every gate that the later epics add.

**Covers.** `features/00-foundation.md`

**Depends on.** Nothing.

**Exit criteria.** A fresh clone runs `make test`, `make lint`, `make bench`,
`make corpus` and `make conformance`. The `dev` branch exists. `.golangci.yml` pins the
linter set. **`go.mod` declares Go 1.24**, which it does not today. `CLAUDE.md` and
`.claude/` are tracked.

### Epic 1: License compliance

**Goal.** State the correct license terms for every part of the repository.

**Covers.** `features/01-licensing.md`

**Depends on.** Nothing. This epic runs first among the content epics, because the release
cannot ship without it.

**Exit criteria.** `LICENSE` and `NOTICE` exist. The README, the package documentation and
`data/ja4plus-mapping.csv` carry the FoxIO attribution. No document claims that the
FoxIO-licensed methods are BSD 3-Clause. **The README names the methods it implements
under the license and asserts no equality with FoxIO's list.**

### Epic 2: Correctness audit

**Goal.** Find and close every logic defect in the library, the parser and the
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

**Exit criteria.** `make corpus` fetches the corpus at the pinned commit. The harness reads
both the per-stream vectors and the per-packet vectors. **The harness reads the register,
and a comparison the register names is expected to differ.** The harness reports one row
per capture and per method.

### Epic 5: Conformance gap closure

**Goal.** Make every vector match, or record a decline.

**Covers.** `features/05-conformance-gaps.md`

**Depends on.** Epic 4 and Epic 11. The deviation list that Epic 4 produces defines the
work, and Epic 11 supplies the material that decides each disputed value.

**Exit criteria.** The conformance suite reports no deviation that the register does not
hold. Tunnel decapsulation and pcapng decryption-secret reading are implemented, or a
named requirement records why a vector is unreachable and the maintainer accepted it.

### Epic 6: Fuzz testing

**Goal.** Prove that no packet input can panic the library.

**Covers.** `features/06-fuzz-testing.md`

**Depends on.** Epic 0.

**Exit criteria.** A fuzz target exists for every parser entry point. A seed corpus exists
for each. A short fuzz run gates every pull request. A long fuzz run runs nightly. Every
crash the fuzzer finds is closed and its input joins the seed corpus.

### Epic 7: Supply chain and CI gates

**Goal.** Make the build reproducible and the dependencies watched.

**Covers.** `features/07-supply-chain.md`

**Depends on.** Epic 0.

**Exit criteria.** `govulncheck` gates every pull request. Dependabot watches Go modules
and GitHub Actions. **Every action reference is pinned to a commit hash**, which
`release.yml` does not do today. Coverage has a floor that CI enforces. Benchmarks run in
CI and report a regression.

### Epic 11: FoxIO reference material

**Goal.** Commit the material that every ruling cites, so a reader can check a claim
without leaving the repository.

**Covers.** `features/11-foxio-reference.md`

**Depends on.** Epic 0.

**Exit criteria.** `docs/specs/foxio/` holds one transcription per FoxIO image, the text
of the deleted `technical_details/*.md` files, and the Zeek reading. Each transcription
numbers its rules. `testdata/deviations.json` exists and the conformance suite reads it.

### Epic 8: Parity with the port

**Goal.** Close every row of the register that names a change to this repository.

**Covers.** `features/08-python-parity.md`

**Depends on.** Epic 4 and Epic 11.

**Exit criteria.** Every register row that names a change is closed and carries a test.
Every row that names no change carries a test that holds the current behaviour. `docs/
parity.md` records the port version it was read from. **No test in this repository runs
Python.**

### Epic 12: JA4LS

**Goal.** Implement the eleventh method.

**Covers.** `features/12-ja4ls.md`

**Depends on.** Epic 8, because the JA4L rows decide the form that JA4LS also writes.

**Exit criteria.** `JA4LFingerprinter` emits a result with `Type: "ja4ls"`. The
conformance suite compares it against the FoxIO vectors. Every document that states a
method count states eleven methods and ten fingerprinters, and a test holds that count.

### Epic 9: Database lookup

**Goal.** Decide and implement where the remote database lookup belongs.

**Covers.** `features/09-database-lookup.md`

**Depends on.** Epic 2.

**Exit criteria.** Network input and output sit behind an explicit boundary. **The remote
lookup carries its own opt-in, separate from the local lookup.** The client sets a
timeout, verifies the server certificate, and bounds the response size. The lookup table
reloads after an update within the same process.

### Epic 13: Live capture

**Goal.** Read packets from an interface until the operator stops the process.

**Covers.** `features/13-live-capture.md`

**Depends on.** Epic 2 and Epic 3. The monitor makes an unbounded state table reachable,
so the audit closes that first.

**Exit criteria.** `ja4plus watch` reads an interface on Linux with no cgo. The `libpcap`
build tag reaches macOS. **The default build and every released binary hold no cgo.** The
monitor answers a termination signal, holds bounded memory, and writes a statistics line
that reports the drop count.

### Epic 14: Documentation site

**Goal.** Publish the documentation to GitHub Pages.

**Covers.** `features/14-documentation.md`

**Depends on.** Epic 12, because the site holds one page per method.

**Exit criteria.** `mkdocs build --strict` succeeds. The site holds one page per method,
a usage guide, an output schema, a concurrency page and an API reference. A push to
`master` publishes it. A broken internal link fails the build.

### Epic 15: Mutation sweep

**Goal.** Find the tests that no mutation makes fail.

**Covers.** `features/15-mutation-sweep.md`

**Depends on.** Epic 6.

**Exit criteria.** `make mutate` runs the sweep over a named package set and writes a
report. Every candidate is settled: the test gains an assertion, or the report records why
the mutation is equivalent. The sweep runs on a schedule and does not gate a pull request.

### Epic 16: Pre-release validation

**Goal.** Prove that the artifact a user installs works.

**Covers.** `features/16-pre-release-validation.md`

**Depends on.** Every epic that changes behaviour.

**Exit criteria.** `go install` from a clean module cache produces a program that
fingerprints a capture. Each released binary runs on its platform and fingerprints a
capture. The documentation site builds from the committed pins in an empty environment.

### Epic 10: API freeze and release

**Goal.** Freeze the exported API and release `v1.0.0`.

**Covers.** `features/10-release.md`

**Depends on.** Every other epic.

**Exit criteria.** The exported API is recorded in `docs/api/v1.md`. The README, the
package documentation and the CHANGELOG describe the released behaviour. **GoReleaser
builds the tag** and attaches five binaries, the checksums and the software bill of
materials. `pkg.go.dev` serves the documentation, and GitHub Pages serves the site.

## Milestones

| Milestone | Epics | What "shippable" means |
|---|---|---|
| M1: Ready to work | Epic 0, Epic 1, Epic 11 | The repository runs every gate, the license is correct, and the reference material is committed. The library is safe to distribute. |
| M2: Known-correct | Epic 2, Epic 3, Epic 4 | Every defect the audit found is closed, the concurrency contract holds, and the deviation list is known. |
| M3: Conformant | Epic 5, Epic 6, Epic 8, Epic 12 | Every FoxIO vector matches or carries a register entry, no generated input panics the library, and the two implementations agree on eleven methods. |
| M4: Hardened | Epic 7, Epic 9, Epic 15 | The supply chain is watched, the network boundary is explicit, and the sweep found no unsettled candidate. |
| M5: Complete | Epic 13, Epic 14 | The monitor reads an interface, and the documentation site publishes. |
| M6: Released | Epic 16, Epic 10 | The artifacts install and run from a clean environment, and `v1.0.0` is tagged and published. |

## Assumptions

1. The maintainer accepts a Go 1.24 module floor, and accepts that consumers on Go 1.22
   and Go 1.23 stay on `v0.3.0`.
2. FoxIO keeps publishing the corpus at `FoxIO-LLC/ja4`. A pinned commit protects the
   project from a move for the life of the pin.
3. The FoxIO Wireshark vectors are authoritative for JA4D and JA4D6, because the FoxIO
   Python vectors for `dhcpv6.pcap` are an empty list.
4. The maintainer wants `dev` as the integration branch and `master` as the live branch.
   `master` stays releasable at all times.
5. A conformance failure blocks a merge. A benchmark regression warns and does not block.
6. **The port's rulings are adopted without re-litigation.** Each one carries a
   measurement in a closed port issue. This project re-measures a ruling only when a Go
   fact contradicts it.
7. **The macOS monitor is an opt-in build, and no released binary carries cgo.** The
   maintainer accepts that a macOS user who wants the monitor builds from source with the
   `libpcap` build tag.
8. The documentation site needs Python in one CI job. The maintainer accepts that, because
   the site matches the port's site and no Go generator produces the same pages.

## Risks & open questions

### R1 — The license split is a release blocker (resolved 2026-08-06)

FoxIO License 1.1 is a non-commercial license. `LICENSE-JA4` covers JA4 alone under BSD
3-Clause. The repository README claims BSD 3-Clause for the whole library and links to a
`LICENSE` file that does not exist.

Epic 1 implements the model that the FoxIO licensing FAQ recommends: the original Go code
stays BSD 3-Clause, and a `NOTICE` file carries the FoxIO terms.

**This spec is not legal advice.**

**The maintainer resolved this risk on 2026-08-06.** The dual model is sufficient for
`v1.0.0`. Epic 1 records the decision in `docs/audit/license-decision.md`.

**Round 3 adds one requirement.** The port's issues #388 and #466 measured three FoxIO
records at the pinned commit and found three different method lists: nine names, twelve
names and thirteen names. The README therefore names the methods this project implements
and asserts no equality with FoxIO's list.

Source: <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>,
<https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4>,
<https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md>, read 2026-08-06 at commit
`27f0cbf`.

### R2 — Two vectors may be unreachable (open)

`chrome-cloudflare-quic-with-secrets.pcapng` carries TLS secrets in pcapng Decryption
Secrets Blocks. `gopacket` does not read those blocks. `dtls-udp.notest.cap` carries the
`notest` marker, which means FoxIO excludes it from their own suite.

Epic 5 treats both as named requirements with their own issues. If reading a Decryption
Secrets Block proves impossible within `gopacket`, the requirement records the reason and
the maintainer accepts it before Epic 10 releases.

### R3 — Encapsulation support is unscoped until Epic 4 runs (open)

The corpus holds `gre-sample.pcap`, `gre-erspan-vxlan.pcap` and `tcpdump-geneve.pcap`.
`tshark` decapsulates all three. The library appears not to. Epic 5 is sized after Epic 4
finishes.

### R4 — The port carries the same license gap (closed, out of scope)

`Crank-Git/ja4plus` shipped the correction in its Epic 1. This project records the finding
and acts only on its own side.

### R5 — `gopacket` upstream is unmaintained (open)

`github.com/google/gopacket` has had no release since v1.1.19 in 2022. The community fork
is `github.com/gopacket/gopacket`. Epic 7 decides whether to migrate before the freeze.

**Round 3 raises the cost of this question.** `features/13-live-capture.md` builds on
`pcapgo.NewEthernetHandle`, so a migration now moves the monitor as well as the parser. A
decision after Epic 13 is more expensive than a decision before it.

### R6 — This is a large `v1.0.0` (open)

The maintainer chose one `v1.0.0` that carries every register row, JA4LS, the monitor, the
documentation site, the mutation sweep and the pre-release validation. **Seventeen feature
sets reach one tag.**

The gain is a freeze that covers the final shape: no exported name moves in a `v1.1.0`,
because JA4LS and the monitor are already in. The cost is a long path to the first `v1`
tag, and no user gets the license correction until the whole set lands.

**One mitigation is available and this spec does not take it.** Epic 1 alone could ship as
`v0.4.0` before the rest, because the license correction is the one change that a user is
harmed by waiting for. The maintainer decides whether to take it.

### R7 — The macOS monitor introduces cgo to a no-cgo project (open)

`CLAUDE.md` states "No cgo. The build cross-compiles to five platforms." The `libpcap`
build tag contradicts that sentence for one build.

`features/13-live-capture.md` contains the contradiction three ways. The default build
selects the pure-Go backend and holds no cgo. GoReleaser builds no tagged binary with the
tag. CI builds the tagged path on macOS to prove it compiles, and gates nothing else on
it. **Epic 13 rewrites the `CLAUDE.md` sentence** so that the rule states the containment
rather than an absolute.

The residual risk is that a macOS user reads the README, builds from source without the
tag, and finds `watch` unavailable. FR-capture-24 answers that with a message that names
the tag.

### R8 — A ruling can move on the port's side after this spec is approved (open)

Every register row is reversible. The port shipped `v1.1.0` on 2026-08-11, and it may rule
again.

This spec records the port version each row was read from. **The mitigation is a check,
not a promise.** Epic 8 adds a test that reads the port's `docs/specs/spec.md` register at
a pinned commit and compares its row count against the register here. **The test reads a
committed copy under `docs/specs/foxio/port-register.md` and performs no network call**,
so it obeys rule 3. A count that moves reports that a re-read is due.

### R9 — Three rulings the port never made (open, and each one blocks a requirement)

**FoxIO settles none of these three, and the port settled none of them either.** Each one
is the maintainer's to rule on. **An engineer who reaches one of these stops and asks.** A
requirement below is not built until the ruling exists, because a guess here produces two
answers across the two repositories, which is the one outcome parity exists to prevent.

The maintainer confirmed on 2026-08-11 that all three need a ruling. **A ruling lands in
this repository and in the port together.**

| Question | What is already settled | What is not | Blocks |
|---|---|---|---|
| **What does the ALPN field write when the first ALPN value is empty?** | A one-byte first value repeats the byte and writes `hh`. A first byte that is not alphanumeric writes `99`. | A zero-byte value. No FoxIO source states a rule, no vector carries the input, and the port's issues #141, #162 and #522 never reached it. | FR-parity-8, FR-parity-9, FR-parity-10 |
| **Does `CloseOpenWindows` belong on the `Fingerprinter` interface?** | The method exists, and the port's name decides the word under parity rule 2. | Where it sits. On `Fingerprinter` it matches the port and breaks every third-party implementation of an exported interface. On a second optional interface it breaks nothing and is the more idiomatic Go shape. **The freeze makes this the last chance to choose.** | FR-parity-30, FR-parity-31 |
| **Does `--types ja4l` alone print the JA4LS value?** | `JA4LFingerprinter` writes both methods. | The filter token. The port's filter names ten fingerprinters, so `ja4l` there reaches both values. FR-ja4ls-11 and FR-ja4ls-12 propose `ja4ls` as its own token here, which is more useful and which differs from the port. | FR-ja4ls-11, FR-ja4ls-12 |

**The second question has a deadline that the other two do not.** `Fingerprinter` is an
exported interface. Adding a method to it is a breaking change that `v0.3.0` permits and
that `v1.0.0` forbids for the whole `v1` series. If the ruling arrives after the freeze,
the only remaining answer is the optional interface.

## Issue map

`/spec-to-issues` created these on 2026-08-11, from spec version 3. Every issue carries the
marker `<!-- spec:ja4plus-go feature:<id> -->`, so a later planning wave reads the id and
re-issues nothing that already exists.

**Epic 8 reached the tracker as two epics.** Its 60 requirements slice along eight seams, and
one issue-flow batch holds six sub-issues at most. Epic 8a carries the TLS and latency methods,
and Epic 8b carries the TCP, HTTP, certificate and DHCP methods. Both point at
`features/08-python-parity.md`.

| Epic | Epic issue | Sub-issues | Feature file |
|---|---|---|---|
| Epic 0: Foundation | #3 | #4, #5, #6, #7, #8 | `features/00-foundation.md` |
| Epic 1: License compliance | #9 | #10, #11, #12, #13 | `features/01-licensing.md` |
| Epic 11: FoxIO reference material | #14 | #15, #16, #17, #18, #19 | `features/11-foxio-reference.md` |
| Epic 2: Correctness audit | #20 | #21, #22, #23, #24, #25 | `features/02-correctness-audit.md` |
| Epic 3: Concurrency contract | #26 | #27, #28, #29, #30 | `features/03-concurrency.md` |
| Epic 4: Conformance harness | #31 | #32, #33, #34, #35, #36 | `features/04-conformance-harness.md` |
| Epic 5: Conformance gap closure | #37 | #38, #39, #40, #41, #42 | `features/05-conformance-gaps.md` |
| Epic 6: Fuzz testing | #43 | #44, #45, #46, #47 | `features/06-fuzz-testing.md` |
| Epic 8a: Parity — the TLS and latency methods | #48 | #49, #50, #51, #52, #53 | `features/08-python-parity.md` |
| Epic 8b: Parity — the TCP, HTTP, certificate and DHCP methods | #54 | #55, #56, #57, #58 | `features/08-python-parity.md` |
| Epic 12: JA4LS | #59 | #60, #61, #62, #63 | `features/12-ja4ls.md` |
| Epic 7: Supply chain and CI gates | #64 | #65, #66, #67, #68, #69, #70 | `features/07-supply-chain.md` |
| Epic 9: Database lookup | #71 | #72, #73, #74, #75 | `features/09-database-lookup.md` |
| Epic 13: Live capture | #76 | #77, #78, #79, #80, #81, #82 | `features/13-live-capture.md` |
| Epic 14: Documentation site | #83 | #84, #85, #86, #87, #88 | `features/14-documentation.md` |
| Epic 15: Mutation sweep | #89 | #90, #91, #92, #93 | `features/15-mutation-sweep.md` |
| Epic 16: Pre-release validation | #94 | #95, #96, #97, #98, #99 | `features/16-pre-release-validation.md` |
| Epic 10: API freeze and release | #100 | #101, #102, #103, #104, #105, #106 | `features/10-release.md` |

### Issues that wait on a ruling

Five issues carry `status:needs-feedback`. **No worker may guess an answer to any of them.**

| Issue | Question | Recorded as |
|---|---|---|
| #50 | What the ALPN field writes when the first ALPN value is empty. | R9 question 1 |
| #53 | Whether `CloseOpenWindows` sits on `Fingerprinter` or on a second optional interface. **This one expires at the API freeze.** | R9 question 2 |
| #61 | Whether `--types ja4l` alone prints the JA4LS value. | R9 question 3 |
| #70 | Whether the project moves to the `gopacket` fork before the freeze. | R5 |
| #72 | Where the remote database lookup belongs. | FR-lookup-2 |

## Changelog

| Round | Date | What changed |
|---|---|---|
| 1 | 2026-08-06 | First draft, written from the Phase 1 interview and from the FoxIO reference at commit `27f0cbf`. |
| 2 | 2026-08-06 | The maintainer approved the spec and the scaffold. R1 resolved: the dual BSD 3-Clause and FoxIO `NOTICE` model is sufficient for `v1.0.0`. |
| 3 | 2026-08-11 | Revised after a read of the port at `v1.1.0`. Added the `Parity with ja4plus` register, which carries about twenty rows the port's own spec directs at this repository. Added Epics 11 through 16: the FoxIO reference material, JA4LS, live capture, the documentation site, the mutation sweep and the pre-release validation. Removed three non-goals, under the maintainer's rule that only a capability Go cannot achieve stays out of scope. Restated the JA4TScan decline on the ground that FoxIO publishes no format, rather than on the port's capability-boundary ground. Deleted FR-parity-8 through FR-parity-14, because the port's parity rule 3 rejects a cross-language test rig. Added R6, R7 and R8. |
| 4 | 2026-08-11 | The maintainer approved the spec and the scaffold. R6 resolved: the license correction waits for the full `v1.0.0`, and no `v0.4.0` ships first. Added R9, which holds the three rulings that neither FoxIO nor the port has made. The maintainer confirmed that all three need a ruling, and each one blocks its requirements until the ruling exists. |
| 5 | 2026-08-11 | Repaired four method counts that round 3 changed in `spec.md` and left stale in the round 2 feature files. FR-licensing-5 named nine methods under FoxIO License 1.1 and now names ten, and it states that JA4LS joins the list when Epic 12 lands. FR-release-7 and FR-release-17 named ten methods and now name eleven through ten fingerprinters. FR-foundation-20 asked for a benchmark for each of ten methods, and it now names the count the library implements today and points at Epic 12 for the eleventh. Added FR-licensing-5a, which states that `NOTICE` asserts no equality with FoxIO's own method list. Found while `/spec-to-issues` read the feature files. |
| 6 | 2026-08-11 | Epic 0 shipped. #32, which `features/04-conformance-harness.md` holds, moved into the Epic 0 batch: #6 adds a `corpus` target, and the target needs the fetch script that #32 writes. Without the move the criterion "make corpus fetches the corpus" could not pass inside Epic 0. The criterion "make conformance without a corpus prints a message that names make corpus" stays with #33, because `features/00-foundation.md:174` gives Epic 0 only the target that calls the harness. The `features/00-foundation.md` status moves to `built`. |
| 7 | 2026-08-11 | Epic 1 shipped. `LICENSE`, `NOTICE`, `data/README.md`, `docs/audit/license-decision.md` and `doc.go` land, and the README no longer states that the library is BSD 3-Clause without the FoxIO qualification. The maintainer named `Crank-Git` as the copyright holder and 2026 as the year. FR-licensing-14 landed as `data/README.md`, because `lookup.go` reads the first CSV row as the column header and sets no `Reader.Comment`, so a header comment would break every lookup. #114 joined the batch: `.claude/rules/rulings.md` named an absent `.claude/rules/conformance.md`, and it now points at `.claude/rules/parity.md`. `NOTICE` names nine methods, and Epic 12 adds JA4LS. |
| 8 | 2026-08-11 | FR-reference-25 and FR-reference-26 move from #19 to #33. Both name the conformance suite, and this repository holds no conformance suite today. A read of every Go file reaches `foundation_test.go` alone, which asserts the `make conformance` recipe and not a suite. #33 of Epic 4 builds the suite, so the two requirements land there. Acceptance criterion 6 of `features/11-foxio-reference.md` moves with them. #19 keeps FR-reference-17 through FR-reference-24, FR-reference-27 and FR-reference-28. `testdata/deviations.json` lands as an empty array, because no conformance run has measured a deviation. |
| 9 | 2026-08-11 | The maintainer ruled that the CI conformance job of #36 reports and does not fail on a deviation. FR-conformance-34 and FR-conformance-35 change meaning for that slice: the job runs the suite and publishes the counts. Epic 5 makes the job fail on a deviation. The reason is the measurement of #33, which found 302 matches and 1858 deviations over 38 captures against an empty register. A job that fails on a deviation stays red on every pull request until Epic 5 closes the list. FR-conformance-36 holds without a change, because a skipped suite that reports success hides every deviation. |
| 10 | 2026-08-11 | The maintainer ruled on #38 that the register and the exclusions page hold two distinct classes of fact. `testdata/deviations.json` holds a decline, where this project compared its output against a FoxIO value and chose to differ. `docs/audit/conformance-exclusions.md` holds an exclusion, where the suite makes no comparison at all. One question settles which record a fact reaches: does the guard "an entry whose comparison now matches fails the suite" make sense for this fact? `dtls-udp.notest.cap` decides the boundary, because FoxIO marks it `notest` and it reaches no `<capture>/<stream>/<method>` register key. The maintainer also renamed `docs/audit/conformance-exceptions.md` to `docs/audit/conformance-exclusions.md`, because this table bars `exception` as a synonym for `deviation` and bars `exception file` as a synonym for `register`. `## Terms` gains the word `exclusion`. FR-gaps-5, FR-gaps-20 and FR-release-44 carry the new name and require nothing new. The ruling opens no issue in the port, because it moves no fingerprint value and no exported name. |
| 11 | 2026-08-11 | The maintainer accepted eight exported names before the Epic 10 freeze: `ErrNoSecret`, `KeyLog`, `ParseKeyLog`, `ReadKeyLogFromCapture`, `KeyLog.Secret`, `KeyLog.ClientRandoms`, `KeyLog.Len` and `DecryptQUICPacket`. #40 of Epic 5 builds them for FR-gaps-15 through FR-gaps-18, and this is the first slice of the session to widen the exported surface. The `Interface` row of the register records the parity direction: this project shipped the key-log interface first, the port holds no such interface, and the port adopts these names under rule 2. The `Terms` table gains `key log`, `secret` and `decryption secrets block`. |
| 12 | 2026-08-11 | The maintainer ruled that a tunneled connection carries two keys, and not one. The reported key holds the outer address pair with the inner port pair, and the time-to-live reads the outer address layer. The grouping key holds the inner address pair with the inner port pair. The reason is that a mirror sends both directions of one session from one outer address pair, so the outer pair separates no direction and one connection then holds two measurement points that belong to two endpoints. `gre-erspan-vxlan.pcap` is that capture. The ruling adopts `Crank-Git/ja4plus` issue #242 under `.claude/rules/parity.md` rule 2, because this project shipped no tunnel decapsulation and the port ruled first. **The ruling opens no issue in the port, because the decision already lives there.** FR-gaps-13 and FR-gaps-14 of `features/05-conformance-gaps.md` now state the two-key rule, and FR-gaps-14a and FR-gaps-14b joined them. Recorded by #39. |
| 13 | 2026-08-11 | The infrastructure batch shipped, and **it moves no fingerprint value**. #162 states how `docs/audit/findings.md` classifies a `.go` file that a later issue adds to an audited directory, and the `Terms` table gains `added file`. #148 derives every fingerprinter list from `Processor.fingerprinters`, and it requires a `SyncProcessor` wrapper for each exported method of `Processor`. #165 adds `testdata/foxio/reference/` to the corpus, so a reading cites a FoxIO file and a line at the pinned commit. #142 makes the CI job read a marker line that only the conformance suite writes, so an untagged skip no longer fails the job with the wrong reason. The review of the batch then found that the corpus cache key named the pinned commit alone. Every run after #165 restored a corpus without the reference tree, and it downloaded the archive again. The key now reads the hash of `scripts/fetch-corpus.sh` too, so a layout change moves the key. |
| 14 | 2026-08-11 | The maintainer ruled that this repository adopts the value decline the port made under its issue 138. The QUIC CRYPTO stream reassembly of #42 makes the library produce a JA4 value and a JA4S value on every QUIC stream of the corpus that carries a handshake. The FoxIO Python implementation reads no QUIC handshake, so its expected-output file omits the stream and the suite reports the deviation kind `the library produces a value the vector does not hold`. The FoxIO Rust implementation produces the value the library produces, so the library is right and the reference published nothing to compare. Each deviation reaches `testdata/deviations.json` with `"capability": false`, and the key takes the shape `<capture>/<stream>/<method>` that `testdata/README.md` states. The port's own key shape is `<capture>/<method>`, and this repository declines it, because this suite compares per stream and a capture that holds two streams would collapse to one key. **The ruling opens no issue in the port, because the decision already lives there.** These are the first entries the register has ever held. Recorded by #42. |
| 15 | 2026-08-12 | The maintainer ruled that the library fills the TCP client measurement point from the packet `python/ja4.py:570` names, and that point `C` moves. The rule reads every packet that carries `ACK` and no `SYN`, with the relative sequence number 1 and the relative acknowledgement number 1. A payload does not bar the packet, and `python/common.py:101` omits `C` from the fields it declines to update, so a later packet replaces the point. A packet that carries a whole HTTP request moves no point, because `python/common.py:77-83` gives it a separate cache. **The four FoxIO implementations state three different rules, so this is a ruling and not a reading.** `docs/specs/foxio/JA4L.md` R33 records the four rules, and R34 records that the per-stream vector holds `2181_64` on stream 0 of `badcurveball.pcap` while the per-packet vector holds `2177_64_114797` on frame 9. Wireshark bars a payload-bearing packet at `wireshark/source/packet-ja4.c:1302`, Rust reaches a terminal state at `rust/ja4/src/time/tcp.rs:145`, and Zeek reads the second packet of the originator at `zeek/ja4l/main.zeek:103`. The ruling follows Python, because the per-stream vector is the set this suite compares per stream, and the Python rule reaches it on every comparison the set holds. **The ruling knowingly gives up the per-packet vector.** Thirty-five entries reach `testdata/deviations.json` with `"capability": false` and the ruling `#196`, and each reason states the part a divergence alone, because #197 owns the third part. **The conformance harness now compares the last emission** for a per-stream method that the vector holds once, at `conformance_adapters_test.go:435`. The library keeps its per-packet streaming contract, it suppresses no intermediate value, and it gains no flush. The same slice repaired two defects that the harness change exposed, and the reference is unanimous on both, so neither is a ruling: point `A` and point `B` no longer move, and the two endpoint names of the relative number read the grouping address pair. Measured against `epic/48-parity-tls-latency` at `3e7a47a` with the corpus present: 43 `JA4L-C` comparisons moved to match on 22 captures, and 35 per-packet `JA4L` comparisons gained a registered divergence. The per-stream set reports 703 matches and 514 deviations before, and 744 matches and 457 deviations after. The per-packet set reports 332 matches and 834 deviations before, and 332 matches and 833 deviations after. The register holds 150 keys before and 185 after. #205 and #206 hold the two comparisons the harness change leaves worse, both on `chrome-cloudflare-quic-with-secrets.pcapng` stream 0. **The ruling opens no issue in the port, because the port is the Python reading and the decision already lives there.** Recorded by #196. |
| 16 | 2026-08-12 | An engineer recorded the reading of the JA4L third part, and the question reaches the maintainer. **The reading is that the third part holds two different things, and that one rule for both produces a new wrong value.** On a TCP connection the third number is the Wireshark part c, which `docs/specs/foxio/JA4L.md` R24 names as the numerator of `ja4.ja4l_delta`. The `tcpdump-geneve.pcap` frame 13 vector holds `ja4.ja4l` as `93_64_124` and `ja4.ja4l_delta` as `1.3`, and `124 / 93` reads `1.3`. The `badcurveball.pcap` frame 9 vector holds `ja4.ja4l` as `2177_64_114797` and `ja4.ja4l_delta` as `52.7`, and `114797 / 2177` reads `52.7`. Issue #127 declines that part c, so the TCP part count is settled and this slice adds one test that holds it. **On a QUIC connection the third part is the marker `quic`, and the question is open.** `docs/specs/foxio/JA4L.md` R35 records the new fact. The two FoxIO vector sets state two different part counts for one QUIC connection, and two pairs separate the part count alone. On stream 36 of `ssh2.pcapng` the per-stream vector holds `JA4L-C` as `169_128` while the per-packet vector holds `ja4.ja4l` as `169_128_quic` on frame 1147. On stream 22 of `tls3.pcapng` the per-stream vector holds `JA4L-C` as `336_128` while the per-packet vector holds `ja4.ja4l` as `336_128_quic` on frame 162. **Two rulings point opposite ways.** Issue #127 writes the marker on a QUIC connection, and round 15 above follows the per-stream set where the two sets disagree. The measurement reads `epic/48-parity-tls-latency` at `887ab53` with the corpus present. The marker moves the library value on 16 per-packet comparisons and on 16 per-stream comparisons, across 3 captures. It closes 2 per-packet comparisons. It opens 13 per-stream comparisons that match exactly today. The per-stream set reports 744 matches and 457 deviations without the marker, and 731 matches and 470 deviations with it. The per-packet set reports 332 matches and 833 deviations without it, and 334 matches and 831 deviations with it. The register holds 185 keys before and 185 after, and no entry reads as closed. **This slice moves no fingerprint, and it writes no register entry.** The reason is that `.claude/rules/rulings.md` names a disagreement between the FoxIO implementations as a stop condition, and `.claude/rules/parity.md` names the vector set as the gate. Recorded by #197. |
| 17 | 2026-08-11 | The maintainer ruled on R9 question 2, and the question closes. `CloseOpenWindows` sits on a second optional interface, which this repository names `WindowCloser`, and the exported `Fingerprinter` interface does not change. The reason is that a new method on an exported interface breaks every third-party implementation, and `v1.0.0` forbids that break for the whole `v1` series. A caller discovers the interface with a type assertion, as a caller of `io.WriterTo` does. **FR-parity-30 changes meaning.** It read that every fingerprinter exports `CloseOpenWindows`, and that a stateless fingerprinter returns an empty slice. Under the ruling a stateless fingerprinter implements nothing, and `Processor` skips it. FR-parity-31 and FR-parity-32 hold without a change. A `type:spec-update` issue proposes the new wording of FR-parity-30, of R9 question 2 and of the four JA4SSH register rows, because a spec edit is its own issue. The same slice repaired the JA4SSH window: the threshold reads the packet count the caller names, it holds no upper cap, it counts the SSH packets of the two directions alone, and it declines a window that holds no SSH packet. The HASSH trigger goes, because the port holds no such rule. Measured against `epic/48-parity-tls-latency` at `ec0f63e` with the corpus present: 1807 JA4SSH comparisons moved on seven captures, the run reports 1035 matches before and after, 3155 deviations before and 1348 after, and 150 register keys before and after. **The ruling opens no issue in the port, because the port already carries `close_open_windows` and Python states no interface.** Recorded by #53. |
| 18 | 2026-08-12 | The maintainer ruled that the library writes the marker `quic` as the third part of a JA4L value on a QUIC connection. Two parts stay on a TCP connection. **Issue #127 holds the original ruling, and this slice reverses nothing.** The QUIC half of #127 was ruled in session 3, and the code never carried it. #197 found the gap. The deciding rule is that the library matches the port one to one, and that it follows the FoxIO material where that leaves a choice. **Round 16 above cited the wrong Python.** `python/ja4.py` is FoxIO's reference Python inside the corpus, and it is not the port. **The port writes the marker.** `ja4plus/fingerprinters/ja4l.py:62` defines `QUIC_MARKER = "quic"`, `:549` and `:602` write three parts with it, and `:446`, `:466` and `:482` write two parts on a TCP connection. The FoxIO material reaches the same answer, because `.claude/rules/rulings.md` ranks an image first and `docs/specs/foxio/JA4L.md` R3 states that a value holds three parts. The literal `quic` follows `wireshark/source/packet-ja4.c:1441` and `:1447`. **The two rulings do not collide.** #127 answers a part count, which an image decides, and round 15 above answers a value, which the per-stream set decides. **The match count falls, and the ruling accepts that.** A fingerprint exists for a comparison with another implementation. A rule that raised the match count against one vector set, and diverged from the port, would defeat the register. Measured on `batch/210-session5-followups` at `0751acc` with the corpus present: the marker moves the library value on 32 comparisons, across 3 captures. It closes 2 per-packet comparisons, and it opens 13 per-stream comparisons that match without it. The per-stream set reports 744 matches before and 731 after. The per-packet set reports 332 matches before and 334 after. The run reports 1076 matches before and 1065 after. Thirteen entries reach `testdata/deviations.json` with `"capability": false` and the ruling `#197`, and each reason states the per-stream divergence alone. The register holds 185 keys before and 198 after, and no entry reads as closed. **The ruling opens no issue in the port, because the port already writes the marker.** Recorded by #197. |
| 19 | 2026-08-12 | **The spec gains two requirements and one term, and it reverses nothing.** FR-gaps-14d states that `JA4Fingerprinter` and `JA4SFingerprinter` each hold an index that pairs the reported key with the grouping key, so `CleanupConnection` removes a tunneled connection. FR-gaps-14e states that `CleanupConnection` falls back to the key the caller gave, so a caller that names the grouping key removes the connection. The `## Terms` table gains `index`. **The two requirements record behaviour that #193 landed, and they complete FR-gaps-14c.** #169 added FR-gaps-14c for JA4L. The survey that #169 required found the same mismatch on JA4 and on JA4S, and #193 records that finding. **This is a reading and not a ruling.** No FoxIO source addresses a state table, because a state table reaches no fingerprint value. **The project manager accepted the two requirements in this round, and it opened no separate issue for them.** The ground is that they complete the pattern of FR-gaps-14c, and that they describe behaviour that lands in the same commit. **The change moves no fingerprint value.** Measured on `batch/210-session5-followups` at `c4978ab` with the corpus present: the run reports 1065 matches, 1288 deviations and 198 accepted deviations before and after. The register holds 198 keys before and after, and no entry reads as closed. That count holds the 13 entries of #197 and the 35 per-packet entries of #196. Coverage reads 71.4%. **The change opens no issue in the port, and the port needs none.** `ja4plus/fingerprinters/ja4.py` and `ja4plus/fingerprinters/ja4s.py` name `grouping`, `innermost` and `inner_` on no line, so the port holds no grouping key on those two methods and no two-key mismatch. `ja4s.py:143` writes `self._quic_dcids[f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"] = dcid`, and `ja4s.py:196-206` removes the same form. `ja4.py:449` writes `self._quic_dcid_to_tuple[dcid_key] = tuple_key`, and `ja4.py:473-481` matches the same shape. **The port reads the outer address layer on each QUIC branch.** `ja4.py:422` and `ja4s.py:83` each read `udp = packet.getlayer(UDP)`, so the port decapsulates neither method. Port issue #594 records that. **This repository holds the leak because it decapsulates and the port does not.** The port reaches FR-gaps-14d and FR-gaps-14e when it closes #594. Recorded by #193. |
