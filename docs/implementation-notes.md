# Implementation notes

This page states the decisions that shape the code, and the reason for each one. It
answers the question a reader asks after they read the interface: why is it built this
way.

## The library writes nothing to the terminal

**The library writes nothing to standard output and nothing to standard error.** Every
line that a user sees comes from `cmd/ja4plus`.

A library that prints takes a decision away from its caller. A monitor that writes
structured logs cannot suppress a line that a library wrote.

## A fingerprinter returns an error, and it never panics

**Every packet is untrusted input.** A fingerprinter bounds-checks each length field
before it slices, and a malformed packet produces an error rather than a panic.

`ProcessPacket` on `Processor` returns two slices, and the second holds the errors of the
individual fingerprinters. **An error of one fingerprinter is non-fatal.** The other
fingerprinters still return their results for the same packet, and the caller continues.

That shape follows from what a fingerprint tool does. One malformed packet in a capture of
millions must not stop the run.

## Ten fingerprinters, and one of them writes two methods

`Processor` builds ten fingerprinter types. **`JA4LFingerprinter` writes both JA4L and
JA4LS**, so the count of fingerprinters and the count of methods are two different
numbers.

That is why `--types` accepts `ja4l` and `ja4ls` as separate tokens while one constructor,
`NewJA4L`, serves both. `ja4l` prints the client value and the server value, and `ja4ls`
prints the server value alone.

**Read the fingerprinter count as a count of types, and never as a count of methods.** The
method pages of this site state the method set.

## The lock-free core

**One `Processor` serves one goroutine, and no lock guards fingerprinter state.** The
per-packet path stays free of a lock so that a sharded caller keeps its throughput.

`SyncProcessor` carries the lock instead, for a caller that cannot route packets. The
[concurrency page](concurrency.md) states both patterns.

Two rules follow from that design, and the code holds both.

- **No fingerprinter carries a mutex of its own.** A lock on the core path defeats the
  design, and `SyncProcessor` is the supported answer.
- **No package-level mutable variable reaches a fingerprinter.** Package-level state
  breaks the shard model, because two shards would then share it.

## Every state map has a removal path

A monitor runs for days, so state with no removal path is a leak. Every state map reaches
`CleanupConnection` and `Reset`.

**Seven fingerprinters carry a bound as well, because a caller can forget the call.** Every
packet is untrusted input, so a sender opens one entry at the cost of one packet. **An
unbounded map is therefore a memory-exhaustion path**, and batch #432 closed the last nine
of them on 2026-08-14.

| Fingerprinter | Entry bound | Idle limit | How it evicts |
|---|---|---|---|
| JA4 | 1000 QUIC fragment connections | 30 seconds | The least recently touched connection leaves when the table is full. |
| JA4L | 10000 connections | 600 seconds | The least recently touched connection leaves when the table is full. |
| JA4S | 10000 connections | 600 seconds | The least recently touched connection leaves when the table is full. |
| JA4SSH | 10000 connections, and 1000 handshakes | 600 seconds | The least recently active connection leaves when the table is full. |
| JA4H | 100 streams | 600 seconds | The stream that received no segment longest leaves at the insert that reaches the bound. |
| JA4TS | 1000 connections | 120 seconds | The oldest connection leaves when the table is full. |
| JA4X | 50 streams, and 1000 certificates | A sweep every 30 seconds | The oldest stream leaves when the table is full, and the sweep drops the certificate record. |

**The TCP stream reassembler holds two bounds for one stream: 1 MB of stored bytes, and 4096
stored segments.** JA4H and JA4X each hold one reassembler, and each one refuses a further
segment of a stream that reaches either bound.

**The two bounds refuse independently, and neither one masks the other.** A sender of one-byte
segments reaches the segment bound at 4096 stored bytes. A sender of one large segment reaches
the byte bound with one stored segment. A refused segment leaves no trace, so the stream stores
it again after a removal frees the room.

**The maintainer ruled the segment bound on 2026-08-14**, and issue #596 holds the ruling and
the reversal path. `DefaultMaxSegments` in `internal/parser/tcp_stream.go` states the value.

**JA4T, JA4D and JA4D6 hold no per-connection state**, because each one reads a single
packet. None of the three needs a bound.

**JA4SSH sweeps for aged connections every 1000 packets**, and not for each packet. **The
eviction clock reads the capture timestamp**, and it does not read the wall clock. So a
capture file replays the same eviction that the live traffic produced.

## The packet decoder

The library reads packets through `github.com/gopacket/gopacket`. **That module is the
maintained fork, and it is not `github.com/google/gopacket`.** The maintainer decided the
move on 2026-08-13.

A caller builds the `gopacket.Packet` and passes it in, so the caller chooses the decode
options and the link type.

## The build holds no cgo, except behind one tag

**No package of the default build imports cgo.** `CGO_ENABLED=0 go build ./...` succeeds,
so a user who wants a binary with no C dependency sets that variable and gets one.

The release workflow builds five binaries:

| Operating system | Architecture |
|---|---|
| `linux` | `amd64` |
| `linux` | `arm64` |
| `darwin` | `amd64` |
| `darwin` | `arm64` |
| `windows` | `amd64` |

A build without cgo cross-compiles from one machine, and it links no system library at run
time. That is what makes the five-way build cheap.

**The release build sets `CGO_ENABLED=0` for each of the five builds.** So every released
artifact holds the setting, and the default of the build machine decides nothing.
`.goreleaser.yaml` states it in the build environment, and `release_cgo_test.go` guards it.

**No workflow of this repository sets that variable as a workflow-level, job-level or
step-level `env` key.** The release workflow runs `go test -race`, and the race detector
needs cgo. Such a setting would stop that step before it reached the build, so
`.goreleaser.yaml` owns the release build alone. `TestNoWorkflowSetsCgoEnabled` holds that
property, and it reads every workflow rather than the release workflow alone.

**One `run` line of `.github/workflows/ci.yml` still prefixes one `go build` command with
`CGO_ENABLED=0`.** A shell prefix binds one command, so it reaches no other step of the
job and it builds no release artifact. The guard permits it for that reason.

**#583 measured a gap on 2026-08-14, and #105 closed it on 2026-08-15 UTC.** The release
job ran on `ubuntu-latest`, so the `linux/amd64` build was native and it took the Go
default of `1`. The four cross-compiles took `0`. **GoReleaser now cross compiles all five
artifacts from one environment**, so one entry covers every platform and no artifact takes
the default. **Issue #583 is the reversal path.**

**Read the setting of any binary with `go version -m`.** It prints one `build
CGO_ENABLED=` line, so a reader confirms the property of an artifact rather than trusting
this page.

**One build path uses cgo, and the `libpcap` build tag selects it.** It exists so that
live capture reaches macOS, because the pure-Go capture handle reaches Linux alone. **That
tag builds no release artifact.** The [live-capture page](live-capture.md) states what is
built today.

## The language version and the build toolchain answer different questions

**These two statements answer two different questions, and this section states both.**

- **A language version decides which consumer compiles the module.**
- **A build toolchain decides which standard library a built binary links.**

**The language version is 1.26.** `go.mod` declares `go 1.26.0`, and a language version is
not a toolchain. So a consumer on a Go 1.26 toolchain compiles this module.

**The maintainer moved the version from 1.25 to 1.26 on 2026-09-30 UTC, and issue #791
holds the ruling.** The `golang.org/x/crypto` and `golang.org/x/net` dependencies each
declare `go 1.26.0` in their own `go.mod`. **A Go 1.25 consumer no longer compiles this
module.**

**The maintainer first moved the version from 1.24 to 1.25 on 2026-08-15, and issue #725 holds
the ruling.** The `gopacket` v1.7.1 dependency declares `go 1.25.0` in its own `go.mod`, and
it repairs a decoder panic on untrusted input, under `GHSA-6h9g-cjv3-pg2c`. **A Go 1.24
consumer no longer compiles this module.** The ruling lands in v1.1.0, and it moves no build
toolchain.

**The minimum build toolchain is `go1.26.11`.** A user who builds a binary from this source
takes go1.26.11 or a later toolchain, and the measurement below states why. `go1.26.11` is
the oldest Go 1.26 toolchain this project measured at zero called vulnerabilities, and no
claim here covers a patch that the tables do not name. A toolchain and a language version
are two different settings, and a reader who conflates them draws the wrong conclusion about
vulnerability exposure.

### The measurement

The maintainer ruled the toolchain question on 2026-08-14, and issue #472 holds the ruling.
**A vulnerability count is a live measurement, so each table below carries the date of the
run.** `govulncheck` reads the standard library of the `go` command on the PATH, so the
toolchain decides the result.

`govulncheck` v1.6.0 reported this on 2026-08-14, against the vulnerability database that
<https://vuln.go.dev> published at 2026-08-13 21:43:54 UTC:

| Toolchain | Called standard library vulnerabilities | Exit status |
|---|---|---|
| go1.24.13 | 13 | 3 |
| go1.25.13 | 0 | 0 |
| go1.26.5 | 4 | 3 |
| go1.26.6 | 0 | 0 |

`govulncheck` v1.6.0 reported this on 2026-10-14 UTC, against the vulnerability database
that <https://vuln.go.dev> updated at 2026-10-08 22:31:09 UTC:

| Toolchain | Called standard library vulnerabilities | Exit status |
|---|---|---|
| go1.26.8 | 9 | 3 |
| go1.26.9 | 0 | 0 |

`govulncheck` v1.6.0 reported this on 2026-10-28 UTC, against the vulnerability database
that <https://vuln.go.dev> updated at 2026-10-27 21:16:18 UTC:

| Toolchain | Called standard library vulnerabilities | Exit status |
|---|---|---|
| go1.26.9 | 1 | 3 |
| go1.26.10 | 0 | 0 |

`govulncheck` v1.6.0 reported this on 2026-11-15 UTC, against the vulnerability database
that <https://vuln.go.dev> updated at 2026-11-11 02:51:11 UTC:

| Toolchain | Called standard library vulnerabilities | Exit status |
|---|---|---|
| go1.26.10 | 1 | 3 |
| go1.26.11 | 0 | 0 |

**A later toolchain is not a clean toolchain by itself.** go1.26.5 is later than go1.25.13,
and it carries four. go1.26.8 is later than go1.26.6, and it carries nine. go1.26.9 carried
none on 2026-10-14 UTC, and it carries one on 2026-10-28 UTC. go1.26.10 carried none on
2026-10-28 UTC, and it carries one on 2026-11-15 UTC. So a user on the Go 1.26 line takes
go1.26.11 or later.

**No Go 1.24 patch clears the 13.** go1.24.13 is the newest Go 1.24 patch, and each
advisory names a fix in a go1.25.x release or a later one.

**The go1.24.13 row is a record of the 2026-08-14 measurement, and it names no toolchain a
builder may use today.** The language version moved to 1.25 on 2026-08-15, and to 1.26 on
2026-09-30 UTC, so a Go 1.24 toolchain or a Go 1.25 toolchain compiles no source of this
module.

**Every count above moves without a change to this repository**, because the vulnerability
database is live. Run `make vuln` to take the measurement again on your own toolchain.

**This project builds and releases on the range `~1.26.11`.**
`.github/workflows/ci.yml` names that range for every job, and
`.github/workflows/release.yml` names it for every released binary.

## The library embeds the fingerprint mapping, and a user replaces it

The library embeds `data/ja4plus-mapping.csv`, so a lookup needs no file and no network.
**`LookupFingerprint` performs no network input and no network output.**

`ja4plus db update` downloads a newer table into a cache, and `ja4plus db info` reports
which table the run reads. `GetDatabaseInfo` returns the same record to a Go caller.

**FoxIO publishes that mapping file, and FoxIO License 1.1 covers it.** The
[license page](licensing.md) states the terms.

## The output matches the FoxIO reference, and the register records each difference

**The FoxIO reference decides every disputed fingerprint value.** A test of this library
that disagrees with a FoxIO vector is wrong, and no vector is edited to make a test pass.

The repository holds a conformance suite that compares this library against the FoxIO
corpus. `make corpus` fetches the corpus at a pinned commit, and `make conformance` runs
the comparison.

**Each accepted difference carries an entry in `testdata/deviations.json`.** An entry
names the capture, the value this library produces, the value the reference produces, the
issue that settled it and one sentence of reason. **An entry whose comparison now matches
fails the suite**, so a difference that closes cannot sit in the file unnoticed.

**`make corpus` fetches the corpus, and no commit of this repository holds it**, because
FoxIO licenses that material. `testdata/foxio.pin` holds the commit, and the corpus is at
commit `16b96d95c220762cf658f67d678cda2aac95c81e` of <https://github.com/FoxIO-LLC/ja4>.

**The suite fails on a difference that the register does not hold.** It also fails on a
register entry whose comparison now matches. Each run rewrites
[`docs/audit/conformance.md`](https://github.com/Crank-Git/ja4plus-go/blob/master/docs/audit/conformance.md),
and that report owns the conformance figures. `docs/specs/foxio/` transcribes each FoxIO image
as numbered rules, and each ruling of this project cites one of them.

## Two implementations, one answer

A Python port of this project exists, and a user who runs both must get one answer. The
[parity page](parity.md) records how each name of the port maps onto this library.

**The shared FoxIO vector set is the gate, and no test of this repository runs Python.** A
cross-language test rig would couple two repositories that move at different speeds. It
would then fail for a reason that the change under test did not cause. Two implementations
that each match the reference match each other.

## Where a disputed value stops

**Where the FoxIO implementations disagree with each other, a person decides.** That is a
ruling, and the maintainer makes it. An engineer records a reading, which is a conclusion
about what a source states, with the file and the line that support it.

A ruling that no register entry and no test records is a ruling that the next reader
cannot find. So every ruling carries one or the other, and every ruling is reversible with
a new fact.
