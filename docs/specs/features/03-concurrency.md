---
id: concurrency
feature: Concurrency contract
epic: "Epic 3: Concurrency contract"
status: issued
issues: [26, 27, 28, 29, 30]
mockups: []
---

## Purpose

The library holds per-connection state and does not say who may touch it. Nine of the ten
fingerprinters hold unguarded maps and slices. `JA4XFingerprinter` alone holds a
`sync.Mutex`, which suggests that safety was intended and was not finished.

`Processor.GetShardKey` exists to route packets to shards. That is a shard-per-goroutine
design, and it is a sound one. Nothing in the exported documentation states it, so a
caller who shares one `Processor` between goroutines writes a data race and gets no
warning.

This feature set makes the contract explicit, and gives the caller a safe option when
they want one. The core stays lock-free and fast. A new `SyncProcessor` wraps it for
callers who share one instance.

## User stories

- As a library author, I want the documentation to state whether I may share a
  `Processor`, so that I do not write a data race.
- As a library author who runs one goroutine per shard, I want no lock on the per-packet
  path, so that my throughput stays high.
- As a library author who wants simplicity over throughput, I want a type I can share
  from many goroutines, so that I do not write the sharding myself.
- As a maintainer, I want a test that fails under the race detector when the contract
  breaks, so that a later change cannot break it silently.

## Functional requirements

### The documented contract

- **FR-concurrency-1** — The documentation comment on `Processor` states that one
  `Processor` serves one goroutine.
- **FR-concurrency-2** — The documentation comment on each of the ten fingerprinter types
  states that one instance serves one goroutine.
- **FR-concurrency-3** — The documentation comment on `Processor` names `GetShardKey` as
  the way to route packets to more than one `Processor`.
- **FR-concurrency-4** — The documentation comment on `Processor` names `SyncProcessor`
  as the way to share one instance.
- **FR-concurrency-5** — The package documentation in `doc.go` holds a section that
  states the contract for the whole package.
- **FR-concurrency-6** — The README holds a section that states the contract and shows
  both patterns.

### The safe wrapper

- **FR-concurrency-7** — The package exports a `SyncProcessor` type.
- **FR-concurrency-8** — `NewSyncProcessor` returns a `SyncProcessor` that holds a new
  `Processor`.
- **FR-concurrency-9** — `SyncProcessor` exports `ProcessPacket` with the same signature
  as `Processor.ProcessPacket`.
- **FR-concurrency-10** — `SyncProcessor` exports `Reset` with the same signature as
  `Processor.Reset`.
- **FR-concurrency-11** — `SyncProcessor` exports `CleanupConnection` with the same
  signature as `Processor.CleanupConnection`.
- **FR-concurrency-12** — `SyncProcessor` exports `GetShardKey` with the same signature
  as `Processor.GetShardKey`.
- **FR-concurrency-13** — `SyncProcessor` holds one `sync.Mutex` and acquires it for the
  whole of each exported call.
- **FR-concurrency-14** — Every exported method of `SyncProcessor` is safe to call from
  any number of goroutines at the same time.
- **FR-concurrency-15** — The documentation comment on `SyncProcessor` states that it
  serializes every call, and that a sharded `Processor` gives higher throughput.

### The core

- **FR-concurrency-16** — `JA4XFingerprinter` keeps its mutex, or removes it, and the
  choice is consistent with the other nine fingerprinters.
- **FR-concurrency-17** — `Processor` acquires no lock on the per-packet path.
- **FR-concurrency-18** — `GetShardKey` returns the same key for both directions of one
  connection.
- **FR-concurrency-19** — `GetShardKey` returns the same key for every packet of one QUIC
  connection, including a packet that carries a changed connection identifier.

### The tests

- **FR-concurrency-20** — A test drives one `SyncProcessor` from at least eight
  goroutines and passes under `-race`.
- **FR-concurrency-21** — A test drives one `Processor` per shard, routes packets with
  `GetShardKey`, and passes under `-race`.
- **FR-concurrency-22** — A test calls `Reset` on a `SyncProcessor` while other goroutines
  call `ProcessPacket`, and passes under `-race`.
- **FR-concurrency-23** — A test calls `CleanupConnection` on a `SyncProcessor` while
  other goroutines call `ProcessPacket`, and passes under `-race`.
- **FR-concurrency-24** — A benchmark reports the per-packet cost of `Processor` and of
  `SyncProcessor` side by side.

## User flows

### A caller shards for throughput

1. The caller creates one `Processor` for each shard.
2. The caller creates one goroutine for each shard.
3. For each packet, the caller calls `GetShardKey`.
4. The caller sends the packet to the goroutine that owns that key.
5. That goroutine calls `ProcessPacket` on its own `Processor`.
6. No goroutine touches another goroutine's `Processor`.

### A caller shares one instance

1. The caller creates one `SyncProcessor` with `NewSyncProcessor`.
2. The caller passes it to every goroutine.
3. Each goroutine calls `ProcessPacket` when it has a packet.
4. `SyncProcessor` serializes the calls.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- `SyncProcessor` does not embed `Processor`. Embedding would export the unguarded
  methods and would break the contract that the wrapper exists to keep.
- `SyncProcessor` holds a `Processor` in an unexported field, and exposes no way to reach
  it. A caller who reaches the inner `Processor` can break the contract.
- The mutex covers the whole call, not part of it. A result slice that a fingerprinter
  returns must not escape while the lock is released.
- `GetShardKey` sorts the five-tuple, so both directions produce one key. A QUIC packet
  whose connection identifier has changed still maps to the original tuple, because the
  fingerprinters hold the identifier-to-tuple map.
- The race tests use a capture from the corpus when Epic 4 has landed, and a built packet
  otherwise. A race test must not need a network.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `processor.go` | The documentation comment on `Processor` gains the contract. |
| `sync_processor.go` | New. Holds `SyncProcessor`. |
| `ja4.go` … `ja4d6.go` | Each type's documentation comment gains the contract. |
| `doc.go` | Gains a concurrency section. |
| `README.md` | Gains a concurrency section with both patterns. |
| `sync_processor_test.go` | New. Holds the race tests. |
| `benchmark_test.go` | Gains the side-by-side benchmark. |

## Interfaces

`SyncProcessor` is a module contract inside this package. Its shape mirrors `Processor`.

```go
// SyncProcessor wraps a Processor and serializes every call.
// Every method is safe to call from any number of goroutines.
// A SyncProcessor gives lower throughput than one Processor for each shard.
type SyncProcessor struct { /* unexported */ }

func NewSyncProcessor() *SyncProcessor
func (p *SyncProcessor) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, []error)
func (p *SyncProcessor) Reset()
func (p *SyncProcessor) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string)
func (p *SyncProcessor) CloseOpenWindows() []FingerprintResult
func (p *SyncProcessor) CloseConnectionWindow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) []FingerprintResult
func (p *SyncProcessor) GetShardKey(packet gopacket.Packet) string
```

The Go memory model decides what "safe" means here. See
<https://go.dev/ref/mem>. The race detector documentation is at
<https://go.dev/doc/articles/race_detector>.

## Edge cases & failures

| Case | What happens |
|---|---|
| A caller shares a bare `Processor` between goroutines. | The documentation states that this is not allowed. The race detector reports it. The library does not detect it at runtime. |
| A caller calls `Reset` on a `SyncProcessor` during a `ProcessPacket` call. | The mutex serializes the two calls. `Reset` runs before or after, never during. |
| A packet has neither a TCP layer nor a UDP layer. | `GetShardKey` returns an empty string. The caller decides what to do with it. The documentation states this. |
| A caller holds a result slice that a fingerprinter returned, and then calls `Reset`. | The returned slice is a copy that the caller owns. `Reset` does not change it. The audit in Epic 2 confirms this. |
| The shard count is one. | The sharded pattern reduces to a single `Processor`, which is correct and needs no lock. |

## Acceptance criteria

- [ ] `go doc github.com/Crank-Git/ja4plus-go Processor` prints the concurrency contract.
- [ ] `go doc` for each of the ten fingerprinter types prints the concurrency contract.
- [ ] `go doc github.com/Crank-Git/ja4plus-go SyncProcessor` prints the wrapper contract.
- [ ] `NewSyncProcessor` returns a usable `SyncProcessor`.
- [ ] `SyncProcessor` exports `ProcessPacket`, `Reset`, `CleanupConnection`,
      `CloseOpenWindows`, `CloseConnectionWindow` and `GetShardKey`, and nothing else.
- [ ] A test drives one `SyncProcessor` from eight goroutines and passes under
      `go test -race`.
- [ ] A test drives four sharded `Processor` values and passes under `go test -race`.
- [ ] A test that shares one bare `Processor` between two goroutines fails under
      `go test -race`, and it is marked so that CI does not run it.
- [ ] `GetShardKey` returns one key for a packet and for its reply.
- [ ] The benchmark reports a per-packet time for `Processor` and for `SyncProcessor`.
- [ ] The README shows both patterns as compiling Go code.

## Out of scope

- This feature set does not add a lock to any fingerprinter.
- This feature set does not add a worker pool, a queue or a shard manager. The caller
  owns those.
- This feature set does not bound the memory that a `Processor` holds. Epic 2 owns that
  through finding S1.
- This feature set does not make `lookup.go` safe for concurrent use. Epic 9 owns it.

## Open questions

None.
