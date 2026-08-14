---
paths:
  - "*.go"
  - "internal/parser/*.go"
---

# Concurrency contract

This is an architecture invariant. Read it before you change any fingerprinter state, any
`Processor` method, or anything in `internal/parser/` that holds a map.

`docs/specs/features/03-concurrency.md` holds the requirements. This file holds the rule
that a change must not break.

## The contract

**One `Processor` serves one goroutine.** Every fingerprinter holds per-connection state
in a map or a slice, and none of it is guarded. This is a deliberate design, not an
oversight: the per-packet path stays lock-free so that a sharded caller keeps its
throughput.

A caller has two supported patterns.

1. **Shard.** Create one `Processor` for each goroutine. Route each packet with
   `GetShardKey`, which returns one key for both directions of a connection. No goroutine
   touches another goroutine's `Processor`.
2. **Share one `SyncProcessor`.** It wraps a `Processor` and serializes every call with
   one mutex. It costs one mutex acquisition per packet.

## Rules

- **Do not add a mutex to a fingerprinter.** That is what `SyncProcessor` is for. A lock
  on the core path defeats the design.
- **Do not add a package-level mutable variable** that a fingerprinter reads or writes.
  Package-level state breaks the shard model, because two shards then share it.
- **`SyncProcessor` does not embed `Processor`.** Embedding would export the unguarded
  methods and break the contract the wrapper exists to keep. It holds a `Processor` in an
  unexported field and exposes no way to reach it.
- **The mutex covers the whole call.** A result must not escape while the lock is
  released.
- **A new exported type that holds state documents its contract** in its doc comment. Say
  which of the two patterns applies.
- **A new state map has a removal path.** Add it to `CleanupConnection` and to `Reset`.
  State with no removal path leaks in a long-running monitor.
- **The lookup table of `lookup.go` is process-wide state, and one `atomic.Pointer` holds
  it.** #74 repaired the unguarded package-level state that suspected finding S3 records.
  A reader loads one immutable snapshot, so the steady-state read path takes no lock and
  this contract holds. **A reader that finds a changed cache file calls `rebuildTable`, and
  `rebuildTable` takes a mutex.** So the read path is lock-free in the steady state, and it
  is not lock-free at every call. **No fingerprinter reads that state**,
  so the rule above still bars a package-level variable on the packet path. See
  `docs/specs/features/09-database-lookup.md`, FR-lookup-19 through FR-lookup-22.

## Tests

A change that touches state runs `go test -race ./...`. A change that adds an exported
method to `Processor` adds the matching method to `SyncProcessor` and a race test for it.

One test deliberately shares a bare `Processor` between two goroutines and is expected to
fail under `-race`. It is marked so that CI does not run it. It exists to prove the
contract is real. Do not "fix" it.
