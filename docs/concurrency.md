# Concurrency

!!! danger "One `Processor` serves one goroutine"

    Every fingerprinter holds per-connection state, and no lock guards it. Two goroutines
    that share one `Processor` write a data race. **The library does not detect that race
    at run time**, and it reports no error. The race detector reports it.

This page states the contract, and it states the two patterns that the library supports.
Read it before you give a `Processor` to a second goroutine.

## Why the core holds no lock

**The lock-free core is a design decision, and never an oversight.** A lock on the
per-packet path costs every packet, including the packets of a caller that uses one
goroutine. The library therefore puts the cost where the caller asks for it.

A caller who wants more than one goroutine takes one of the two patterns below. Each one
is supported, and each one has a different cost.

| Pattern | What it costs | When to take it |
|---|---|---|
| Shard | No lock on the per-packet path. | The caller can route packets. |
| Share a `SyncProcessor` | One mutex acquisition for each call. | The caller cannot route packets. |

## Pattern 1: shard

**Give each goroutine its own `Processor`, and route each packet by its connection.**
`GetShardKey` produces the routing key.

`GetShardKey` returns the sorted five-tuple, so a packet and its reply return one key.
That property is what makes the pattern correct: both directions of one connection reach
one shard, and one shard holds the whole connection.

Three more properties matter to a caller.

- **It reads no QUIC connection identifier.** Every packet of one QUIC connection returns
  one key after the identifier changes.
- **It returns an empty string for a packet that carries neither TCP nor UDP.** The caller
  decides what to do with an empty key.
- **It acquires no lock and holds no state.**

This program starts one goroutine for each shard, and it routes each packet to exactly one
of them:

```go
package main

import (
    "fmt"
    "hash/fnv"
    "os"
    "sync"

    ja4plus "github.com/Crank-Git/ja4plus-go"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/pcapgo"
)

func main() {
    const shards = 4

    f, err := os.Open("capture.pcap")
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    defer f.Close()

    reader, err := pcapgo.NewReader(f)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // This Processor computes routing keys, and it processes no packet. GetShardKey
    // holds no state, so one goroutine may use it while the shards run.
    router := ja4plus.NewProcessor()

    queues := make([]chan gopacket.Packet, shards)
    var wg sync.WaitGroup

    for i := range queues {
        queues[i] = make(chan gopacket.Packet, 1024)

        wg.Add(1)
        go func(in <-chan gopacket.Packet) {
            defer wg.Done()

            // This goroutine owns the Processor, and no other goroutine touches it.
            proc := ja4plus.NewProcessor()
            for pkt := range in {
                results, _ := proc.ProcessPacket(pkt)
                for _, r := range results {
                    fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
                }
            }
            // The goroutine that owns the Processor closes its windows.
            for _, r := range proc.CloseOpenWindows() {
                fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
            }
        }(queues[i])
    }

    for {
        data, ci, err := reader.ReadPacketData()
        if err != nil {
            break
        }
        pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
        pkt.Metadata().Timestamp = ci.Timestamp

        // A packet that carries neither TCP nor UDP returns an empty key, and the hash
        // of an empty key sends it to one fixed shard. Every packet reaches one shard.
        h := fnv.New32a()
        _, _ = h.Write([]byte(router.GetShardKey(pkt)))
        queues[h.Sum32()%shards] <- pkt
    }

    for _, q := range queues {
        close(q)
    }
    wg.Wait()
}
```

**The router `Processor` computes keys, and it processes no packet.** `GetShardKey` holds
no state, so that use is safe.

**Each shard closes its own windows.** `CloseOpenWindows` reads the state of one
`Processor`, so the goroutine that owns the `Processor` makes the call.

## Pattern 2: share one `SyncProcessor`

**`SyncProcessor` wraps a `Processor` and serializes every call with one mutex.** Every
method is safe to call from any number of goroutines at the same time.

```go
package main

import (
    "fmt"
    "os"
    "sync"

    ja4plus "github.com/Crank-Git/ja4plus-go"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/pcapgo"
)

func main() {
    f, err := os.Open("capture.pcap")
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    defer f.Close()

    reader, err := pcapgo.NewReader(f)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // Every worker shares this one SyncProcessor, and the mutex serializes each call.
    proc := ja4plus.NewSyncProcessor()

    queue := make(chan gopacket.Packet, 1024)
    var wg sync.WaitGroup

    for i := 0; i < 4; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for pkt := range queue {
                results, _ := proc.ProcessPacket(pkt)
                for _, r := range results {
                    fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
                }
            }
        }()
    }

    for {
        data, ci, err := reader.ReadPacketData()
        if err != nil {
            break
        }
        pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
        pkt.Metadata().Timestamp = ci.Timestamp
        queue <- pkt
    }
    close(queue)
    wg.Wait()

    // Every worker has stopped, so one call closes every open window.
    for _, r := range proc.CloseOpenWindows() {
        fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
    }
}
```

`SyncProcessor` carries the same method set as `Processor`: `ProcessPacket`, `Reset`,
`CleanupConnection`, `CloseOpenWindows`, `CloseConnectionWindow` and `GetShardKey`.

**The mutex covers the whole call.** No result escapes while the lock is released.

**`GetShardKey` takes the mutex too, although it needs no lock.** One rule governs the
whole type, so a reader needs no exception list.

**`SyncProcessor` does not embed `Processor`, and it exposes no way to reach the inner
`Processor`.** Embedding would export the unguarded methods and break the contract that
the wrapper exists to keep. A caller who reaches the inner `Processor` can break that
contract, so the library offers no path to it.

## Which pattern to take

**Take the shard pattern when the caller can route packets.** It gives higher throughput,
because the per-packet path acquires no lock.

**Take `SyncProcessor` when the caller cannot route packets.** An existing worker pool
that pulls from one queue is that case.

**Never mix the two on one `Processor`.** A `SyncProcessor` guards the `Processor` that it
holds, and it guards no other one.

## The state that a long run holds

**Call `CleanupConnection` for a connection that ends.** Every fingerprinter holds
per-connection state, and a caller that never releases it holds the state of every
connection it has seen.

Two fingerprinters carry a bound of their own, and neither bound replaces the call.

- **JA4SSH holds at most 10000 connections.** It evicts the least recently active
  connection when the table is full, and it drops a connection that is idle past 600
  seconds.
- **JA4H holds at most 100 streams**, and it drops a stream that is idle past 600 seconds.

`Reset` drops every connection at once. It suits the end of a capture file, and it does
not suit a monitor that must keep the connections that are still live.

## The database lookup holds one snapshot

**The mapping table is process-wide state, and one `atomic.Pointer` publishes it.** Every
goroutine of a program shares it, and no fingerprinter reads it. So the shard rule above
still holds: no package-level variable reaches the per-packet path.

**A reader loads the pointer and it reads one immutable snapshot.** `activeTable` in
`lookup.go` loads that pointer, and it returns the snapshot when the cache file is
unchanged. **That is the steady-state read, and it takes no lock.**

**A read that finds a changed cache file calls `rebuildTable`, and `rebuildTable` takes a
mutex.** So a reader takes the mutex on the path that rebuilds. **One goroutine parses the
file, and the others wait for it.** The read path is lock-free in the steady state, and it
is not lock-free at every call.

`LookupFingerprint` performs no network input and no network output. **The function that
reaches the network lives in the `ja4db` package**, and the
[usage guide](usage.md#the-database-lookup) names it.

## The tests that hold this contract

`go test -race ./...` runs the race tests of the library. `race_test.go` and
`sync_processor_test.go` hold them.

Several tests share one `SyncProcessor` between eight goroutines. They cover
`ProcessPacket`, `Reset`, `CleanupConnection`, `CloseConnectionWindow` and `GetShardKey`.
`TestShardedProcessors_SendEachConnectionToOneShard` proves the other pattern: it shows
that `GetShardKey` sends each connection to one shard.

**One test proves the contract by failing.**
`TestBareProcessor_ReportsARaceBetweenTwoGoroutines` in `race_negative_test.go` shares a
bare `Processor` between two goroutines, and the race detector reports the race. The build
tag `racecontract` keeps it out of every default run, so `go test -race ./...` never runs
it. Run it on purpose:

```bash
go test -tags racecontract -race -run TestBareProcessor_ReportsARaceBetweenTwoGoroutines .
```

**That test is expected to fail, and it is not a defect.** It exists to prove that the
contract on this page is real.
