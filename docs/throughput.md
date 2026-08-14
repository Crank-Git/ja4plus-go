# Packet throughput

**Wire-speed performance is out of scope for this project.** The `Non-goals` section of the
specification records that decline. The project measures the packet throughput, it records
the measurement, and it sets no target.

This page holds one measurement. It names the machine, the date and the command, because a
throughput number without those three states nothing a reader can reproduce.

## Measure it yourself

```bash
make bench
```

The target runs `go test -run '^$' -bench=. -benchmem ./...`. It runs the benchmarks and
no other test, and it reports the allocation count beside the time.

**Run the benchmark on your own hardware before you plan around a number.** The
measurement below reads one machine, and your machine is a different one.

## The measurement

| Record | Value |
|---|---|
| Date | 2026-08-14 |
| Operating system | `darwin` |
| Architecture | `arm64` |
| Processor | `Apple M4` |
| Command | `make bench` |

The output, verbatim:

```text
BenchmarkProcessorProcessesOneSYNPacket-10        	  218550	      6166 ns/op	    3865 B/op	      82 allocs/op
BenchmarkSyncProcessorProcessesOneSYNPacket-10    	  220341	      6051 ns/op	    3865 B/op	      82 allocs/op
BenchmarkJA4FingerprintsOneClientHello-10         	  105469	     12176 ns/op	    3305 B/op	     177 allocs/op
BenchmarkJA4SFingerprintsOneServerHello-10        	  657949	      1911 ns/op	     744 B/op	      28 allocs/op
BenchmarkJA4HFingerprintsOneHTTPRequest-10        	   52396	     22476 ns/op	    6876 B/op	     173 allocs/op
BenchmarkJA4LFingerprintsOneTCPHandshake-10       	  345261	      3276 ns/op	    2264 B/op	      46 allocs/op
BenchmarkJA4XFingerprintsOneCertificate-10        	   70819	     18584 ns/op	   13388 B/op	     205 allocs/op
BenchmarkJA4SSHFingerprintsOneSSHPacket-10        	  654200	      2142 ns/op	    1168 B/op	      22 allocs/op
BenchmarkJA4TFingerprintsOneSYNPacket-10          	 1232340	       970.6 ns/op	     632 B/op	      14 allocs/op
BenchmarkJA4TSFingerprintsOneSYNACKPacket-10      	  886860	      1867 ns/op	    1040 B/op	      24 allocs/op
BenchmarkJA4DFingerprintsOneDHCPMessage-10        	  796105	      1756 ns/op	     480 B/op	      22 allocs/op
BenchmarkJA4D6FingerprintsOneDHCPv6Message-10     	  709458	      1664 ns/op	     472 B/op	      21 allocs/op
```

## How to read the benchmark set

**Two benchmarks measure a whole `Processor`, and ten measure one fingerprinter.**

- `BenchmarkProcessorProcessesOneSYNPacket` runs every fingerprinter of the library
  against one TCP SYN packet. That is the cost of one `ProcessPacket` call.
- `BenchmarkSyncProcessorProcessesOneSYNPacket` runs the same packet through
  `SyncProcessor`, from one goroutine.
- Each remaining benchmark drives one fingerprinter with the packet that the method
  reads. `BenchmarkJA4FingerprintsOneClientHello` reads a TLS ClientHello, and
  `BenchmarkJA4XFingerprintsOneCertificate` reads one X.509 certificate.

**Each benchmark resets the state inside the timed loop.** The reset cost is therefore
part of every number above, and a long run amortizes it.

**A per-method number is not a share of the `Processor` number.** The `Processor`
benchmark sends one SYN packet, and a SYN packet reaches the methods that read a SYN. It
does not reach JA4, JA4H or JA4X.

## What the two `Processor` rows say about the mutex

In this run `SyncProcessor` reported 6051 ns/op and `Processor` reported 6166 ns/op. The
allocation counts are equal, at 3865 B/op and 82 allocs/op.

**Read no mutex cost from that pair.** The difference is smaller than the run-to-run
variation of one measurement, and the benchmark drives `SyncProcessor` from one goroutine.
An uncontended mutex is cheap, and this pair measures nothing else.

**The mutex costs throughput under contention, and this benchmark applies none.** The
[concurrency page](concurrency.md) states the two patterns and their trade. Measure the
patterns against your own traffic before you pick one.

## Where the allocations come from

The library allocates on the per-packet path, and the counts above show it. Two facts
bound what a caller can conclude.

- **`gopacket` decodes each packet, and that decode allocates.** The numbers above
  include it, because the benchmark builds a `gopacket.Packet`.
- **This project holds one performance requirement about allocation, and it is a
  no-regression rule.** `ProcessPacket` allocates no more for each packet after a change
  than before it. The requirement names no absolute number.

**The library holds no `sync.Pool`.** No buffer pool exists on the per-packet path today.

## The state that bounds a long run

A monitor that runs for days holds state for each connection it has seen. Two
fingerprinters carry a bound, and the [concurrency page](concurrency.md) states the caller
duty that goes with them.

| Fingerprinter | Bound | Idle limit |
|---|---|---|
| JA4SSH | 10000 connections | 600 seconds |
| JA4H | 100 streams | 600 seconds |

**JA4SSH sweeps for aged connections every 1000 packets.** It does not sweep for each
packet, so the sweep cost spreads across the run.

**A bound is not a substitute for `CleanupConnection`.** Call it for a connection that
ends.

## What this page does not claim

- **It states no packets-per-second figure.** A packets-per-second number depends on the
  traffic mix, and every benchmark above drives one packet shape.
- **It states no target.** The project sets none.
- **It compares this library with no other implementation.** No such measurement exists in
  this repository.
