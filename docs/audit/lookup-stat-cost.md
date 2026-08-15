# The per-lookup `os.Stat` cost of the reload detection

**Issue #573 re-measured the cost that #74 added, and this page records the measurement and
the answer.** #74 replaced `sync.Once` with an `atomic.Pointer` snapshot on 2026-08-14, and
`activeTable` of `lookup.go` now stats the cache file at each lookup.

**The answer is answer 1 of #573: this project accepts the cost and it changes no code.**
Issue #573 is the reversal path.

## The machine and the date

**Every figure of this page comes from one machine on one day.** A later reader re-measures
rather than trusts these numbers, because a syscall cost moves with the machine.

| Fact | Value |
|---|---|
| Date | 2026-08-15 UTC |
| Processor | Apple M4, 10 cores |
| Operating system | macOS 26.6.1, build 25G76, Darwin 25.6.0 |
| Toolchain | go1.26.5 darwin/arm64 |
| Base | `origin/batch/679-http3-and-lookup-cost` at `3bf88a8` |

**#74 measured the same machine on 2026-08-14, and it named the Darwin version.** That
record reads `macOS 25.6.0`, and `sw_vers` reports the product version `26.6.1`. The two
name one machine, and `25.6.0` is the Darwin kernel version.

## The measurement

**Each row runs `go test -bench` with `-count=5` or more, and each cell states the median.**

| What the benchmark measures | Cost | Where the benchmark lives |
|---|---|---|
| One lookup, at the user cache path, with no cache file | **459 ns/op** | `BenchmarkLookupFingerprint` of `lookup_reload_test.go` |
| One lookup, at a short path, with a cache file present | **660 ns/op** | Issue #573, a scratch benchmark |
| The map read alone, with no stat | **6.2 ns/op** | `BenchmarkLookupTableRead` of `lookup_reload_test.go` |

**The map read reproduces the 6.6 ns/op that #74 recorded before its change.** So the stat
is the whole of the added cost, and #74 read it correctly.

**The recorded 614 ns/op of #74 sits inside the measured range, so this measurement confirms
that figure.**

### The cache path moves the cost, and the code does not

**One `os.Stat` costs more on a deeper path**, because the kernel resolves each component.
So the same line of code measures two numbers on one machine.

| Cache path | Cost of one lookup |
|---|---|
| `$HOME/Library/Caches/ja4plus/ja4plus-mapping.csv` | 459 ns/op |
| `/private/tmp/j573p/Library/Caches/ja4plus/ja4plus-mapping.csv` | 660 ns/op |
| `/tmp/j573h/Library/Caches/ja4plus/ja4plus-mapping.csv` | 1065 ns/op |

**The third row costs more than the second row because `/tmp` is a symbolic link to
`/private/tmp` on macOS.** The two paths hold the same number of components, and the
kernel resolves one link for the third row.

## No caller reaches `LookupFingerprint` per packet

**Four call sites of the module reach `LookupFingerprint`, and every one of them sits in
`cmd/ja4plus`.** The command
`grep -rn --include='*.go' 'LookupFingerprint' .` produces the list, and a filter that drops
`_test.go` leaves these.

| Call site | Rate |
|---|---|
| `cmd/ja4plus/main.go:313`, `:347`, `:378` | Once for each printed fingerprint of `ja4plus analyze`. |
| `cmd/ja4plus/watch.go:974` | Once for each emitted fingerprint of `ja4plus watch`. |

**No fingerprinter reaches it, and neither `processor.go` nor `sync_processor.go` reaches
it.** `examples/` reaches it in no file. The issue states the fingerprinter half of that
reading, and this page adds the two command paths.

**`monitorApplication` of `cmd/ja4plus/watch.go` is the closest thing to a per-packet
caller, and it is not one.** A fingerprint reaches the writer once for each emission, and
an emission needs a handshake rather than a packet. The `--lookup` option gates the call,
so a monitor that omits the option reaches no lookup at all.

**A monitor must emit about 21800 fingerprints in one second before the stat consumes one
percent of one core.** That figure divides 10 ms by 459 ns.

## What a real run costs

**A benchmark of one call is not the number that decides this, and #573 states that.** The
table below times `ja4plus analyze` over 20 runs of each capture, with the lookup and
without it.

| Capture | Fingerprints | Without `--lookup` | With `--lookup` |
|---|---|---|---|
| `tls-handshake.pcapng` | 181 | 9.61 ms | 9.91 ms |
| `ssh2.pcapng` | 138 | 13.03 ms | 13.39 ms |
| `tls3.pcapng` | 76 | 19.02 ms | 19.30 ms |
| `ssh-scp-1050.pcap` | 10 | 185.34 ms | 183.36 ms |
| `http2-with-cookies.pcapng` | 7 | 429.96 ms | 393.47 ms |

**The capture that emits the most fingerprints pays 83 µs for the stat**, which is 181
lookups at 459 ns. That is 0.9 percent of a 9.61 ms run.

**Two rows report a faster run with the lookup than without it**, so the noise of this
measurement exceeds the effect it tries to read. The predicted cost is the reliable figure,
and the measured difference is not.

## The three answers, and the reason for answer 1

**#573 names three candidate answers, and this page takes answer 1.**

- **Answer 1 — accept 459 ns/op.** The cost reaches no packet path, and it reaches 0.9
  percent of the measured run that emits the most fingerprints. **The chosen answer costs nothing to build, and it
  states no staleness window.**
- **Answer 2 — throttle the stat.** `## Answer 2 needs a ruling` below states the reading.
  It buys a saving that no measurement of this page shows a need for.
- **Answer 3 — add an exported name for the writer.** #100 freezes the exported surface at
  `v1.0.0`, so that answer belongs to the maintainer. **No measurement of this page makes
  answer 3 necessary.**

## Answer 2 needs a ruling

**Question 3 of #573 asks whether a staleness window needs a ruling, and it does.**

- **FR-lookup-18 states no interval.** It reads:

  > The library reloads the table after a database update, within the same process.

  A throttle adds an interval that the requirement does not hold.
- **`docs/specs/features/09-database-lookup.md` `### An analyst updates the database` step 6
  states the mechanism.** It reads:

  > A running process stats the cache file at its next lookup, and `activeTable` of
  > `lookup.go` rebuilds the table from the new file.

  **A throttle falsifies `at its next lookup`.**
- **The `## Behaviour rules` of that file publish the reload.** A staleness window changes
  what a user reads there.

**So answer 2 amends a published requirement and a published user flow.** `CLAUDE.md`
`## Conventions` names `A question the maintainer must rule` as one of the five filing
cases, and this is one. **A worker builds no throttle without that ruling.**

## What this reading does not cover

- **No figure of this page comes from Linux or from Windows.** A stat costs a different
  number on each kernel and on each file system.
- **No measurement reads a network file system.** A cache path on one would cost far more
  than 459 ns.
- **No measurement of this page moves a fingerprint value.** The conformance run before the
  change and the run after it report the same counts.
