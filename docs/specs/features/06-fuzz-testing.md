---
id: fuzz-testing
feature: Fuzz testing
epic: "Epic 6: Fuzz testing"
status: issued
issues: [43, 44, 45, 46, 47]
mockups: []
---

## Purpose

Every packet that this library reads is untrusted input. A network monitor feeds it
whatever arrives on the wire, and an attacker who can send a packet chooses that input.
A parser that reads a length field and slices without a bounds check turns a crafted
packet into a panic, and a panic in a monitor is a denial of service.

The unit tests use packets that a person wrote, so they test the shapes that a person
thought of.

This feature set adds a fuzz target for every parser entry point, seeds each from the
corpus, gates a short run on the batch pull request, and adds one nightly fuzz run.

## What Epic 6 built

**The four members of Epic 6 landed on 2026-08-14, and this section states the result.**
Each count below comes from a command that this section names. Read this section before you
read a requirement, because the requirements were written before the tree held any of it.

| What | Count | The command that measured it |
|---|---|---|
| Fuzz targets that `make fuzz` runs | 15 | `make fuzz` |
| Targets that #44 added | 13 | `grep -rn --include='*_test.go' '^func Fuzz' .` |
| Targets the tree already held | 2 | The same command, less the 13 above. |
| Files that hold the 13 new targets | 10 | The same command. |
| Seed files under the two corpus directories | 30 | `find testdata/fuzz internal/parser/testdata/fuzz -type f -not -name README.md` |

**The two targets the tree already held are `FuzzNoExportedFunctionPanicsOnAnyFrame` in
`audit_panic_test.go` and `FuzzTCPOptionEntriesReadsAnyOptionRegion` in
`ja4t_option_byte_count_test.go`.** No member of Epic 6 seeds either one.

**`internal/parser` holds 13 files that are not test files**, measured on 2026-08-14. Seven
of them carry a fuzz target in a file beside them.

### One target found a live panic in released code

**`FuzzParseServerHelloReadsAnyPayload` panicked after 1.14 seconds, on its first run.**
`ParseServerHello` read `extLen` from the wire and indexed `extData`, which the code clamps
to the end of the record. A record that declares a `supported_versions` length of 2 or more
and that holds no extension data made the guard true and the slice empty.

**#556 repaired `internal/parser/tls.go`, and that repair merged to `dev` separately.** The
crashing input is now a tracked seed at
`internal/parser/testdata/fuzz/FuzzParseServerHelloReadsAnyPayload/issue-556-supported-versions-declares-data-the-record-holds-not`,
which is the worked example of FR-fuzz-24.

**Epic 6 changed no line of the library.** A proof that no input panics the library reads the
code, and it never changes the code. **The one new file that is not a test file is
`internal/fuzzprop/fuzzprop.go`**, and ten `*_fuzz_test.go` files are the only files that
import it.

## User stories

- As a library author, I want a guarantee that no packet can panic the library, so that a
  hostile packet cannot stop my monitor.
- As a maintainer, I want a crash that the fuzzer finds to become a permanent test, so
  that the same crash cannot return.
- As a maintainer, I want a short fuzz run on every pull request, so that an obvious
  regression fails fast.

## Functional requirements

### The targets

- **FR-fuzz-1** — A fuzz target exists for `parser.ParseClientHello`.
- **FR-fuzz-2** — A fuzz target exists for `parser.ParseServerHello`.
- **FR-fuzz-3** — A fuzz target exists for the QUIC Initial packet decoder.
- **FR-fuzz-4** — A fuzz target exists for the QUIC CRYPTO frame reassembler.
- **FR-fuzz-5** — A fuzz target exists for the HTTP request parser.
- **FR-fuzz-6** — A fuzz target exists for the SSH packet parser.
- **FR-fuzz-7** — A fuzz target exists for the SSH KEXINIT parser.
- **FR-fuzz-8** — A fuzz target exists for the X.509 certificate parser.
- **FR-fuzz-9** — A fuzz target exists for the TCP stream reassembler.
- **FR-fuzz-10** — A fuzz target exists for the DHCPv4 parser.
- **FR-fuzz-11** — A fuzz target exists for the DHCPv6 parser.
- **FR-fuzz-12** — A fuzz target exists for `Processor.ProcessPacket`, which takes raw
  bytes and builds a packet from them.
- **FR-fuzz-13** — A fuzz target exists for each tunnel decoder that
  `features/05-conformance-gaps.md` adds. **This requirement names a file that no line of
  the tree holds**, and the reading below states what #44 built instead.

**FR-fuzz-13 names four decoders, and this repository holds none of them.** The
`## Data touched` table of `features/05-conformance-gaps.md` names `internal/parser/tunnel.go`
as a new file that holds the GRE, ERSPAN, VXLAN and Geneve decoders. **`ls
internal/parser/tunnel*` reports `tunnel_test.go` and `tunnel_fuzz_test.go` alone.**
`isTunnelLayerType` in `internal/parser/packet.go` states the reason:

> `gopacket` at v1.1.19 registers a decoder for each one, so the standard decode chain
> already reads the inner packet and this package adds no decoder.

**So a requirement that reads as four targets is satisfied by one.**
`FuzzCheckTunnelReadsAnyFrame` in `internal/parser/tunnel_fuzz_test.go` drives the
decapsulation code that this repository does hold: `TunnelDepth`, `CheckTunnel`,
`GetTCPLayer`, `GetUDPLayer`, `GetTCPPayload`, `GetIPInfo` and `GetGroupingIPInfo`. Its
seeds nest zero, one, four and five GRE layers, so they reach `MaxTunnelDepth` and one layer
past it. **#44 invented no decoder, and this round invents none.**

**`features/05-conformance-gaps.md` is the page of another feature, and this round does not
edit it.** A reader who needs the other half of this reading reads that page's
`## Data touched` table against the tree. **The round reports the disagreement and leaves
the repair to the epic that owns that page.**

### The properties each target asserts

- **FR-fuzz-14** — A target fails when the code under test panics.
- **FR-fuzz-15** — A target fails when the code under test reads past the end of its
  input.
- **FR-fuzz-16** — A target fails when the code under test does not return within one
  second for an input of 64 KB or less.
- **FR-fuzz-17** — A target fails when the code under test allocates more than 64 MB for
  one input.
- **FR-fuzz-18** — A target asserts that the same input produces the same output on a
  second call.

**One helper package carries all five, and #45 built it.** `internal/fuzzprop` exports
`ExactInput` and `Check`, and every one of the 13 targets calls both. Thirteen copies of one
property drift apart, and the two packages cannot share a `_test.go` file.
`internal/fuzzprop/fuzzprop_test.go` holds ten tests that prove each property fires.

**`internal/fuzzprop` sits under `internal/`, so the `v1.0.0` freeze binds no name it
exports.**

### FR-fuzz-14 needs no code, and #45 added none

**The Go test runner already fails a target on a panic, on both paths**, read at `go1.26.5`.
The seed replay path recovers the panic at `testing/testing.go:1955` and panics again at
`testing/testing.go:1974`. The worker path loses the worker process, and the coordinator
reports `fuzzing process hung or terminated unexpectedly` at `internal/fuzz/worker.go:145`.

**A recover-and-fail wrapper is worse than the default**, because it stops the runtime before
the runtime prints the stack. The crash report would then name the wrapper.

### FR-fuzz-15 is subsumed for one read, and `ExactInput` closes the second

**FR-fuzz-15 names a read past the end of the input, and Go reports that defect two ways.**
FR-fuzz-14 catches one of the two, and it does not catch the other.

1. **`input[i]` at or above the length panics.** FR-fuzz-14 fails the target, so this read
   needs no mechanism of its own. It is subsumed.
2. **`input[:n]` above the length and at or below the capacity panics for nothing.** It
   returns the bytes that follow the input in memory, and the target reads them as input.

**The second read is reachable, so FR-fuzz-15 is not fully subsumed.** `mutateBytes` writes
into a scratch slice at `internal/fuzz/mutator.go:112`, and `internal/fuzz/mutator.go:113`
assigns that scratch slice to the value the target receives.
**`internal/fuzz/mutator.go:107` is the assignment that gives the slice a capacity of
`maxPerVal` bytes**, and `internal/fuzz/mutator.go:106` is the test above it.
`internal/fuzz/mutator.go:56` computes `maxPerVal` from the whole byte budget. **Each line
above was measured at go1.26.5 on 2026-08-14**, and `internal/fuzzprop/fuzzprop.go` cites the
same four lines.

**One measured seed replay reported `len=5 cap=8` at go1.26.5.** **That measurement reads a
seed replay, and a seed replay reaches no mutator.** So it proves that the engine hands the
target a slice whose capacity is above its length, and it proves nothing about the four lines
above. **The conclusion holds under either path**, because FR-fuzz-15 needs one slice whose
capacity is above its length.

**`ExactInput` returns a copy whose capacity equals its length**, so the second read panics
and FR-fuzz-14 then reports it. #45 measured both sides: the same expression returns 6 bytes
before the copy, and after the copy it raises
`runtime error: slice bounds out of range [:6] with capacity 5`.

### FR-fuzz-17 names no mechanism, and #45 chose one by measurement

**The requirement bounds bytes, and it names no way to count them.** #45 read three
mechanisms and took the third.

| Mechanism | Why it fits, or does not |
|---|---|
| `testing.AllocsPerRun` | It counts allocations, and FR-fuzz-17 bounds bytes. It also calls the function more than one time and it stops the garbage collector, so it changes the run it measures. |
| `runtime.ReadMemStats` | It reports the bytes. One call measured **24736 ns**, so two calls for each input spend about 50 microseconds of every execution. |
| `runtime/metrics.Read` | **Chosen.** It reports the same bytes, and one call measured **230.7 ns**. |

Both measurements ran on an Apple M4 at `go1.26.5`, at `-benchtime 2000x`.
`/gc/heap/allocs:bytes` is documented as `Cumulative sum of memory allocated to the heap by
the application.`, so the difference of two reads is the count of bytes one call allocated.

**`Check` compares the lower of two duration measurements against the FR-fuzz-16 bound.** A
scheduler delay adds time and it never removes time, and the fuzz engine runs ten workers at
once on this machine. A parser that needs more than one second needs it on both calls.

**No input of any target reached 100 ms**, which is one tenth of the FR-fuzz-16 bound. #45
set the bound to 100 ms, ran every target for 10 seconds, executed about 7.7 million inputs
across the 15 targets, and recorded zero FR-fuzz-16 failures. **The bound needs no move, and
no member moved it.**

### The seed corpus

- **FR-fuzz-19** — Each target has a seed corpus under `testdata/fuzz/`.
- **FR-fuzz-20** — The seed corpus for a target holds at least one input that the code
  accepts.
- **FR-fuzz-21** — The seed corpus for a target holds at least one input that the code
  rejects.
- **FR-fuzz-22** — `scripts/seed-fuzz.sh` extracts seed inputs from the FoxIO corpus.
- **FR-fuzz-23** — The seed corpus is tracked in git, because it holds no FoxIO material
  once it is reduced to a protocol record.
- **FR-fuzz-24** — Each crash that the fuzzer finds joins the seed corpus as a named file.

**FR-fuzz-19 names one directory, and the tree holds two.** Go reads
`testdata/fuzz/<TargetName>/` under the directory of the package that holds the target. So
the seeds of the root package live at `testdata/fuzz/`, and the seeds of `internal/parser`
live at `internal/parser/testdata/fuzz/`. **Go states the location, and no member of Epic 6
chose it.** The requirement holds for both directories.

**The 30 seed files cover the 13 targets of Epic 6, and they cover neither pre-existing
target.** `FuzzNoExportedFunctionPanicsOnAnyFrame` and
`FuzzTCPOptionEntriesReadsAnyOptionRegion` carry `f.Add` seeds alone.

### `JA4PLUS_SEEDGEN=1` must never reach a CI job

**`fuzz_seed_corpus_test.go` of each package builds every seed, asserts the result of the
code for it, and then compares the tracked file against the value it built.**
`JA4PLUS_SEEDGEN=1` switches that test from compare to write.

**A CI job that sets `JA4PLUS_SEEDGEN` turns the guard into a rubber stamp.** The test then
rewrites every seed to match whatever the code now does, and it reports success whatever the
code does. **The guard can then never fail.** An engineer sets the variable by hand, after a
deliberate change to a seed, and never in a workflow file.

**#47 built two checks that hold this rule, and both are in the tree.**

- Each fuzz job of `.github/workflows/ci.yml` and `.github/workflows/fuzz.yml` refuses a run
  that carries the variable, with `if [ -n "${JA4PLUS_SEEDGEN:-}" ]; then`.
- `TestNoWorkflowSetsTheSeedGenerationVariable` in `fuzz_job_test.go` reads both files for an
  assignment and for an environment key. `TestEachFuzzJobRefusesASeedCorpusWrite` reads both
  jobs for the refusal.

**`testdata/fuzz/README.md` states the same rule**, because a person who changes a seed reads
that file first.

### The gates

- **FR-fuzz-25** — `.github/workflows/ci.yml` runs each fuzz target for 30 seconds on
  every pull request. **This project runs CI once for each batch, so the job runs on the
  batch pull request alone.** The reading below states why.
- **FR-fuzz-26** — The pull-request fuzz job fails when any target finds a crash.
- **FR-fuzz-27** — `.github/workflows/fuzz.yml` runs each fuzz target for 10 minutes on a
  nightly schedule.
- **FR-fuzz-28** — The nightly job opens an issue when a target finds a crash.
- **FR-fuzz-29** — The nightly job attaches the crashing input to the issue.
- **FR-fuzz-30** — `go test ./...` runs every seed input as a normal test, with no fuzz
  time.

### FR-fuzz-25 reads "every pull request", and the job runs on the batch pull request

**The `fuzz` job of `.github/workflows/ci.yml` declares no trigger of its own**, so it takes
the two triggers at the head of that file:

```yaml
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master, dev]
```

**Two facts hold the job back from a member pull request.** A member pull request targets an
integration branch such as `epic/43-fuzz-testing`, and no branch filter names an integration
branch. Every member commit ends with `[skip ci]`, and the documentation states
`Skip instructions only apply to the push and pull_request events.`

**So the batch pull request into `dev` is the first run of this job.**
`TestThePullRequestFuzzJobAddsNoTrigger` in `fuzz_job_test.go` reads the job for a trigger key
and fails on one.

### FR-fuzz-27 ships in this batch, and the first nightly run starts later

**A scheduled workflow starts no run until the workflow file reaches the default branch.**
The default branch of this repository is `master`, and Epic 6 merges to `dev`. The
documentation states both halves:

> Scheduled workflows run on the latest commit on the default branch.

> This event will only trigger a workflow run if the workflow file exists on the default
> branch.

Verified against
<https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>,
retrieved 2026-08-14.

**A reader who watches the Actions page of `dev` for a nightly run sees nothing, and that is
the documented behavior rather than a defect.** The first nightly run starts after
`.github/workflows/fuzz.yml` reaches `master`, through `dev` and a release.
**`.github/workflows/fuzz.yml` carries a `workflow_dispatch` trigger beside the schedule**, so
a maintainer starts a nightly fuzz run by hand before then.

### A run longer than 10 minutes needs `-timeout 0`

`go help testflag` states `-timeout d ... The default is 10 minutes (10m).` So a 10-minute
fuzz run under that default panics before the fuzz run ends, and the nightly command carries
`-timeout 0`. **`make fuzz` runs 30 seconds for each target, so the recipe never meets the
limit and it needs no change.** A later issue that raises the fuzz time of any command carries
the flag with it.

### A timeout is not a crash, and the nightly job separates the two

**A job that reads the exit status alone would open a false issue on each stalled night.**
Issue #568 records a measured stall of `FuzzParseCryptoFramesReadsAnyPayload`, and #568
reproduced that stall on 2026-08-14. `### The stall of #568 is a coverage minimization`
below states the reading. The `Classify the result` step reads the tree instead, and it
returns one of three results.

| Result | What produced it | What the job does |
|---|---|---|
| `clean` | The run exited 0. | The job passes. |
| `crash` | The run failed, and the tree gained an input file. | The job opens an issue, and it fails. |
| `failure` | The run failed, and the tree gained no input file. | The job opens no issue, and it fails. |

A stall, a build failure and a failing seed each reach `failure`. Each one turns the job red
and names itself in the log, and none of them opens an issue.

### The stall of #568 is a coverage minimization

**Issue #568 states two readings, and the measurement of 2026-08-14 separates them.**

> 1. The fuzz engine stalls, and `ParseCryptoFrames` returns for every input.
> 2. `ParseCryptoFrames` hangs on an input, and the engine reports the stall rather than the
>    input.

**Reading 1 holds, and reading 2 is false.** Every measurement below ran on an Apple M4 at
`go1.26.5` on 2026-08-14, and the machine carried other work throughout.

#### `ParseCryptoFrames` cannot fail to return

**Every loop of `ParseCryptoFrames` in `internal/parser/quic.go` consumes one input byte or
it leaves.** The outer loop advances `pos` on each branch, and it breaks on an unknown frame
type. **The one loop that reads an attacker-controlled trip count is the additional ACK range
loop**, and the count reaches 4611686018427387903. **`DecodeVarint` bounds that loop
anyway.** Each iteration calls `DecodeVarint`, and `DecodeVarint` returns an error when
`pos` reaches the length of the input. **Each successful `DecodeVarint` advances `pos` by
one byte at least**, so the iteration count cannot exceed the input length.

**The 40 runs that carried no minimization bound reported 60794671 executions and no
failure.** No run reported the FR-fuzz-16 message, which `Check` in `internal/fuzzprop`
writes when the lower of two calls takes more than one second.

#### The parser holds 0.03 percent of the cost of one execution

**`BenchmarkParseCryptoFramesReadsTheFuzzCorpus` in
`internal/parser/quic_crypto_fuzz_cost_test.go` reports 28.13 ns for one call**, at
`-benchtime 2s`. **`BenchmarkParseCryptoFramesUnderTheFuzzPropertiesReadsTheFuzzCorpus`
reports 642.4 ns**, over the same corpus. **The second benchmark copies the shape of `check`
in `internal/fuzzprop/fuzzprop.go`, and it omits three steps of it.** It omits the two
`time.Now` and `time.Since` pairs, the FR-fuzz-16 duration comparison and the FR-fuzz-17
allocation comparison. **So 642.4 ns is a lower bound of the harness cost.**

**The fuzz engine reported about 120000 executions each second over 10 workers**, which is
about 83 microseconds for one execution on one worker. **So the engine holds about 99
percent of that time**, the property harness holds about 0.8 percent, and the parser holds
about 0.03 percent. **Neither the parser nor the property harness can produce a stall of
seconds.**

#### The coordinator counts no execution while a worker minimizes

**One coverage minimization occupies one worker, and the coordinator counts no execution
until that minimization returns.** `logStats` in `internal/fuzz/fuzz.go` prints `minimizing`
for a crash minimization alone, so a coverage minimization prints nothing at all.

**A run of `-fuzztime 30s` from an empty cache corpus reproduced the reported signature.**
Run 5 of ten reported this:

```
fuzz: elapsed: 15s, execs: 203058 (3516/sec), new interesting: 53 (total: 59)
fuzz: elapsed: 18s, execs: 203058 (0/sec), new interesting: 53 (total: 59)
fuzz: elapsed: 21s, execs: 203058 (0/sec), new interesting: 53 (total: 59)
```

**`GODEBUG=fuzzdebug=1` names what those six seconds held.** The same run then reported three
minimizations that each covered the whole window:

```
minimizing took: 23.009211375s
minimizing took: 23.428790875s
minimizing took: 18.708534583s
```

**The frozen count reports that no worker fuzzed during that window.** `workerFuzzDuration`
in `internal/fuzz/worker.go` gives a worker 100 milliseconds of fuzzing for each input, so a
worker that fuzzes returns a result ten times each second. **The debug log names three
minimizations that cover the window, and it names no state for the other seven workers.**

**The longest minimization of the 30-second runs took 26.39531s, and the longest of the
10-second runs took 9.1589115s.** **So the fuzz time bounds the minimization, and convergence
does not.** `go help testflag` states `-fuzzminimizetime t ... The default is 60s.`, which is
twice the 30 seconds that `make fuzz` gives each target.

#### The stall needs a corpus that grows

**Ten runs against a cache corpus of 83 entries held 37877 executions each second at least,
and every one passed.** Each one reported `new interesting: 0`.

**A rate of `0/sec` on the last line of a run reports no stall.** `CoordinateFuzzing` in
`internal/fuzz/fuzz.go` defers one more `logStats` call, and that call divides a delta of
about zero executions by a delta of about zero seconds. **Every one of those ten runs holds
one such line, and each one sits at the same elapsed time as the periodic line above it.**
**A stall holds the same execution count over two periodic lines**, three seconds apart.

**Ten runs from an empty cache corpus reported 41 to 71 new interesting inputs each, and two
of them stalled.** **The report of #568 records `total: 67` and `total: 71`**, so that run sat
in the same phase.

**A fresh CI runner holds no cache corpus**, so a nightly fuzz run starts in the phase that
stalls.

#### The failure of the report is a known defect of the Go fuzz coordinator

**A second reader confirmed this reading against the `go1.26.5` source on 2026-08-14**, and
the defect is already reported and already repaired upstream.

**The reported run failed with `context deadline exceeded` and it wrote no input file.**
`testing/fuzz.go:368-377` prints `Failing input written to %s` for a `fuzzCrashError` alone.
**`context.DeadlineExceeded` is no `fuzzCrashError`**, so that branch never runs and no
reproducer reaches the corpus.

**The defect is one asymmetry, and `internal/fuzz/fuzz.go` holds both halves.**
`fuzz.go:105-117` reads `doneC` from the parent `timerCtx`, and `fuzz.go:129` suppresses the
error against the child `fuzzCtx`:

```
if err == fuzzCtx.Err() || isInterruptError(err) {
```

**`context/context.go:556-574` orders the cancellation, and the order is synchronous.**
`cancelCtx.cancel` stores its own error at `:561`, closes its own Done channel at `:567`,
then cancels each child at `:569-572`. **So a reader that wakes on the parent Done channel
can read a child error of nil**, and the comparison at `fuzz.go:129` then fails.

**The leaked value is `context.DeadlineExceeded`**, because `cancelCtx.cancel` gives each
child the error value of its parent.

**Two probes measured the window.** One measured 48 nil child reads over 200000 rounds, and
an independent one measured 51. **Both report a rate near 0.025 percent.**

**The minimization is a co-occurrence, and never the cause.** `internal/fuzz/worker.go:239-262`
gives `minimize` its own `WithTimeout(ctx, MinimizeTimeout)`. On expiry it returns the
original input with a nil error, so `-fuzzminimizetime` delivers no `DeadlineExceeded` to
the coordinator. **A long minimization instead parks the coordinator in the `select` on
`doneC`**, and that is the state the race needs. **So the two findings fit together**, and
the parked coordinator explains a symptom rate far above 0.025 percent.

**The Go project holds the defect as `golang/go#75804`.** It opened on 2025-10-08 and it
closed on 2026-07-23. The title reads:

> testing: Fuzz testing with `fuzztime` flag sometimes fails incorrectly with 'context deadline exceeded'

| Change | Branch | Status | Submitted |
|---|---|---|---|
| CL 774140 | `master` | MERGED | 2026-07-23 |
| CL 804900 | `release-branch.go1.27` | MERGED | 2026-07-27 |

**The repair reads `if err == ctx.Err() || err == fuzzCtx.Err() || isInterruptError(err) {`.**

**No backport reaches go1.26, so `go1.26.5` carries the defect.** **The repair arrives in
go1.27.** That matters to this project, because every CI job builds on the `~1.26.6` range.

**This project files nothing upstream**, because the Go project reported the defect and
repaired it already.

Verified against <https://github.com/golang/go/issues/75804>,
<https://go-review.googlesource.com/changes/774140> and
<https://go-review.googlesource.com/changes/804900>, each retrieved 2026-08-14.

#### The upstream workaround, and why this project declines it

**An execution count removes the race, and this project keeps the duration.**
`fuzz.go:105` builds the `timerCtx` only when `opts.Timeout > 0`. **A `-fuzztime` that
states an execution count, such as `1000000x`, sets no timeout**, so no `timerCtx` exists
and the race cannot happen.

**The project manager declined that workaround on 2026-08-14, for two reasons.**

1. **An execution count gives each run an unpredictable wall-clock time.** `make fuzz` runs
   15 targets on a thermally limited laptop, so a run of unknown length is worse than a rare
   false failure.
2. **go1.27 removes the need.** CL 804900 reaches that release, and this project moves with
   its toolchain.

**Issue #568 is the reversal path.** A reader who wants the workaround reopens that question
there, and this page records the decision rather than the derivation.

#### What this repository changes: one flag of `make fuzz`

**The parser needs no repair, and `internal/fuzzprop/fuzzprop.go` needs no repair.** The
coordinator belongs to the Go toolchain, and this repository holds no line of it.

**The maintainer ruled the one repair on 2026-08-14**, and the `fuzz` recipe of the
`Makefile` now passes `-fuzzminimizetime 5s` beside `-fuzztime 30s`. The recipe comment
states the reasoning, the accepted cost and the reading of the workflow.

**The cost: the engine minimizes the reproducer of a real crash less, so that input can land
larger than a reader wants.** **The maintainer accepted that cost on 2026-08-14.** A bound
whose cost no page records is a bound the next reader removes.

**`.github/workflows/fuzz.yml` needs no such flag, and this change edits no line of it.**
That workflow gives each target `-fuzztime 10m`, so the 60-second default spends about a
tenth of one run rather than twice one run. **Its `timeout-minutes` comment already reads
the default**, and it budgets for it.

#### What the bound measured

**Two sets of ten runs differ in the flag alone.** Each one ran the target at `-fuzztime 30s`
from an empty cache corpus, which is the condition that stalled without the bound.

| Set | Runs that stalled | Longest minimization | Lowest rate of a periodic line |
|---|---|---|---|
| No bound | 2 of 10 | 26.39531s | 3516/sec, and two lines at 0/sec |
| `-fuzzminimizetime 5s` | 0 of 10 | 4.923318375s | 8691/sec |

**The bound holds.** No minimization of the bounded set reached 5 seconds, and no periodic
line of the bounded set reported 0/sec.

**The bound raised no execution total, and this page reports that rather than hides it.**
The unbounded set reported 23106050 executions over its ten runs, and the bounded set
reported 17907431. **The bounded set found more interesting inputs**, at 64 to 77 for each
run against 41 to 71. **Each new input costs one more minimization**, so a shorter
minimization buys more of them rather than more executions.

**The two sets ran at different times and under different machine loads**, so the execution
totals compare weakly. **The stall count compares strongly**, because a stall is a frozen
count over two periodic lines and no load produces one.

## User flows

### A contributor runs the fuzzer

1. Run `make fuzz`. Each target runs for 30 seconds.
2. A crash writes its input to `testdata/fuzz/FuzzName/`.
3. Run `go test ./internal/parser -run FuzzName`. The seed input reproduces the crash.
4. Change the code.
5. The test passes and the input stays in the seed corpus.

### The nightly job finds a crash

1. The scheduled workflow runs each target for 10 minutes.
2. A target finds a crash and writes the input.
3. The job opens an issue that names the target and attaches the input.
4. An engineer adds the input to the seed corpus and closes the crash.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- A fuzz target never reaches the network and never reads a file outside
  `testdata/fuzz/`.
- A crashing input joins the seed corpus before the fix lands, so that the test fails
  first. **The one crash of Epic 6 landed both halves in one commit**, `ce2a296` of #556,
  which added `internal/parser/tls.go` and the seed together. So no commit of this
  repository holds the seed and no repair. **The rule states the intent, and the seed is a
  permanent regression guard either way.**
- A seed input is a protocol record, not a capture. It holds no FoxIO material, so it is
  safe to track in git.
- The time bound in FR-fuzz-16 catches a quadratic parser. A parser that is slow on a
  small input is a denial of service even when it does not panic.
- The nightly job opens one issue for each distinct crash, not one for each run.

## Data touched

No entity changes. The following files change.

**This table names the files Epic 6 changed, and every path in it is a path the tree
holds.** The first draft of this page named `internal/parser/fuzz_test.go` and `fuzz_test.go`
as new files. **The tree holds neither one.** #44 wrote one target file for each source file
instead, which keeps a target beside the code it drives.

| File | Change | Member |
|---|---|---|
| 7 `*_fuzz_test.go` files of `internal/parser/` | New. They hold 10 targets. | #44 |
| 3 `*_fuzz_test.go` files at the root | New. They hold 3 targets. | #44 |
| `internal/fuzzprop/fuzzprop.go` | New. `ExactInput` and `Check` carry FR-fuzz-14 through FR-fuzz-18. | #45 |
| `internal/fuzzprop/fuzzprop_test.go` | New. Ten tests prove that each property fires. | #45 |
| `testdata/fuzz/**` | New. 3 target directories, 30 seed files in total with the directory below. | #46 |
| `internal/parser/testdata/fuzz/**` | New. 10 target directories. | #46 |
| `testdata/fuzz/README.md` | New. It holds the FR-fuzz-23 license reading. | #46 |
| `fuzz_seed_corpus_test.go` of each package | New. The guard of FR-fuzz-19, FR-fuzz-20 and FR-fuzz-21. | #46 |
| `scripts/seed-fuzz.sh` | New. FR-fuzz-22. | #46 |
| `scripts/seed-fuzz-reduce.awk` | New. It reduces one captured record. | #46 |
| `.github/workflows/ci.yml` | Gains the short fuzz job, and no existing job moves. | #47 |
| `.github/workflows/fuzz.yml` | New. It holds the nightly job. | #47 |
| `fuzz_job_test.go` | New. It holds each property of the two jobs. | #47 |

**No member edits the `Makefile`.** The `fuzz` target of `features/00-foundation.md` reads
the target list from the tree with `go test -list '^Fuzz'`, so it found the 13 new targets
without a change.

**No member changes a line of any file that the library already held.** `git diff --stat
origin/dev...` names one file that is not a test file, and that file is new:
`internal/fuzzprop/fuzzprop.go`. **Ten `*_fuzz_test.go` files import it, and no other file
does**, so no line of the library reaches it.

**No member edits `testdata/deviations.json`.** So no fingerprint value moves, and Epic 6
writes no register entry.

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| Go fuzzing | Go 1.24 or later | <https://go.dev/security/fuzz/> |
| `testing.F` | Go 1.24 or later | <https://pkg.go.dev/testing#F> |
| `runtime/metrics` | Go 1.24 or later | <https://pkg.go.dev/runtime/metrics> |
| GitHub Actions schedule trigger | Current | <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule> |
| `gh issue create` | Current | <https://cli.github.com/manual/gh_issue_create> |

**The first draft named `runtime.ReadMemStats`, and no line of the tree calls it.** #45
measured it at 24736 ns for one call and took `runtime/metrics` at 230.7 ns instead. The
`### FR-fuzz-17 names no mechanism` section above holds the measurement.

**The first draft named `actions/github-script` at v7, and no line of the tree uses it.**
`.github/workflows/fuzz.yml` opens its issue with `gh issue create` and `--body-file`,
because the GitHub CLI is preinstalled on every GitHub-hosted runner.

**Every measurement of this page ran at `go1.26.5` on 2026-08-14.** `go.mod` declares
`go 1.24.0`, which states the language version and states no build toolchain. `CLAUDE.md`
`## Stack` holds that reading.

Go's built-in fuzzing writes a failing input to `testdata/fuzz/<FuzzName>/` and replays
every file in that directory during a normal `go test` run. FR-fuzz-24 and FR-fuzz-30
follow that behavior rather than adding a mechanism.

## Edge cases & failures

| Case | What happens |
|---|---|
| A target finds the same crash on two runs. | The seed corpus already holds the input. The fuzzer does not write a second file. |
| A crashing input is larger than 1 MB. | The engineer reduces it before it joins the seed corpus, so that the replay stays fast. |
| The 30-second run finds no crash and the nightly run does. | That is the expected split. The short run catches a regression, and the long run explores. |
| A target times out because the machine is slow, not because the parser is slow. | The bound in FR-fuzz-16 is one second for an input of 64 KB. A target that fails on a slow runner records the measurement and the bound moves once, with a reason. |
| The nightly job runs on a repository with no open-issue permission. | The job fails and names the permission. The workflow declares `issues: write`. |

## Acceptance criteria

**The Epic 6 round read every criterion against the merged tree on 2026-08-14.** A criterion
is marked below only where a command or a file proves it, and a criterion that no run of this
repository has observed says so.

- [x] A fuzz target exists for each of the eleven entry points named in FR-fuzz-1 through
      FR-fuzz-11. **Nine of the eleven are entry points of `internal/parser`, and two are
      not.** FR-fuzz-10 and FR-fuzz-11 name the DHCPv4 parser and the DHCPv6 parser, and
      `ComputeJA4D` in `ja4d.go` and `ComputeJA4D6` in `ja4d6.go` are functions of the root
      package. **The first draft of this criterion called all eleven "parser entry points",
      and that sentence is false.**
- [x] A fuzz target exists for `Processor.ProcessPacket`. `FuzzProcessPacketReadsAnyFrame`
      in `processor_fuzz_test.go`.
- [x] Each target has a seed corpus with at least one accepted and one rejected input.
      `TestEachTargetOfThisPackageHoldsAnAcceptedSeedAndARejectedSeed` of each package fails
      when a target loses either one. **The criterion reaches the 13 targets of Epic 6, and
      it reaches neither pre-existing target.**
- [x] `go test ./...` replays every seed input and passes. That is FR-fuzz-30, and it was
      already true on the base.
- [x] `make fuzz` runs each target for 30 seconds. The run covers 15 targets.
- [x] A deliberately introduced missing bounds check makes a target fail within 30 seconds.
      **#47 proved this by measurement, and it invented no defect to prove it.** It reverted
      the #556 guard in `internal/parser/tls.go`, and
      `FuzzParseServerHelloReadsAnyPayload` panicked in **0.06 seconds**. `git checkout --`
      then restored the file. **The first, unplanned proof is stronger: the same target
      found the same defect in 1.14 seconds when no person had planted it.**
- [x] The CI fuzz job fails when a target finds a crash. `make fuzz` exits 1 on the first
      target that fails, and the job reads that status.
- [x] `.github/workflows/fuzz.yml` runs on a nightly schedule. The file declares
      `cron: '17 5 * * *'`. **No run has started**, because the file has not reached
      `master`. The `### FR-fuzz-27 ships in this batch` section above states the rule.
- [ ] The nightly job opens an issue that names the target and holds the crashing input.
      **Nobody has observed this.** The `gh issue create` call, the `issues: write` scope and
      the deduplication search are read against the documentation, and never against a run.
- [x] No exported function panics for any input in any seed corpus. `go test ./...` replays
      every seed and passes. **This criterion was false when #44 landed**, and #556 made it
      true.

## Out of scope

- This feature set does not fuzz the command-line program's argument parsing.
- This feature set does not fuzz the CSV parser in `lookup.go`, because that input is
  embedded and not attacker-controlled. `features/09-database-lookup.md` covers the
  downloaded file.
- This feature set does not add a continuous fuzzing service such as OSS-Fuzz.

## Open questions

**The maintainer ruled the `make fuzz` question on 2026-08-14, and it stays open no longer.**
The recipe passes `-fuzzminimizetime 5s`, and the maintainer accepted the cost that the
recipe comment states. The `What this repository changes` subsection of
`### The stall of #568 is a coverage minimization` above holds the record.

**The coordinator question closed on 2026-08-14, and no question of this page waits on the
maintainer today.** A second reader confirmed the reading against the `go1.26.5` source, and
the Go project holds the defect as `golang/go#75804`. **This project files nothing upstream.**

**One fact outlives this page, and a reader of a red fuzz job needs it.** `go1.26.5` carries
the defect, no backport reaches go1.26, and the repair arrives in go1.27. **So a fuzz job of
this project can report `context deadline exceeded` on a clean run until the toolchain
moves.**
