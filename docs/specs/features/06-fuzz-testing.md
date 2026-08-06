---
id: fuzz-testing
feature: Fuzz testing
epic: "Epic 6: Fuzz testing"
status: planned
issues: []
mockups: []
---

## Purpose

Every packet that this library reads is untrusted input. A network monitor feeds it
whatever arrives on the wire, and an attacker who can send a packet chooses that input.
A parser that reads a length field and slices without a bounds check turns a crafted
packet into a panic, and a panic in a monitor is a denial of service.

The library holds nine parser files. None has a fuzz target. The unit tests use packets
that a person wrote, so they test the shapes that a person thought of.

This feature set adds a fuzz target for every parser entry point, seeds each from the
corpus, gates a short run on every pull request, and runs a long fuzz nightly.

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
  `features/05-conformance-gaps.md` adds.

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

### The gates

- **FR-fuzz-25** — `.github/workflows/ci.yml` runs each fuzz target for 30 seconds on
  every pull request.
- **FR-fuzz-26** — The pull-request fuzz job fails when any target finds a crash.
- **FR-fuzz-27** — `.github/workflows/fuzz.yml` runs each fuzz target for 10 minutes on a
  nightly schedule.
- **FR-fuzz-28** — The nightly job opens an issue when a target finds a crash.
- **FR-fuzz-29** — The nightly job attaches the crashing input to the issue.
- **FR-fuzz-30** — `go test ./...` runs every seed input as a normal test, with no fuzz
  time.

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
  first.
- A seed input is a protocol record, not a capture. It holds no FoxIO material, so it is
  safe to track in git.
- The time bound in FR-fuzz-16 catches a quadratic parser. A parser that is slow on a
  small input is a denial of service even when it does not panic.
- The nightly job opens one issue for each distinct crash, not one for each run.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `internal/parser/fuzz_test.go` | New. Holds the parser targets. |
| `fuzz_test.go` | New. Holds the `Processor` target. |
| `testdata/fuzz/**` | New. Holds the seed corpora. |
| `scripts/seed-fuzz.sh` | New. |
| `.github/workflows/ci.yml` | Gains the short fuzz job. |
| `.github/workflows/fuzz.yml` | New. Holds the nightly job. |
| `Makefile` | The `fuzz` target from `features/00-foundation.md` calls these. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| Go fuzzing | Go 1.24 | <https://go.dev/security/fuzz/> |
| `testing.F` | Go 1.24 | <https://pkg.go.dev/testing#F> |
| `runtime.ReadMemStats` | Go 1.24 | <https://pkg.go.dev/runtime#ReadMemStats> |
| GitHub Actions schedule trigger | Current | <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule> |
| `actions/github-script` | v7 | <https://github.com/actions/github-script> |

Go's built-in fuzzing writes a failing input to `testdata/fuzz/<FuzzName>/` and replays
every file in that directory during a normal `go test` run. FR-fuzz-24 and FR-fuzz-30
follow that behaviour rather than adding a mechanism.

## Edge cases & failures

| Case | What happens |
|---|---|
| A target finds the same crash on two runs. | The seed corpus already holds the input. The fuzzer does not write a second file. |
| A crashing input is larger than 1 MB. | The engineer reduces it before it joins the seed corpus, so that the replay stays fast. |
| The 30-second run finds no crash and the nightly run does. | That is the expected split. The short run catches a regression, and the long run explores. |
| A target times out because the machine is slow, not because the parser is slow. | The bound in FR-fuzz-16 is one second for an input of 64 KB. A target that fails on a slow runner records the measurement and the bound moves once, with a reason. |
| The nightly job runs on a repository with no open-issue permission. | The job fails and names the permission. The workflow declares `issues: write`. |

## Acceptance criteria

- [ ] A fuzz target exists for each of the eleven parser entry points named in FR-fuzz-1
      through FR-fuzz-11.
- [ ] A fuzz target exists for `Processor.ProcessPacket`.
- [ ] Each target has a seed corpus with at least one accepted and one rejected input.
- [ ] `go test ./...` replays every seed input and passes.
- [ ] `make fuzz` runs each target for 30 seconds.
- [ ] A deliberately introduced missing bounds check makes a target fail within 30
      seconds.
- [ ] The CI fuzz job fails when a target finds a crash.
- [ ] `.github/workflows/fuzz.yml` runs on a nightly schedule.
- [ ] The nightly job opens an issue that names the target and holds the crashing input.
- [ ] No exported function panics for any input in any seed corpus.

## Out of scope

- This feature set does not fuzz the command-line program's argument parsing.
- This feature set does not fuzz the CSV parser in `lookup.go`, because that input is
  embedded and not attacker-controlled. `features/09-database-lookup.md` covers the
  downloaded file.
- This feature set does not add a continuous fuzzing service such as OSS-Fuzz.

## Open questions

None.
