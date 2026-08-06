---
id: correctness-audit
feature: Correctness audit
epic: "Epic 2: Correctness audit"
status: planned
issues: []
mockups: []
---

## Purpose

The library grew fast. Ten fingerprinters, nine parser files and a command-line program
reached `v0.3.0` in a small number of commits. Before an API freeze, every file needs a
read that looks for a defect rather than for a feature.

This feature set is the audit and the closure of what it finds. The audit is read-only
and produces a findings report. The closure changes the code and adds a regression test
for each finding.

The maintainer chose to close every confirmed finding without a triage step. Severity
decides the order of the work, not whether the work happens.

## User stories

- As a maintainer, I want a written record of every defect that the audit found, so that
  I can see what changed and why.
- As a library author, I want a regression test for every closed finding, so that the
  defect cannot return.
- As a maintainer, I want the audit to state what it checked, so that I know which parts
  of the library are unexamined.

## Functional requirements

### The audit

- **FR-audit-1** — The audit reads every `.go` file in the repository root, in
  `internal/parser/` and in `cmd/ja4plus/`.
- **FR-audit-2** — The audit records one row per file, with the file path and the audit
  date.
- **FR-audit-3** — The audit reports each finding with a file path, a line number, a
  severity and a failure scenario.
- **FR-audit-4** — A failure scenario names the input and the wrong result. It does not
  name a code smell.
- **FR-audit-5** — The audit assigns one of three severities to each finding: `critical`,
  `major` or `minor`.
- **FR-audit-6** — A `critical` finding is a wrong fingerprint, a panic, a data race, or
  an unbounded growth of state.
- **FR-audit-7** — A `major` finding is a wrong result for an uncommon input, or a
  contract that the code states and does not keep.
- **FR-audit-8** — A `minor` finding is a defect that produces no wrong result.
- **FR-audit-9** — The audit writes its report to `docs/audit/findings.md`.
- **FR-audit-10** — The audit records a finding that it cannot confirm as `unconfirmed`,
  with the reason.

### The checks the audit runs

- **FR-audit-11** — The audit checks every length field that a parser reads against the
  remaining buffer length before the parser slices.
- **FR-audit-12** — The audit checks every integer conversion for truncation and for
  sign change.
- **FR-audit-13** — The audit checks every map read and every slice index for a missing
  bounds check.
- **FR-audit-14** — The audit checks that no exported function panics on any input.
- **FR-audit-15** — The audit checks that every state map has a removal path.
- **FR-audit-16** — The audit checks that the `results` slice in every fingerprinter has
  a removal path.
- **FR-audit-17** — The audit checks that `CleanupConnection` removes every entry that
  the named connection created, in every fingerprinter.
- **FR-audit-18** — The audit checks that `Reset` clears every field that holds state.
- **FR-audit-19** — The audit checks that the library writes nothing to standard output
  and nothing to standard error.
- **FR-audit-20** — The audit checks every error return for a swallowed error.
- **FR-audit-21** — The audit checks that a hash of an empty input produces the literal
  value that the FoxIO specification names, for every method that hashes.
- **FR-audit-22** — The audit checks that every sort is stable and that its key matches
  the FoxIO specification.
- **FR-audit-23** — The audit checks every GREASE filter against the values in RFC 8701.
- **FR-audit-24** — The audit checks `cmd/ja4plus/main.go` for an unhandled error and for
  an exit code that does not match the outcome.

### The closure

- **FR-audit-25** — Each confirmed finding produces a code change that removes it.
- **FR-audit-26** — Each confirmed finding produces a test that fails before the change
  and passes after it.
- **FR-audit-27** — Each closed finding records the commit that closed it in
  `docs/audit/findings.md`.
- **FR-audit-28** — A finding that the maintainer decides not to close records the reason
  in `docs/audit/findings.md`.

## User flows

### The audit runs

1. An engineer reads one file.
2. The engineer applies every check in FR-audit-11 through FR-audit-24 to that file.
3. The engineer records each finding with its file, line, severity and failure scenario.
4. The engineer records the file as audited, even when it holds no finding.
5. The engineer repeats for the next file.

### A finding closes

1. An engineer reads the finding and the failure scenario.
2. The engineer writes a test that reproduces the failure scenario. The test fails.
3. The engineer changes the code.
4. The test passes.
5. `go test -race ./...` passes.
6. The engineer records the commit in `docs/audit/findings.md`.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- The audit changes no code. The audit and the closure are separate steps.
- A finding without a failure scenario is not a finding. It is a style opinion, and the
  audit does not record it.
- A closure changes only what the finding names. A closure does not refactor adjacent
  code.
- A closure that changes an exported signature is recorded, because Epic 10 freezes the
  API and needs to know.
- A finding that the conformance harness would catch is still a finding. The audit does
  not wait for Epic 4.

## Data touched

No entity changes. The audit produces `docs/audit/findings.md`. The closures change the
files that the findings name, and add tests beside them.

## Interfaces

The audit reads two specifications to decide whether a result is correct.

| Specification | What it decides | URL |
|---|---|---|
| FoxIO JA4+ technical details | The definition of each method. | <https://github.com/FoxIO-LLC/ja4/tree/main/technical_details> |
| RFC 8701 | The GREASE values that a parser must filter. | <https://www.rfc-editor.org/rfc/rfc8701> |

The FoxIO Python reference at `python/` and the Wireshark plugin at `wireshark/` decide a
disputed result. Both are read at commit `27f0cbf`.

## Edge cases & failures

| Case | What happens |
|---|---|
| A finding turns out to be a deliberate design choice. | The finding records the reason and closes as `no change needed`. |
| Closing a finding changes a fingerprint that a test asserts. | The test is wrong when the FoxIO reference disagrees with it. The engineer changes the test and records why. |
| Closing a finding changes an exported signature. | The change lands before Epic 10, and `docs/api/v1.md` records the final shape. |
| Two findings need the same change. | One change closes both. Both records name the same commit. |

## Suspected findings

The survey that produced this spec found three candidates. Each needs confirmation, and
each is listed here so that the audit starts with a concrete target.

### S1 — The `results` slice grows without a bound

Every fingerprinter appends to `results` and only `Reset` clears it.
`Processor.CleanupConnection` does not touch `results`. The documented purpose of
`CleanupConnection` is "to prevent state leaks in long-running processes", so a slice
that grows for the life of the process defeats it.

Files: `ja4.go`, `ja4s.go`, `ja4h.go`, `ja4t.go`, `ja4ts.go`, `ja4l.go`, `ja4x.go`,
`ja4ssh.go`, `ja4d.go`, `ja4d6.go`.

Failure scenario: a monitor that runs for a day and calls `CleanupConnection` for every
closed connection still holds one `FingerprintResult` for every fingerprint it has ever
produced. Memory grows until the process ends.

### S2 — `sync.Once` prevents a database reload

`lookup.go` loads the mapping table once through `lookupOnce`. `db update` writes a new
cache file. A process that updates the database and then performs a lookup reads the old
table, because `sync.Once` has already run.

File: `lookup.go`, near line 31.

Failure scenario: a long-running program calls the update path and then looks up a
fingerprint that only the new table holds. The lookup returns no result.

### S3 — Package-level lookup state is unguarded

`lookupDB`, `dbSource` and `dbCachePath` are package-level variables. `sync.Once`
guards the write. No lock guards a read that happens while another goroutine runs the
update path.

File: `lookup.go`, near line 28.

Failure scenario: one goroutine calls the update path while a second goroutine reads
`dbSource`. The race detector reports a data race.

## Acceptance criteria

- [ ] `docs/audit/findings.md` records every `.go` file in the root, in
      `internal/parser/` and in `cmd/ja4plus/` as audited, with a date.
- [ ] Every finding in `docs/audit/findings.md` holds a file path, a line number, a
      severity and a failure scenario.
- [ ] S1, S2 and S3 each hold a verdict of `confirmed`, `no change needed` or
      `unconfirmed`.
- [ ] Every `confirmed` finding names the commit that closed it.
- [ ] Every closed finding has a test, and that test fails when the change is reverted.
- [ ] `go test -race ./...` passes.
- [ ] `go vet ./...` reports nothing.
- [ ] No exported function panics for any input in the fuzz seed corpus.
- [ ] `docs/audit/findings.md` lists every exported signature that a closure changed.

## Out of scope

- This feature set does not add the conformance harness. Epic 4 does that.
- This feature set does not add a mutex to a fingerprinter. Epic 3 owns the concurrency
  contract.
- This feature set does not change the network boundary. Epic 9 owns it, and S2 and S3
  hand over to it.
- This feature set does not restructure a package.

## Open questions

None.
