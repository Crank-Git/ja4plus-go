---
id: mutation-sweep
feature: Mutation sweep
epic: "Epic 15: Mutation sweep"
status: issued
issues: [89, 90, 91, 92, 93]
mockups: []
---

## Purpose

Coverage measures which lines a test runs. It does not measure whether a test would fail
if the line were wrong. A fingerprinter can hold 95 percent coverage and still pass every
test after a bit flip in the code that builds the fingerprint.

A mutation sweep measures the second property. It changes one expression, runs the suite,
and records whether a test failed. **A mutation that survives names a test that runs a
line and asserts nothing about it.**

The port ran this sweep before its `v1.0.0` and settled every candidate it found. This
project runs the same kind of sweep before the freeze, because the freeze is the moment
after which a defect is expensive to correct.

## User stories

- As a maintainer, I want to know which tests assert nothing, so that a defect does not
  reach `v1.0.0` behind a green suite.
- As an engineer, I want a report I can act on, so that I know which assertion to add.
- As a maintainer, I want the sweep off the pull-request path, so that a slow tool does
  not block a merge.

## Functional requirements

### The tool

- **FR-mutation-1** — The project runs `gremlins` as the mutation tool.
- **FR-mutation-2** — The tool version is pinned in `.gremlins.yaml` or in the Makefile.
- **FR-mutation-3** — `make mutate` runs the sweep.
- **FR-mutation-4** — The sweep runs over a named package set, and the set is recorded.
- **FR-mutation-5** — `make mutate PKG=<path>` runs the sweep over one package.

### The report

- **FR-mutation-6** — The sweep writes a report to `docs/mutation_reports/`.
- **FR-mutation-7** — The report names each mutation, its file, its line and its verdict.
- **FR-mutation-8** — A verdict is one of `KILLED`, `LIVED`, `NOT COVERED`, `TIMED OUT`
  or `NOT VIABLE`.
- **FR-mutation-9** — The report records the tool version and the date.
- **FR-mutation-10** — The report is tracked in git.

### The settlement

- **FR-mutation-11** — A settlement covers each mutation with the verdict `LIVED` on code
  that can move a fingerprint value.
- **FR-mutation-12** — A settlement is an added assertion, or a recorded reason why the
  mutation changes no observable behaviour.
- **FR-mutation-13** — `docs/mutation_settlements/` records each settlement and one count
  of every `LIVED` mutation that no settlement covers.
- **FR-mutation-14** — Each settlement names the mutation and the issue that closed it.
- **FR-mutation-15** — A settlement that says "equivalent mutation" states the reason in
  one sentence.
- **FR-mutation-16** — `docs/mutation_sweep.md` explains the sweep, the report and the
  settlement procedure.

#### The ruling that narrowed FR-mutation-11

**The maintainer ruled the settlement scope on 2026-08-14, in issue #92.** Issue #634
carries the amendment of FR-mutation-11 and FR-mutation-13, and `docs/mutation_sweep.md`
states the procedure that applies the rule.

> **A LIVED mutation on code that can move a fingerprint value is settled. Every other LIVED mutation is counted and recorded.**

**Before the ruling, FR-mutation-11 settled every `LIVED` mutation.** `./internal/parser`
alone holds 223 `LIVED` and 4 `TIMED OUT` mutations of 882, measured on 2026-08-14. **The
reason for the ruling is reviewability.** A worker that writes `equivalent mutation` 227
times produces a record nobody can check. A rubber stamp then hides the weak test that the
sweep exists to find.

**The reversal path is issue #92.** A reversal restores the rule that every `LIVED`
mutation carries a settlement, and it states the reason.

### The gate

- **FR-mutation-17** — The sweep runs on a schedule and not on a pull request.
- **FR-mutation-18** — The scheduled run opens an issue when a new `LIVED` mutation
  appears.
- **FR-mutation-19** — The sweep does not block a merge.
- **FR-mutation-20** — `features/16-pre-release-validation.md` checks that the last sweep
  meets FR-mutation-11 before the release.

## User flows

### An engineer settles a candidate

1. The engineer runs `make mutate PKG=./internal/parser`.
2. The report names a `LIVED` mutation at a file and a line.
3. The engineer reads the test that covers the line.
4. The engineer reads whether the mutated expression can move a fingerprint value.
5. If the expression can move no fingerprint value, the engineer counts the mutation and
   writes no settlement.
6. If the test asserts nothing about the value, the engineer adds the assertion. The
   mutation is then killed.
7. If the mutation changes no observable behaviour, the engineer records the reason as an
   equivalent mutation.
8. The engineer commits the report and the settlement together.

## Screens & states

This feature set changes no screen. The report is a file.

## Behaviour rules

- **A sweep measures the tests, not the code.** A surviving mutation is a missing
  assertion, and it is not always a defect.
- **An equivalent mutation is a real answer, and it needs a reason.** A settlement that
  claims equivalence without stating why is a settlement a later reader cannot check.
- **The sweep is slow, so it does not gate a pull request.** It runs on a schedule and
  before the release.
- **A report is committed.** A measurement that lives only in a terminal is a measurement
  nobody can compare against.

## Data touched

| File | Change |
|---|---|
| `.gremlins.yaml` | New. The pinned configuration. |
| `Makefile` | The `mutate` target. |
| `docs/mutation_reports/` | New. |
| `docs/mutation_settlements/` | New. |
| `docs/mutation_sweep.md` | New. A site page. |
| `.github/workflows/mutation.yml` | New. The scheduled run. |
| Test files across the module | The assertions that settle a candidate. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `gremlins` | v0.6.0, published 2025-12-05 | <https://pkg.go.dev/github.com/go-gremlins/gremlins> |
| `gremlins` documentation | Current | <https://gremlins.dev> |

Read 2026-08-11. **`gremlins` is at a pre-1.0 version, and its own documentation states
that configuration flags and configuration files may change between minor releases.**
FR-mutation-2 pins the version for that reason. The project is Apache 2.0 licensed and is
not archived.

## Edge cases & failures

| Case | Expected behaviour |
|---|---|
| The sweep takes longer than the CI job limit. | FR-mutation-4 narrows the package set. The report records which packages were swept and which were not. |
| A mutation makes the suite hang. | The verdict is `TIMED OUT`. FR-mutation-11 reads it like a `LIVED` mutation. |
| A mutation does not compile. | The verdict is `NOT VIABLE`. No settlement is needed. |
| A line is not covered at all. | The verdict is `NOT COVERED`. The coverage floor of `features/07-supply-chain.md` owns that gap, not this feature set. |
| The tool changes its verdict names in a minor release. | The pin holds. A bump is a commit that does nothing else. |
| A settlement is recorded and the mutation later dies. | The settlement stays as a record. It names the issue that changed the test. |

## Acceptance criteria

1. `make mutate` runs and writes a report to `docs/mutation_reports/`.
2. The report holds a verdict for every mutation the tool applied.
3. Every `LIVED` mutation of the most recent report that can move a fingerprint value has
   a settlement.
4. The settlement record counts every other `LIVED` mutation of that report.
5. Every settlement that claims equivalence states one sentence of reason.
6. `docs/mutation_sweep.md` builds into the site.
7. The scheduled workflow runs and does not appear as a required check on a pull request.
8. A deliberately weakened assertion produces a new `LIVED` mutation in the next sweep.

## Out of scope

- A mutation-score target. The sweep finds candidates; it sets no number.
- Sweeping `cmd/ja4plus`. The command-line program is covered by the integration test, and
  a sweep there measures the test harness more than the program.
- Sweeping generated code or test files.
- Blocking a merge on the sweep.

## Open questions

1. **Is `gremlins` the right tool?** It is the most actively maintained option, at v0.6.0
   in December 2025, but it is pre-1.0 and its configuration may move. `go-mutesting` is
   the alternative and is less actively maintained. **The first sweep is the evaluation:
   if `gremlins` cannot complete a run over `internal/parser` within the CI job limit, the
   choice is reconsidered before Epic 15 closes.**
2. **Which package set does FR-mutation-4 name?** `internal/parser` holds the code that a
   crafted packet reaches, so it is the highest-value target. The ten fingerprinters
   are the second. The set is fixed after the first sweep measures the runtime.
