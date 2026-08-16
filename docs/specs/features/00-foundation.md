---
id: foundation
feature: Foundation
epic: "Epic 0: Foundation"
status: built
issues: [3, 4, 5, 6, 7, 8, 32]
mockups: []
---

## Purpose

The repository already has a test suite, a CI workflow and a release workflow. It does
not have the gates that the later epics need. This feature set adds the missing parts of
the harness, so that every later epic has a command to run and a gate to pass.

This is a smaller foundation epic than a greenfield project needs. The spec records what
already exists, and adds only what is missing.

### What already exists

| Item | State |
|---|---|
| Test harness | `go test ./...` covers every file. |
| CI workflow | `.github/workflows/ci.yml` builds and tests on Go 1.22, 1.23 and 1.24, and runs `golangci-lint`. |
| Release workflow | `.github/workflows/release.yml` builds five platforms on a `v*` tag and attaches checksums. |
| Build commands | `Makefile` holds `build`, `test`, `lint`, `bench` and `clean`. |
| Module | `go.mod` declares `github.com/Crank-Git/ja4plus-go` at Go 1.22. |

### What is missing

| Item | Why it is needed |
|---|---|
| `.golangci.yml` | CI uses `version: latest`, so a linter release can fail the build with no code change. |
| A benchmark | `make bench` runs `go test -bench=.`, and the repository holds no benchmark. |
| A coverage floor | CI writes `coverage.out` and never reads it. **Epic 7 closed this row on 2026-08-13.** |
| A corpus command | Epic 4 needs `make corpus` and `make conformance`. |
| The `dev` branch | The chosen branch model is dev-and-live. |
| Tracked agent configuration | `.gitignore` ignores `CLAUDE.md` and `.claude/`, so worktree workers cannot read them. |
| A CHANGELOG | The release notes are generated, and `v1.0.0` needs a written history. |

**The table above records the state at the first draft, and it is not a reading of the tree
today.** Read a row as a start state, and never as a claim about the present tree.
`## Behaviour rules` below states what the tree holds for the coverage floor row.

## User stories

- As a maintainer, I want one command per gate, so that I can run locally what CI runs.
- As a library author, I want a pinned linter set, so that a lint release cannot break my
  pull request.
- As an agent that builds an issue, I want `CLAUDE.md` and `.claude/` inside my worktree,
  so that I follow the project conventions.

## Functional requirements

- **FR-foundation-1** — `go.mod` declares `go 1.25`.

  **The maintainer ruled this version on 2026-08-15, and issue #725 holds the ruling.** The
  requirement named `go 1.24` until that date. `github.com/gopacket/gopacket` v1.7.1 declares
  `go 1.25.0` in its own `go.mod`, and Go requires the main module to declare a language
  version at or above every dependency. **So the move is forced and never chosen.**

  **`GHSA-6h9g-cjv3-pg2c` decided it.** v1.7.1 repairs a panic on the TCP MPTCP option, on
  the ordinary Ethernet to IP to TCP path that every fingerprint of this library reads. **No
  patch release of the 1.6 line carries that repair**, so the choice was v1.7.1 with Go 1.25
  or v1.6.1 with the panic.

  **Every Go 1.24 consumer is dropped, and that cost is the accepted one.** The ruling lands
  in v1.1.0, because a minimum language version raise is a minor version change.
  **`goToolchainRange` does not move**, because this ruling moves a language version and no
  build toolchain. `TestGoModDeclaresGo125` in `internal/repocheck/foundation_test.go` holds the ruling, and
  **issue #725 is the reversal path**.
- **FR-foundation-2** — `.github/workflows/ci.yml` builds and tests on Go 1.26 only.

  **The maintainer amended this requirement on 2026-08-13, and the amendment is
  provisional.** The requirement named Go 1.24 until that date. On go1.24.13, the newest
  Go 1.24 patch, `govulncheck` v1.6.0 reported 9 vulnerabilities of the standard library
  that this library calls, measured on 2026-08-13. Each one names a fix in a go1.25.x
  release, and none names a fix in a go1.24.x release. So no Go 1.24 patch clears them.
  Comment 5286440152 of #65 holds the decision, and issue #65 is the reversal path.
  **This amendment does not move FR-foundation-1**, because `go.mod` states a language
  version and never a toolchain. **A separate ruling moved FR-foundation-1 to `go 1.25` on
  2026-08-15**, and issue #725 holds it.

  **That count carries its date, because the vulnerability database is live.** The same
  command on the same toolchain reported 13 on 2026-08-14, and #472 measured it. **No line
  of this repository changed between the two measurements.** So a reader reads the figure
  as a measurement of one day, and never as a property of go1.24.13.
- **FR-foundation-3** — `.golangci.yml` exists and names every enabled linter.
- **FR-foundation-4** — `.github/workflows/ci.yml` pins the `golangci-lint` version to a
  released version number.
- **FR-foundation-5** — `.gitignore` does not ignore `CLAUDE.md`.
- **FR-foundation-6** — `.gitignore` does not ignore `.claude/`.
- **FR-foundation-7** — `.gitignore` ignores `.claude/settings.local.json`.
- **FR-foundation-8** — `.gitignore` ignores `.claude/worktrees/`.
- **FR-foundation-9** — `.gitignore` ignores `.claude/agent-memory-local/`.
- **FR-foundation-10** — `.gitignore` ignores `CLAUDE.local.md` and `.claude.local.md`.
- **FR-foundation-11** — `.gitignore` ignores `.issue-flow.local.json`.
- **FR-foundation-12** — `.gitignore` does not ignore any path under `docs/specs/`.
- **FR-foundation-13** — The repository holds a `dev` branch that starts at `master`.
- **FR-foundation-14** — `.github/workflows/ci.yml` runs on a pull request that targets
  `dev`.
- **FR-foundation-15** — `Makefile` holds a `corpus` target that runs the corpus fetch
  script.
- **FR-foundation-16** — `Makefile` holds a `conformance` target that runs the
  conformance suite.
- **FR-foundation-17** — `Makefile` holds a `cover` target that reports total statement
  coverage.
- **FR-foundation-18** — `Makefile` holds a `fuzz` target that runs each fuzz target for
  30 seconds.
- **FR-foundation-19** — The repository holds a benchmark for `Processor.ProcessPacket`.
- **FR-foundation-20** — The repository holds one benchmark for each method the library
  implements. `benchmark_test.go` holds ten benchmarks, and JA4LS has none. **Epic 12
  built JA4LS, and the JA4LS benchmark stays open.**
- **FR-foundation-21** — `CHANGELOG.md` exists and follows the Keep a Changelog format.
- **FR-foundation-22** — `CHANGELOG.md` records `v0.1.0`, `v0.2.0` and `v0.3.0` from the
  git history.
- **FR-foundation-23** — `README.md` and `doc.go` each state a minimum build toolchain, and
  each one separates that statement from the language version.

  **The maintainer ruled this question on 2026-08-14, and issue #472 holds the ruling.** The
  ruling picked candidate answer 1 of #472: the two pages state a minimum build toolchain,
  and `go.mod` does not move. **So the #472 ruling moved FR-foundation-1 nowhere**, and it
  left the language version at 1.24. **The ruling reaches no part of Epic 10 (#100)**,
  because it changes nothing a consumer needs. **Issue #472 is the reversal path.**

  **A later ruling moved the language version to 1.25 on 2026-08-15, and issue #725 holds
  it.** That ruling moves no build toolchain, so this requirement and `goToolchainRange`
  each stay where #472 left them. **The two rulings answer two different questions**, and a
  reader who conflates them draws the wrong conclusion about vulnerability exposure.

  `internal/repocheck/go_toolchain_statement_test.go` holds this requirement.

## User flows

### A maintainer prepares a fresh clone

1. Clone the repository.
2. Run `make corpus`. The command fetches the corpus into `testdata/foxio/`.
3. Run `make test`. The unit tests pass.
4. Run `make conformance`. The conformance suite runs and reports its result.
5. Run `make lint`. The linter reports nothing.
6. Run `make bench`. The benchmarks report times and allocations.

### An agent builds an issue

1. The agent creates a worktree from `dev`.
2. The worktree holds `CLAUDE.md` and `.claude/`, because both are tracked.
3. The agent reads the conventions and builds the issue.
4. The agent opens a pull request that targets the batch integration branch.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- `make corpus` is idempotent. A second run downloads nothing when the corpus is present
  and the pin has not changed.
- `make conformance` fails with a clear message when the corpus is absent. The message
  names `make corpus`.
- The coverage floor is recorded as a number in a file, not as a hard-coded value in the
  workflow. **Epic 7 created that file on 2026-08-13, under issue #68**, and Epic 7 set the
  first value. **Epic 0 created no such file at any time.** `git ls-files .coverage-floor`
  returns the path, and the file holds `75.0`, measured on 2026-08-13 at commit `6681d3e`.
  **`make cover` reads the FoxIO corpus, so the same command reports two numbers**: 75.0
  with the corpus and 74.4 without it. `features/07-supply-chain.md`
  `### The coverage floor file` holds the measurement and the environment rule. **A person
  who raises the floor under FR-supply-19 runs `make corpus` first.**
- A benchmark takes its input from a packet that the test builds, not from the corpus.
  Benchmarks must run without a network.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `go.mod` | The `go` directive moves to `1.25`. **It read `1.24` until the #725 ruling of 2026-08-15.** |
| `.github/workflows/ci.yml` | The matrix reduces to one Go version. The linter version pins. The `dev` branch joins the triggers. |
| `.golangci.yml` | New. |
| `.gitignore` | The `CLAUDE.md` and `.claude/` lines are removed. The Claude Code block is appended. |
| `Makefile` | The `corpus`, `conformance`, `cover` and `fuzz` targets are added. |
| `CHANGELOG.md` | New. |
| `benchmark_test.go` | New. |

**The `.github/workflows/ci.yml` row read `The matrix reduces to Go 1.24.` until
2026-08-13.** The FR-foundation-2 amendment above moved every job to Go 1.26, and the
workflow states the range `~1.26.6`. **The row now names no version**, so the amendment is
the one place that carries it.

## Interfaces

This feature set uses two external interfaces.

| Interface | Version | Documentation |
|---|---|---|
| GitHub Actions workflow syntax | Current | <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions> |
| `golangci-lint` configuration | Pinned in `.golangci.yml` | <https://golangci-lint.run/usage/configuration/> |

The Go toolchain interfaces are `go build`, `go test`, `go test -bench`,
`go test -fuzz` and `go tool cover`. All are documented at
<https://pkg.go.dev/cmd/go>.

## Edge cases & failures

| Case | What happens |
|---|---|
| `make corpus` runs with no network. | The command fails, names the network as the cause, and leaves any existing corpus in place. |
| `make conformance` runs with no corpus. | The suite skips with a message that names `make corpus`. CI treats a skip as a failure. |
| The pinned `golangci-lint` version is withdrawn. | CI fails. The maintainer moves the pin in one commit. |
| A consumer on Go 1.22 imports the module. | The Go toolchain refuses the build and names the required version. The README states the floor. |

## Acceptance criteria

- [ ] `go build ./...` succeeds on Go 1.25.
- [ ] `go build ./...` fails on Go 1.24 with a message that names the required version.
- [ ] `make lint` runs the pinned linter version and reports nothing.
- [ ] `git check-ignore CLAUDE.md` reports no match.
- [ ] `git check-ignore .claude/settings.json` reports no match.
- [ ] `git check-ignore .claude/settings.local.json` reports a match.
- [ ] `git check-ignore docs/specs/spec.md` reports no match.
- [ ] `git rev-parse dev` resolves.
- [ ] `make corpus` fetches the corpus and a second run downloads nothing.
- [ ] `make conformance` without a corpus prints a message that names `make corpus`.
- [ ] `make cover` prints a total coverage percentage.
- [ ] `make bench` reports a time and an allocation count for `Processor.ProcessPacket`.
- [ ] `make bench` reports a result for each method the library implements.
      `benchmark_test.go` holds ten benchmarks, and the JA4LS benchmark stays open.
- [ ] `CHANGELOG.md` holds one section for each of `v0.1.0`, `v0.2.0` and `v0.3.0`.
- [ ] A pull request that targets `dev` starts the CI workflow.

## Out of scope

- This feature set does not add the conformance harness. Epic 4 does that. Epic 0 adds
  only the `Makefile` targets that call it.
- This feature set does not add the fuzz targets. Epic 6 does that. Epic 0 adds only the
  `fuzz` target that calls them.
- This feature set does not add `govulncheck` or Dependabot. Epic 7 does that.
- This feature set does not change any fingerprinter.

## Open questions

None.
