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
| A coverage floor | CI writes `coverage.out` and never reads it. |
| A corpus command | Epic 4 needs `make corpus` and `make conformance`. |
| The `dev` branch | The chosen branch model is dev-and-live. |
| Tracked agent configuration | `.gitignore` ignores `CLAUDE.md` and `.claude/`, so worktree workers cannot read them. |
| A CHANGELOG | The release notes are generated, and `v1.0.0` needs a written history. |

## User stories

- As a maintainer, I want one command per gate, so that I can run locally what CI runs.
- As a library author, I want a pinned linter set, so that a lint release cannot break my
  pull request.
- As an agent that builds an issue, I want `CLAUDE.md` and `.claude/` inside my worktree,
  so that I follow the project conventions.

## Functional requirements

- **FR-foundation-1** — `go.mod` declares `go 1.24`.
- **FR-foundation-2** — `.github/workflows/ci.yml` builds and tests on Go 1.26 only.

  **The maintainer amended this requirement on 2026-08-13, and the amendment is
  provisional.** The requirement named Go 1.24 until that date. On go1.24.13, the newest
  Go 1.24 patch, `govulncheck` v1.6.0 reports 9 vulnerabilities of the standard library
  that this library calls. Each one names a fix in a go1.25.x release, and none names a
  fix in a go1.24.x release. So no Go 1.24 patch clears them. Comment 5286440152 of #65
  holds the decision, and issue #65 is the reversal path. **FR-foundation-1 does not
  move**, because `go.mod` states a language version and never a toolchain.
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
  workflow. **Epic 7 creates that file, under issue #68.** Epic 7 sets the first value.
  **Epic 0 created no such file at any time.**
- A benchmark takes its input from a packet that the test builds, not from the corpus.
  Benchmarks must run without a network.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `go.mod` | The `go` directive moves to `1.24`. |
| `.github/workflows/ci.yml` | The matrix reduces to Go 1.24. The linter version pins. The `dev` branch joins the triggers. |
| `.golangci.yml` | New. |
| `.gitignore` | The `CLAUDE.md` and `.claude/` lines are removed. The Claude Code block is appended. |
| `Makefile` | The `corpus`, `conformance`, `cover` and `fuzz` targets are added. |
| `CHANGELOG.md` | New. |
| `benchmark_test.go` | New. |

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

- [ ] `go build ./...` succeeds on Go 1.24.
- [ ] `go build ./...` fails on Go 1.23 with a message that names the required version.
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
