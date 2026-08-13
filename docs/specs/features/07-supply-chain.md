---
id: supply-chain
feature: Supply chain and CI gates
epic: "Epic 7: Supply chain and CI gates"
status: issued
issues: [64, 65, 66, 67, 68, 69, 70]
mockups: []
---

## Purpose

A security library carries a higher standard for its own dependencies than an ordinary
library. This one has three gaps. No job scans for a known vulnerability. No tool watches
the dependencies for an update. Every GitHub Action reference is a moving tag, so a
compromised action would run with the release token.

The library depended on `github.com/google/gopacket`, which has published no release since
v1.1.19 on 2020-10-19. The community maintains `github.com/gopacket/gopacket`. A dependency
change after an API freeze is harder than one before it, so the decision belonged here.
**The maintainer decided the move on 2026-08-13, and #438 carried it**, so the library
depends on `github.com/gopacket/gopacket` v1.6.1 today.
`docs/audit/dependency-decision.md` records the decision.

This feature set adds the missing gates and settles the dependency question.

## User stories

- As a library author, I want a vulnerability in a dependency to fail the build, so that
  I learn about it from CI and not from an incident.
- As a maintainer, I want dependency updates proposed automatically, so that the library
  does not drift on to unsupported versions.
- As a maintainer, I want a pinned action reference, so that a compromised action tag
  cannot reach my release token.
- As a maintainer, I want a coverage floor, so that a change cannot quietly remove tests.

## Functional requirements

### Vulnerability scanning

- **FR-supply-1** — `.github/workflows/ci.yml` runs `govulncheck ./...` on every pull
  request.
- **FR-supply-2** — The job fails when `govulncheck` reports a vulnerability that the
  library calls.
- **FR-supply-3** — The job pins the `govulncheck` version.
- **FR-supply-4** — `Makefile` holds a `vuln` target that runs the same command.
- **FR-supply-5** — A vulnerability that the library does not call records a note and
  does not fail the job.

### Dependency updates

- **FR-supply-6** — `.github/dependabot.yml` exists.
- **FR-supply-7** — Dependabot watches the `gomod` ecosystem at the repository root.
- **FR-supply-8** — Dependabot watches the `github-actions` ecosystem.
- **FR-supply-9** — Dependabot opens a pull request that targets `dev`.
- **FR-supply-10** — Dependabot runs weekly.
- **FR-supply-11** — A Dependabot pull request runs the whole CI workflow, including
  conformance.

### Pinned actions

- **FR-supply-12** — Every `uses:` reference in every workflow names a full commit hash.
- **FR-supply-13** — Every `uses:` reference carries a trailing comment that names the
  human-readable version.
- **FR-supply-14** — Every workflow declares the least `permissions` block that it needs.
- **FR-supply-15** — `.github/workflows/ci.yml` declares `contents: read` and nothing
  more.

### Coverage

- **FR-supply-16** — `.github/workflows/ci.yml` measures total statement coverage.
- **FR-supply-17** — The job fails when coverage falls below the value in
  `.coverage-floor`.
- **FR-supply-18** — The job prints the measured coverage and the floor.
- **FR-supply-19** — The floor rises when coverage rises, in a commit that does nothing
  else.
- **FR-supply-20** — The job reports per-package coverage as a build summary.

### Benchmarks

- **FR-supply-21** — `.github/workflows/ci.yml` runs `go test -bench=. -benchmem ./...`.
- **FR-supply-22** — The job compares the result with the result from the base branch.
- **FR-supply-23** — The job posts a comment when a benchmark is more than 20 percent
  slower.
- **FR-supply-24** — The benchmark job does not fail the build. It warns only.

### The `gopacket` decision

- **FR-supply-25** — The project records a decision on `github.com/google/gopacket` in
  `docs/audit/dependency-decision.md`.
- **FR-supply-26** — The record names the last release date of each candidate.
- **FR-supply-27** — The record names every behaviour difference that the conformance
  suite reveals between the candidates.
- **FR-supply-28** — The project completes any migration before Epic 10 freezes the API.
- **FR-supply-29** — A migration keeps every exported signature of this library
  unchanged, or Epic 10 records the change.

### The coverage floor file

**FR-supply-17 reads `.coverage-floor` and FR-supply-19 raises the value, so neither one
creates the file.** The three requirements below create it. They carry the last three
numbers of this list, so no citation of an earlier requirement breaks.

- **FR-supply-30** — The repository holds a `.coverage-floor` file.
- **FR-supply-31** — The first value of `.coverage-floor` is the total statement coverage
  that `make cover` reports at the commit that creates the file.
- **FR-supply-32** — The commit that creates `.coverage-floor` names the command that
  measured the value.

## User flows

### A vulnerability appears in a dependency

1. `govulncheck` reports it on the next pull request or on the next Dependabot run.
2. The CI job fails and names the vulnerability and the calling path.
3. Dependabot opens a pull request that raises the dependency.
4. The whole CI workflow runs on that pull request, including conformance.
5. The maintainer merges it into `dev`.

### A change removes tests

1. The pull request runs the coverage job.
2. Coverage falls below `.coverage-floor`.
3. The job fails and prints both numbers.
4. The contributor adds the missing tests.

### The maintainer settles the `gopacket` question

1. Read the release history of both candidates.
2. Create a branch that changes the import path.
3. Run the conformance suite on both branches.
4. Record both results in `docs/audit/dependency-decision.md`.
5. Choose, and record the reason.

## Screens & states

The project has no user interface. The CI build summary is the only reader-facing output.

| State | What it shows |
|---|---|
| Coverage passes | The measured coverage, the floor, and a per-package table. |
| Coverage fails | The measured coverage, the floor, and the packages whose coverage fell. |
| Benchmark regression | A table of the changed benchmarks with the base value and the head value. |

## Behaviour rules

- A pinned action reference is a full 40-character commit hash. A tag is not a pin,
  because a tag moves.
- The coverage floor never falls. A change that reduces coverage fixes the change, not
  the floor.
- A benchmark warns and does not block, because runner variance produces false failures.
  A real regression is confirmed by hand.
- `govulncheck` reports by calling path, so a vulnerability in an unused function is a
  note and not a failure.
- The dependency decision is written before the migration starts, not after.
- FR-supply-12, FR-supply-13 and FR-supply-14 bind every workflow file, and never a named
  list of them. A workflow that a later epic creates arrives with every action pinned, and
  this feature set gains no requirement for it.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `.github/dependabot.yml` | New. |
| `.github/workflows/ci.yml` | Gains the vulnerability, coverage and benchmark jobs. Pins every action. |
| `.github/workflows/release.yml` | Pins every action. Declares least permissions. |
| `.github/workflows/fuzz.yml` | Pins every action. Epic 6 creates the file. |
| `.coverage-floor` | New. The coverage job reads it. Issue #68 creates the file. |
| `Makefile` | Gains the `vuln` target. |
| `docs/audit/dependency-decision.md` | New. |
| `go.mod`, `go.sum` | Change if the `gopacket` decision is a migration. |

**Three rows above name a file that the tree does not hold on 2026-08-13.** They name
`.github/dependabot.yml`, `.github/workflows/fuzz.yml` and `.coverage-floor`. **This
feature set creates two of the three, and it creates no workflow file.** FR-supply-6
creates `.github/dependabot.yml`, and the two bullets below carry the other two rows.

- `.github/workflows/fuzz.yml`. `features/06-fuzz-testing.md:132` names it `New.`, and
  FR-fuzz-27 states the nightly run that it holds. Issue #47 creates it. FR-supply-12,
  FR-supply-13 and FR-supply-14 bind it when it arrives.
- `.coverage-floor`. **This feature set creates it, and FR-supply-30 states that.** Two
  records named a different creator. The Epic 0 file table named Epic 0, `CLAUDE.md` names
  issue #68, and Epic 0 carries `status: built` while the tree holds no such file. **Epic
  0 created the file at no point, and no later change removed it.**
  `git log --all -- .coverage-floor` returns no commit, measured on 2026-08-13 at
  `8c3e0ae`. The project manager settled the question on 2026-08-13, and issue #429
  records that scope decision.
  `features/00-foundation.md` `## Behaviour rules` records the other half.

`git ls-tree -r --name-only origin/dev -- .github` returns `.github/workflows/ci.yml` and
`.github/workflows/release.yml` alone, measured on 2026-08-13 at `76659bb`. Issue #426
records the reading, and it moved no requirement between two epics.

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `govulncheck` | Pinned in the workflow | <https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck> |
| Go vulnerability database | Current | <https://vuln.go.dev> |
| Dependabot configuration | Version 2 | <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference> |
| GitHub Actions permissions | Current | <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions> |
| `github.com/google/gopacket` | v1.1.19 | <https://pkg.go.dev/github.com/google/gopacket> |
| `github.com/gopacket/gopacket` | Latest release | <https://pkg.go.dev/github.com/gopacket/gopacket> |

The engineer reads the release history of both `gopacket` candidates on `pkg.go.dev`
before FR-supply-25, and cites the dates in the record.

## Edge cases & failures

| Case | What happens |
|---|---|
| `govulncheck` reports a vulnerability with no fixed version. | The job fails. The maintainer records an accepted risk in `docs/audit/dependency-decision.md`, and the job gains a named exclusion with an expiry date. |
| Dependabot opens a pull request that breaks conformance. | The conformance job fails and the pull request does not merge. The maintainer decides. |
| A pinned action hash points at a deleted commit. | The workflow fails and names the action. The maintainer moves the pin. |
| The coverage measurement varies between runs. | Coverage from `go test -coverprofile` is deterministic for a deterministic suite. A varying number means a non-deterministic test, which is a defect. |
| The `gopacket` fork produces a different fingerprint for a capture. | The conformance suite catches it. The record names it and the decision accounts for it. |
| The benchmark comparison has no base result. | The job posts the head results and does not warn. |

## Acceptance criteria

- [ ] `make vuln` runs `govulncheck ./...`.
- [ ] The CI vulnerability job fails when a test dependency with a known called
      vulnerability is added.
- [ ] `.github/dependabot.yml` watches `gomod` and `github-actions`.
- [ ] A Dependabot pull request targets `dev`.
- [ ] Every `uses:` reference in every workflow is a 40-character commit hash with a
      version comment.
- [ ] `.github/workflows/ci.yml` declares `permissions: contents: read`.
- [ ] The CI coverage job prints the measured coverage and the floor.
- [ ] The CI coverage job fails when a test file is deleted.
- [ ] The repository holds a `.coverage-floor` file.
- [ ] The commit that creates `.coverage-floor` names the command that measured the
      value.
- [ ] The CI benchmark job posts a comparison and does not fail the build.
- [ ] `docs/audit/dependency-decision.md` records the `gopacket` decision, both release
      dates, and the reason.
- [ ] `go test -race ./...` passes after any dependency migration.
- [ ] `make conformance` reports zero deviations after any dependency migration.

## Out of scope

- This feature set does not add signed releases or SLSA provenance.
- This feature set does not add a software bill of materials.
- This feature set does not add CodeQL. `golangci-lint` and `govulncheck` cover the Go
  cases that matter here.
- This feature set does not add a `SECURITY.md`.

## Open questions

None. Risk R5 in `../spec.md` records the `gopacket` question that FR-supply-25 settles.
