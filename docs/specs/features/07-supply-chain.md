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
- **FR-supply-9** — Dependabot opens a version update pull request that targets `dev`. A
  security update pull request targets the default branch, and the default branch is
  `master`.

  **#477 amended this requirement on 2026-08-13, and the amendment is provisional.** The
  requirement read `Dependabot opens a pull request that targets \`dev\`.` until that date.
  **That sentence promises what the platform does not deliver**, because `target-branch`
  moves a version update alone.

  **GitHub states the limit, and no configuration key escapes it:**

  > All options marked with a security updates icon also change how Dependabot creates pull
  > requests for security updates, except where `target-branch` is used.

  The page renders an icon where this quotation writes `a security updates icon`. Verified
  against
  <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference>,
  retrieved 2026-08-13. **#477 read the page rather than adopting the sentence**, and it
  read the same sentence at the address GitHub redirects to,
  <https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference>.

  The same page states the rule three more times, once for each option that names it:

  > All pull requests for security updates are created with the chosen assignees, unless
  > `target-branch` defines updates to a non-default branch.

  **`.github/dependabot.yml` holds `target-branch: "dev"` on both ecosystems, and that is
  correct for a version update.** `gh repo view Crank-Git/ja4plus-go` reports the default
  branch as `master`, measured on 2026-08-13. So a security update reaches `master`, and it
  reaches `dev` through a later merge.

  **The one other lever belongs to the maintainer, and this amendment does not pull it.**
  A repository whose default branch is `dev` receives every security update on `dev`. That
  is a repository setting, and no session changes it.

  **Issue #66 is the reversal path.** #66 built `.github/dependabot.yml`, and the comment
  block of that file records the same reading. A reversal states which of the two answers
  the project takes: the default branch moves to `dev`, or the requirement returns to its
  first wording and stays false.

  **No maintainer comment and no project manager comment confirms this amendment**, and
  #477 measured that rather than adopting it. The body of issue #477 cites comment
  5286085774 of #439 and comment 5286440152 of #65 as the confirmation. **Neither comment
  names FR-supply-9, Dependabot or `target-branch`.** Comment 5286085774 of #439 decides the
  English question, and comment 5286440152 of #65 decides the Go 1.26 move. **So this
  amendment is unconfirmed, and a later reader reads it as unconfirmed.**

  **Comment 5286179281 of #66 states the one limit that no issue can close.**

  > **FR-supply-9 and FR-supply-11 cannot be proven by this issue.** No Dependabot pull
  > request exists until the schedule fires.

  The first Dependabot pull request is the first proof of the sentence above.
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
- **FR-supply-23** — The job writes the comparison to the build summary, and it prints one
  warning annotation when a benchmark is more than 20 percent slower.

  **#69 amended this requirement on 2026-08-13, and the amendment is provisional.** The
  requirement read `The job posts a comment when a benchmark is more than 20 percent
  slower.` until that date. A pull-request comment needs `pull-requests: write`, and
  FR-supply-15 gives `.github/workflows/ci.yml` `contents: read` and nothing more.

  **A widening does not buy the promise.** GitHub gives a fork pull request a read-only
  token whatever the `permissions` block states:

  > if the workflow was triggered by a pull request event other than `pull_request_target`
  > from a forked repository, and the **Send write tokens to workflows from pull requests**
  > setting is not selected, the permissions are adjusted to change any write permissions to
  > read only.

  > You can use the `permissions` key to add and remove `read` permissions for forked
  > repositories, but typically you can't grant `write` access.

  Verified against
  <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions>,
  retrieved 2026-08-13. **So a requirement that promises a comment on every regression
  cannot be met by widening**, and it stays false for every contributor who forks.

  **Three options were read and each one was declined.** Option A adds
  `pull-requests: write` at the workflow level, which breaks FR-supply-15 and gives a write
  scope to six jobs, five of which build pull-request code, inside the epic whose purpose is
  to reduce that exposure. Option B adds a job-level `permissions` block on the benchmark
  job alone, which fails `TestTheCIWorkflowGrantsNoJobLevelPermission`, the guard #68
  landed. Option C adds a second workflow file on `workflow_run` that reads an artifact and
  posts the comment, which adds a new write-scoped surface for a warning. **Each option
  still meets the fork limit above.**

  **A build summary is not a comment, and an annotation is not a comment.** The requirement
  now names what the job writes, and it promises no comment. `## Screens & states` below
  already states that the CI build summary is the only reader-facing output of this project.

  **#68 set the precedent on the same shape**, when it read FR-supply-19 as a rule for a
  person rather than widening the block.

  Comment 5286981123 of #69 holds the decision, and **issue #69 is the reversal path**. A
  reversal states which of the three costs the project accepts, and it answers the fork
  limit above.
- **FR-supply-24** — The benchmark job does not fail the build. It warns only.

### The `gopacket` decision

- **FR-supply-25** — The project records a decision on `github.com/google/gopacket` in
  `docs/audit/dependency-decision.md`.
- **FR-supply-26** — The record names the last release date of each candidate.
- **FR-supply-27** — The record names every behavior difference that the conformance
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

**The three requirements above name a command, and none of them names an environment.**
That silence produced the first failure of the gate, and this reading closes it. **No
requirement text changes here, because none of the three is false.**

`make cover` reads the FoxIO corpus, and `.gitignore` holds the corpus out of the tree. So
the same command reports two numbers. The measurement on 2026-08-13, at commit `83f2127`
and at commit `7210e80`:

| Corpus | Root package | Total |
|---|---|---|
| Present | 93.2 percent | 75.0 percent |
| Absent | 92.0 percent | 74.4 percent |

**#68 measured 75.0 with the corpus, and the coverage job fetched no corpus, so the floor
was unmeetable on the day it was written.** The `conformance` job read the corpus pin and
cached the corpus, and no step of the `coverage` job did.

**`.coverage-floor` describes the whole suite, and the coverage job fetches the corpus.**
The repair of the Epic 7 batch gate added the four corpus steps to that job on 2026-08-13,
and it left the floor at 75.0. `.coverage-floor` holds one number and no comment, because
`TestTheCoverageFloorIsOneNumber` fails on a second value. So the comment above the
`coverage` job of `.github/workflows/ci.yml` states the environment, and it states the
declined alternative.

**A person who measures a new floor under FR-supply-19 runs `make corpus` first.** A
measurement without the corpus reads 0.6 points low, and it writes a floor that the job
meets on a tree with fewer tests.

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
| Benchmark regression | A table of every benchmark either commit holds, with the base value, the head value and the change. A benchmark more than 20 percent slower carries a mark, and the job prints one warning annotation. |

## Behaviour rules

- A pinned action reference is a full 40-character commit hash. A tag is not a pin,
  because a tag moves.
- The coverage floor never falls. A change that reduces coverage fixes the change, not
  the floor.
- A benchmark warns and does not block, because runner variance produces false failures.
  A real regression is confirmed by hand.
- **A benchmark warns through the build summary and through a warning annotation, and never
  through a pull-request comment.** A comment needs a write scope that FR-supply-15 refuses
  and that a fork pull request never receives. The FR-supply-23 amendment above states the
  reading.
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

**This feature set built two of the three files that it had to create, and Epic 7 merged
them on 2026-08-13.** The reading below states what the tree holds today. **#477 measured
each sentence of it at commit `6681d3e`, and it adopted no earlier count.**

**One row above names a file that the tree does not hold**, and that row is
`.github/workflows/fuzz.yml`. `git ls-tree -r --name-only HEAD -- .github` returns
`.github/dependabot.yml`, `.github/workflows/ci.yml` and `.github/workflows/release.yml`,
measured on 2026-08-13 at `6681d3e`. The same command against `origin/dev` returns the same
three paths.

- `.github/dependabot.yml`. **Issue #66 created it, and the tree holds it.** FR-supply-6
  states the requirement, and the file carries the reading of every key it sets.
- `.coverage-floor`. **Issue #68 created it, and the tree holds it.** `git ls-files
  .coverage-floor` returns the path, and the file holds `75.0`, measured on 2026-08-13 at
  `6681d3e`. **This feature set creates it, and FR-supply-30 states that.** Two records
  named a different creator. The Epic 0 file table named Epic 0, and Epic 0 carries
  `status: built`. **Epic 0 created the file at no point.** The project manager settled the
  question on 2026-08-13, and issue #429 records that scope decision.
  `features/00-foundation.md` `## Behaviour rules` records the other half.
- `.github/workflows/fuzz.yml`. **The tree holds no such file.**
  `features/06-fuzz-testing.md` names it `New.`, and FR-fuzz-27 states the nightly run that
  it holds. Issue #47 creates it. FR-supply-12, FR-supply-13 and FR-supply-14 bind it when
  it arrives.

**An earlier reading of this section named three absent files, and #66 and #68 falsified
two of the three.** Issue #426 recorded that reading on 2026-08-13 at `76659bb`, and it
moved no requirement between two epics. **The count was correct on the day it was written**,
and this round replaces it rather than correcting a number inside it.

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
| `govulncheck` reports a vulnerability with no fixed version. | The calling path decides the exit status, and the fix status does not. A call that reaches the vulnerable symbol fails the job. A vulnerability that no call reaches exits 0, and the scanner prints a count of that kind. The maintainer records an accepted risk in `docs/audit/dependency-decision.md`. **The job gains no exclusion**, because the tool supports none. |
| Dependabot opens a pull request that breaks conformance. | The conformance job fails and the pull request does not merge. The maintainer decides. |
| A pinned action hash points at a deleted commit. | The workflow fails and names the action. The maintainer moves the pin. |
| The coverage measurement varies between runs. | Coverage from `go test -coverprofile` is deterministic for a deterministic suite. A varying number means a non-deterministic test, which is a defect. |
| The `gopacket` fork produces a different fingerprint for a capture. | The conformance suite catches it. The record names it and the decision accounts for it. |
| The benchmark comparison has no base result. | The job posts the head results and does not warn. |

**#477 repaired both halves of the first row on 2026-08-13, and it read the tool rather
than the requirement.** The row promised a failure that the fix status does not produce,
and it promised an exclusion that the tool does not offer.

**The calling path decides the exit status.** The `vuln` target of `Makefile` records the
three sources of `golang.org/x/vuln` v1.6.0 that state the rule, and `parseFlags` in
`internal/scan/flags.go` sets the default scan level to `symbol`. **A called vulnerability
exits 3, and an uncalled one exits 0.** FR-supply-2 and FR-supply-5 each state one half of
that separation, and neither one reads the fix status.

**The tool offers no exclusion, and it states so.**

> There is no support for silencing vulnerability findings. See https://go.dev/issue/61211 for updates.

Verified against <https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck>, retrieved
2026-08-13. **The page renders `cmd/govulncheck/doc.go` of `golang.org/x/vuln`, and #486
read that file at v1.6.0**, which `.github/workflows/ci.yml` pins.
`golang.org/x/vuln@v1.6.0/cmd/govulncheck/doc.go:95` holds the sentence, and it wraps the
URL in no angle bracket. **The quotation above reproduces the tool's text**, and round 44 of
the `## Changelog` of `docs/specs/spec.md` holds the same text. **So a named exclusion with an expiry date is unbuildable**, and the maintainer
records an accepted risk in `docs/audit/dependency-decision.md` alone.

## Acceptance criteria

- [ ] `make vuln` runs `govulncheck ./...`.
- [ ] The CI vulnerability job fails when a test dependency with a known called
      vulnerability is added.
- [ ] `.github/dependabot.yml` watches `gomod` and `github-actions`.
- [ ] A Dependabot version update pull request targets `dev`.
- [ ] A Dependabot security update pull request targets `master`, which is the default
      branch.
- [ ] Every `uses:` reference in every workflow is a 40-character commit hash with a
      version comment.
- [ ] `.github/workflows/ci.yml` declares `permissions: contents: read`.
- [ ] The CI coverage job prints the measured coverage and the floor.
- [ ] The CI coverage job fails when a test file is deleted.
- [ ] The repository holds a `.coverage-floor` file.
- [ ] The commit that creates `.coverage-floor` names the command that measured the
      value.
- [ ] The CI benchmark job writes a comparison to the build summary and does not fail the
      build.
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
