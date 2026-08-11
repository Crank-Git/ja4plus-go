---
id: release
feature: API freeze and release
epic: "Epic 10: API freeze and release"
status: issued
issues: [100, 101, 102, 103, 104, 105, 106]
mockups: [mockups/02-cli-output.html]
---

## Purpose

Every other epic changes the library. This one records what the library became, freezes
its exported API, and releases `v1.0.0`.

A `v1` release in Go is a promise. The Go module system treats `v1.x.y` as compatible
with every other `v1`, and a consumer upgrades without reading a note. Breaking that
promise means `v2` and a changed import path. So the freeze is the point at which every
exported name stops moving.

The README also needs a rewrite. It describes a library that this work changed. It states
one license that is wrong. It documents no concurrency contract. It links to a `LICENSE`
file that did not exist.

## User stories

- As a library author, I want a `v1.0.0` that will not break my build, so that I can
  depend on it without pinning a commit.
- As a library author, I want the README to describe the library I get, so that I do not
  discover a difference at runtime.
- As an analyst, I want the command-line program documented with real output, so that I
  know what to expect before I run it.
- As a maintainer, I want a release that needs no manual step, so that tagging is the
  whole process.

## Functional requirements

### The API record

- **FR-release-1** — The project records every exported name in `docs/api/v1.md`.
- **FR-release-2** — Each record holds the name, the signature and one sentence that
  states what it does.
- **FR-release-3** — The record names every type, function, method, constant and
  variable that the package exports.
- **FR-release-4** — A test compares the exported API with `docs/api/v1.md` and fails when
  they differ.
- **FR-release-5** — The record states that `v1` will not remove or change any name in it.

### Package documentation

- **FR-release-6** — `doc.go` holds a package comment that opens with one sentence that
  states what the package does.
- **FR-release-7** — The package comment holds a section on the eleven methods. It states
  that ten fingerprinters carry them, because `JA4LFingerprinter` writes JA4L and JA4LS.
- **FR-release-8** — The package comment holds a section on the concurrency contract.
- **FR-release-9** — The package comment holds a section on the license split.
- **FR-release-10** — The package comment holds a runnable example.
- **FR-release-11** — Every exported name has a documentation comment.
- **FR-release-12** — Every documentation comment opens with the name it documents.
- **FR-release-13** — The package holds a runnable `Example` function for `Processor`.
- **FR-release-14** — The package holds a runnable `Example` function for
  `SyncProcessor`.
- **FR-release-15** — The package holds a runnable `Example` function for
  `LookupFingerprint`.
- **FR-release-16** — `go test ./...` runs every example and checks its output.

### The README

- **FR-release-17** — The README states the eleven methods and the protocol each reads. It
  states that ten fingerprinters carry them.
- **FR-release-18** — The README states the Go version floor.
- **FR-release-19** — The README holds an install command that names `v1.0.0`.
- **FR-release-20** — The README holds a library example that compiles.
- **FR-release-21** — The README holds a command-line example with real output.
- **FR-release-22** — The README holds a concurrency section with both patterns.
- **FR-release-23** — The README holds a license section that states the split.
- **FR-release-24** — The README holds a conformance section that names the FoxIO commit
  the library is tested against.
- **FR-release-25** — The README states which functions reach the network.
- **FR-release-26** — The README states how to report a vulnerability.
- **FR-release-27** — Every badge in the README links to a target that exists.
- **FR-release-28** — Every code block in the README is checked by a test or by a script.

### The CHANGELOG

- **FR-release-29** — `CHANGELOG.md` holds a `v1.0.0` section.
- **FR-release-30** — The section records every changed fingerprint as a breaking
  behaviour change.
- **FR-release-31** — The section records every added exported name.
- **FR-release-32** — The section records every removed exported name.
- **FR-release-33** — The section records the license correction.
- **FR-release-34** — The section records the Go version floor change.

### The release

- **FR-release-35** — `.github/workflows/release.yml` runs the conformance suite before
  it builds.
- **FR-release-35a** — GoReleaser builds the release. `.goreleaser.yaml` holds the
  configuration, and the workflow holds no inline build matrix.
- **FR-release-35b** — GoReleaser builds five artifacts: Linux amd64, Linux arm64, Darwin
  amd64, Darwin arm64 and Windows amd64.
- **FR-release-35c** — Every artifact is built with `CGO_ENABLED=0`.
- **FR-release-35d** — No artifact is built with the `libpcap` build tag.
- **FR-release-35e** — GoReleaser writes a checksum file for every artifact.
- **FR-release-35f** — GoReleaser writes a software bill of materials for every artifact.
- **FR-release-35g** — The build stamps the version, the commit and the build date into
  the program.
- **FR-release-35h** — `goreleaser check` gates every pull request that touches
  `.goreleaser.yaml`.
- **FR-release-35i** — `goreleaser release --snapshot --clean` runs on a pull request and
  publishes nothing.
- **FR-release-35j** — The GoReleaser version is pinned in the workflow.
- **FR-release-35k** — Every action reference in the workflow is pinned to a commit hash.
- **FR-release-36** — The release workflow fails when the conformance suite reports a
  deviation.
- **FR-release-37** — The release workflow builds on Go 1.24.
- **FR-release-38** — The release workflow attaches `LICENSE` and `NOTICE` to the
  release.
- **FR-release-39** — The release workflow reads the release notes from `CHANGELOG.md`.
- **FR-release-40** — The `v1.0.0` tag is created on `master`.
- **FR-release-41** — `pkg.go.dev` serves the `v1.0.0` documentation after the release.

### The release gate

- **FR-release-42** — The release does not proceed until
  `docs/audit/license-decision.md` records the maintainer's decision.
- **FR-release-43** — The release does not proceed until `make conformance` reports zero
  deviations.
- **FR-release-44** — The release does not proceed until every entry in
  `docs/audit/conformance-exclusions.md` holds the maintainer's acceptance.
- **FR-release-45** — The release does not proceed until `go test -race ./...` passes.
- **FR-release-46** — The release does not proceed until `govulncheck ./...` reports
  nothing.
- **FR-release-47** — The release does not proceed until `make prerelease` passes.
  `features/16-pre-release-validation.md` holds the cases.
- **FR-release-48** — The release does not proceed until `testdata/deviations.json` holds
  no entry whose comparison now matches.
- **FR-release-49** — The release does not proceed until every register row of
  `features/08-python-parity.md` is closed.
- **FR-release-50** — The release does not proceed until `mkdocs build --strict`
  succeeds.
- **FR-release-51** — The CHANGELOG records `CloseOpenWindows` as a breaking change to the
  exported `Fingerprinter` interface.
- **FR-release-52** — The CHANGELOG records JA4LS as a new method, and states eleven
  methods and ten fingerprinters.

## User flows

### The maintainer releases `v1.0.0`

1. Merge `dev` into `master`.
2. Run `make corpus` and `make conformance`. The suite reports zero deviations.
3. Run `go test -race ./...`. The suite passes.
4. Run `make vuln`. The scan reports nothing.
5. Confirm that every release gate in FR-release-42 through FR-release-46 is met.
6. Tag `v1.0.0` on `master`.
7. The release workflow runs conformance, builds five binaries, and publishes.
8. Confirm that `pkg.go.dev` serves the documentation.

### A user adopts the library

1. Read the README.
2. Run `go get github.com/Crank-Git/ja4plus-go@v1.0.0`.
3. Copy the library example.
4. Read the concurrency section and choose a pattern.
5. Read the license section and decide whether to contact FoxIO.

## Screens & states

The command-line program is the only reader-facing surface.
`mockups/02-cli-output.html` shows its output.

| Screen | Purpose | States |
|---|---|---|
| `ja4plus <capture>` | Print every fingerprint in a capture. | Populated, empty capture, unreadable file, unsupported link type. |
| `ja4plus db info` | Print the database state. | Embedded, cached. |
| `ja4plus db update` | Download a new database. | Success, network failure, validation failure. |
| `ja4plus --version` | Print the version. | Always one line. |

## Behaviour rules

- The freeze covers exported names only. An unexported change is free.
- A name that Epic 2, Epic 3, Epic 8 or Epic 9 changed lands before the freeze, not after.
- The README states what the library does today. It carries no plan and no promise about
  a later version.
- The CHANGELOG records a changed fingerprint as breaking, even when no signature moved.
  A caller who stored a fingerprint is affected by it.
- A release gate that fails stops the release. No gate is waived without a written record.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `docs/api/v1.md` | New. |
| `api_test.go` | New. Compares the exported API with the record. |
| `doc.go` | Rewritten. |
| `example_test.go` | New. Holds the runnable examples. |
| `README.md` | Rewritten. |
| `CHANGELOG.md` | Gains the `v1.0.0` section. |
| `.github/workflows/release.yml` | Gains the conformance gate and the notes source. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| Go module version rules | Current | <https://go.dev/doc/modules/version-numbers> |
| Go documentation comments | Current | <https://go.dev/doc/comment> |
| Testable examples | Go 1.24 | <https://go.dev/blog/examples> |
| `pkg.go.dev` publishing | Current | <https://pkg.go.dev/about> |
| `softprops/action-gh-release` | v2, pinned to a commit hash | <https://github.com/softprops/action-gh-release> |
| Keep a Changelog | 1.1.0 | <https://keepachangelog.com/en/1.1.0/> |

The API comparison in FR-release-4 uses `go/packages` or `golang.org/x/exp/apidiff`. The
engineer confirms the chosen package against its documentation before use, and records
the choice in the issue.

## Edge cases & failures

| Case | What happens |
|---|---|
| The API test finds a name that `docs/api/v1.md` does not hold. | The test fails. The engineer adds the name to the record, or unexports it. |
| A conformance deviation appears after the tag is pushed. | The release workflow fails before it publishes. The maintainer deletes the tag and fixes the deviation. |
| `pkg.go.dev` does not show the new version. | The module proxy caches. The maintainer requests the version once and waits. |
| A README code block stops compiling. | The check in FR-release-28 fails. The block is fixed with the code. |
| The maintainer has not recorded the license decision. | FR-release-42 stops the release. |
| A user on Go 1.22 tries to install `v1.0.0`. | The toolchain refuses and names the required version. The README states the floor. |

## Acceptance criteria

- [ ] `docs/api/v1.md` records every exported name with its signature.
- [ ] `go test ./...` fails when an exported name is added and the record is not updated.
- [ ] `go doc github.com/Crank-Git/ja4plus-go` prints the methods, the concurrency
      contract and the license split.
- [ ] Every exported name has a documentation comment that opens with its name.
- [ ] `go test ./...` runs the `Processor`, `SyncProcessor` and `LookupFingerprint`
      examples and checks their output.
- [ ] The README library example compiles and runs.
- [ ] The README command-line example output matches the real program output.
- [ ] The README names the FoxIO commit that the library is tested against.
- [ ] Every README badge links to a target that returns a success status.
- [ ] `CHANGELOG.md` holds a `v1.0.0` section that records the license correction, the Go
      floor change, every added name, every removed name and every changed fingerprint.
- [ ] The release workflow runs the conformance suite and fails on a deviation.
- [ ] The release workflow attaches `LICENSE` and `NOTICE`.
- [ ] `go get github.com/Crank-Git/ja4plus-go@v1.0.0` resolves after the release.
- [ ] `pkg.go.dev` serves the `v1.0.0` documentation.

## Out of scope

- This feature set does not add a `v2` plan.
- This feature set does not add a deprecation policy beyond the `v1` promise.
- This feature set does not submit this library to the FoxIO implementations table. That
  is a task the maintainer may do after the release.
- This feature set does not publish a container image.

## Open questions

None.
