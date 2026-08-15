---
id: pre-release-validation
feature: Pre-release validation
epic: "Epic 16: Pre-release validation"
status: issued
issues: [94, 95, 96, 97, 98, 99]
mockups: []
---

## Purpose

Every gate in this project runs against the working tree. **No gate runs against the thing
a user installs.** A module can pass every test in the repository and still fail for a
user, because the repository holds files the module does not publish, and the working tree
holds a build cache the user does not have.

The port found this. Its Epic 11 built a clean environment, installed the published
artifact into it, and fingerprinted a capture from there. That epic found defects that no
working-tree test could find.

This feature set does the same for Go. It proves that `go install` works from a clean
module cache, that each released binary runs on its platform, and that the documentation
site builds from its committed pins alone.

## User stories

- As a user, I want `go install` to produce a working program, so that the install
  instruction in the README is true.
- As a user, I want the binary I download to run on my platform, so that I do not build
  from source.
- As a maintainer, I want the release blocked when the artifact is broken, so that I do
  not publish a tag I must delete.
- As a maintainer, I want the check to read the tag I pushed, so that I promote no broken
  release.

## Functional requirements

### The clean environment

- **FR-prerelease-1** — A case builds a clean environment that holds no source of this
  repository.
- **FR-prerelease-2** — The environment holds an empty `GOMODCACHE`.
- **FR-prerelease-3** — The environment holds an empty `GOCACHE`.
- **FR-prerelease-4** — The case removes the environment when it finishes.
- **FR-prerelease-5** — `make prerelease` runs every case of this feature set.

### The module install

- **FR-prerelease-6** — A case runs `go install github.com/Crank-Git/ja4plus-go/cmd/
  ja4plus@<version>` in the clean environment.
- **FR-prerelease-7** — The installed program prints its version, and the version matches
  the tag.
- **FR-prerelease-8** — The installed program fingerprints a capture and produces the
  expected value.
- **FR-prerelease-9** — A case runs `go get` for the library in an empty module and
  compiles a program that imports it.
- **FR-prerelease-10** — That program calls `Processor.ProcessPacket` and
  `Processor.CloseOpenWindows`.
- **FR-prerelease-11** — The case reads no file of this repository.

### The published module contents

- **FR-prerelease-12** — A case lists the files that the module publishes.
- **FR-prerelease-13** — The published module holds `data/ja4plus-mapping.csv`, which
  `go:embed` needs.
- **FR-prerelease-14** — The published module holds `LICENSE` and `NOTICE`.
- **FR-prerelease-15** — The published module holds no capture file of the corpus.
- **FR-prerelease-16** — The published module holds no `site/` directory.
- **FR-prerelease-17** — A case asserts the module size is below a recorded ceiling.

### The binaries

- **FR-prerelease-18** — A case runs each released binary on its own platform.
- **FR-prerelease-19** — Each binary prints its version, and the version matches the tag.
- **FR-prerelease-20** — Each binary fingerprints a capture and produces the expected
  value.
- **FR-prerelease-21** — A case asserts that each binary holds no dynamic link to
  libpcap.
- **FR-prerelease-22** — A case verifies each checksum against the published file.

### The documentation site

- **FR-prerelease-23** — A case installs `docs/requirements.txt` into an empty environment.
- **FR-prerelease-24** — The case runs `mkdocs build --strict` and it succeeds.
- **FR-prerelease-25** — The case reads no generator version that is not pinned.

### The release gate

**FR-prerelease-26 carries an amendment that the maintainer ruled on 2026-08-15 UTC**, and
#633 applies it. The ruling stands at
https://github.com/Crank-Git/ja4plus-go/issues/633#issuecomment-5299776974. **The
pre-amendment requirement named a moment at which no tag exists.** It read
`make prerelease` passes before the maintainer creates the tag, and five of the cases read
a published release. So the requirement asked a case to read something the moment does not
hold, and the case asserted nothing for that reason. #633 renamed that case to
`TestTheReleaseGateRunsAgainstTheTagUnderTest`, and the case now reads the tag.
**The amended requirement names the release gate**: the maintainer pushes the tag, the run
reads that tag, and the promotion waits on the result. **#633 is the reversal path.**

- **FR-prerelease-26** — `make prerelease` runs against the tag under test. The maintainer
  promotes the release only when every case passes or carries a recorded reason.
- **FR-prerelease-27** — A case asserts that `testdata/deviations.json` holds no entry
  whose comparison now matches.
- **FR-prerelease-28** — A case asserts that the most recent sweep records every `LIVED`
  mutation as settled or as counted. FR-mutation-11 states which of the two each mutation
  takes.
- **FR-prerelease-29** — A case asserts that no tracked document states a method count
  that `features/12-ja4ls.md` forbids.
- **FR-prerelease-30** — A case asserts that the README links to the documentation site
  and that the link resolves.

**FR-prerelease-28 follows FR-mutation-11, and #642 aligned the two on 2026-08-15 UTC.**
The maintainer amended FR-mutation-11 on 2026-08-14, and #634 carried that amendment into
`docs/specs/features/15-mutation-sweep.md`. The pre-amendment requirement read as follows.

> A case asserts that every `LIVED` mutation of the most recent sweep is settled.

That requirement asked for a settlement for each of the 223 `LIVED` mutations that
`docs/mutation_reports/2026-08-14-internal-parser.md` holds. **The amended
FR-mutation-11 asks for a settlement on code that can move a fingerprint value, and it
counts every other mutation.** So a case that demanded 223 settlements would read the
tracked record as incomplete work. **#642 is the reversal path**, and a reversal restores
the sentence above.

**No case decides the fingerprint risk of one mutation.** That reading is a person's work,
and `docs/mutation_settlements/` holds the record of it.
`TestEveryLivedMutationOfTheMostRecentSweepIsSettled` holds the property a machine holds:
the record covers the sweep that the tree carries today.

## User flows

### A maintainer prepares a release

1. The maintainer pushes the tag on the release commit.
2. GoReleaser builds the artifacts and publishes the release.
3. The maintainer downloads the artifacts and runs `make prerelease` against that tag.
4. Every case passes.
5. The maintainer promotes the release.

### A case finds a broken artifact

1. `go install` in the clean environment fails, because the module publishes no embedded
   database.
2. The case reports the missing path.
3. The maintainer promotes no release, and it records the reason.
4. The maintainer repairs the module, and the next attempt takes the next version.

## Screens & states

This feature set changes no screen.

## Behaviour rules

- **A case that reads the working tree proves nothing.** FR-prerelease-11 is the rule that
  makes the rest meaningful.
- **The check gates the promotion.** A published tag cannot be moved, and a deleted tag
  stays in the module proxy cache. So the maintainer pushes the tag, the run reads it, and
  a failing case stops the promotion.
- **A binary case runs on the platform it tests.** A Linux runner cannot prove that the
  Darwin binary runs.
- **The corpus is FoxIO-licensed material.** FR-prerelease-15 keeps it out of the
  published module, and it is the license rule as well as a size rule.

## Data touched

| File | Change |
|---|---|
| `scripts/prerelease.sh` | New. Builds the clean environment and runs the cases. |
| `prerelease_test.go` | New. Build tag `prerelease`. |
| `Makefile` | The `prerelease` target. |
| `.github/workflows/prerelease.yml` | New. Runs the cases on a matrix of platforms. |
| `testdata/prerelease/` | New. One small capture and its expected values. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| Go module proxy | Current | <https://proxy.golang.org> |
| `go install` reference | Go 1.24 | <https://go.dev/ref/mod#go-install> |
| `go mod` file selection | Go 1.24 | <https://go.dev/ref/mod#zip-path-size-constraints> |
| GoReleaser | v2 | <https://goreleaser.com/customization/> |

Retrieved 2026-08-11.

**A published module is immutable and a deleted tag stays in the proxy cache.** That is
the reason the amended FR-prerelease-26 gates the promotion. The maintainer spends one tag
on each attempt, and a failing case costs no published release.

## Edge cases & failures

| Case | Expected behavior |
|---|---|
| The module proxy has not seen the tag yet. | The install case retries for a recorded time, then fails with a message that names the proxy. |
| The clean environment inherits a `GOFLAGS` value from the host. | FR-prerelease-1 clears the environment. A leaked flag would invalidate the case. |
| A binary is built for a platform no runner offers. | The case records the platform as unchecked and names it in the release notes. It does not pass silently. |
| `go install` succeeds and the program cannot find the embedded database. | FR-prerelease-13 fails first and names the missing path. |
| The site build reaches the network for an unpinned package. | FR-prerelease-25 fails. |
| The tag exists and a case fails. | The maintainer deletes the release, and the tag stays in the proxy. The next release takes the next version. |
| The tag exists, a case fails, and the maintainer accepts the failure. | The maintainer records the reason and promotes the release. FR-prerelease-26 permits one recorded reason for each failing case. |
| The run reads no tag under test. | The release gate case fails and it names the tag it looked for. A run that reads no release proves nothing about the artifact. |

## Acceptance criteria

1. `make prerelease` runs every case and reports one summary.
2. `go install` from a clean module cache produces a program that fingerprints the test
   capture correctly.
3. An empty module that imports the library compiles and runs, reading no file of this
   repository.
4. The published module holds the embedded database, `LICENSE` and `NOTICE`, and holds no
   corpus capture.
5. Each released binary runs on its platform and prints the tag version.
6. No released binary holds a dynamic link to libpcap.
7. Every published checksum verifies.
8. `mkdocs build --strict` succeeds from `docs/requirements.txt` alone.
9. Every gate of FR-prerelease-27 through FR-prerelease-30 passes.

## Out of scope

- Publishing the release. `features/10-release.md` owns that.
- Testing a platform that no runner offers. The case records it as unchecked.
- A package for a system package manager.
- A container image.

## Open questions

1. **Which platforms can CI actually run the binaries on?** GitHub-hosted runners offer
   Linux and macOS on both architectures, and Windows on amd64. Linux arm64 needs a
   runner that may not be free. The case that cannot run records the platform as
   unchecked, and the release notes name it.
2. **Does the module size ceiling of FR-prerelease-17 have a number yet?** It is measured
   once at Epic 16 and recorded then. A ceiling invented before the measurement would be
   arbitrary. **#97 measured it on 2026-08-14, and `publishedModuleSizeCeiling` in
   `prerelease_module_contents_test.go` holds the number.** The module zip of `v0.3.0`
   measures 2253962 bytes compressed and 2444024 bytes uncompressed. `assets/logo.png` is
   2192430 uncompressed bytes, which is 89.7 percent of the uncompressed total. The
   ceiling is 4 MiB, and it reads the compressed zip size. A corpus capture and a built
   site each add more than 2 MiB, so either one crosses it.
