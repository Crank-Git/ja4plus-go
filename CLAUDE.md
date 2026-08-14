# ja4plus-go

A Go library and command-line program for JA4+ network fingerprinting. It reads packets
through `gopacket`. JA4+ is a set of standards that FoxIO publishes. This library is an
independent Go implementation.

**FoxIO names twelve methods. This project implements eleven of them.**
**`JA4LFingerprinter` writes both JA4L and JA4LS, so ten fingerprinters carry eleven
methods.** Read the ten as a count of fingerprinters, and never as a count of methods. A
document that states "ten methods" is wrong, and a test holds that count.

The library is at `v0.3.0`. The current work takes it to `v1.0.0`, which freezes the
exported API. Four things must be true before that freeze: the output must match the FoxIO
reference, the concurrency contract must be explicit and correct, the license must state
the FoxIO terms, and this library and the Python port must produce the same fingerprint.

## Where the design lives

Design lives in `docs/specs/`. Read `docs/specs/spec.md` and the relevant
`docs/specs/features/*.md` before you build a feature. Open `docs/specs/spec.html` in a
browser for the readable overview.

The `## Terms` table in `docs/specs/spec.md` is this project's controlled vocabulary.
Read it before you write a domain word in a document, an issue, or a code comment.

`docs/specs/foxio/` holds the evidence. It transcribes each FoxIO image as numbered rules,
recovers the seven text specifications that FoxIO deleted, and records the reading of each
reference implementation. **Read the transcription before you change a fingerprint value.**

The `## Parity with ja4plus` section of `docs/specs/spec.md` holds the divergence register.
The Python port at `Crank-Git/ja4plus` shipped first and ruled first, and about twenty rows
of that register name a change to this repository. Read
`.claude/rules/parity.md` before you touch a fingerprint value or an exported name.

## Stack

- Go 1.24 or later. **That sentence states a language version, and it states no build
  toolchain.** #438 established the reading on 2026-08-13, and `go.mod` declares
  `go 1.24.0`. **The `or later` names the toolchain that compiles the module**, and it
  names no toolchain that builds a released binary.
- **The minimum build toolchain is go1.25.13, and it answers a different question from the
  language version above.** A language version decides which consumer compiles the module.
  **A build toolchain decides which standard library a built binary links.** So a Go 1.24
  toolchain compiles this module and it links 13 called vulnerabilities, measured on
  2026-08-14.
- **The maintainer ruled the toolchain question on 2026-08-14**, and #472 holds the ruling
  and the reversal path. `README.md` and `doc.go` state the measurement. **Every CI job
  builds on the range `~1.26.6`**, and `goToolchainRange` in `foundation_test.go` states
  that range once for both workflows.
- `github.com/gopacket/gopacket` for packet decoding. The maintainer decided the move from
  `github.com/google/gopacket` on 2026-08-13, and #438 carried it.
- `golang.org/x/crypto` for SSH and hashing.
- **The default build holds no cgo, and it cross-compiles to five platforms.** Every
  released binary is built with `CGO_ENABLED=0`.
- **One build path uses cgo, and the `libpcap` build tag selects it.** It exists so that
  `ja4plus watch` reaches macOS, because `pcapgo`'s pure-Go capture handle is Linux-only.
  Never add a cgo dependency outside that tag, and never build a release artifact with it.
- MkDocs with the Material theme for the documentation site. It runs in one CI job and no
  Go code depends on it.

## Layout

| Path | Holds |
|---|---|
| `*.go` at the root | Package `ja4plus`: one fingerprinter per method, `Processor`, the local database lookup. |
| `ja4db/` | Package `ja4db`: the remote lookup at `ja4db.com`. It is the one package of the library that reaches the network. |
| `internal/parser/` | Protocol decoding for TLS, QUIC, HTTP, SSH, TCP streams, X.509 and GREASE. |
| `internal/dbcache/` | The validation of a downloaded database, the 16 MB bound and the atomic cache write. |
| `cmd/ja4plus/` | The command-line program. |
| `data/` | The embedded FoxIO fingerprint mapping. |
| `internal/capture/` | Opening a live interface. Holds the pure-Go backend, the libpcap backend, the unsupported-platform fallback, and one permission probe for each of Linux, macOS and every other platform. |
| `internal/keylog/` | Reading a pcapng Decryption Secrets Block and a key log in the NSS key log format. |
| `testdata/foxio/` | The fetched FoxIO corpus. Not tracked in git. |
| `testdata/deviations.json` | The register: one entry per accepted difference from a FoxIO value. Tracked. |
| `docs/specs/` | The spec package. Tracked. Not published to the site. |
| `docs/specs/foxio/` | The FoxIO transcriptions and readings that every ruling cites. |
| `docs/audit/` | Audit findings, the conformance report and the recorded decisions. |
| `docs/` (the rest) | The pages the documentation site publishes. |

A new fingerprinter file goes at the root. New protocol decoding goes in
`internal/parser/`. Interface capture goes in `internal/capture/`. Nothing that reads a
packet belongs in `cmd/`.

**Every network call of the library goes in `ja4db/`.** The maintainer ruled that boundary
on 2026-08-14, and `docs/audit/network-boundary.md` holds the record. The core package
imports no HTTP client, and `network_boundary_test.go` fails on an import that breaks the
rule.

## Commands

| Command | What it does |
|---|---|
| `make build` | Build the command-line program into `bin/`. |
| `make test` | Run the unit tests under the race detector. |
| `make lint` | Run `golangci-lint` at the pinned version, with one cache for this checkout. |
| `make lint-cache-check` | Prove the stale linter cache defect of #257, and prove the repair. |
| `make corpus` | Fetch the FoxIO corpus at the pinned commit. |
| `make conformance` | Run the conformance suite against the corpus. |
| `make fuzz` | Run each fuzz target for 30 seconds. **The tree holds 15 targets**, measured on 2026-08-14. |
| `make bench` | Run the benchmarks with allocation counts. |
| `make cover` | Report total statement coverage. |
| `make vuln` | Scan for a known vulnerability with `govulncheck`. Install the version that `.github/workflows/ci.yml` pins. |
| `make mutate` | **Not built yet.** #90 adds the target, under Epic #89. It runs the mutation sweep over the named package set. Slow. Gates nothing. |
| `make prerelease` | Run the pre-release cases behind the `prerelease` build tag. #95 added the target on 2026-08-14, under Epic #94. It runs the clean environment case alone today, and it prints one summary line for each case. |
| `make docs` | Build the documentation site with `mkdocs build --strict`. #84 added the target on 2026-08-14. Install the pins of `docs/requirements.txt` first, or override the generator: `make docs MKDOCS=.venv/bin/mkdocs`. |

Run `make corpus` once before `make conformance`. The conformance suite skips without it.

**`make fuzz` reads the target list from the tree**, with `go test -list '^Fuzz'` over
`go list ./...`. So a new target joins the run without an edit to the `Makefile`. Epic 6
added 13 targets on 2026-08-14, and the recipe found every one of them. **The two targets
that the tree already held are `FuzzNoExportedFunctionPanicsOnAnyFrame` and
`FuzzTCPOptionEntriesReadsAnyOptionRegion`.** Re-measure the count with
`grep -rn --include='*_test.go' '^func Fuzz' .` rather than reading it from a document.

**One run of `make fuzz` takes about 8 minutes**, because it fuzzes 15 targets in turn for
30 seconds each.

**The `Makefile` defines every row of this table except the `mutate` row.** An absent
target is work a later issue does, and never a broken target.

- `make mutate` exits 2. It prints one line that names the target:
  ``make: *** No rule to make target `mutate'.  Stop.``
- **`make prerelease` needs the `prerelease` entry of the `.PHONY` line.** #95 added the
  target on 2026-08-14, and no directory of that name exists today. A later commit that
  adds one would stop the target, and the entry holds the recipe against that.
  `TestTheMakefileRunsThePrereleaseCases` in `prerelease_registry_test.go` holds the entry.
- **`make docs` needs the `docs` entry of the `.PHONY` line, and that entry is not
  decoration.** `docs/` is a directory of this repository, so make reads the bare target
  name as that directory and finds it already up to date. Without the `.PHONY` entry it
  prints ``make: Nothing to be done for `docs'.`` and it exits 0 without a site build.
  `TestTheMakefileBuildsTheSite` in `mkdocs_config_test.go` holds the entry.
- `make vuln` exits 3 when the library calls a vulnerable function. It exits 0 when a
  vulnerable module reaches the build and no call reaches it, and it prints a count of
  that second kind. **The scanner reads the Go version of the `go` command on the PATH**,
  so a second toolchain reports a second result.

## A change is done when

1. `go build ./...` succeeds.
2. `go test -race ./...` passes.
3. `make lint` reports nothing. **Run the linter through `make lint`, and never as a bare
   `golangci-lint run`.** A bare run reads the linter cache of the whole user account. That
   cache holds an absolute path from another checkout, and #257 records the false failure
   it produces.
4. `make conformance` reports no deviation that `testdata/deviations.json` does not hold,
   and the register holds no entry whose comparison now matches.
5. Coverage does not fall below the value in `.coverage-floor`. **#68 created that file on
   2026-08-13, and this step is runnable today.** Run `make cover`, and read the total
   against the value in the file. The CI coverage job fails on a total below it.
6. `make docs` succeeds, when the change touches a page. **#84 made this step runnable on
   2026-08-14.** Install the pins of `docs/requirements.txt` into a virtual environment
   first. The site publishes `docs/` and it excludes `docs/specs/` and `docs/audit/`, so a
   change to the spec package alone leaves this step untouched.

## Conventions

- **No agent runs `git stash` in a worktree of this repository.** Every worktree shares one
  stash ref, so a stash here destroys the work of another worktree. Copy the file with `cp`
  before you change it. Restore a committed file with `git checkout -- <file>`.
  `.claude/rules/worktrees.md` holds the reason, the third alternative and the git hook.
- **The project manager runs one cross-member review at every batch gate.** Spawn it with
  no `name`. Read the spawn response. A response that names a mailbox reached the
  cross-session path, and that path can return an idle signal and no text. A cross-member
  review that returns no text checked nothing. The project manager then runs the six
  categories by hand, and it says so in the gate comment.
  `.claude/rules/cross-member-review.md` holds the measurement, the return contract and
  the procedure.
- **A finding earns a tracker issue in five cases, and never otherwise.** The maintainer
  adopted this policy on 2026-08-13. A finding earns an issue when it touches one of these.
  - Behavior.
  - A fingerprint value.
  - A guard that guards nothing.
  - A blocked epic.
  - A question the maintainer must rule.

  **The batch documentation round repairs every other finding, in the batch that found it,
  and it files no issue.** A falsified sentence, a moved citation, a missing term and a
  stale count each reach the round. **The round reports a finding that turns out to touch
  behavior**, and that finding then becomes an issue under the five cases above.

  The measurement that earned the policy: of 42 loose open issues, about twenty repaired a
  sentence, a citation, a term or a stale count. **Each repair produced more issues.** #410
  exists because #398 edited a file. #419 exists because #355 edited a file. #436 exists
  because #70 measured something. **The backlog regenerated at about the rate it closed.**
- **The FoxIO reference decides every disputed fingerprint.** A test that disagrees with
  the reference is wrong. Never change a FoxIO vector to make a test pass.
- **Where the FoxIO implementations disagree, a person decides.** That is a ruling, not a
  reading, and it is the maintainer's to make. Stop and ask. A ruling lands in this
  repository and in the Python port together, or in neither.
- **A ruling carries a register entry or a test.** A ruling that records neither is a
  ruling the next reader cannot find.
- **A ruling record quotes no live measurement without its date.** A live measurement reads
  a source that moves without a change to this repository. The `govulncheck` count is one
  such measurement. On `go1.24.13` it reported 9 vulnerabilities of the standard library
  that this library calls on 2026-08-13, and 13 on 2026-08-14. **No line of this repository
  changed between the two runs.** So write the date beside every live figure. Four places
  carry one.
  - A ruling comment.
  - A pull-request body.
  - A document.
  - A code comment.

  `TestTheToolchainPagesDateTheVulnerabilityMeasurement` in `go_toolchain_statement_test.go`
  holds the rule for `README.md` and for `doc.go`. Batch #493 earned this rule.
- **Every date of this repository states the UTC calendar day.** Batch #493 recorded the
  ambiguity. The environment reported 2026-08-13 local and 2026-08-14 UTC on one day, and
  each tracker timestamp reads UTC. A ruling record names a reversal path, so two clocks
  give one ruling two dates. **Write the UTC day, and never the local day.**
- **Never run the Python port from a test.** The shared FoxIO vector set is the parity
  gate. See `.claude/rules/parity.md`.
- **One `Processor` serves one goroutine.** The core is lock-free by design. Route packets
  with `GetShardKey`, or share one `SyncProcessor`. Read `.claude/rules/concurrency.md`
  before you touch fingerprinter state.
- **Every packet is untrusted input.** Bounds-check every length field before you slice.
- **The library writes nothing to standard output or standard error.** All output belongs
  to `cmd/ja4plus`.
- **A fingerprinter returns a non-fatal error, never a panic.**
- **Match the surrounding style.** Do not reformat or refactor code the change does not
  need.
- Commit messages use the form `type(scope): summary`, as the existing history does.

## License

The original Go code is BSD 3-Clause. FoxIO licenses every method except JA4 under FoxIO
License 1.1, which permits non-commercial use only. `NOTICE` holds the FoxIO terms. Do
not write that this library is BSD 3-Clause without that qualification. See
`docs/specs/features/01-licensing.md`.

**Never state that this project's method list equals FoxIO's.** Three FoxIO records at the
pinned commit name three different sets: `License FAQ.md:5` names twelve methods, the
FoxIO `README.md:293` names nine, and `LICENSE:3` names thirteen and spells the scanner
`JA4SScan`. Name the methods this project implements, and cite the pinned commit.
