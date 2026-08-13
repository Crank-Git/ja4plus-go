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

- Go 1.24 or later.
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
| `*.go` at the root | Package `ja4plus`: one fingerprinter per method, `Processor`, the database lookup. |
| `internal/parser/` | Protocol decoding for TLS, QUIC, HTTP, SSH, TCP streams, X.509 and GREASE. |
| `cmd/ja4plus/` | The command-line program. |
| `data/` | The embedded FoxIO fingerprint mapping. |
| `internal/capture/` | Opening a live interface. Holds the pure-Go backend and the libpcap backend. |
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

## Commands

| Command | What it does |
|---|---|
| `make build` | Build the command-line program into `bin/`. |
| `make test` | Run the unit tests under the race detector. |
| `make lint` | Run `golangci-lint` at the pinned version, with one cache for this checkout. |
| `make lint-cache-check` | Prove the stale linter cache defect of #257, and prove the repair. |
| `make corpus` | Fetch the FoxIO corpus at the pinned commit. |
| `make conformance` | Run the conformance suite against the corpus. |
| `make fuzz` | Run each fuzz target for 30 seconds. |
| `make bench` | Run the benchmarks with allocation counts. |
| `make cover` | Report total statement coverage. |
| `make vuln` | **Not built yet.** #65 adds the target. It runs `govulncheck`. |
| `make mutate` | **Not built yet.** #90 adds the target, under Epic #89. It runs the mutation sweep over the named package set. Slow. Gates nothing. |
| `make prerelease` | **Not built yet.** #95 through #99 add the target, under Epic #94. It installs the built artifact into a clean environment and runs it. |
| `make docs` | **Not built yet.** #84 configures MkDocs and adds the target. It builds the documentation site with `mkdocs build --strict`. |

Run `make corpus` once before `make conformance`. The conformance suite skips without it.

**The `Makefile` defines the first nine rows of this table, and none of the last four.**
An absent target is work a later issue does, and never a broken target. **`make docs`
exits 0, and that exit code reports no site build.**

- `make vuln`, `make mutate` and `make prerelease` each exit 2. Each one prints one line
  that names the target: ``make: *** No rule to make target `vuln'.  Stop.``
- `make docs` prints ``make: Nothing to be done for `docs'.``, because `docs/` is a
  directory and the name holds no recipe.

## A change is done when

1. `go build ./...` succeeds.
2. `go test -race ./...` passes.
3. `make lint` reports nothing. **Run the linter through `make lint`, and never as a bare
   `golangci-lint run`.** A bare run reads the linter cache of the whole user account. That
   cache holds an absolute path from another checkout, and #257 records the false failure
   it produces.
4. `make conformance` reports no deviation that `testdata/deviations.json` does not hold,
   and the register holds no entry whose comparison now matches.
5. **This step is unrunnable today, because the repository holds no `.coverage-floor` file.
   #68 builds it.** Coverage does not fall below the value in `.coverage-floor`.
6. **This step is unrunnable today, because the `Makefile` defines no `docs` target. #84
   builds it.** `make docs` succeeds, when the change touches a page.

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
- **The FoxIO reference decides every disputed fingerprint.** A test that disagrees with
  the reference is wrong. Never change a FoxIO vector to make a test pass.
- **Where the FoxIO implementations disagree, a person decides.** That is a ruling, not a
  reading, and it is the maintainer's to make. Stop and ask. A ruling lands in this
  repository and in the Python port together, or in neither.
- **A ruling carries a register entry or a test.** A ruling that records neither is a
  ruling the next reader cannot find.
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
