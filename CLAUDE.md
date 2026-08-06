# ja4plus-go

A Go library and command-line program for JA4+ network fingerprinting. It implements ten
JA4+ methods and reads packets through `gopacket`. JA4+ is a set of standards that FoxIO
publishes. This library is an independent Go implementation.

The library is at `v0.3.0`. The current work takes it to `v1.0.0`, which freezes the
exported API. Three things must be true before that freeze: the output must match the
FoxIO reference, the concurrency contract must be explicit and correct, and the license
must state the FoxIO terms.

## Where the design lives

Design lives in `docs/specs/`. Read `docs/specs/spec.md` and the relevant
`docs/specs/features/*.md` before you build a feature. Open `docs/specs/spec.html` in a
browser for the readable overview.

The `## Terms` table in `docs/specs/spec.md` is this project's controlled vocabulary.
Read it before you write a domain word in a document, an issue, or a code comment.

## Stack

- Go 1.24 or later.
- `github.com/google/gopacket` for packet decoding.
- `golang.org/x/crypto` for SSH and hashing.
- No cgo. The build cross-compiles to five platforms.

## Layout

| Path | Holds |
|---|---|
| `*.go` at the root | Package `ja4plus`: one fingerprinter per method, `Processor`, the database lookup. |
| `internal/parser/` | Protocol decoding for TLS, QUIC, HTTP, SSH, TCP streams, X.509 and GREASE. |
| `cmd/ja4plus/` | The command-line program. |
| `data/` | The embedded FoxIO fingerprint mapping. |
| `testdata/foxio/` | The fetched FoxIO corpus. Not tracked in git. |
| `docs/specs/` | The spec package. Tracked. |
| `docs/audit/` | Audit findings, the conformance report and the recorded decisions. |

A new fingerprinter file goes at the root. New protocol decoding goes in
`internal/parser/`. Nothing that reads a packet belongs in `cmd/`.

## Commands

| Command | What it does |
|---|---|
| `make build` | Build the command-line program into `bin/`. |
| `make test` | Run the unit tests under the race detector. |
| `make lint` | Run `golangci-lint` at the pinned version. |
| `make corpus` | Fetch the FoxIO corpus at the pinned commit. |
| `make conformance` | Run the conformance suite against the corpus. |
| `make fuzz` | Run each fuzz target for 30 seconds. |
| `make bench` | Run the benchmarks with allocation counts. |
| `make cover` | Report total statement coverage. |
| `make vuln` | Run `govulncheck`. |

Run `make corpus` once before `make conformance`. The conformance suite skips without it.

## A change is done when

1. `go build ./...` succeeds.
2. `go test -race ./...` passes.
3. `golangci-lint run` reports nothing.
4. `make conformance` reports no new deviation.
5. Coverage does not fall below the value in `.coverage-floor`.

## Conventions

- **The FoxIO reference decides every disputed fingerprint.** A test that disagrees with
  the reference is wrong. Never change a FoxIO vector to make a test pass.
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

The original Go code is BSD 3-Clause. FoxIO licenses nine of the ten methods under FoxIO
License 1.1, which permits non-commercial use only. `NOTICE` holds the FoxIO terms. Do
not write that this library is BSD 3-Clause without that qualification. See
`docs/specs/features/01-licensing.md`.
