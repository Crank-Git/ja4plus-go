---
id: python-parity
feature: Python parity
epic: "Epic 8: Python parity"
status: planned
issues: []
mockups: []
---

## Purpose

The maintainer owns a second implementation, `Crank-Git/ja4plus`, written in Python. It
is at version `v0.6.0`, and it holds capability that the Go library does not. A user who
moves between the two finds a different API and, in some places, a different result.

This feature set records every difference and closes the ones that apply to Go. A
difference that exists because Python and Go differ is recorded and not closed. A
difference that exists because the Go library is behind is closed.

The maintainer chose feature parity, "if applicable of course". That qualifier is the
rule this feature set follows: parity where the capability belongs in a Go library, and a
written reason where it does not.

## User stories

- As a user who runs both libraries, I want the same input to produce the same
  fingerprint, so that I can compare results across the two.
- As a user who moves from Python to Go, I want a familiar API, so that I do not relearn
  the library.
- As a maintainer, I want a written table of the differences, so that I know which
  library leads on which capability.

## Functional requirements

### The parity table

- **FR-parity-1** — The project records a table at `docs/parity.md`.
- **FR-parity-2** — The table holds one row for each exported name in the Python package.
- **FR-parity-3** — Each row records the Go equivalent, or records `none`.
- **FR-parity-4** — Each row with `none` records `applicable` or `not applicable`.
- **FR-parity-5** — Each `not applicable` row records the reason in one sentence.
- **FR-parity-6** — Each `applicable` row names the issue that closes it.
- **FR-parity-7** — The table names the Python version that it was read from.

### The output parity test

- **FR-parity-8** — A test reads every capture in the corpus with the Go library and
  writes every fingerprint to a file.
- **FR-parity-9** — `scripts/python-parity.sh` runs the Python library over the same
  captures and writes the same shape of file.
- **FR-parity-10** — The test compares the two files as an exact string match.
- **FR-parity-11** — The test reports a difference with the capture, the method and both
  values.
- **FR-parity-12** — The parity test runs only with the `parity` build tag.
- **FR-parity-13** — The parity test skips with a message when the Python library is
  absent.
- **FR-parity-14** — The parity test does not gate a pull request, because it needs a
  second language runtime.
- **FR-parity-15** — A difference that the FoxIO reference resolves against Go produces a
  Go closure.
- **FR-parity-16** — A difference that the FoxIO reference resolves against Python
  produces an entry in `docs/parity.md` and no change here.

### The known gaps

- **FR-parity-17** — The Go library exports a function that computes a JA4X fingerprint
  from a DER-encoded certificate, matching `compute_ja4x_from_der`.
- **FR-parity-18** — The Go library exports a function that computes a JA4X fingerprint
  from a PEM-encoded certificate, matching `compute_ja4x_from_pem`.
- **FR-parity-19** — The Go library exports a `generate` helper for each of the ten
  methods, matching the Python `generate_ja4*` functions.
- **FR-parity-20** — The project decides whether the Python `Collector` belongs in Go,
  and records the decision in `docs/parity.md`.
- **FR-parity-21** — The repository holds an `examples/` directory with a runnable
  program for each of three cases: read a capture, run a live monitor, look up a
  fingerprint.
- **FR-parity-22** — The repository holds `docs/usage.md`, matching the Python
  `docs/usage.md`.
- **FR-parity-23** — The repository holds `docs/api_reference.md`, or states that
  `pkg.go.dev` serves that role.
- **FR-parity-24** — The repository holds `docs/implementation_notes.md`, matching the
  Python file.

## User flows

### The parity table is built

1. Read the Python `ja4plus/__init__.py` and record every exported name.
2. Read each Python module and record every public function and class.
3. For each name, find the Go equivalent.
4. Record `none` where there is no equivalent.
5. Decide `applicable` or `not applicable` for each `none`.
6. Write the table to `docs/parity.md`.

### A difference is found and closed

1. Run `scripts/python-parity.sh` to produce the Python output.
2. Run the parity test. It reports a difference for one capture and one method.
3. Read the FoxIO vector for that capture and that method.
4. The FoxIO value matches Python, so Go is wrong.
5. Close the Go defect and add a test.
6. Re-run. The difference is gone.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- The FoxIO reference decides every difference. Neither library is authoritative over the
  other.
- A Go closure follows Go conventions. Parity means the same capability, not the same
  spelling. A Python function that returns a tuple becomes a Go function that returns two
  values.
- A capability that Python has because Python has it is `not applicable`. An example is a
  helper that exists to work around dynamic typing.
- The parity test never gates a pull request. It runs by hand and before a release.
- A Python defect that this work finds produces an issue in `Crank-Git/ja4plus`. This
  project records it and changes nothing there.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `docs/parity.md` | New. |
| `docs/usage.md` | New. |
| `docs/implementation_notes.md` | New. |
| `examples/` | New. Holds three runnable programs. |
| `ja4x.go` | Gains the DER and PEM helpers. |
| `ja4.go` … `ja4d6.go` | Gain a `generate` helper where one is missing. |
| `parity_test.go` | New. Carries the `parity` build tag. |
| `scripts/python-parity.sh` | New. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `Crank-Git/ja4plus` | v0.6.0 | <https://github.com/Crank-Git/ja4plus> |
| Python package API | v0.6.0 | <https://github.com/Crank-Git/ja4plus/blob/master/docs/api_reference.md> |
| `crypto/x509` | Go 1.24 | <https://pkg.go.dev/crypto/x509> |
| `encoding/pem` | Go 1.24 | <https://pkg.go.dev/encoding/pem> |

### Python exported names, read at v0.6.0

The Python package exports ten fingerprinter classes, a `Processor`, ten `generate_ja4*`
functions, `compute_ja4x_from_der` and `compute_ja4x_from_pem`. It also holds
`ja4plus/collector.py` and `ja4plus/ja4db.py`, which the parity table covers.

## Edge cases & failures

| Case | What happens |
|---|---|
| The Python library is not installed. | The parity test skips with a message that names the install command. |
| Python and Go both differ from FoxIO. | Both are wrong. Go closes its defect here and the record names the Python issue. |
| A Python name has two Go equivalents. | The table records both and names which one is idiomatic. |
| The Python library changes after the table is written. | The table names the version it was read from. A later version produces a new issue. |
| A Go closure would break an exported signature. | Epic 10 records the change. The closure lands before the freeze. |

## Acceptance criteria

- [ ] `docs/parity.md` holds one row for every exported Python name at v0.6.0.
- [ ] Every row records a Go equivalent or `none`.
- [ ] Every `none` row records `applicable` or `not applicable` with a reason.
- [ ] `docs/parity.md` names the Python version it was read from.
- [ ] The Go library exports a JA4X function that takes DER bytes.
- [ ] The Go library exports a JA4X function that takes PEM bytes.
- [ ] The Go library exports a `generate` helper for each of the ten methods.
- [ ] `docs/parity.md` records the `Collector` decision and its reason.
- [ ] `examples/` holds three programs, and each compiles.
- [ ] `docs/usage.md` and `docs/implementation_notes.md` exist.
- [ ] `go test -tags parity ./...` without Python installed skips with a clear message.
- [ ] `go test -tags parity ./...` with Python installed reports zero differences, or
      `docs/parity.md` records every remaining difference with a reason.

## Out of scope

- This feature set does not change `Crank-Git/ja4plus`.
- This feature set does not make the two libraries share a test corpus format. Each reads
  the FoxIO corpus in its own way.
- This feature set does not add a Python binding for the Go library.
- This feature set does not add a live capture loop. An example may show one using a
  third-party capture package, and the library itself stays capture-free.

## Open questions

- **Q1** — Does the Python `Collector` belong in a Go library, or does a Go caller build
  it from `Processor` and `GetShardKey`? FR-parity-20 records the decision. The engineer
  reads `ja4plus/collector.py` before deciding.
