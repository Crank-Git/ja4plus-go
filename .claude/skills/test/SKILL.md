---
name: test
description: Run the right test suite for a change in ja4plus-go. Use when asked to test, verify a change, check for a regression, or confirm that work is done.
allowed-tools: Bash, Read
---

# Test ja4plus-go

Pick the suite that matches the change. Run the unit tests always. Run the others when the
table says so.

| You changed | Run |
|---|---|
| Anything | `make test` |
| A fingerprinter or `internal/parser/` | `make test`, then `make conformance` |
| Fingerprinter state, `Processor`, or `SyncProcessor` | `make test`, then the race tests |
| A parser that reads a length field | `make test`, then `make fuzz` |
| A dependency, `go.mod` or a workflow | `make test`, `make lint`, `make vuln` |
| Anything on the per-packet path | Add `make bench` and compare with the base branch |

## 1. Unit tests

```
make test
```

This runs `go test -race ./...`. It needs no network and no corpus.

## 2. Conformance

The conformance suite needs the FoxIO corpus. Fetch it once.

```
make corpus
make conformance
```

If `make conformance` prints a message that names `make corpus`, the corpus is missing.
Run `make corpus` and try again.

Read `docs/audit/conformance.md` after the run. A deviation row holds the expected value
and the produced value.

**The FoxIO reference decides every disputed fingerprint.** If a library test and a FoxIO
vector disagree, the test is wrong. Never change a vector to make a test pass.

## 3. Fuzz

```
make fuzz
```

Each target runs for 30 seconds. A crash writes its input to `testdata/fuzz/<FuzzName>/`.

Reproduce a crash with the written input:

```
go test ./internal/parser -run <FuzzName>
```

Leave the crashing input in the seed corpus. It becomes a permanent regression test.

## 4. Lint and vulnerabilities

```
make lint
make vuln
```

## 5. Coverage

```
make cover
```

Compare the printed value with `.coverage-floor`. Coverage must not fall below it. If it
did, add the missing tests. Do not lower the floor.

## A change is done when

1. `go build ./...` succeeds.
2. `make test` passes.
3. `make lint` reports nothing.
4. `make conformance` reports no new deviation.
5. Coverage is at or above the floor.

Report the real output. If a suite fails, say so and show the failure. If you skipped a
suite, say which and why.
