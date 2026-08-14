# The network boundary decision

**This file records a ruling that the maintainer made. It makes no decision.** FR-lookup-1
requires the record, FR-lookup-2 requires the three options, and FR-lookup-3 requires the
reason. `docs/specs/features/09-database-lookup.md` states each requirement.

A ruling is the maintainer's alone. `.claude/rules/rulings.md` holds that rule.

## The decision

**The maintainer ruled the question on 2026-08-14.** Comment 5294420180 of issue #72 holds
the ruling, and the ruling states:

> **The remote lookup moves to a separate package.** The core package holds no remote lookup
> and it imports no HTTP client.

**Issue #72 is the reversal path.**

## The three options

FR-lookup-2 names three options, and this list holds each one.

1. **Keep the remote lookup in the package.**
2. **Move it behind a build tag.**
3. **Move it to a separate package.**

**Each option holds FR-lookup-4, and each one holds it at a different strength.** FR-lookup-4
states two rules. The default build of the library performs no network input and no network
output. The one exception is a call of a function whose name states that reach.

| Option | What holds FR-lookup-4 | Outcome |
|---|---|---|
| Keep the remote lookup in the package. | A naming convention and the documentation. | Declined. |
| Move it behind a build tag. | The default build, and a second build path. | Declined. |
| **Move it to a separate package.** | **The import list of the core package.** | **Chosen.** |

## The reason

**A naming convention holds FR-lookup-4 only while every later contributor reads the
convention.** The first option leaves the network code and the offline code in one package.
A later change then adds network input and network output, and it crosses no package line. A
reviewer who reads that change reads no import that reports it.

**A build tag holds the requirement, and it adds a second build path.** `CLAUDE.md` states
that one build path uses cgo and that the `libpcap` tag selects it. A second tag doubles the
build matrix for a guarantee that a package boundary already gives.

**A separate package makes the guarantee structural.** The core package imports no HTTP
client, so no line of it reaches the network. A reader of the import list sees the boundary,
and no reader needs the doc comment to see it.

**The move happens before the API freeze.** #100 freezes the exported API at `v1.0.0`, and
#101 records that API. An exported name that moves after the freeze is a breaking change.
FR-lookup-7 states the same order.

## What the decision produces

**The package is `ja4db`, at `github.com/Crank-Git/ja4plus-go/ja4db`.** The name states the
service that the package reaches.

**Two exported names move, and five stay.** The two are the whole set that needs an HTTP
client, so the set is minimal.

| Name | Package after the move | Reason |
|---|---|---|
| `RemoteLookupConfig` | `github.com/Crank-Git/ja4plus-go/ja4db` | The `HTTPClient` field holds a `*http.Client`. |
| `LookupFingerprintRemote` | `github.com/Crank-Git/ja4plus-go/ja4db` | The function builds the request and reads the response. |
| `LookupResult` | The core package | `LookupFingerprint` returns it, and that path reaches no network. |
| `LookupFingerprint` | The core package | It reads the embedded table or the cache file. |
| `CachedDatabasePath` | The core package | `loadDB` of the core package calls it on every load. |
| `DatabaseInfo` | The core package | `GetDatabaseInfo` returns it. |
| `GetDatabaseInfo` | The core package | It reports the loaded table, and it reaches no network. |

**Each moved name keeps its spelling.** FR-lookup-4 turns on the name of the function, and
`LookupFingerprintRemote` states the network reach. The qualified form is
`ja4db.LookupFingerprintRemote`.

**`ja4db` imports the core package for `LookupResult`, and the core package imports `ja4db`
nowhere.** The import graph holds no cycle.

**The command-line program keeps its own HTTP client.** `ja4plus db update` downloads the
mapping file, and `CLAUDE.md` states that all output belongs to `cmd/ja4plus`. The boundary
binds the library, and a program that a user runs by name states its own reach.

## The measurement

**The core package imported `net/http` at one place before the move.** `lookup.go:11` held
that import on 2026-08-14, at commit `a6fd50d`, and no other production file of the library
held one.

`go list -deps .` reports the transitive import graph of the core package. The count of
lines that name the HTTP client moved from 5 to 0.

| State | Lines that `go list -deps .` reports for the HTTP client |
|---|---|
| Before the move | `net/http`, `net/http/httptrace`, `net/http/internal`, `net/http/internal/ascii`, `net/http/internal/httpcommon` |
| After the move | None. |

**This change moves no fingerprint value.** The database lookup maps a fingerprint to an
application, and it computes none. `testdata/deviations.json` and `CHANGELOG.md` are
unchanged, and the conformance count is unchanged.

## The guard

**`network_boundary_test.go` holds the property, and it makes no network call.** The guard
holds three parts.

1. `TestNoProductionFileOfTheCorePackageImportsAnHTTPClient` reads the abstract syntax tree
   of every production Go file outside `cmd/` and `ja4db/`. It fails on an import of
   `net/http` or of a subpackage of it.
2. `TestTheRemoteLookupPackageImportsAnHTTPClient` reads `ja4db/` with the same reader, and
   it fails when that reader finds nothing. A clean result from a broken reader guards
   nothing.
3. `TestTheDependencyGraphOfTheCorePackageHoldsNoHTTPClient` reads `go list -deps .`. A
   dependency of this module that adds the import reaches the released binary, and no walk
   of this repository sees it.

**`TestTheNetworkBoundaryRecordNamesTheDecisionAndTheReason` reads this page.** It fails when
the page names fewer than the three options of FR-lookup-2.

## A later decision

**Only the maintainer changes the decision above.** `.claude/rules/rulings.md` holds that
rule. A reversal records the new option, the date and the reason, and it names issue #72.
