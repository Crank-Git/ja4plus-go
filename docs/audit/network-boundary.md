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
| `CachedDatabasePath` | The core package | `rebuildTable` and `updateCache` of the core package each call it, and neither one reaches the network. |
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

## The amendment of 2026-08-15

**The maintainer narrowed the boundary on 2026-08-15.** Comment 5299776533 of issue #613
holds the ruling, and the ruling states:

> **The boundary names an HTTP call and a remote lookup, and it never named a raw socket.**

**The ruling keeps `internal/capture/` inside the library layout table of `CLAUDE.md`.** It
moves no code, and it moves no fingerprint value.

### The question the amendment answers

**Epic 13 added `internal/capture`, and that package opens a raw socket in the default
build.** `captureRefusal` in `internal/capture/permission_linux.go` calls `syscall.Socket`,
and `open` in `internal/capture/pcapgo_linux.go` calls `pcapgo.NewEthernetHandle`. The Epic
13 cross-member review found both calls on 2026-08-14, and issue #613 records the reading.

**Each citation above names an identifier, and it names no line.**
`.claude/rules/ste.md` `## How a citation names its target` states that rule for the code of
this library. **The first draft of this page cited `pcapgo_linux.go` at line 31**, and the
sub-merge of #609 moved that call to another line inside one batch. So this page carries the
worked example of the rule it follows.
`TestTheAmendmentCitesAnIdentifierThatTheCaptureBackendDeclares` holds each identifier.

**A remote lookup and a raw capture socket are two reaches.** The decision above governs an
outbound lookup at `ja4db.com`. A raw capture socket reads a local interface, and it reaches
no remote host. So the amendment narrows the words of the rule, and the guard below states
the narrowed extent.

**The word `library` carried two extents before the ruling.** `CLAUDE.md` listed
`internal/capture/` inside the library layout table, and
`docs/specs/features/13-live-capture.md` placed the same package outside the library. The
`## Terms` table of `docs/specs/spec.md` now holds one row for the word, and
`.claude/rules/ste.md` rule 6 states one word, one meaning.

### The guard

**`TestNoProductionFileOutsideTheCaptureBackendOpensASocket` holds the amendment.** It reads
each production Go file outside `cmd/` and `ja4db/`, and it reports each call of a function
that opens a socket. It permits `internal/capture/` alone, so a second package that calls one
of those functions fails the test.

**The guard reads a call site, and it reads no import.** One import carries both meanings:
`pcapgo.NewReader` reads a capture file, and `pcapgo.NewEthernetHandle` opens a packet
socket.

**A dot import writes a call as a bare identifier, and the guard reports the import instead.**
`syscall.Socket` reads as a selector, and `import . "syscall"` makes the same call read as
`Socket`. So the guard fails on a dot import of any package that
`socketOpenFunction` names, and a dot import defeats it in no file.

**The guard resolves no type, so it reaches a direct call alone.** A package that calls an
exported helper of `internal/capture` opens a socket, and the guard reports nothing about it.
**That limit is stated and it is not repaired**, because a type-resolving reader costs a
second build of the module and it guards one hypothetical case.

**Three tests prove that the guard reports something.** A permit list that permits every
package guards nothing.

1. `TestTheSocketReaderReportsAPackageOutsideTheCaptureBackendThatOpensASocket` builds a
   second package that calls `syscall.Socket`, and it requires the report.
2. `TestTheSocketPermitListNamesTheCaptureBackendAlone` requires the permit list to decline
   the root package, `ja4db/` and `internal/parser/`.
3. `TestTheCaptureBackendOpensASocket` requires the reader to find the call that
   `internal/capture` holds today.

### The reversal path

**Issue #613 is the reversal path.** A reversal states that the boundary names every network
reach. It then moves `internal/capture` out of the layout table of `CLAUDE.md`, and it
removes the permit entry of the guard.

## A later decision

**Only the maintainer changes the decision above.** `.claude/rules/rulings.md` holds that
rule. A reversal records the new option, the date and the reason, and it names issue #72.
