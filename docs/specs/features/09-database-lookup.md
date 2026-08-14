---
id: database-lookup
feature: Database lookup
epic: "Epic 9: Database lookup"
status: issued
issues: [71, 72, 73, 74, 75]
mockups: []
---

## Purpose

`lookup.go` maps a fingerprint to an application name. It reads an embedded copy of
`data/ja4plus-mapping.csv`, and it can read a downloaded copy instead. The package
`github.com/Crank-Git/ja4plus-go/ja4db` asks `ja4db.com` over the network.

Three things about that design needed a decision before an API freeze. **Epic 9 settled
all three on 2026-08-14**, and each paragraph below states the state the epic left.

**The library performed network input and output from the core package.** A fingerprinting
library that reaches the network surprises a caller who embeds it in a monitor. #72 moved
`RemoteLookupConfig` and `LookupFingerprintRemote` to `ja4db`, so the core package imports
no HTTP client. `docs/audit/network-boundary.md` holds the maintainer's ruling, and
`network_boundary_test.go` fails on an import that breaks it.

**The client had no timeout.** `RemoteLookupConfig.HTTPClient` fell back to
`http.DefaultClient`, which has no timeout at all. #73 gave the package a default client
with a 10-second timeout, a redirect rule, a 1 MB body bound and a `User-Agent` header.

**The table loaded once through `sync.Once`.** A process that updated the database and then
looked up a fingerprint read the old table. Epic 2 records that as suspected finding S2,
and suspected finding S3 records the unguarded package-level state that went with it. #74
replaced the loader with one `atomic.Pointer[lookupTable]`, and #75 added the validation
and the atomic cache write of `internal/dbcache`.

## User stories

- As a library author, I want to know whether importing this library can cause a network
  call, so that I can satisfy my own security review.
- As a library author, I want a timeout on any network call the library makes, so that a
  slow server cannot stall my monitor.
- As an analyst, I want `ja4plus db update` to take effect immediately, so that I do not
  restart the program to use a fresh database.
- As a maintainer, I want the lookup state safe for concurrent use, so that it does not
  break the concurrency contract that Epic 3 sets.

## Functional requirements

### The boundary

- **FR-lookup-1** — The project records a decision on where the remote lookup belongs, in
  `docs/audit/network-boundary.md`.
- **FR-lookup-2** — The decision names one of three options: keep the remote lookup in
  the package, move it behind a build tag, or move it to a separate package.
- **FR-lookup-3** — The record names the reason.
- **FR-lookup-4** — The default build of the library performs no network input and no
  network output unless the caller calls a function whose name states that it does.
- **FR-lookup-5** — The package documentation states which functions reach the network.
- **FR-lookup-6** — The README states which functions reach the network.
- **FR-lookup-7** — The implementation follows the recorded decision before Epic 10
  freezes the API.

### The client

- **FR-lookup-8** — A remote lookup never uses `http.DefaultClient`.
- **FR-lookup-9** — A remote lookup uses a client with a timeout when the caller supplies
  none.
- **FR-lookup-10** — The default timeout is 10 seconds.
- **FR-lookup-11** — A remote lookup verifies the server certificate.
- **FR-lookup-12** — A remote lookup rejects a redirect to a scheme other than `https`.
- **FR-lookup-13** — A remote lookup bounds the response body to 1 MB.
- **FR-lookup-14** — A remote lookup that exceeds the bound returns an error and reads no
  more.
- **FR-lookup-15** — A remote lookup escapes the fingerprint before it builds the request
  URL.
- **FR-lookup-16** — A remote lookup sends a `User-Agent` header that names the library
  and its version.
- **FR-lookup-17** — A remote lookup honors the context that the caller supplies.

### The cache and the reload

- **FR-lookup-18** — The library reloads the table after a database update, within the
  same process.
- **FR-lookup-19** — The library replaces `sync.Once` with a mechanism that supports a
  reload.
- **FR-lookup-20** — Every read of the loaded table is safe for concurrent use.
- **FR-lookup-21** — Every read of the source and of the cache path is safe for
  concurrent use.
- **FR-lookup-22** — A reload that fails leaves the previous table in place.
- **FR-lookup-23** — The library validates a downloaded database before it replaces the
  cache.
- **FR-lookup-24** — Validation checks that the file parses as CSV and holds the expected
  columns.
- **FR-lookup-25** — Validation rejects a file larger than 16 MB.
- **FR-lookup-26** — The library writes the cache file atomically, through a temporary
  file and a rename.
- **FR-lookup-27** — `GetDatabaseInfo` reports the source, the path and the record count.

**#74 replaced the package-level variables `dbSource` and `dbCachePath` with fields of the
unexported `lookupTable` type.** A reader loads one immutable snapshot through
`activeTable` of `lookup.go`, so FR-lookup-20 and FR-lookup-21 hold with no lock on the
steady-state read path.

**A reader that finds a changed cache file calls `rebuildTable`, and `rebuildTable` takes a
mutex.** So the read path is lock-free in the steady state, and it is not lock-free at every
call. `.claude/rules/concurrency.md` `## Rules` states the same property, and
`docs/concurrency.md` `## The database lookup holds one snapshot` states it for a user.

## User flows

### A caller looks up a fingerprint offline

1. The caller calls `LookupFingerprint`.
2. The library loads the table on the first call, from the cache when one exists and from
   the embedded copy otherwise.
3. The library returns the result or `nil`.
4. No network call happens.

### An analyst updates the database

1. Run `ja4plus db update`.
2. The program downloads the database with a timeout and a size bound.
3. The program validates the file.
4. The program writes the cache atomically.
5. The program ends. It marks no table, because `ja4plus db update` runs in its own
   process.
6. A running process stats the cache file at its next lookup, and `activeTable` of
   `lookup.go` rebuilds the table from the new file.

**`runDBUpdate` of `cmd/ja4plus` writes the cache file and it prints. It marks nothing.**
`invalidateLookupTable` of `lookup.go` is unexported, and no package outside the root
package reaches it, because #100 freezes the exported surface. **The stat of the cache file
is the mechanism that reloads the table**, and it is not a mark.

### A caller opts in to a remote lookup

1. The caller builds a `RemoteLookupConfig` with their own client and endpoint.
2. The caller calls the remote lookup function with a context that carries a deadline.
3. The library performs one HTTPS request within the bound.
4. The library returns the result, or an error that names the cause.

## Screens & states

The command-line program prints the database state. `mockups/02-cli-output.html` shows it
as part of the command-line output mockup.

| State | What `ja4plus db info` shows |
|---|---|
| Embedded | The source `embedded`, the record count, and no path. |
| Cached | The source `cache`, the record count, the path and the file time. |
| Update available | The same, plus a line that names `ja4plus db update`. |

## Behaviour rules

- The library never reaches the network as a side effect of a lookup. A network call
  happens only when the caller calls a function that says so.
- A failed update never damages a working cache. The library validates first and renames
  last.
- A reload is atomic from a reader's view. A reader sees the old table or the new one,
  never a partial one.
- The embedded copy is the last resort and always works. A process that reads a corrupt
  cache file and holds no previous table falls back to the embedded copy. `GetDatabaseInfo`
  then reports the source `embedded`. A process that already holds a table keeps that
  table, which FR-lookup-22 states.
- The remote endpoint is configurable, so the library never hard-codes a host that a
  caller cannot change.

## Data touched

### `LookupResult`

| Field | Type | Meaning |
|---|---|---|
| `Application` | `string` | The application name for the fingerprint. |
| `Type` | `string` | The record type. |
| `Notes` | `string` | Free text from the mapping file. |

### `DatabaseInfo`

| Field | Type | Meaning |
|---|---|---|
| `Source` | `string` | `embedded` or `cache`. |
| `Path` | `string` | The cache path, empty when the source is `embedded`. |
| `Entries` | `int` | The record count in the loaded table. |
| `ModTime` | `time.Time` | The cache file time, zero when the source is `embedded`. |

**This table named the last two fields `Records` and `Updated` until 2026-08-14, and the
code has never held either name.** #74 and #75 each measured the difference, and each left
the code alone. **#100 freezes the exported API at `v1.0.0`, so a rename moves the frozen
surface.** **So this round repaired the table and no line of `lookup.go`.** Issue #100 is
the reversal path for a reader who wants the other pair of names.

### Files

| File | Change |
|---|---|
| `lookup.go` | The load path and the state guard change. `atomic.Pointer[lookupTable]` replaces `sync.Once`. |
| `ja4db/lookup.go` | New. It holds `RemoteLookupConfig`, `LookupFingerprintRemote` and the hardened client. |
| `ja4db/doc.go` | New. It states that this package reaches the network. |
| `internal/dbcache/dbcache.go` | New. It validates a downloaded database, holds the 16 MB bound and writes the cache file atomically. |
| `cmd/ja4plus/main.go` | The `db update` path writes the cache through `internal/dbcache`. |
| `docs/audit/network-boundary.md` | New. It records the boundary ruling of 2026-08-14. |
| `network_boundary_test.go` | New. It fails when a production file of the core package imports an HTTP client. |
| `lookup_reload_test.go` | New. It holds the reload, fallback and race tests. |
| `ja4db/hardening_test.go` | New. It holds the timeout, redirect, bound and `User-Agent` tests. |
| `internal/dbcache/dbcache_test.go` | New. It holds the validation and atomic-write tests. |

**`lookup_remote.go` no longer exists.** The maintainer ruled on 2026-08-14 that the remote
lookup moves to a package rather than behind a build tag. #72 then moved the file into
`ja4db/`, and the build-tag option never shipped.

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| `net/http` client | Go 1.24 | <https://pkg.go.dev/net/http#Client> |
| `crypto/tls` | Go 1.24 | <https://pkg.go.dev/crypto/tls> |
| `sync/atomic` | Go 1.24 | <https://pkg.go.dev/sync/atomic> |
| `os.CreateTemp` and `os.Rename` | Go 1.24 | <https://pkg.go.dev/os> |
| `ja4db.com` read API | Unversioned | <https://ja4db.com> |

The `ja4db.com` API is not documented at a stable versioned URL. The code reads the
endpoint from `RemoteLookupConfig.Endpoint` and defaults to
`https://ja4db.com/api/read/`. The engineer confirms the response shape against a live
call before changing the parser, and records the observed shape in the issue.

**The response shape of `ja4db.com` is unconfirmed.** Risk R6 below records this.

## Edge cases & failures

| Case | What happens |
|---|---|
| The remote server never responds. | The client times out after 10 seconds and returns an error that names the timeout. |
| The remote server returns 2 GB. | The library stops at 1 MB and returns an error that names the bound. |
| The remote server returns a redirect to `http://`. | The library refuses the redirect and returns an error. |
| The cache file is corrupt. | The library falls back to the embedded copy, and `GetDatabaseInfo` reports the source `embedded`. |
| An update runs while another goroutine looks up a fingerprint. | The reader sees the old table or the new one. The race detector reports nothing. |
| The cache directory is not writable. | The update fails, names the path, and leaves the embedded copy in use. |
| The fingerprint holds a character that changes the URL path. | The library escapes it, so the request reaches the intended endpoint. |
| Two goroutines call the update path at the same time. | One wins. The other sees the result of the winner. Neither writes a partial file. |

## Acceptance criteria

- [ ] `docs/audit/network-boundary.md` records the decision and its reason.
- [ ] The implementation follows the recorded decision.
- [ ] `go doc` for the package states which functions reach the network.
- [ ] A remote lookup against a server that never responds returns an error within 11
      seconds.
- [ ] A remote lookup against a server that returns 2 MB returns an error that names the
      bound.
- [ ] A remote lookup against a server that redirects to `http://` returns an error.
- [ ] A remote lookup sends a `User-Agent` that names the library and version.
- [ ] A test updates the database and then looks up a fingerprint that only the new table
      holds, in one process, and finds it.
- [ ] A test runs the update path and the lookup path from separate goroutines and passes
      under `go test -race`.
- [ ] A failed update leaves the previous cache file unchanged.
- [ ] A corrupt cache file makes the library fall back to the embedded copy.
- [ ] `ja4plus db info` prints the source, the record count and the path.
- [ ] A downloaded file larger than 16 MB is rejected before it reaches the cache.

## Out of scope

- This feature set does not add an automatic update on a schedule.
- This feature set does not add a second database source.
- This feature set does not fuzz the CSV parser for the embedded copy.
  `features/06-fuzz-testing.md` records why. The downloaded file is validated instead.
- This feature set does not change `data/ja4plus-mapping.csv` itself.
  `features/01-licensing.md` owns its attribution.

## Open questions

- **Q1 — closed on 2026-08-14.** The maintainer chose the third of the three boundary
  options: the remote lookup moves to a separate package. `docs/audit/network-boundary.md`
  records the decision and the reason, which FR-lookup-1 asks for. #72 carried the move.
- **R6** — The `ja4db.com` response shape is unconfirmed, because the service publishes no
  versioned API documentation. The engineer confirms it against a live call and records
  the observed shape before changing the response parser. Until then, the current parser
  stays.
