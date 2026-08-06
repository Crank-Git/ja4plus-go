---
id: database-lookup
feature: Database lookup
epic: "Epic 9: Database lookup"
status: planned
issues: []
mockups: []
---

## Purpose

`lookup.go` maps a fingerprint to an application name. It reads an embedded copy of
`data/ja4plus-mapping.csv`, and it can read a downloaded copy instead. It can also ask
`ja4db.com` over the network.

Three things about that design need a decision before an API freeze.

The library performs network input and output. A fingerprinting library that reaches the
network surprises a caller who embeds it in a monitor. The reach is opt-in today, and
`LookupFingerprintRemote` is an exported name that a caller can call by accident.

The client has no timeout. `RemoteLookupConfig.HTTPClient` falls back to
`http.DefaultClient`, which has no timeout at all. A slow or hostile server holds the
calling goroutine for as long as it likes.

The table loads once through `sync.Once`. A process that updates the database and then
looks up a fingerprint reads the old table. Epic 2 records this as suspected finding S2,
and suspected finding S3 records the unguarded package-level state that goes with it.

This feature set settles the boundary, fixes the client, and makes the reload work.

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
- **FR-lookup-17** — A remote lookup honours the context that the caller supplies.

### The cache and the reload

- **FR-lookup-18** — The library reloads the table after a database update, within the
  same process.
- **FR-lookup-19** — The library replaces `sync.Once` with a mechanism that supports a
  reload.
- **FR-lookup-20** — Every read of the loaded table is safe for concurrent use.
- **FR-lookup-21** — Every read of `dbSource` and of the cache path is safe for
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
5. The program marks the table for reload.
6. The next lookup in the same process reads the new table.

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
- The embedded copy is the last resort and always works. A corrupt cache falls back to it
  and records the reason.
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
| Source | `string` | `embedded` or `cache`. |
| Path | `string` | The cache path, empty when the source is `embedded`. |
| Records | `int` | The record count in the loaded table. |
| Updated | `time.Time` | The cache file time, zero when the source is `embedded`. |

### Files

| File | Change |
|---|---|
| `lookup.go` | The load path, the client and the state guard change. |
| `lookup_remote.go` | New, if the decision moves the remote lookup behind a build tag. |
| `cmd/ja4plus/main.go` | The `db update` path triggers the reload. |
| `docs/audit/network-boundary.md` | New. |
| `lookup_test.go` | Gains the timeout, bound, validation and reload tests. |

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
| The cache file is corrupt. | The library falls back to the embedded copy and records the reason in `DatabaseInfo`. |
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

- **Q1** — Which of the three boundary options does the maintainer want? FR-lookup-1
  records the decision. The engineer proposes one with a reason before the work starts.
- **R6** — The `ja4db.com` response shape is unconfirmed, because the service publishes no
  versioned API documentation. The engineer confirms it against a live call and records
  the observed shape before changing the response parser. Until then, the current parser
  stays.
