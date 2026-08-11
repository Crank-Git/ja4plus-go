# The correctness audit findings report

**Report status:** in progress

This file is the record of the correctness audit. `docs/specs/features/02-correctness-audit.md`
states every requirement, and FR-audit-9 names this path. Issue #21 defines the record.
Issues #22, #23, #24 and #25 fill it.

`audit_record_test.go` holds the shape of this file. A row that omits a field fails that
test, so read `## The record` before you add one.

**The audit changes no code.** The audit and the closure are two steps. A finding without
a failure scenario is a style opinion, and this report records no style opinion.

## The report status

The status line at the top of this file holds one of two values.

- `in progress` — one issue of the audit still runs.
- `complete` — every file carries an audit date, and no finding stays `open`.

**Issue #25 sets the status to `complete`.** The test applies the closing rules once it
reads that value. An earlier change fails the suite.

## The audit set

FR-audit-1 states the set:

> The audit reads every `.go` file in the repository root, in `internal/parser/` and in
> `cmd/ja4plus/`.

**A file whose name ends in `_test.go` is outside the set.** The `## Purpose` section of
the feature file counts "Ten fingerprinters, nine parser files and a command-line program".
Those counts hold only without the test files. `internal/parser/` holds ten files that
ship, and nine of them decode a protocol. The audit reads a file that ships, because every
check in FR-audit-11 through FR-audit-24 names shipped behaviour.

`internal/capture/` is outside the set, because FR-audit-1 names three directories and that
directory is none of them.

The `Read by` column names each issue that reads the file. The three audit issues run at
the same time. Each one records its own audit date in its own table, under
`## The files each issue audited`.

<!-- audit-set:begin -->
| File | Read by |
|---|---|
| `doc.go` | #22, #23, #24 |
| `ja4.go` | #22, #23, #24 |
| `ja4d.go` | #22, #23, #24 |
| `ja4d6.go` | #22, #23, #24 |
| `ja4h.go` | #22, #23, #24 |
| `ja4l.go` | #22, #23, #24 |
| `ja4s.go` | #22, #23, #24 |
| `ja4ssh.go` | #22, #23, #24 |
| `ja4t.go` | #22, #23, #24 |
| `ja4ts.go` | #22, #23, #24 |
| `ja4x.go` | #22, #23, #24 |
| `lookup.go` | #22, #23, #24 |
| `processor.go` | #22, #23, #24 |
| `sync_processor.go` | #22, #23, #24 |
| `types.go` | #22, #23, #24 |
| `internal/parser/grease.go` | #22, #23, #24 |
| `internal/parser/hash.go` | #22, #23, #24 |
| `internal/parser/http.go` | #22, #23, #24 |
| `internal/parser/packet.go` | #22, #23, #24 |
| `internal/parser/quic.go` | #22, #23, #24 |
| `internal/parser/ssh.go` | #22, #23, #24 |
| `internal/parser/tcp_stream.go` | #22, #23, #24 |
| `internal/parser/testhelpers.go` | #22, #23, #24 |
| `internal/parser/tls.go` | #22, #23, #24 |
| `internal/parser/x509_utils.go` | #22, #23, #24 |
| `cmd/ja4plus/main.go` | #25 |
<!-- audit-set:end -->

`internal/parser/testhelpers.go` carries no `_test.go` suffix, so the compiler builds it
into the package that ships. The audit reads it for that reason.

## The record

### The fields of a finding

FR-audit-3 states the fields:

> The audit reports each finding with a file path, a line number, a severity and a
> failure scenario.

Each findings table holds these eight columns, in this order.

| Column | What it holds |
|---|---|
| `ID` | The identifier of the finding, in the form `F-<issue>-<number>`. |
| `File` | The path of the file, in a code span, as the audit set writes it. |
| `Line` | The line number, as one decimal number. |
| `Severity` | One of `critical`, `major` and `minor`. |
| `Status` | One of the five values under `### The five statuses`. |
| `Failure scenario` | One sentence that names the input and the wrong result. |
| `Closing commit` | The abbreviated commit hash, in a code span. Empty until the closure. |
| `Reason` | One sentence. Empty for an `open` finding. |

An `open` finding reached no outcome, so the reader declines a reason on it. A `confirmed`
finding may state why the closure took the shape it took. The other three statuses require
the reason.

**A cell holds no vertical bar character.** The reader splits a row on that character, so
a cell that holds one breaks the row.

**The identifier names the issue that wrote the row.** Issue #22 writes `F-22-1`,
`F-22-2` and so on. No two issues share a number, so no two of them collide.

### A failure scenario names the input and the wrong result

FR-audit-4 states the rule:

> A failure scenario names the input and the wrong result. It does not
  name a code smell.

**Read this rule before you write a row.** The audit records a defect that a reader can
reproduce. It records no opinion about the shape of the code.

The two examples below state the form. Neither one records a defect of this repository.

```
Bad:  This parser could panic on a crafted record.
Good: A TLS record whose length field exceeds the remaining buffer makes `ja4.go:49`
      panic.
```

The bad example names no input and no result. The good example names both, so a reader
builds the packet and sees the panic.

The reader in `audit_record_test.go` declines a scenario in three cases.

- The scenario is shorter than 40 characters.
- The scenario ends with no full stop.
- The scenario holds a hedge word, such as `could`, `might` or `refactor`.

Those three cases catch the common form of a code smell. They prove no scenario correct,
so read the rule as well as the test.

### The three severities

FR-audit-5 allows three values, and FR-audit-6 through FR-audit-8 define them.

> The audit assigns one of three severities to each finding: `critical`,
  `major` or `minor`.

> A `critical` finding is a wrong fingerprint, a panic, a data race, or
  an unbounded growth of state.

> A `major` finding is a wrong result for an uncommon input, or a
  contract that the code states and does not keep.

> A `minor` finding is a defect that produces no wrong result.

Severity decides the order of the work. It does not decide whether the work happens,
because the maintainer chose to close every confirmed finding.

### The five statuses

| Status | What it means | What the row also holds |
|---|---|---|
| `open` | The audit reproduced the failure scenario, and no commit closes it yet. | Nothing more. |
| `confirmed` | A commit closed the finding. FR-audit-27 requires the commit. | The closing commit. |
| `no change needed` | The code is a deliberate design choice. | The reason. |
| `unconfirmed` | The audit reached no proof of the failure scenario. FR-audit-10 requires the reason. | The reason. |
| `declined` | The maintainer decided not to close the finding. FR-audit-28 requires the reason. | The reason. |

**Only the maintainer writes `declined`.** `.claude/rules/rulings.md` holds that rule. An
engineer who reaches a question that no source settles records the reading and stops.

**A `confirmed` row names the commit that closed the finding.** Two findings that one
change closes name the same commit.

### Where a row goes

Each issue owns two tables and writes to no other table. The markers around each table
name the owner.

| Section marker | Owner | The checks it applies |
|---|---|---|
| `files:22` and `findings:22` | issue #22 | FR-audit-11, FR-audit-12, FR-audit-13 and FR-audit-23. |
| `files:23` and `findings:23` | issue #23 | FR-audit-15, FR-audit-16, FR-audit-17 and FR-audit-18. |
| `files:24` and `findings:24` | issue #24 | FR-audit-14, FR-audit-19, FR-audit-20, FR-audit-21 and FR-audit-22. |
| `files:25` and `findings:25` | issue #25 | FR-audit-24. |

**Issue #25 also closes each finding that the other three record.** The plan on issue #20
assigns that work to it, together with FR-audit-27 and FR-audit-28. It writes the closing
commit and the reason into the row that already holds the finding, and it owns the table
under `## The exported signatures a closure changed`.

## The files each issue audited

FR-audit-2 requires the row:

> The audit records one row per file, with the file path and the audit
  date.

**Record a file even when it holds no finding.** The report states what the audit read, so
a reader knows which parts of the library are unexamined.

The audit date is the date the engineer read the file, in the form `YYYY-MM-DD`.

### The files of issue #22

This table belongs to issue #22.

<!-- files:22:begin -->
| File | Audit date |
|---|---|
<!-- files:22:end -->

### The files of issue #23

This table belongs to issue #23.

<!-- files:23:begin -->
| File | Audit date |
|---|---|
| `doc.go` | 2026-08-11 |
| `ja4.go` | 2026-08-11 |
| `ja4d.go` | 2026-08-11 |
| `ja4d6.go` | 2026-08-11 |
| `ja4h.go` | 2026-08-11 |
| `ja4l.go` | 2026-08-11 |
| `ja4s.go` | 2026-08-11 |
| `ja4ssh.go` | 2026-08-11 |
| `ja4t.go` | 2026-08-11 |
| `ja4ts.go` | 2026-08-11 |
| `ja4x.go` | 2026-08-11 |
| `lookup.go` | 2026-08-11 |
| `processor.go` | 2026-08-11 |
| `sync_processor.go` | 2026-08-11 |
| `types.go` | 2026-08-11 |
| `internal/parser/grease.go` | 2026-08-11 |
| `internal/parser/hash.go` | 2026-08-11 |
| `internal/parser/http.go` | 2026-08-11 |
| `internal/parser/packet.go` | 2026-08-11 |
| `internal/parser/quic.go` | 2026-08-11 |
| `internal/parser/ssh.go` | 2026-08-11 |
| `internal/parser/tcp_stream.go` | 2026-08-11 |
| `internal/parser/testhelpers.go` | 2026-08-11 |
| `internal/parser/tls.go` | 2026-08-11 |
| `internal/parser/x509_utils.go` | 2026-08-11 |
<!-- files:23:end -->

### The files of issue #24

This table belongs to issue #24.

<!-- files:24:begin -->
| File | Audit date |
|---|---|
<!-- files:24:end -->

### The files of issue #25

This table belongs to issue #25.

<!-- files:25:begin -->
| File | Audit date |
|---|---|
<!-- files:25:end -->

## The findings

Each table below holds the findings of one issue. The tables are empty until the audit
runs.

### The findings of issue #22

This table belongs to issue #22. It holds a finding of a parser input: a length field, an
integer conversion, a map read, a slice index or a GREASE filter.

<!-- findings:22:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
<!-- findings:22:end -->

### The findings of issue #23

This table belongs to issue #23. It holds a finding of the state a fingerprinter keeps: a
state table, the `results` slice, `CleanupConnection` or `Reset`.

<!-- findings:23:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
| F-23-1 | `ja4.go` | 18 | critical | open | A capture that holds 100000 packets with a TLS client hello leaves 100000 results in the JA4 results slice. CleanupConnection removes none of them. |  |  |
| F-23-2 | `ja4s.go` | 16 | critical | open | A capture that holds 100000 packets with a TLS server hello leaves 100000 results in the JA4S results slice. CleanupConnection removes none of them. |  |  |
| F-23-3 | `ja4h.go` | 18 | critical | open | A capture that holds 100000 HTTP requests leaves 100000 results in the JA4H results slice. CleanupConnection removes none of them. |  |  |
| F-23-4 | `ja4t.go` | 18 | critical | open | A capture that holds 100000 TCP SYN packets leaves 100000 results in the JA4T results slice. CleanupConnection removes none of them. |  |  |
| F-23-5 | `ja4ts.go` | 13 | critical | open | A capture that holds 100000 TCP SYN-ACK packets leaves 100000 results in the JA4TS results slice. CleanupConnection removes none of them. |  |  |
| F-23-6 | `ja4l.go` | 27 | critical | open | A capture that holds 100000 TCP handshakes leaves 100000 results in the JA4L results slice. CleanupConnection removes none of them. |  |  |
| F-23-7 | `ja4x.go` | 38 | critical | open | A capture that holds 100000 distinct certificates leaves 100000 results in the JA4X results slice. CleanupConnection removes none of them. |  |  |
| F-23-8 | `ja4ssh.go` | 44 | critical | open | A capture that fills 100000 JA4SSH windows leaves 100000 results in the JA4SSH results slice. CleanupConnection removes none of them. |  |  |
| F-23-9 | `ja4d.go` | 59 | critical | open | A capture that holds 100000 DHCP messages leaves 100000 results in the JA4D results slice. CleanupConnection removes none of them. |  |  |
| F-23-10 | `ja4d6.go` | 71 | critical | open | A capture that holds 100000 DHCPv6 messages leaves 100000 results in the JA4D6 results slice. CleanupConnection removes none of them. |  |  |
| F-23-11 | `ja4.go` | 123 | critical | open | A caller that names the server endpoint first leaves one entry in the QUIC fragment table of JA4. The entry stays for every QUIC connection whose client hello spans two datagrams. |  |  |
| F-23-12 | `ja4x.go` | 109 | major | open | A capture where two connections carry one certificate, with a CleanupConnection call between them, produces one JA4X result and not two. |  |  |
| F-23-13 | `ja4l.go` | 219 | critical | open | A caller that passes `TCP` as the `proto` argument leaves one entry in the JA4L connections table for every connection it closes. |  |  |
| F-23-14 | `lookup.go` | 37 | major | open | A program that calls LookupFingerprint before a new mapping file reaches the cache path reads the embedded table for the life of the process. A lookup of a fingerprint that only the new file holds returns nil. |  |  |
<!-- findings:23:end -->

`audit_state_test.go` holds the measurement of each finding above. Read it before you
close one, because a test there states the behavior the audit read.

Three readings support the rows.

- **No exported method reads a results slice.** Every fingerprinter appends each result to
  it. `ProcessPacket` returns the same result to the caller. Only `Reset` clears the slice,
  so the slice holds one copy of every fingerprint for the life of the process.
- **Three fingerprinters key their state by a tuple that the caller supplies in one
  order.** `ja4s.go`, `ja4h.go` and `ja4x.go` remove both directions of the tuple.
  `ja4.go` removes one, which F-23-11 records.
- **`Reset` clears every field that holds state, in every fingerprinter.** FR-audit-18
  reaches no finding. `TestReset_ClearsEveryStateFieldOfEveryFingerprinter` walks the field
  graph of the ten fingerprinters and holds that result.

### The findings of issue #24

This table belongs to issue #24. It holds a finding of a contract the library states: a
panic, a write to standard output or to standard error, a swallowed error, an empty-input
hash or a sort.

<!-- findings:24:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
<!-- findings:24:end -->

### The findings of issue #25

This table belongs to issue #25. It holds a finding of the command-line program: an
unhandled error, or an exit code that does not match the outcome.

<!-- findings:25:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
<!-- findings:25:end -->

## The suspected findings

The survey that produced the feature file names three candidates. Each one needs
confirmation. The `## Suspected findings` section of
`docs/specs/features/02-correctness-audit.md` holds the failure scenario of each one.

**A suspected finding is a candidate, and not a finding.** The owner confirms it and
records one row for each defect it reaches, in its own findings table. It then writes the
status here, and the `Findings` column names those rows.

The last acceptance criterion set of the feature file states the outcome:

> S1, S2 and S3 each hold a verdict of `confirmed`, `no change needed` or
      `unconfirmed`.

The `Status` column holds one of those three values. The `## Terms` table of
`docs/specs/spec.md` bars the word `verdict`, which it reserves as a barred synonym of
`ruling`, so this report writes `Status` for the column. The value `open` holds the state
before the owner reaches the candidate, and issue #25 leaves none.

<!-- suspected:begin -->
| ID | Files | Owner | Status | Findings | Reason |
|---|---|---|---|---|---|
| S1 | the ten fingerprinter files | #23 | confirmed | F-23-1 through F-23-10 | Every fingerprinter appends each result to its results slice. No exported method reads that slice, and only Reset clears it. |
| S2 | `lookup.go` | #23 | confirmed | F-23-14 | The `sync.Once` at `lookup.go:37` loads the mapping table once for the life of the process. The doc comment of `LookupFingerprint` states that the cache file decides the table. |
| S3 | `lookup.go` | #23 | unconfirmed |  | No code writes `lookupDB`, `dbSource` or `dbCachePath` outside `lookupOnce.Do`, so `sync.Once` orders that write before every read that `loadDB` returns to. |
<!-- suspected:end -->

Issue #23 owns all three, because each candidate names state that a long-running process
keeps. S2 and S3 hand over to Epic 9, which owns the network boundary. A status of
`unconfirmed` or `no change needed` here states which part Epic 9 takes.

## The exported signatures a closure changed

The last acceptance criterion of the feature file requires this table. Epic 10 freezes the
exported API, so it reads this table to learn the final shape.

**Add a row when a closure changes an exported signature.** `docs/api/v1.md` records the
final shape of that signature.

<!-- signatures:begin -->
| Finding | Symbol | Before | After | Commit |
|---|---|---|---|---|
<!-- signatures:end -->
