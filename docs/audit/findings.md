# The correctness audit findings report

**Report status:** complete

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

**The status reads `complete`, so the closing rules apply.** Every file of the audit set
carries an audit date, and no finding stays `open`.
`TestACompleteReportLeavesNoOpenFindingAndNoUnauditedFile` holds that result.

## The audit set

FR-audit-1 states the set:

> The audit reads every `.go` file in the repository root, in `internal/parser/` and in
> `cmd/ja4plus/`.

**A file whose name ends in `_test.go` is outside the set.** The `## Purpose` section of
the feature file counts "Ten fingerprinters, nine parser files and a command-line program".
Those counts hold only without the test files. `internal/parser/` holds ten files that
ship, and nine of them decode a protocol. The audit reads a file that ships, because every
check in FR-audit-11 through FR-audit-24 names shipped behavior.

`internal/capture/` is outside the set, because FR-audit-1 names three directories and that
directory is none of them. **The classification of `## The files a later issue added` still
covers it.** Issue #611 measured the earlier state: the guard read the three directories
alone, so every file of `internal/capture/` passed it without a classification.

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

## The files a later issue added

The audit ran in Epic 2, and it read the files the repository held then. **A later epic
adds a file to a classification root, and no audit reads that file.** A `Read by` row for
it records an audit that nobody performed, so the audit set never gains one.

**The report classifies such a file as an added file, and the `Added by` column names the
issue that added it.** That classification states the true history of the file, and it
claims no audit.

`classificationRoots` in `audit_record_test.go` names each root. It holds the three
directories of the audit set, and it holds `internal/capture/`. **No audit reads
`internal/capture/`**, so every file that ships from it carries an added files row and
none of them carries a `Read by` row.

The two classifications cover each classification root. One audit issue reads the file, or
one later issue added it. **A file that carries neither classification fails
`TestTheReportClassifiesEveryGoFileOfEveryClassificationRoot`**, so the guard keeps its
force and an added file reaches an honest row.

**The name of that test states no count of directories.** Issue #611 records the reason:
the earlier name stated three, and the fourth root left the name stale.

Issue #162 states this classification, and the project manager decided it on issue #40.

<!-- added-files:begin -->
| File | Added by |
|---|---|
| `internal/parser/ssh_tracker.go` | #200 |
| `cmd/ja4plus/types.go` | #61 |
| `internal/parser/x509_identifiers.go` | #490 |
| `internal/parser/icmp_quoted.go` | #494 |
| `state_bound.go` | #565 |
| `cmd/ja4plus/watch.go` | #79 |
| `cmd/ja4plus/statistics.go` | #81 |
| `internal/capture/capture.go` | #77 |
| `internal/capture/pcapgo_linux.go` | #77 |
| `internal/capture/unsupported.go` | #77 |
| `internal/capture/libpcap.go` | #78 |
| `internal/capture/permission_darwin.go` | #82 |
| `internal/capture/permission_linux.go` | #82 |
| `internal/capture/permission_other.go` | #82 |
| `internal/capture/linktype.go` | #609 |
| `internal/capture/deadline.go` | #610 |
<!-- added-files:end -->

**The table holds 16 rows, and no audit reads any of the 16 files.** Each row names the
issue that added the file after the audit of Epic 2.

- Issue #200 added `internal/parser/ssh_tracker.go`.
- Issue #61 added `cmd/ja4plus/types.go`.
- Issue #490 added `internal/parser/x509_identifiers.go`.
- Issue #494 added `internal/parser/icmp_quoted.go`.
- Issue #565 added `state_bound.go`.
- Issue #79 added `cmd/ja4plus/watch.go`.
- Issue #81 added `cmd/ja4plus/statistics.go`.
- Issue #77 added `internal/capture/capture.go`, `internal/capture/pcapgo_linux.go` and
  `internal/capture/unsupported.go`.
- Issue #78 added `internal/capture/libpcap.go`.
- Issue #82 added `internal/capture/permission_darwin.go`,
  `internal/capture/permission_linux.go` and `internal/capture/permission_other.go`.
- Issue #609 added `internal/capture/linktype.go`.
- Issue #610 added `internal/capture/deadline.go`.

**Issue #611 wrote the eight rows that name a file of `internal/capture/`.** The directory
holds eight files that ship and seven test files, measured on 2026-08-14 with
`git ls-files internal/capture/`. **A test file carries no row**, because `goFilesOfRoots`
in `audit_record_test.go` drops a file whose name ends in `_test.go`.

**Issue #610 wrote the ninth row that names a file of `internal/capture/`, and the directory
holds nine files that ship and eight test files**, measured on 2026-08-15 with
`git ls-files internal/capture/`. The measurement above reads 2026-08-14, and the two
disagree because #610 added `internal/capture/deadline.go` and
`internal/capture/deadline_test.go` between the two days.

**The merge of `dev` into `epic/76-live-capture` met two tables, and it holds the union of
them.** `dev` carried the row of #565, and the integration branch carried the row of #79 and
the row of #81. **Each row states one file that one issue added**, so no row of either table
contradicts a row of the other, and the union states the whole history.

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

**A closing commit names a commit that the integration branch reaches.** The batch process
squash-merges a sub-branch, so the commits of that branch become unreachable and one squash
commit replaces them. A hash that an author records while the work sits on the sub-branch
therefore names nothing after the merge. Record the squash commit instead.

A commit that no branch reaches still answers `git cat-file` in the clone that wrote it,
and it is absent from every fresh clone. Reachability is therefore the property this rule
needs, and existence is not.
`TestEveryConfirmedFindingNamesAClosingCommitThatHeadReaches` holds the rule.

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
<!-- files:24:end -->

### The files of issue #25

This table belongs to issue #25.

<!-- files:25:begin -->
| File | Audit date |
|---|---|
| `cmd/ja4plus/main.go` | 2026-08-11 |
<!-- files:25:end -->

## The findings

Each table below holds the findings of one issue. The tables are empty until the audit
runs.

### The findings of issue #22

This table belongs to issue #22. It holds a finding of a parser input: a length field, an
integer conversion, a map read, a slice index or a GREASE filter.

`audit_parser_test.go` builds the input of each finding below and asserts the value the
library produces today. A reader who reverses a finding starts there.

**Three findings hand over to another epic, and issue #25 recorded the deferral under
FR-audit-28. Each one carries the status `declined` and the reason.** The maintainer named
all three on issue #25 on 2026-08-11.

- **F-22-1** hands over to **#50 of Epic 8a**. `docs/specs/foxio/JA4.md` R19 records a
  reference split of four results for a non-alphanumeric ALPN value. A FoxIO vector
  reaches the value, so `.claude/rules/parity.md` rule 1 settles it and no ruling applies.
- **F-22-9** and **F-22-10** hand over to **#42 of Epic 5**. FR-gaps-21 asks the library to
  reassemble a client hello that spans more than one CRYPTO frame, and a parser that
  discards collected fragments cannot satisfy it.

**F-22-14 through F-22-26 record the thirteen `nilerr` sites of `internal/parser/quic.go`
as correct.** Issue #4 routed them here. The port declines the same input, states the
decline as an architecture invariant, and reached it through its own issues #319 and #382.
Its QUIC reader returns `None, None` for a datagram that holds no QUIC and for a QUIC
datagram it cannot read. **A change that propagates the error at any of the thirteen sites
moves this project away from the port.**

<!-- findings:22:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
| F-22-1 | `internal/parser/tls.go` | 323 | critical | declined | The capture `tls-non-ascii-alpn.pcapng` stream 0 makes `ALPNValue` return `bd`, and the FoxIO vector holds `99`. |  | Issue #50 of Epic 8a owns the repair, because a FoxIO vector reaches the value and the register records the split. |
| F-22-2 | `internal/parser/tls.go` | 131 | major | confirmed | A ClientHello whose extensions length field reaches past its own TLS record makes `ParseClientHello` read `0x1603` as an extension type. | `5515a3c` |  |
| F-22-3 | `internal/parser/tls.go` | 223 | major | confirmed | A ServerHello whose extensions length field reaches past its own TLS record makes `ParseServerHello` read the next record as extension bytes. | `5515a3c` |  |
| F-22-4 | `internal/parser/ssh.go` | 40 | major | confirmed | An SSH packet whose length is 1024 and whose padding length is 8 makes `IsSSHPacket` return false. | `5515a3c` | The repair moved the conformance count, and issue #53 of Epic 8a owns the JA4SSH surplus that the ten new rows add to. |
| F-22-5 | `internal/parser/ssh.go` | 79 | major | confirmed | An SSH KEXINIT packet whose length is 1024 and whose padding length is 8 makes `ParseSSHPacket` return nil. | `5515a3c` | The repair moved the conformance count, and issue #53 of Epic 8a owns the JA4SSH surplus that the ten new rows add to. |
| F-22-6 | `internal/parser/x509_utils.go` | 36 | major | confirmed | The identifier `2.100.3` makes `OIDToHex` return `b403`, and X.690 encodes it as `813403`. | `5515a3c` |  |
| F-22-7 | `internal/parser/tcp_stream.go` | 42 | major | confirmed | A reassembler whose stream limit is 0 makes the first `AddSegment` call panic with an index out of range. | `5515a3c` |  |
| F-22-8 | `internal/parser/tcp_stream.go` | 93 | major | confirmed | A reassembler whose byte limit is below 0 makes `GetStream` panic with a slice bound out of range. | `5515a3c` |  |
| F-22-9 | `internal/parser/quic.go` | 337 | critical | declined | A QUIC Initial datagram whose last CRYPTO frame is truncated makes `ParseQUICInitial` discard the earlier fragments and return no ClientHello. |  | Issue #42 of Epic 5 owns the repair under FR-gaps-21, which asks the library to reassemble a hello that spans more than one CRYPTO frame. |
| F-22-10 | `internal/parser/quic.go` | 803 | critical | declined | A QUIC server Initial whose last CRYPTO frame is truncated makes `ParseQUICServerInitial` discard the earlier fragments and return no ServerHello. |  | Issue #42 of Epic 5 owns the repair under FR-gaps-21, which asks the library to reassemble a hello that spans more than one CRYPTO frame. |
| F-22-11 | `ja4.go` | 181 | critical | confirmed | A ClientHello whose signature algorithm list opens with `0a0a` makes `computeJA4RawFromClientHello` write that GREASE value into the raw JA4. | `5515a3c` |  |
| F-22-12 | `ja4.go` | 266 | critical | confirmed | A ClientHello whose signature algorithm list opens with `0a0a` makes `ja4ExtensionHash` hash that GREASE value into part c. | `5515a3c` |  |
| F-22-13 | `ja4.go` | 288 | critical | confirmed | A ClientHello whose signature algorithm list opens with `0a0a` makes `computeJA4RawOriginalOrder` write that GREASE value into the wire-order raw JA4. | `5515a3c` |  |
| F-22-14 | `internal/parser/quic.go` | 229 | minor | no change needed | A QUIC Initial datagram whose token length varint is truncated makes `ParseQUICInitial` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
| F-22-15 | `internal/parser/quic.go` | 240 | minor | no change needed | A QUIC Initial datagram whose payload length varint is truncated makes `ParseQUICInitial` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
| F-22-16 | `internal/parser/quic.go` | 427 | minor | no change needed | A QUIC Initial datagram whose token length varint is truncated makes `DecryptQUICInitialCrypto` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
| F-22-17 | `internal/parser/quic.go` | 436 | minor | no change needed | A QUIC Initial datagram whose payload length varint is truncated makes `DecryptQUICInitialCrypto` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
| F-22-18 | `internal/parser/quic.go` | 573 | minor | no change needed | A QUIC ACK frame whose largest acknowledged varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-19 | `internal/parser/quic.go` | 579 | minor | no change needed | A QUIC ACK frame whose ACK delay varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-20 | `internal/parser/quic.go` | 585 | minor | no change needed | A QUIC ACK frame whose ACK range count varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-21 | `internal/parser/quic.go` | 591 | minor | no change needed | A QUIC ACK frame whose first ACK range varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-22 | `internal/parser/quic.go` | 599 | minor | no change needed | A QUIC ACK frame whose gap varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-23 | `internal/parser/quic.go` | 605 | minor | no change needed | A QUIC ACK frame whose ACK range varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-24 | `internal/parser/quic.go` | 614 | minor | no change needed | A QUIC ACK frame whose ECN count varint is truncated makes `ParseCryptoFrames` return no error. |  | The port breaks its ACK loop and returns the fragments it holds. |
| F-22-25 | `internal/parser/quic.go` | 720 | minor | no change needed | A QUIC server Initial whose token length varint is truncated makes `ParseQUICServerInitial` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
| F-22-26 | `internal/parser/quic.go` | 731 | minor | no change needed | A QUIC server Initial whose payload length varint is truncated makes `ParseQUICServerInitial` return no error. |  | The port returns one value for a datagram that holds no QUIC and for a QUIC datagram it cannot read. |
<!-- findings:22:end -->

### The findings of issue #23

This table belongs to issue #23. It holds a finding of the state a fingerprinter keeps: a
state table, the `results` slice, `CleanupConnection` or `Reset`.

<!-- findings:23:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
| F-23-1 | `ja4.go` | 18 | critical | confirmed | A capture that holds 100000 packets with a TLS client hello leaves 100000 results in the JA4 results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-2 | `ja4s.go` | 16 | critical | confirmed | A capture that holds 100000 packets with a TLS server hello leaves 100000 results in the JA4S results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-3 | `ja4h.go` | 18 | critical | confirmed | A capture that holds 100000 HTTP requests leaves 100000 results in the JA4H results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-4 | `ja4t.go` | 18 | critical | confirmed | A capture that holds 100000 TCP SYN packets leaves 100000 results in the JA4T results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-5 | `ja4ts.go` | 13 | critical | confirmed | A capture that holds 100000 TCP SYN-ACK packets leaves 100000 results in the JA4TS results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-6 | `ja4l.go` | 27 | critical | confirmed | A capture that holds 100000 TCP handshakes leaves 100000 results in the JA4L results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-7 | `ja4x.go` | 38 | critical | confirmed | A capture that holds 100000 distinct certificates leaves 100000 results in the JA4X results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-8 | `ja4ssh.go` | 44 | critical | confirmed | A capture that fills 100000 JA4SSH windows leaves 100000 results in the JA4SSH results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-9 | `ja4d.go` | 59 | critical | confirmed | A capture that holds 100000 DHCP messages leaves 100000 results in the JA4D results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-10 | `ja4d6.go` | 71 | critical | confirmed | A capture that holds 100000 DHCPv6 messages leaves 100000 results in the JA4D6 results slice. CleanupConnection removes none of them. | `5515a3c` | The repair removes the results slice, because ProcessPacket returns each result to the caller. |
| F-23-11 | `ja4.go` | 123 | critical | confirmed | A caller that names the server endpoint first leaves one entry in the QUIC fragment table of JA4. The entry stays for every QUIC connection whose client hello spans two datagrams. | `5515a3c` |  |
| F-23-12 | `ja4x.go` | 109 | major | confirmed | A capture where two connections carry one certificate, with a CleanupConnection call between them, produces one JA4X result and not two. | `5515a3c` | The fingerprinter holds a stream index of the hashes it wrote, so the deduplication of a live connection stays. |
| F-23-13 | `ja4l.go` | 219 | critical | confirmed | A caller that passes `TCP` as the `proto` argument leaves one entry in the JA4L connections table for every connection it closes. | `5515a3c` |  |
| F-23-14 | `lookup.go` | 37 | major | declined | A program that calls LookupFingerprint before a new mapping file reaches the cache path reads the embedded table for the life of the process. A lookup of a fingerprint that only the new file holds returns nil. |  | Issue #75 of Epic 9 owns the reload, and `.claude/rules/concurrency.md` names this state a known exception under repair. |
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

`audit_panic_test.go` reproduced every `open` row. Issue #25 reversed each assertion in
the commit that closed the finding, so every test of that file now states the repaired
result. Two rows close as `no change needed`, and `## The three rulings of 2026-08-11`
states the reason.

<!-- findings:24:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
| F-24-1 | `ja4.go` | 52 | critical | confirmed | A packet whose UDP layer type carries another concrete type makes `NewJA4().ProcessPacket` panic with an interface conversion. | `5515a3c` |  |
| F-24-2 | `ja4d.go` | 74 | critical | confirmed | A packet whose UDP layer type carries another concrete type makes `NewJA4D().ProcessPacket` panic with an interface conversion. | `5515a3c` |  |
| F-24-3 | `ja4d.go` | 85 | critical | confirmed | A packet that holds a UDP header on port 68 and a DHCPv4 layer of another concrete type makes `NewJA4D().ProcessPacket` panic. | `5515a3c` |  |
| F-24-4 | `ja4h.go` | 65 | critical | confirmed | An HTTP request packet makes a zero-value `JA4HFingerprinter` panic with a nil pointer dereference of the reassembler field. | `5515a3c` |  |
| F-24-5 | `ja4l.go` | 187 | critical | confirmed | A TCP packet makes a zero-value `JA4LFingerprinter` panic with an assignment to an entry in a nil map. | `5515a3c` |  |
| F-24-6 | `ja4x.go` | 80 | critical | confirmed | A TCP packet that holds a payload makes a zero-value `JA4XFingerprinter` panic with an assignment to an entry in a nil map. | `5515a3c` |  |
| F-24-7 | `ja4ssh.go` | 134 | critical | confirmed | A TCP payload that opens with `SSH-` makes a zero-value `JA4SSHFingerprinter` panic with an assignment to an entry in a nil map. | `5515a3c` |  |
| F-24-8 | `ja4.go` | 115 | critical | confirmed | A call of `Reset` on a zero-value `Processor` panics with a nil pointer dereference of the JA4 fingerprinter field. | `5515a3c` |  |
| F-24-9 | `processor.go` | 62 | critical | confirmed | A TCP packet makes `ProcessPacket` of a zero-value `SyncProcessor` panic with a nil pointer dereference of the processor field. | `5515a3c` |  |
| F-24-10 | `ja4.go` | 141 | major | no change needed | A TLS record whose handshake length exceeds the record makes `ComputeJA4` return the empty string, which also names a packet with no ClientHello. |  | The port states that a fingerprinter which cannot parse a packet returns nothing, and `Processor.ProcessPacket` is the API that carries the error. |
| F-24-11 | `ja4s.go` | 61 | major | unconfirmed | A QUIC Initial datagram that the parser cannot read makes JA4S return no error, and `ja4.go:56` returns an error on the same failure. |  | No crafted datagram of `audit_panic_test.go` makes `parser.ParseQUICInitial` return an error, so the test skips. |
| F-24-12 | `ja4x.go` | 271 | major | no change needed | The DER buffer `30 03 02 01 00` makes `ComputeJA4XFromDER` return the empty string, which also names a buffer that holds no certificate. |  | The port states that a fingerprinter which cannot parse a packet returns nothing, and `Processor.ProcessPacket` is the API that carries the error. |
| F-24-13 | `lookup.go` | 55 | major | unconfirmed | A cache file whose first row is not valid CSV leaves the table empty, so `LookupFingerprint` returns no result for every fingerprint. |  | Issue #24 measured that the loader ran once for each process, through `lookupOnce`. No test of that audit reached it with a crafted cache file. #74 replaced that loader on 2026-08-14. `## What Epic 9 changed under S2, S3 and F-24-13 through F-24-15` below names that test. |
| F-24-14 | `lookup.go` | 72 | major | unconfirmed | A cache row that holds an unescaped double quote makes the loader skip it, so `LookupFingerprint` returns no result for that row. |  | Issue #24 measured that the loader ran once for each process, through `lookupOnce`. No test of that audit reached it with a crafted cache file. #74 replaced that loader on 2026-08-14. `## What Epic 9 changed under S2, S3 and F-24-13 through F-24-15` below names that test. |
| F-24-15 | `lookup.go` | 43 | minor | unconfirmed | A cache file that the process cannot read makes the loader use the embedded table, and `GetDatabaseInfo` reports the source as embedded. |  | Issue #24 measured that the loader ran once for each process, through `lookupOnce`. No test of that audit reached it with a crafted cache file. #74 replaced that loader on 2026-08-14. `## What Epic 9 changed under S2, S3 and F-24-13 through F-24-15` below names that test. |
| F-24-16 | `internal/parser/quic.go` | 637 | critical | confirmed | Thirteen CRYPTO fragments of which two share the offset 11 reassemble to the bytes of the first fragment, and the wire order names the second. | `5515a3c` | FR-audit-22 asks for a stable sort, and no FoxIO source states a rule for a duplicate offset. |
<!-- findings:24:end -->

#### What issue #24 checked and found clean

**FR-audit-19 reaches no finding.** No file of the repository root and no file of
`internal/parser/` writes to standard output or to standard error.
`TestTheLibrarySourceHoldsNoWriteToStandardOutputOrStandardError` scans the shipped
source, and `TestTheLibraryWritesNothingWhenItReadsACraftedFrame` reads the two file
descriptors while the library reads every crafted frame of the table. Every write sits in
`cmd/ja4plus/main.go`, which `CLAUDE.md` names as the owner of all output.

**FR-audit-21 reaches no finding.** `internal/parser/hash.go:8` holds the literal
`000000000000`, and `TruncatedHash` of `internal/parser/hash.go` returns it for an empty
input. `docs/specs/foxio/zeek.md:48` records the reading of
`zeek/utils/common.zeek:63`, and `docs/specs/foxio/JA4.md` R24 and R30,
`docs/specs/foxio/JA4S.md` R23 and `docs/specs/foxio/JA4H.md` R27 each name the same
value. **Issue #57 of Epic 8b held the decision for the JA4X empty list, and the ruling of
2026-08-14 supersedes that sentence.** Issue #582 built the ruling, and the paragraph below
states it.

**Four call sites of the root package write no sentinel, and the tree holds no fifth.**
`ja4hHashCallSites` in `ja4h_empty_header_list_test.go` names each one, and
`TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed` reads the syntax tree against that
list.

| Function | File | Sites without the sentinel |
|---|---|---|
| `computeJA4HFromRequest` | `ja4h.go` | 1, which is part b. |
| `computeJA4XWithRaw` | `ja4x.go` | 3, which are the three JA4X parts. |

**JA4H part b writes no sentinel.** The maintainer ruled on 2026-08-14 that an empty header
list hashes to `e3b0c44298fc`. R18 of `docs/specs/foxio/JA4H.md` names no sentinel, and R27
confines the sentinel to part c and to part d, so FR-audit-21 reads no sentinel for part b.
Issue #527 is the reversal path.

**No part of JA4X writes the sentinel.** R12 of `docs/specs/foxio/JA4X.md` transcribes a
reference split for an empty list, and the maintainer ruled that split on 2026-08-14: an
empty list hashes. Issue #582 is the reversal path, and the port half is
`Crank-Git/ja4plus#619`.

**Every other section of every method still calls `TruncatedHash`.**

**FR-audit-22 reaches one finding, and F-24-16 holds it.** Five other sorts use
`sort.Slice`, which is not stable, and each one changes no result. `ja4.go:163`, `:176`,
`:243` and `:260` sort a `[]uint16` by the value itself, and `ja4h.go:248` sorts a
`[]string` by the string itself. Two elements that those keys rank equal are the same
value, so their order changes no output. `ja4h.go:261` sorts cookie pairs by the name, and
`parser.HTTPRequest.Cookies` is a map, so the key separates every element.

**The thirteen `nilerr` sites of `internal/parser/quic.go` belong to issue #22.** The
maintainer recorded the port evidence on that issue. Issue #24 records none of them.

### The findings of issue #25

This table belongs to issue #25. It holds a finding of the command-line program: an
unhandled error, or an exit code that does not match the outcome. FR-audit-24 states the
two checks, and F-25-1, F-25-7, F-25-8 and F-25-9 hold the result.

`cmd/ja4plus/audit_closure_test.go` reproduces each of those four. The file is the only
test file of the command-line program, and issue #25 added it.

**Five rows name a file that another issue read.** F-25-2 through F-25-6 hold the panic
that F-24-1, F-24-2 and F-24-3 name, at five sites that no issue recorded. Issue #25
reached them through
`TestNoLibraryFileAssertsAGopacketLayerTypeWithOneResult` of `audit_panic_test.go`, which
scans the shipped source for a type assertion that takes one result. The closure of the
three recorded sites left the five, so the scan is the reason the report holds them. The
rows sit here because issue #25 wrote them, and `### The record` states that rule.

<!-- findings:25:begin -->
| ID | File | Line | Severity | Status | Failure scenario | Closing commit | Reason |
|---|---|---|---|---|---|---|---|
| F-25-1 | `cmd/ja4plus/main.go` | 156 | major | confirmed | A capture whose last packet record header is truncated makes `ja4plus analyze` print the results it reached and exit 0. | `5515a3c` |  |
| F-25-2 | `ja4d6.go` | 85 | critical | confirmed | A packet whose UDP layer type carries another concrete type makes `NewJA4D6().ProcessPacket` panic with an interface conversion. | `5515a3c` |  |
| F-25-3 | `ja4d6.go` | 96 | critical | confirmed | A packet that holds a UDP header on port 546 and a DHCPv6 layer of another concrete type makes `NewJA4D6().ProcessPacket` panic. | `5515a3c` |  |
| F-25-4 | `ja4s.go` | 61 | critical | confirmed | A packet whose UDP layer type carries another concrete type makes `NewJA4S().ProcessPacket` panic with an interface conversion. | `5515a3c` |  |
| F-25-5 | `internal/parser/packet.go` | 43 | critical | confirmed | A packet whose IPv4 layer type carries another concrete type makes `parser.GetIPInfo` panic with an interface conversion. | `5515a3c` |  |
| F-25-6 | `internal/parser/packet.go` | 47 | critical | confirmed | A packet whose IPv6 layer type carries another concrete type makes `parser.GetIPInfo` panic with an interface conversion. | `5515a3c` |  |
| F-25-7 | `cmd/ja4plus/main.go` | 163 | major | confirmed | A capture that holds a truncated ClientHello makes `ja4plus analyze` report no parse failure on standard error. | `5515a3c` |  |
| F-25-8 | `cmd/ja4plus/main.go` | 220 | major | confirmed | A standard output that takes no byte makes `ja4plus analyze --csv` write no row and exit 0. | `5515a3c` |  |
| F-25-9 | `cmd/ja4plus/main.go` | 339 | major | confirmed | A server that answers `ja4plus db update` with an endless body makes the program write every byte of it to the cache path. | `5515a3c` |  |
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
| S2 | `lookup.go` | #23 | confirmed | F-23-14 | The `sync.Once` at `lookup.go:37` loaded the mapping table once for the life of the process. The doc comment of `LookupFingerprint` stated that the cache file decides the table. Epic 9 closed the candidate on 2026-08-14. |
| S3 | `lookup.go` | #23 | unconfirmed |  | No code wrote `lookupDB`, `dbSource` or `dbCachePath` outside `lookupOnce.Do`, so `sync.Once` ordered that write before every read that `loadDB` returned to. Epic 9 removed all three variables on 2026-08-14. |
<!-- suspected:end -->

Issue #23 owns all three, because each candidate names state that a long-running process
keeps. S2 and S3 hand over to Epic 9, which owns the network boundary. A status of
`unconfirmed` or `no change needed` here states which part Epic 9 takes.

## What Epic 9 changed under S2, S3 and F-24-13 through F-24-15

**This section states what Epic 9 left, and it re-adjudicates no status above.** A status
is the audit's to set, and this section reports the tree instead.

**#74 replaced `sync.Once` with one `atomic.Pointer[lookupTable]` on 2026-08-14.** The
package-level variables `lookupDB`, `dbSource` and `dbCachePath` no longer exist. The
source, the cache path and the file time are fields of the unexported `lookupTable` type.
`activeTable` of `lookup.go` publishes one immutable snapshot for every reader.

**Five tests now reach the loader with a crafted cache file, and the audit of issue #24
had none.** They live in `lookup_reload_test.go`.

| Test | What it reaches |
|---|---|
| `TestTheLookupTable_ReloadsWhenTheCacheFileChanges` | A new cache file inside one process. |
| `TestTheLookupTable_KeepsThePreviousTableWhenAReloadFails` | A cache file that the parser rejects. |
| `TestTheLookupTable_FallsBackToTheEmbeddedCopyWhenTheCacheIsCorrupt` | A corrupt cache file, with no previous table. |
| `TestTheLookupTable_ReadsTheEmbeddedCopyWhenTheCacheFileGoes` | A deleted cache file. |
| `TestTheLookupTable_ReportsNoRaceWhenAnUpdateRunsBesideALookup` | The update path and the lookup path together, under the race detector. |

**So the `Reason` cell of F-24-13, of F-24-14 and of F-24-15 no longer describes the
tree.** Each cell states the measurement of issue #24 in the past tense, and the round of
2026-08-14 wrote that tense. **A reader who wants those three statuses re-adjudicated
raises that with the maintainer**, because a documentation round sets no audit status.

## The exported signatures a closure changed

The last acceptance criterion of the feature file requires this table. Epic 10 freezes the
exported API, so it reads this table to learn the final shape.

**Add a row when a closure changes an exported signature.** `docs/api/v1.md` records the
final shape of that signature.

**No closure of issue #25 changed an exported signature, so the table holds no row.**
Every repair sits behind an exported name that keeps its shape. F-24-10 and F-24-12 are
the two findings whose repair would change one, and the maintainer closed both as
`no change needed`. `## The three rulings of 2026-08-11` states the reason.

## The three rulings of 2026-08-11

The maintainer ruled on three findings that no source settles. Each ruling is reversible,
and `.claude/rules/rulings.md` states the rule that only the maintainer makes one.

### F-24-10 and F-24-12 — the one-shot functions return one string

`ComputeJA4` returns the empty string for a packet that holds no handshake and for a
packet that holds a handshake the parser cannot read. `ComputeJA4XFromDER` returns the
empty string for a buffer that holds no certificate and for a buffer that holds a
certificate the parser cannot read. A caller separates neither pair.

**The ruling closes both as `no change needed`.** `Processor.ProcessPacket` is the API
that carries the error, and the `Compute*` one-shot functions carry none. Neither
signature changes.

The port states the architecture invariant that this project follows, at commit
`21299645366591331eb93155355b65a76a3729f3`:

> **Error handling.** A fingerprinter that cannot parse a packet returns nothing. It does
> not raise.

**That invariant already settled thirteen findings of this epic.** F-22-14 through
F-22-26 record the thirteen `nilerr` sites of `internal/parser/quic.go` as
`no change needed` for the same reason. A `Compute*` function that returns an empty string
for a packet it cannot read is the same rule at the exported surface.

`Processor.ProcessPacket` returns `[]error` and separates both pairs.
`TestTheProcessorReturnsAnErrorRatherThanDiscardingIt` holds that measurement.

### F-23-14 — the lookup table loaded once for the life of the process

**This section records a ruling that the maintainer made on 2026-08-11, and every sentence
of the two paragraphs below states the tree of that day.** `lookup.go:37` held a
`sync.Once`. A program that called `LookupFingerprint` before a new mapping file reached
the cache path read the embedded table until it exited. `ja4plus db update` printed
`note: existing processes must be restarted to pick up the new database`, so the
command-line program stated the same behavior.

`.claude/rules/concurrency.md` read that the package-level lookup state of `lookup.go` was
a known exception **under repair**, and it named
`docs/specs/features/09-database-lookup.md`. Issue #75 of Epic 9 carried the title
`Reload the lookup table and hold the db subcommands`, which the maintainer named as this
repair.

**The ruling records F-23-14 as `declined`, and Epic 9 owns the reload.** Issue #25
repairs nothing here.

**Epic 9 built the reload on 2026-08-14, and #74 built it rather than #75.** #74 replaced
the `sync.Once` with one `atomic.Pointer[lookupTable]`, and #75 then added the validation
and the atomic cache write of `internal/dbcache`. **`cmd/ja4plus/main.go` no longer prints
the restart note**, because a running process reads the new database at its next lookup.
**`.claude/rules/concurrency.md` no longer names the state a known exception**, and its
`## The contract` section now states that one `atomic.Pointer` holds the table.
`## What Epic 9 changed under S2, S3 and F-24-13 through F-24-15` above names each test
that holds the repair.

## The JA4SSH surplus belongs to issue #53

The closure of F-22-4 and F-22-5 moved the conformance count. `internal/parser/ssh.go`
compared the padding length against `byte(packetLength)`, which truncated a 32-bit field
to eight bits and declined a valid SSH packet. **The repair is correct on its own terms.**

The measurement is 943 matches and 3431 deviations before the repair, and 943 matches and
3441 deviations after it. Ten new rows name JA4SSH, on `ssh-r.pcap`, `ssh.pcapng`,
`ssh2.pcapng`, `sshv1.pcap` and `v6.pcap`. Each one reads
`the library produces a value the vector does not hold`. No key lost a match, and no key
of another method moved.

**The ten rows add to an over-emission that this library already carries.** The tracked
report on `dev` records 24 surplus JA4SSH rows against 5 missing and 4 differing, and
issue #33 measured 617 JA4SSH values for `ssh-r.pcap` where the vector holds 11.

**Whether JA4SSH over-emits is a separate and larger question, and issue #53 of Epic 8a
owns it.** That issue covers the window and `CloseOpenWindows`, and the maintainer already
ruled its interface. **This report claims no improvement in the conformance count**, and
the direction of the ten rows stays unproven until issue #53 measures the window.

<!-- signatures:begin -->
| Finding | Symbol | Before | After | Commit |
|---|---|---|---|---|
<!-- signatures:end -->
