# Mutation settlements — `./internal/parser`, 2026-08-14

This record settles the surviving mutations of one sweep. #92 wrote it, under FR-mutation-11
through FR-mutation-15. `docs/mutation_sweep.md` states the procedure that produced it.

**The record reads `docs/mutation_reports/2026-08-14-internal-parser.md`**, which #91
committed. That report holds the sweep of `./internal/parser` with `gremlins` v0.6.0.

**A mutation position names a file, a line and a column of the tree at commit `19f1ee4`.** A
later edit moves the line, and the position then names the mutation of the report rather than
the code of today. Read the position against the report, and never against a later tree.

**A citation of this library's own code names the identifier and the file, and it names no
line.** `.claude/rules/ste.md` `## How a citation names its target` states that rule, because
a line number finds the code until the next edit. **A mutation position is a coordinate, and
that rule does not reach one.** The cross-member review of Epic 15 found five reader citations
of the barred form in this record, and round 59 of the `## Changelog` of `docs/specs/spec.md`
records the repair.

**Each settlement below names its issue, and #92 is that issue for every one of them.**
FR-mutation-14 states `Each settlement names the mutation and the issue that closed it.`
**#92 wrote every settlement of this record**, so one issue closes all ten. The heading of
each settlement carries the number, and the sentence above states the reason a reader sees
one number ten times.

## The report, and what it asks for

| Verdict | Count |
|---|---|
| KILLED | 493 |
| **LIVED** | **223** |
| NOT COVERED | 162 |
| TIMED OUT | 4 |
| NOT VIABLE | 0 |
| **Total** | **882** |

**FR-mutation-11 settles a TIMED OUT mutation as it settles a LIVED one, so the report asks
for 227 settlements.** #92 re-measured that number before it settled one mutation.

**227 rows hold 220 distinct mutants.** `ARITHMETIC_BASE` and `INVERT_NEGATIVES` both rewrite
`-` to `+`, so a binary minus produces two rows for one mutant. The report holds seven such
pairs. **No pair reaches the surviving set below**, so the 47 rows of that set are 47
mutants.

## The rule that decides a settlement

**The maintainer ruled the scope on 2026-08-14, in issue #92.** #634 carries the amendment to
FR-mutation-11.

> **A LIVED mutation on code that can move a fingerprint value is settled. Every other LIVED mutation is counted and recorded.**

**This record states the boundary as a rule, and it states no list of file names.** A later
reader applies the same three tests to a report of a package that no sweep has reached.

**Test 1 — the scope test.** Apply the mutation, and run every package that imports the
mutated package. If a test fails, the suite already holds the behavior. Record the mutation
as killed at the wider scope, and settle nothing.

**Test 2 — the value test.** Ask whether the mutated expression computes a byte, an index, a
count or an order that a fingerprint carries. A **value expression** computes part of the
answer. A **guard expression** decides whether the parse continues. Follow the value to the
fingerprinter that reads it, and never to the struct field that holds it.

**Test 3 — the well-formed input test.** A guard expression separates the original from the
mutant on a boundary input alone. Ask whether an input that the wire format permits reaches
that boundary and yields a fingerprint. If only a truncated or a malformed input separates
the two, count the mutation.

**A mutation that fails test 2 and test 3 is counted, and it is never dismissed.** The count
below is the record.

### Test 2 reads the reader, and it does not read the assignment

**A field that no fingerprinter reads carries no fingerprint value.** `readQuotedTCPFields`
of `icmp_quoted.go` is the measured case, and it decides nine mutations of this record.

The function assigns nine TCP flag bits. `QuotedTCPHeader` returns the header to one caller,
which is `ProcessPacket` of `ja4t.go`. That method reads `tcp.SYN` and `tcp.ACK`, and
`generateTCPFingerprint` reads the window, the options, the maximum segment size and the
window scale. **No line of that path reads the other seven bits.**

**The sweep measured the same split without the reading.** The report holds a surviving
mutation for each of the seven bits that no caller reads. It holds no surviving mutation for
`SYN` at `icmp_quoted.go:160`, and none for `ACK` at `icmp_quoted.go:163`. The suite kills
those two, because JA4T reads those two.

**`ProcessPacket` of `ja4ts.go` reads `tcp.RST`, and `ja4ssh.go` reads `FIN`, `RST`, `PSH`
and `URG`.** Each of those readers calls `parser.GetTCPLayer`, and none of them calls
`QuotedTCPHeader`. So a quoted header never reaches them, and the seven bits stay unread on
this path.

## What the re-measurement found

**The report states 223 LIVED, and 43 of them survive every test of this repository.** Three
scopes produce three counts, and each one answers a different question.

| Scope | What it runs | LIVED after the run |
|---|---|---|
| The package | The tests of `./internal/parser` alone. This is the report. | 223 |
| The dependent set | Every package that imports `./internal/parser`. | **43** |
| The conformance suite | The 38 FoxIO captures, behind the `conformance` build tag. | **1 moves a figure** |

**180 of the 223 LIVED mutations die at the dependent scope**, which is 80.7 percent.
`gremlins` runs the tests of the mutated package alone, so the report's `LIVED` states that
no test **of `./internal/parser`** kills the mutation. It never states that no test of this
repository kills it.

**The dependent set is `.`, `./cmd/ja4plus` and `./internal/parser`.** `go list -test -deps`
names those three, measured on 2026-08-14. `./internal/keylog` and `./internal/mutationdiff`
name `internal/parser` in a comment and in a test string, and neither one imports it.

**The conformance suite reaches neither the sweep nor the dependent-scope run.** It sits
behind the `conformance` build tag, `.gremlins.yaml` sets no `tags` key, and a plain
`go test` builds no file of that tag. `CLAUDE.md` records the first half of that reading, and
#92 measured the second half. **So #92 ran the suite against each of the 43 survivors.**

**The suite fails at base, under the known Epic #441 backlog, so its exit code decides
nothing.** The run reads the eight reported figures instead. It reports a mutation as moved
when one figure differs.

The base run reports these figures.

- 38 captures.
- 1754 matches.
- 267 deviations that the register does not hold.
- 585 accepted deviations.
- 175 unaccepted uncovered values.
- 32 accepted uncovered values.
- 0 stale register entries.
- 0 orphan register entries.

**The base run also reports 617 register keys, and that count is not one of the eight.** The
list above held it as a ninth item until round 59 of the `## Changelog` of
`docs/specs/spec.md`, so the sentence above named eight figures over a list of nine. The
`## Parity with ja4plus` register of `docs/specs/spec.md` writes the eight out and then
states the register key count separately, and this record now follows that form.
`docs/mutation_sweep.md` states the same eight, and it enumerates none of them.

**One mutation of the 43 moves a figure.** S2 below settles it.

**The four TIMED OUT mutations reached no conformance run.** Each one is a non-terminating
loop, so the run costs the timeout and it returns no figure. E4 below states the reading.

## The settlements

**Ten mutations carry a settlement of the 47 that survive.** Three gain an assertion, three
state an equivalence reason, and four state the non-termination reading.

**The four of E4 also appear in the counted table below, so the two sets overlap by four.**
The arithmetic of this record is therefore `3 + 3 + 41 = 47`, where the 41 holds the four of
E4. A reader who sizes the remaining work needs one number, and the counted table is that
number.

### S1 — a header that carries no option (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/icmp_quoted.go:108:20` | `CONDITIONALS_BOUNDARY` | `<` to `<=` |
| `internal/parser/icmp_quoted.go:114:16` | `CONDITIONALS_BOUNDARY` | `<` to `<=` |

**The assertion is `TestQuotedTCPHeaderReadsAHeaderThatCarriesNoOption`**, in
`internal/parser/icmp_quoted_test.go`.

`decodeQuotedTCPHeader` bounds the transport region at 20 bytes, and it bounds the data offset
at five words. Each mutant turns the lower bound into an exclusion, so each one declines a
quoted TCP header that carries no option. **A SYN that carries no option is well-formed**, and
`ProcessPacket` of `ja4t.go` reads the quoted header, so each mutant moves a JA4T value to no
value.

**Every other test of that file builds an option region**, so no test reached either lower
bound. The new test builds a 20-byte header with a data offset of five words.

**The test fails against each mutation, measured on 2026-08-14.** It passes against the tree.

### S2 — the earliest terminator (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/http.go:95:80` | `CONDITIONALS_NEGATION` | `<` to `>=` |

**The assertions are `TestHeaderBlockTerminatorReadsTheEarliestTerminator` and
`TestHTTPMessageIsCompleteMeasuresTheBodyFromTheHeaderBlock`**, in
`internal/parser/http_test.go`.

`headerBlockTerminator` reads `\r\n\r\n` and `\n\n`, and it returns the earliest of the two.
The mutant returns the latest one. **A body holds any byte, so a body holds `\n\n` after a
header block that ends at `\r\n\r\n`.** `HTTPMessageIsComplete` measures the body from the
returned offset, and `ja4h.go` emits a JA4H value only for a complete request. So the mutant
moves a complete request to an incomplete one, and the JA4H value disappears.

**No test named `headerBlockTerminator` or `HTTPMessageIsComplete` before #92.** Both are
reached through the root package alone, which is why the sweep reported the mutation as LIVED.

**This is the one mutation of the 43 that moves a conformance figure.** The FoxIO corpus
separates it, and no assertion of this repository did.

**Each test fails against the mutation, measured on 2026-08-14.** Both pass against the tree.

**The comparison that S2 and E1 mutate no longer exists.** #298 replaced the two-literal loop
with a byte scan on 2026-08-15 UTC, and `headerBlockTerminator` now chooses the terminator.
It returns the first line ending that another line ending follows. **#298 declined a regular
expression on cost**, so no expression reaches this path. **This record states what the
sweep of 2026-08-14 measured, and it records no property of the tree today.** Both tests still pass, and each one still holds
the earliest-terminator behavior. A later sweep of `./internal/parser` writes a fresh report
and a fresh record.

### E1 — an equivalent mutation at the same position (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/http.go:95:80` | `CONDITIONALS_BOUNDARY` | `<` to `<=` |

**`\r\n\r\n` and `\n\n` cannot begin at one index, so `index < end` and `index <= end` choose
the same terminator.** The two comparisons differ only when `index` equals `end`. That input
needs one byte to be `\r` for one terminator and `\n` for the other.

### E2 — an equivalent mutation at the request line limit (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/http.go:177:12` | `CONDITIONALS_BOUNDARY` | `>` to `>=` |

**A slice of a string to its own length returns that string, so `IsHTTPRequest` reads the same
bytes under both comparisons.** The two differ only when `len(s)` equals `requestLineLimit`,
and `s[:requestLineLimit]` is then `s`.

### E3 — an equivalent mutation at the declared total length (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/icmp_quoted.go:85:105` | `CONDITIONALS_BOUNDARY` | `<` to `<=` |

**The mutant assigns `end` the value that `end` already holds, so the read continues from the
same offset.** The two differ only when `declared` equals `end`, and the branch then writes
`end = declared`.

### E4 — the four TIMED OUT mutations are non-terminating loops (#92)

| Position | Type | Rewrite |
|---|---|---|
| `internal/parser/ssh_tracker.go:317:15` | `CONDITIONALS_BOUNDARY` | `<` to `<=` |
| `internal/parser/ssh_tracker.go:318:18` | `CONDITIONALS_BOUNDARY` | `>` to `>=` |
| `internal/parser/ssh_tracker.go:318:18` | `CONDITIONALS_NEGATION` | `>` to `<=` |
| `internal/parser/x509_utils.go:64:10` | `CONDITIONALS_BOUNDARY` | `>` to `>=` |

**Each mutation removes the condition that ends a loop, so the suite detects it as a timeout
rather than as a failed assertion.** `vlqEncode` of `x509_utils.go` shifts `val` right by
seven until it reaches zero, and `val >= 0` never ends. `readMessages` of `ssh_tracker.go`
advances `position` through the payload, and each mutant leaves `position` where it is.

**No assertion improves on the timeout.** A test that reaches a non-terminating loop never
returns a value to assert against, so the `TIMED OUT` verdict is the detection.

**The counted table below holds these four as well**, and `## The settlements` above states
that overlap.

## The counted remainder

**41 mutations are counted, and no issue carries them.** The five-case filing policy of
`CLAUDE.md` reaches none of them, and the maintainer's ruling states that the count is the
record.

**A counted backlog is a measurement, and it is not a promise.**

| File | Counted |
|---|---|
| `internal/parser/quic.go` | 24 |
| `internal/parser/icmp_quoted.go` | 9 |
| `internal/parser/http.go` | 4 |
| `internal/parser/ssh_tracker.go` | 3 |
| `internal/parser/x509_utils.go` | 1 |
| **Total** | **41** |

| Mutation type | Counted |
|---|---|
| `CONDITIONALS_BOUNDARY` | 24 |
| `CONDITIONALS_NEGATION` | 9 |
| `ARITHMETIC_BASE` | 8 |
| **Total** | **41** |

| File | Mutation type | Counted |
|---|---|---|
| `internal/parser/http.go` | `CONDITIONALS_BOUNDARY` | 4 |
| `internal/parser/icmp_quoted.go` | `CONDITIONALS_BOUNDARY` | 2 |
| `internal/parser/icmp_quoted.go` | `CONDITIONALS_NEGATION` | 7 |
| `internal/parser/quic.go` | `ARITHMETIC_BASE` | 8 |
| `internal/parser/quic.go` | `CONDITIONALS_BOUNDARY` | 15 |
| `internal/parser/quic.go` | `CONDITIONALS_NEGATION` | 1 |
| `internal/parser/ssh_tracker.go` | `CONDITIONALS_BOUNDARY` | 2 |
| `internal/parser/ssh_tracker.go` | `CONDITIONALS_NEGATION` | 1 |
| `internal/parser/x509_utils.go` | `CONDITIONALS_BOUNDARY` | 1 |

**37 of the 41 carry the report verdict `LIVED`, and 4 carry `TIMED OUT`.**

### Why each group is counted

**The 24 of `quic.go` guard a bounds check.** `ParseQUICInitial` and
`DecryptQUICInitialCrypto` read a length field of an untrusted datagram, and each counted
mutation moves one bound of that read. Every one fails test 3. A datagram that separates the
original from the mutant is truncated. A truncated datagram yields no QUIC client hello, so
it yields no JA4 value. **A bounds check of this library is a safety requirement, and a
different gate owns it.** `CLAUDE.md` states that every packet is untrusted input, the fuzz
suite proves that no input panics, and `.coverage-floor` proves that a test reaches the line.

**The 7 `CONDITIONALS_NEGATION` mutations of `icmp_quoted.go` invert a TCP flag bit that no
fingerprinter reads on this path.** They are the `NS`, `FIN`, `RST`, `PSH`, `URG`, `ECE` and
`CWR` bits of `readQuotedTCPFields`. `### Test 2 reads the reader, and it does not read the
assignment` above states the measurement.

**The 2 `CONDITIONALS_BOUNDARY` mutations of `icmp_quoted.go` guard a malformed quoted
packet.** They sit at `icmp_quoted.go:71:17` and `icmp_quoted.go:90:57`, and each one
separates the original from the mutant on a quoted packet that carries no transport byte.
Each path returns no header under both comparisons, because a later guard declines the same
input.

**Three of the 4 of `http.go` need a header block that ends at offset zero, and one anchor
forbids that offset.** They sit at `internal/parser/http.go:95:54`,
`internal/parser/http.go:95:67` and `internal/parser/http.go:201:14`.

`requestLineRe` in `internal/parser/http.go` opens with `^`, so it matches a request line
at offset zero alone, and it needs at least one method character. `ParseHTTPRequest` returns
nil when that match fails, and `ProcessPacket` of `ja4h.go` reads a request that
`ParseHTTPRequest` returned.
**So every payload that reaches either reader begins with a method character, and no header
terminator begins at offset zero.** Each of the three mutations separates the original from
the mutant at that offset alone.

**One counts under test 3 for a different reason.** `internal/parser/http.go:235:44` reads the
`=` of a cookie pair. It separates the two only on a cookie name of zero length.
**RFC 6265 Section 4.1.1 states that a cookie name is a token.** A token holds at least one
character. So `=value` is a malformed cookie pair, and the wire format does not permit it.

**The 4 non-terminating loops are E4 above**, and they are counted as well as settled.

## What no measurement of this record covers

**The dependent-scope run applies one mutation at a time.** It measures no interaction
between two mutations.

**The conformance run reads 38 captures.** A mutation that moves a fingerprint on a capture
that the corpus does not hold reports `SAME`. **So a `SAME` result is evidence that the
corpus does not separate the mutation, and it is never proof that no input separates it.**
S1 is the worked example: the corpus reports `SAME` for both of its mutations, and a
hand-built packet separates each one.

**No sweep of this repository has run over every package.** The named set holds 1675
mutations, and four paths hold 1592 of them. `./internal/capture`, `./internal/keylog` and
`./internal/fuzzprop` hold the other 83, and no sweep has reached them.

**The four TIMED OUT mutations reached no conformance run**, because each one is a
non-terminating loop.

**The re-measurement ran without the race detector.** `gremlins` runs no race detector
either, so both runs read the same build.
