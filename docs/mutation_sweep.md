# The mutation sweep

Coverage measures which lines a test runs. It does not measure whether a test fails when a
line is wrong. A fingerprinter holds high coverage and still passes every test after a
changed operator in the code that builds the fingerprint.

**A mutation sweep measures the second property.** It changes one expression, it runs the
suite, and it records whether a test failed. **A mutation that survives names a test that
runs a line and asserts nothing about it.**

This page states how the project runs the sweep, how to read the report, and how an
engineer settles a mutation that survives.

## The tool and the run

The project runs `gremlins`. `make mutate` runs the sweep, and it installs the pinned
version first. `GREMLINS_VERSION` in the `Makefile` holds the pin, and `.gremlins.yaml`
holds the configuration.

| Command | What it sweeps |
|---|---|
| `make mutate` | Every package of the module, except `cmd/ja4plus` and `examples/`. |
| `make mutate PKG=./internal/parser` | One path. |

**One sweep of the whole set takes about 20 minutes on a 10-core machine.** That figure is an
extrapolation from four measured paths, and it is not a measurement. Sweep one path while you
work, and sweep the set on the schedule.

**The sweep gates nothing.** It runs on a schedule, it never runs on a pull request, and it
blocks no merge.

## The verdicts

| Verdict | What it means | What it asks for |
|---|---|---|
| `KILLED` | A test failed, so the suite catches the change. | Nothing. |
| `LIVED` | Every test passed, so no test asserts on the change. | A settlement. |
| `TIMED OUT` | The suite did not finish. | A settlement, as for `LIVED`. |
| `NOT COVERED` | No test reaches the line, so the tool ran nothing. | Nothing here. The coverage floor owns that gap. |
| `NOT VIABLE` | The mutated package did not compile. | Nothing. |

**Count a verdict from the `status` field of each mutation, and never from the
`mutants_total` field of the JSON.** `fileReport` of `gremlins` sets `mutants_total` to the
sum of lived, killed and not viable, so it misses every `TIMED OUT` and `NOT COVERED`
mutation. It reported 716 for the `internal/parser` sweep of 2026-08-14, where the true total
is 882. #91 measured that gap.

## Read a verdict at its true scope

**`gremlins` runs the tests of the package that holds the mutation, and it runs no other
package.** The documentation states it, at
<https://gremlins.dev/latest/usage/commands/unleash/>, retrieved 2026-08-14:

> In _normal mode_, Gremlins executes only the tests of the packages where the mutant is found. This is done to optimize the performance, running less test cases for each mutation.

**So `LIVED` states that no test of the mutated package kills the mutation. It never states
that no test of this repository kills it.** That distinction decides most of the settlement
work of this project, because `internal/parser` decodes a packet and the root package asserts
the fingerprint value.

**Three scopes produce three counts, and each one answers a different question.**

| Scope | What it runs | The `internal/parser` sweep of 2026-08-14 |
|---|---|---|
| The package | The tests of the mutated package. This is the report. | 223 `LIVED`, and 4 `TIMED OUT`. |
| The dependent set | Every package that imports the mutated package. | 43 survive. **180 of the 223 die here.** |
| The conformance suite | The 38 FoxIO captures, behind the `conformance` build tag. | 1 of the 43 moves a figure. |

### The dependent scope

**Re-measure a surviving mutation against every package that imports the mutated one, before
you settle it.** Apply the mutation by hand, and run those packages:

```
go test -count=1 . ./internal/parser ./cmd/ja4plus
```

**`go list -test -deps` names the packages that import the mutated one.** Read that list
rather than a list of file names, because a package that names `internal/parser` in a comment
imports nothing.

A mutation that this run kills needs no assertion. The suite already holds the behavior, and
the report calls it `LIVED` because the assertion lives in another package.

### The conformance scope

**The conformance suite reaches neither the sweep nor the dependent-scope run.** It sits
behind the `conformance` build tag, `.gremlins.yaml` sets no `tags` key, and a plain
`go test` builds no file of that tag.

**The suite compares 38 FoxIO captures against the reference, so it is the one check that
reads a fingerprint value directly.** Run it against a mutation that the dependent scope does
not kill:

```
go test -tags conformance -count=1 .
```

**The suite fails at base, under the known Epic #441 backlog, so its exit code decides
nothing.** Read the eight reported figures instead, and compare them against the base run. A
mutation that moves one figure moves a fingerprint value on a FoxIO capture.

**A result that moves no figure is evidence, and it is never proof.** The corpus holds 38
captures, so it separates no mutation that needs an input the corpus does not carry.

**`--integration` runs the whole suite for each mutation, and this project does not set it.**
It multiplies the run by the suite cost. A change of that mode is the maintainer's.

## A duplicate row is one mutant

**`ARITHMETIC_BASE` and `INVERT_NEGATIVES` both rewrite `-` to `+`.** On a binary minus the
two report one position and one rewrite, so the report holds two rows for one mutant. The
`internal/parser` sweep of 2026-08-14 holds seven such pairs, so its 227 surviving rows hold
220 distinct mutants.

Count the rows when you read the report. Count the mutants when you size the work.

## Which mutations the project settles

**The maintainer ruled the scope on 2026-08-14, in issue #92.** The ruling amends
FR-mutation-11 of `docs/specs/features/15-mutation-sweep.md`, and issue #634 carries the
amendment.

> **A LIVED mutation on code that can move a fingerprint value is settled. Every other LIVED mutation is counted and recorded.**

**The reason is reviewability.** One package of this project holds 227 surviving rows. A
worker that writes `equivalent mutation` 227 times produces a record nobody can check, and a
rubber stamp hides the weak test that the sweep exists to find.

### The rule, in three tests

Apply these in order to each surviving mutation. **The rule reads the mutated expression, and
it reads no list of file names**, so it applies to a package that no sweep has reached yet.

**Test 1 — the scope test.** Apply the mutation and run every package that imports the mutated
package. If a test fails, record the mutation as killed at the wider scope. It needs no
settlement, and the suite already holds the behavior.

**Test 2 — the value test.** Ask whether the mutated expression computes a byte, an index, a
count or an order that a fingerprint carries. **A value expression** computes part of the
answer. **A guard expression** decides whether the parse continues. Mutate a value expression
and a well-formed packet yields a different fingerprint. Settle it.

**Test 3 — the well-formed input test.** A guard expression separates the original from the
mutant only on an input that sits on the boundary. Ask whether a packet that the wire format
permits reaches that boundary and yields a fingerprint. If only a truncated or malformed
packet separates the two, count the mutation and settle nothing.

**A mutation that fails test 2 and test 3 is counted, and never dismissed.** The count is the
record, and `docs/mutation_settlements/` holds it.

### Test 2 follows the reader, and it does not read the assignment

**A field that no fingerprinter reads carries no fingerprint value.** Follow the mutated
value to the fingerprinter that reads it, and never stop at the struct field that holds it.

`readQuotedTCPFields` of `icmp_quoted.go` is the measured case. It assigns nine TCP flag
bits, and `ja4t.go` reads two of them. The sweep of 2026-08-14 reported a surviving mutation
for each of the seven bits that no caller reads, and it reported none for the two that JA4T
reads. **The suite killed exactly the two bits that reach a fingerprint value.**

### Why a bounds check is counted and not settled

**A bounds check of this library is a safety requirement, and a different gate owns it.**
`CLAUDE.md` states that every packet is untrusted input and that every length field is
bounds-checked before a slice. **The fuzz suite proves that no input panics**, and
`.coverage-floor` proves that a test reaches the line. Neither property is a fingerprint
value, so the mutation sweep is the wrong instrument for it.

A settlement that added an assertion there would assert the error path of a malformed packet,
which the fuzz targets already reach with far more inputs than one assertion holds.

### A non-terminating loop mutation

**A mutation that removes the condition that ends a loop reports `TIMED OUT`, and the timeout
is the detection.** A test that reaches such a loop returns no value to assert against, so no
assertion improves on the verdict. Record the reading, and count the mutation.

## The settlement procedure

1. Run `make mutate PKG=<path>`. The sweep writes a report to `docs/mutation_reports/`.
2. Read each row whose verdict is `LIVED` or `TIMED OUT`.
3. Run the scope test above. Record every mutation the wider scope kills.
4. Run the conformance scope against each mutation that survives step 3.
5. Apply the value test and the well-formed input test to each mutation that survives.
6. For a mutation that reaches a fingerprint value, read the test that covers the line.
7. Add the assertion that the test lacks. **Run the test against the mutation first, and
   confirm that it fails.** An assertion that passes against the mutation settles nothing.
8. Write the settlement in `docs/mutation_settlements/`. Name the mutation, name the issue,
   and name the assertion.
9. Count every remaining mutation, by file and by mutation type, in the same record.

**Never weaken a test to kill a mutation.** A mutation that a weakened test kills is worse
than one that survives, because the report then reads green over a test that asserts less than
it did. **A settlement adds an assertion to a test. It changes no line of the library.**

**An equivalence claim states its reason in one sentence.** Write the reason that a reader can
check against the code, and never the claim alone.

**Never stream a sweep to the terminal.** A sweep prints one line for each mutation, so it
writes tens of thousands of lines. Redirect the output to a file, read the file, and report
the counts.

## Where the records live

| Record | Path | The site |
|---|---|---|
| The report | `docs/mutation_reports/` | Excluded. One report holds one row for each mutation, and the set grows with each sweep. |
| The settlements | `docs/mutation_settlements/` | Excluded. A settlement is a recorded decision, and `docs/audit/` is the precedent. |
| This page | `docs/mutation_sweep.md` | Published. |

**Each record is tracked in git**, and this page names each path in a code span rather than in
a link. A link from a published page into an excluded directory resolves in the repository and
breaks on the site.
`TestNoPublishedPageLinksIntoAnExcludedDirectory` in `mkdocs_config_test.go` holds that rule.

Read a record in the repository, at
<https://github.com/Crank-Git/ja4plus-go/tree/dev/docs>.
