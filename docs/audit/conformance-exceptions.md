# The conformance exceptions

**The record holds no entry.** The maintainer has accepted none, and FR-gaps-6 requires an
acceptance on every entry.

`docs/specs/features/05-conformance-gaps.md` FR-gaps-5 names this file. The bar for
`v1.0.0` is a byte-identical match on every capture of the corpus. A deviation is closed,
or this file records why the closure is not possible.

**Only the maintainer accepts an entry.** `.claude/rules/rulings.md` gives the ruling to
the maintainer alone. An engineer records the reading and the evidence, opens an issue,
and stops. An engineer never writes an acceptance.

`conformance_exceptions_test.go` holds the shape of this file. A row that omits a column
fails that test, so read `## The fields of an entry` before you add a row.

**Never write a placeholder row.** An entry that names no person and no date fails the
test, and it hides a deviation that the release gate must see. FR-release-44 of
`docs/specs/features/10-release.md` reads this file before the release.

## The relation to the register

**This project holds two records of one class of fact, and the boundary between them is
open.** Issue #38 states the question and the candidate answers. The maintainer decides
it.

| Record | Path | Read by | Holds |
|---|---|---|---|
| The register | `testdata/deviations.json` | The conformance suite | Six fields, and no maintainer name and no date. |
| The exceptions | `docs/audit/conformance-exceptions.md` | A person, at the release gate | The reason, the evidence, the maintainer's name and the date. |

The `## Terms` table of `docs/specs/spec.md` defines the word `register` as
`testdata/deviations.json` alone. That table also bars the word `exception` as a synonym
for `deviation`.

**Add no entry to this file until the maintainer answers #38.** An entry written before
the answer may belong in the register instead, and a fact in two records drifts.

## The fields of an entry

The record table holds these five columns, in this order.

| Column | What it holds |
|---|---|
| `Key` | The capture that carries the deviation, in a code span. Where the deviation reaches one comparison, the key names the capture, the stream and the method, as `testdata/README.md` writes a register key. |
| `Reason` | The reason that the closure is not possible. |
| `Evidence` | The source that supports the reason, as a `file:line` reference or as an issue. |
| `Accepted by` | The name of the maintainer who accepted the entry. |
| `Date` | The acceptance date, written `YYYY-MM-DD`. |

**No column is empty, and no column states nothing.** The reader declines the values
`TBD`, `TODO`, `pending`, `unknown`, `none`, `n/a` and `the maintainer`. The role names no
person, and a reader who cannot name the acceptor cannot reverse the ruling.

**A quotation is verbatim.** `.claude/rules/ste.md` bars a reworded quotation, because a
reworded quotation is no longer evidence. Reproduce a FoxIO value, an error message and a
source sentence exactly, in a code span.

**A cell holds no `|` character.** The reader splits a row on that character.

## The record

<!-- conformance-exceptions:begin -->

| Key | Reason | Evidence | Accepted by | Date |
|---|---|---|---|---|

<!-- conformance-exceptions:end -->

## To add an entry

`docs/specs/features/05-conformance-gaps.md` states this flow under
`### An engineer records an exception`. The steps below name the person who acts at each
one.

1. The engineer reads the deviation row in `docs/audit/conformance.md`.
2. The engineer establishes that the closure is not possible, and records the evidence.
3. The engineer opens an issue that states the question and every candidate answer.
4. The maintainer rules on the issue.
5. The maintainer adds the row, with their name and the date.

**Step 5 belongs to the maintainer.** A row that an engineer writes records no acceptance,
whatever the `Accepted by` column holds.

## To close a deviation

`.claude/skills/conformance/SKILL.md` holds the closure rule, under
`## To close a deviation`. It states FR-gaps-1, FR-gaps-2 and FR-gaps-3. Read it before
you change a fingerprint value.
