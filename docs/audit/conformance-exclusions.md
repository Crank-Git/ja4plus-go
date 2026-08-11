# The conformance exclusions

**The record holds no entry.** The maintainer has accepted none, and FR-gaps-6 requires an
acceptance on every entry.

`docs/specs/features/05-conformance-gaps.md` FR-gaps-5 names this file. The bar for
`v1.0.0` is a byte-identical match on every capture of the corpus. A deviation is closed,
or this file records why the closure is not possible.

**Only the maintainer accepts an entry.** `.claude/rules/rulings.md` gives the ruling to
the maintainer alone. An engineer records the reading and the evidence, opens an issue,
and stops. An engineer never writes an acceptance.

`conformance_exclusions_test.go` holds the shape of this file. An entry that omits a
column fails that test, so read `## The fields of an entry` before you add an entry.

**Never write a placeholder entry.** An entry that names no person and no date fails the
test, and it hides a deviation that the release gate must see. FR-release-44 of
`docs/specs/features/10-release.md` reads this file before the release.

## The boundary against the register

**This project holds two records, and they hold two distinct classes of fact.** The
maintainer ruled on 2026-08-11, in issue #38.

| Record | What it holds |
|---|---|
| `testdata/deviations.json`, the register | **A decline.** This project compared its output against a FoxIO value and chose to differ. |
| `docs/audit/conformance-exclusions.md`, this file | **An exclusion.** The suite makes no comparison at all. |

**One question settles which record a fact reaches.** Does the guard "an entry whose
comparison now matches fails the suite" make sense for this fact? **Yes, and it is a
register entry. No, and it is an exclusion.**

`.claude/rules/parity.md:71` states that guard. An exclusion reaches no comparison that
could later match, so the guard can evaluate nothing.

`dtls-udp.notest.cap` decides the boundary. FoxIO marks the capture `notest` and excludes
it from their own suite, so it yields no stream and no method. It reaches no
`<capture>/<stream>/<method>` register key. FR-gaps-19 records `not applicable` for it, and
FR-gaps-20 requires an entry here.

**This ruling is reversible.** A later reader reverses it with a new fact, and not with a
new opinion.

## The fields of an entry

The record table holds these five columns, in this order.

| Column | What it holds |
|---|---|
| `Key` | The capture that the suite makes no comparison for, in a code span. Where the exclusion reaches one stream, the key names the capture, the stream and the method, as `testdata/README.md` writes a register key. |
| `Reason` | The reason that the suite makes no comparison. |
| `Evidence` | The source that supports the reason, as a `file:line` reference or as an issue. |
| `Accepted by` | The name of the maintainer who accepted the entry. |
| `Date` | The acceptance date, written `YYYY-MM-DD`. |

**No column is empty, and no column states nothing.** The test declines the values `TBD`,
`TODO`, `pending`, `unknown`, `none`, `n/a` and `the maintainer`. The role names no person.
A later maintainer cannot reverse a ruling that names no person.

**A quotation is verbatim.** `.claude/rules/ste.md` bars a reworded quotation, because a
reworded quotation is no longer evidence. Reproduce a FoxIO value, an error message and a
source sentence exactly, in a code span.

**A cell holds no `|` character.** The test splits a table line on that character.

## The record

<!-- conformance-exclusions:begin -->

| Key | Reason | Evidence | Accepted by | Date |
|---|---|---|---|---|

<!-- conformance-exclusions:end -->

## To add an entry

`docs/specs/features/05-conformance-gaps.md` states this flow under
`### An engineer records an exclusion`. The steps below name the person who acts at each
one.

1. The engineer reads the deviation row in `docs/audit/conformance.md`.
2. The engineer applies the one question of `## The boundary against the register`.
3. The engineer establishes that the closure is not possible, and records the evidence.
4. The engineer opens an issue that states the question and every candidate answer.
5. The maintainer rules on the issue.
6. The maintainer adds the entry, with their name and the date.

**Step 6 belongs to the maintainer.** An entry that an engineer writes records no
acceptance, whatever the `Accepted by` column holds.

## To close a deviation

`.claude/skills/conformance/SKILL.md` holds the closure rule, under
`## To close a deviation`. It states FR-gaps-1, FR-gaps-2 and FR-gaps-3. Read it before
you change a fingerprint value.
