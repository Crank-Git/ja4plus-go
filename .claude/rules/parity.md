# Parity with the Python port

The port is `Crank-Git/ja4plus`, at version `v1.1.0`. A user who runs both implementations
must get one answer. **Read this file before you change a fingerprint value or an exported
name.**

The register lives in the `## Parity with ja4plus` section of `docs/specs/spec.md`.
`docs/specs/features/08-python-parity.md` numbers each row as a requirement.

## The three rules

These are the port's own rules. This project adopted them without a change, so one rule
set governs both repositories.

1. **FoxIO decides behavior.** Where FoxIO specifies the output, the vectors decide. This
   rule outranks the port. Where this project disagrees with a vector, this project is
   wrong.
2. **The port decides interface where this project shipped nothing.** Where FoxIO
   specifies nothing, and where this project has no exported name for the behavior, adopt
   the port's choice. **Where this project shipped a name first, the rule runs the other
   way and the port adopted it.** The register records which side each row followed.
3. **The gate is the shared vector set.** Both repositories read the same FoxIO vectors at
   the same pinned commit. Two implementations that each match the reference match each
   other.

## Each repository writes its own controlled vocabulary

**No term of this project has to match a term of the port.** #758 dropped that requirement
on 2026-08-16 UTC, and the `## Terms` table of `docs/specs/spec.md` is now the vocabulary of
this project alone.

**What replaced it: rule 3 above, and the verbatim rule.** The shared vector set is the
gate, and it reads no word of either specification. A value that FoxIO publishes stays
verbatim in both repositories under `.claude/rules/ste.md`
`## What is verbatim, and never rewritten`. So two implementations still produce one answer,
and neither one spends a change on the other's word.

**The measurement that earned the drop.** One word cost five issues and closed no defect.
#356 adopted `one-shot function`, #379 added the Terms row, #397 repaired a note of
`README.md`, #399 found eleven remaining places, and #403 found a block of `README.md` that
listed seven of ten. The same practice produced the citation namespace collision that #254,
#255 and #351 record.

**What the drop does not reach.** A ruling still lands in this repository and in the port
together, or in neither. An exported name still follows rule 2 above. A term that names a
FoxIO value still reads the FoxIO material, and never a word this project prefers.

## Never run the port from a test

**No test in this repository builds, imports or executes Python.** A cross-language test
rig couples two repositories that move at different speeds. It fails for reasons that have
nothing to do with the change under test.

An earlier draft of this project specified such a rig. The port rejected the design, and
round 3 of the spec deleted the seven requirements that held it.

## Where a difference comes from

Read the difference before you close it. The three kinds need three different actions.

| Kind | What it looks like | What to do |
|---|---|---|
| The reference is unanimous and this project differs. | Every FoxIO implementation agrees. | Change the code. The register gains nothing. |
| The FoxIO implementations disagree. | A reference split. | **Stop.** Rule 1 settles nothing. The maintainer rules. |
| The reference holds a proven defect. | A value that describes the capture and not the connection, or a value the published schema forbids. | **Stop.** The maintainer rules, and the register records a decline. |

## A ruling is a person's choice, and a reading is a conclusion about a source

- A **reading** concludes what a source states. It cites a file and a line. An engineer
  writes one.
- A **ruling** decides a question that no source settles. **Only the maintainer makes
  one.**

**A ruling lands in this repository and in the port together, or in neither.** A ruling
made on one side alone produces exactly the disagreement that parity exists to prevent.

When you reach a question no ruling covers:

1. Record the reading, with the evidence.
2. Open an issue here that states the question and every candidate answer.
3. Open an issue in `Crank-Git/ja4plus` that states the same question.
4. Stop. Build nothing that depends on the answer.

`docs/specs/spec.md` R9 holds the three questions that are open today. Two of them block
requirements, and one of them expires at the API freeze.

## Every ruling carries a register entry or a test

- A ruling that a vector reaches carries an entry in `testdata/deviations.json`.
- A ruling that no vector separates carries a test that builds the separating packet.
- A test that holds a ruling names the port issue in a comment, so a reader who reverses
  it knows where the other half lives.
- **A register entry whose comparison now matches fails the conformance suite.** A closed
  deviation cannot sit in the file unnoticed.

## Record the measurement in the pull request

A change that moves a fingerprint states four things.

1. How many values moved.
2. On which captures.
3. The conformance count before and after.
4. The register key count before and after.

**A row that moves no fingerprint says so.** Several register rows record a property
rather than a change, and a reader must be able to tell the two apart.

## Reversibility

Every ruling in the register is reversible. None of them is a permanent commitment, and
none of them needs re-litigating without a new fact. **Re-measure a ruling only when a Go
fact contradicts it.** Each one already carries a measurement in a closed port issue.
