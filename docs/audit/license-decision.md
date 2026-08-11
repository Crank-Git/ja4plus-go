# The license decision

**This file transcribes a decision that the maintainer already made. It makes no
decision.** `docs/specs/spec.md` holds the decision, and the `## Changelog` table records
the round and the date of each part of it.

A ruling is the maintainer's alone. `.claude/rules/rulings.md` holds that rule.

## The decision

**The maintainer resolved risk R1 on 2026-08-06.** Row 2 of the `## Changelog` table in
`docs/specs/spec.md` records it. The row reads:

> | 2 | 2026-08-06 | The maintainer approved the spec and the scaffold. R1 resolved: the dual BSD 3-Clause and FoxIO `NOTICE` model is sufficient for `v1.0.0`. |

`docs/specs/features/01-licensing.md` § Open questions repeats the same resolution. The
dual model is sufficient for `v1.0.0`. The project does not contact FoxIO before the
release.

## The follow-up

**The maintainer resolved risk R6 on 2026-08-11.** Row 4 of the same table records it. The
row reads:

> | 4 | 2026-08-11 | The maintainer approved the spec and the scaffold. R6 resolved: the license correction waits for the full `v1.0.0`, and no `v0.4.0` ships first. Added R9, which holds the three rulings that neither FoxIO nor the port has made. The maintainer confirmed that all three need a ruling, and each one blocks its requirements until the ruling exists. |

The license correction ships in `v1.0.0`. No `v0.4.0` release carries it first.

## What the decision produces

The repository states two licenses, and it names which material each one covers.

- The original Go code carries the BSD 3-Clause license, and `LICENSE` holds that text.
- FoxIO licenses the JA4+ methods that this project implements, except JA4, under FoxIO
  License 1.1. That license permits non-commercial use only.
- `NOTICE` holds the FoxIO terms, and it names the commit at which this project read them.
- `data/README.md` names FoxIO as the source of `data/ja4plus-mapping.csv`.

**This project asserts no equality between its own method list and FoxIO's.** Three FoxIO
records at commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` name three different sets, and
`testdata/foxio.pin` holds that commit.

## A later decision

**Only the maintainer adds a decision to this file.** Each entry states the decision, the
date, and the source that records it. A grant of a commercial exception from FoxIO is one
such entry, and `NOTICE` then gains a paragraph.
