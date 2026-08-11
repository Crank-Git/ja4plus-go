---
id: licensing
feature: License compliance
epic: "Epic 1: License compliance"
status: planned
issues: []
mockups: []
---

## Purpose

The repository states the wrong license, and it states it in a file that does not exist.
This feature set makes every license statement in the repository true.

FoxIO publishes JA4+ under two licenses. `LICENSE-JA4` covers JA4 alone, the TLS client
method, under BSD 3-Clause. `LICENSE` is FoxIO License 1.1, and it names "JA4S, JA4H,
JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4TScan, JA4D, JA4D6, JA4SScan, JA4E, and JA4SSH
(Collectively referred to as JA4+)". FoxIO License 1.1 permits non-commercial use only.

This library implements JA4 plus nine of the FoxIO-licensed methods. The README shows a
BSD 3-Clause badge that links to `LICENSE`, and the repository has no `LICENSE` file.
The repository also embeds `data/ja4plus-mapping.csv`, which is FoxIO's file.

The FoxIO licensing FAQ states the rule for a permissive combination directly: "the
FoxIO license _must_ be included and noted, either in the LICENSE file itself or in a
NOTICE file." The FAQ names `driftnet-io/go-ja4x` as a good example of the pattern.

This spec is not legal advice. It records what the FoxIO documents say and implements the
model that FoxIO recommends.

## User stories

- As a library author, I want to know which parts of this library I may use commercially,
  so that I do not create a compliance problem for my employer.
- As a maintainer, I want the license files to be correct, so that distributing the
  library carries no risk that I have not accepted.
- As FoxIO, I want my license terms carried with my methods, so that my terms reach the
  people who use them.

## Functional requirements

- **FR-licensing-1** — The repository holds a `LICENSE` file at the root.
- **FR-licensing-2** — `LICENSE` holds the BSD 3-Clause text and names the copyright
  holder for the original Go code.
- **FR-licensing-3** — The repository holds a `NOTICE` file at the root.
- **FR-licensing-4** — `NOTICE` reproduces the full text of FoxIO License 1.1.
- **FR-licensing-5** — `NOTICE` names the ten methods in this library that FoxIO License
  1.1 covers: JA4S, JA4H, JA4T, JA4TS, JA4L, JA4LS, JA4X, JA4SSH, JA4D and JA4D6.
  **JA4LS joins the list when `features/12-ja4ls.md` lands**, and Epic 12 makes that edit.
  Until then `NOTICE` names nine, and it names no method the library does not implement.
- **FR-licensing-5a** — `NOTICE` states that this list is the set of methods this library
  implements under the license. **It asserts no equality with FoxIO's own list.** Three
  FoxIO records at the pinned commit name three different sets: `License FAQ.md:5` names
  twelve methods, the FoxIO `README.md:293` names nine, and `LICENSE:3` names thirteen and
  spells the scanner `JA4SScan`.
- **FR-licensing-6** — `NOTICE` states that JA4 is covered by BSD 3-Clause under
  `LICENSE-JA4` at FoxIO.
- **FR-licensing-7** — `NOTICE` states that `data/ja4plus-mapping.csv` comes from FoxIO
  and carries FoxIO License 1.1.
- **FR-licensing-8** — `NOTICE` links to
  <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>.
- **FR-licensing-9** — `NOTICE` states that FoxIO License 1.1 permits non-commercial use
  only.
- **FR-licensing-10** — The README holds a License section that states the split in three
  sentences or fewer.
- **FR-licensing-11** — The README license badge links to `LICENSE`, and the target file
  exists.
- **FR-licensing-12** — The README states that a commercial user must contact FoxIO for
  the JA4+ methods.
- **FR-licensing-13** — The package documentation in `doc.go` states the license split.
- **FR-licensing-14** — `data/ja4plus-mapping.csv` carries a header comment that names
  FoxIO as the source, or an adjacent `data/README.md` states it.
- **FR-licensing-15** — `CHANGELOG.md` records the license correction as a change in the
  release that carries it.

## User flows

### A developer checks whether they may use the library

1. The developer opens the repository.
2. The developer reads the README License section.
3. The section states that the original Go code is BSD 3-Clause.
4. The section states that the nine JA4+ methods carry FoxIO License 1.1.
5. The section states that FoxIO License 1.1 permits non-commercial use only.
6. The section links to `NOTICE` and to the FoxIO license.
7. The developer knows whether to contact FoxIO.

### A maintainer records the license decision

1. The maintainer reads `NOTICE`.
2. The maintainer decides whether to seek written guidance from FoxIO.
3. The maintainer records the decision in `docs/audit/license-decision.md`.
4. Epic 10 reads that record before it releases.

## Screens & states

The project has no user interface. This section does not apply.

## Behaviour rules

- `NOTICE` reproduces the FoxIO text without a change. The text is verbatim evidence.
- `LICENSE` covers the original Go code only. It does not claim to cover the methods.
- No file states that the whole library is BSD 3-Clause.
- The README states the facts. It gives no legal advice and no opinion.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `LICENSE` | New. BSD 3-Clause for the original Go code. |
| `NOTICE` | New. FoxIO License 1.1 text and the method list. |
| `README.md` | The License section is rewritten. The badge target is corrected. |
| `doc.go` | New or changed. The package documentation states the split. |
| `data/README.md` | New. Names FoxIO as the source of the mapping file. |
| `CHANGELOG.md` | One entry. |
| `docs/audit/license-decision.md` | New. Records the maintainer's decision. |

## Interfaces

This feature set reads three external documents. Each is read at FoxIO commit `27f0cbf`,
dated 2026-08-06.

| Document | What it decides | URL |
|---|---|---|
| FoxIO License 1.1 | The terms for the nine JA4+ methods and for the mapping file. | <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE> |
| `LICENSE-JA4` | The terms for JA4 alone. | <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4> |
| FoxIO Licensing FAQ | The rule for combining JA4+ with a permissive license. | <https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md> |

The reference implementation of the pattern is
<https://github.com/driftnet-io/go-ja4x>, which the FAQ names.

## Edge cases & failures

| Case | What happens |
|---|---|
| FoxIO changes the license after this work lands. | `NOTICE` records the commit at which it was read. A later change produces a new issue. |
| A consumer asks whether they may sell a product built on this library. | The README points them to FoxIO. The project gives no answer of its own. |
| FoxIO grants a commercial exception to this project. | The maintainer records it in `docs/audit/license-decision.md` and `NOTICE` gains a paragraph. |
| The maintainer decides to relicense the whole repository under FoxIO License 1.1. | That is a different requirement set. This feature set does not do it. |

## Acceptance criteria

- [ ] `LICENSE` exists at the repository root and holds the BSD 3-Clause text.
- [ ] `NOTICE` exists at the repository root.
- [ ] `NOTICE` holds the FoxIO License 1.1 text without a change.
- [ ] `NOTICE` names JA4S, JA4H, JA4T, JA4TS, JA4L, JA4X, JA4SSH, JA4D and JA4D6.
- [ ] `NOTICE` names `data/ja4plus-mapping.csv` as FoxIO material.
- [ ] `NOTICE` states that FoxIO License 1.1 permits non-commercial use only.
- [ ] The README License section names both licenses and which methods each covers.
- [ ] The README license badge links to a file that exists.
- [ ] `go doc github.com/Crank-Git/ja4plus-go` prints the license split.
- [ ] No file in the repository states that the JA4+ methods are BSD 3-Clause.
- [ ] `docs/audit/license-decision.md` records the maintainer's decision and its date.

## Out of scope

- This feature set does not seek a commercial license from FoxIO.
- This feature set does not split the module into separately licensed packages.
- This feature set does not change `Crank-Git/ja4plus`, the Python port, which carries
  the same gap. Risk R4 in `../spec.md` records that finding.
- This feature set does not add a `SECURITY.md`.

## Open questions

None. The maintainer resolved risk R1 in `../spec.md` on 2026-08-06. The dual model is
sufficient for `v1.0.0`, and the project does not contact FoxIO before the release.
FR-licensing-15 and the `docs/audit/license-decision.md` record carry that decision to
the Epic 10 release gate.
