---
id: foxio-reference
feature: FoxIO reference material
epic: "Epic 11: FoxIO reference material"
status: issued
issues: [14, 15, 16, 17, 18, 19]
mockups: []
---

## Purpose

Every ruling in this project cites a FoxIO source. **Today a reader cannot check one of
those citations without leaving the repository**, and the sources are mostly images. An
image cannot be quoted, cannot be searched, and cannot be read by an agent.

This feature set commits the material that the citations point at. It writes one
transcription per FoxIO image, it recovers the text specifications that FoxIO deleted, and
it records the reading of each reference implementation. It also builds the register file
that holds every accepted difference from a FoxIO value.

**The port did this work first, and its result is the model.** Its
`docs/specs/foxio/README.md` states the procedure and the inventory. This project follows
the same procedure, so a reader who knows one repository can read the other.

**This epic runs before Epic 8.** Epic 8 closes about twenty register rows, and each row
cites material that this epic writes.

## What the source material actually is

The port measured `technical_details/` at the pinned commit on 2026-08-08 and recorded
four facts. This project adopts the measurement and re-runs it against its own pin.

1. The directory holds twelve files: three text files and nine images.
2. **One method of twelve holds a complete text specification, and that method is JA4.**
   `JA4H.md` is 278 bytes and builds no fingerprint.
3. **Three methods reach no image of their own name: JA4LS, JA4TS and JA4TScan.**
   `JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so it specifies the schema of
   JA4TS. The image states no separate server rule, so it specifies no rule for the packet
   that JA4TS reads. `JA4L.png` titles itself
   `JA4L: Light Distance/Location Fingerprint` and states no server rule, so **no image
   specifies JA4LS**.
4. **FoxIO published a text specification for seven methods, and commit `b6f3ff4` deleted
   all seven.** Two exist again at the pinned commit. Five do not, and two of those five
   are the primary source for JA4TS part e and for the JA4TS RST value.

Fact 3 is why `features/12-ja4ls.md` reads the reference implementations rather than an
image. Fact 4 is why FR-reference-12 recovers the deleted text.

## User stories

- As an engineer, I want the rule I am building written as numbered prose, so that I can
  cite a line rather than describe a picture.
- As an engineer, I want to know which FoxIO sources disagree before I write code, so that
  I do not match one reference and break another.
- As a maintainer, I want every accepted difference in one machine-readable file, so that
  a closed deviation cannot sit unnoticed.
- As a reader, I want to check a ruling without cloning the FoxIO repository.

## Functional requirements

### The inventory

- **FR-reference-1** — `docs/specs/foxio/README.md` records the source URL, the pinned
  commit and the retrieval date.
- **FR-reference-2** — The page holds one row per file of `technical_details/`, with the
  byte count and the SHA-256 hash.
- **FR-reference-3** — The page states the one command that reproduces the measurement.
- **FR-reference-4** — The pinned commit equals the commit in `testdata/foxio.pin`.
- **FR-reference-5** — A test reads `testdata/foxio.pin` and the page, and fails when the
  two commits differ.

### The transcriptions

- **FR-reference-6** — `docs/specs/foxio/` holds one page per method that an image
  specifies.
- **FR-reference-7** — Each page numbers its rules `R1`, `R2` and onward.
- **FR-reference-8** — Each rule states one fact.
- **FR-reference-9** — Each rule that an image alone states says so.
- **FR-reference-10** — Each rule that a reference implementation corroborates names the
  implementation, the file and the line.
- **FR-reference-11** — Each rule that the reference implementations contradict is marked
  as a reference split, and the page states each value.
- **FR-reference-12** — `docs/specs/foxio/deleted-text-specifications.md` holds the text
  of the seven deleted files, read at the commit before `b6f3ff4`.
- **FR-reference-13** — That page states that a deleted text specification corroborates an
  image and never outranks it.
- **FR-reference-14** — `docs/specs/foxio/zeek.md` records the reading of the FoxIO Zeek
  package, and names each value it publishes that this project declines.
- **FR-reference-15** — Text copied from FoxIO material is verbatim. No page rewords a
  quotation.
- **FR-reference-16** — No page reproduces a FoxIO image. Each page links to it.

### The port's register copy

- **FR-reference-17** — `docs/specs/foxio/port-register.md` holds the port's `Parity with
  ja4plus-go` section, with the port commit and the retrieval date.
- **FR-reference-18** — The copy is verbatim.

### The citation base

`docs/specs/foxio/README.md` `## How to read a citation` declares seven bases. #254 wrote
that rule and repaired every citation against it. #335 holds the repair with a test,
because a citation that resolves under no base fails silently. A writer joins
`python/ja4.py` to `testdata/foxio/`. That directory exists, and the file does not.

- **FR-reference-18a** — Every path-shaped code span of a page of `docs/specs/foxio/`
  resolves under one of the seven declared bases.
- **FR-reference-18b** — A shape check holds every span on a checkout that ran no
  `make corpus`.
- **FR-reference-18c** — The shape check reads the first directory of the span.
- **FR-reference-18d** — The shape check opens no file of the corpus.
- **FR-reference-18e** — An exception names one page, one span, one count and one reason.
- **FR-reference-18f** — An exception that now resolves fails a test.
- **FR-reference-18g** — No exception covers a whole page.
- **FR-reference-18h** — No citation names a line past the end of the file it names.
- **FR-reference-18i** — The test names the two pages that state their own base.
- **FR-reference-18j** — The test states the reason for each of those two pages.
- **FR-reference-18k** — The recorded FoxIO root directories equal the root directories of
  the fetched corpus.
- **FR-reference-18l** — A test that the corpus gates states in its skip message that it
  read no corpus. **No test of this rule skips in silence.**

### The register file

- **FR-reference-19** — `testdata/deviations.json` exists and is tracked in git.
- **FR-reference-20** — Each entry holds `key`, `capability`, `ours`, `theirs`, `ruling`
  and `reason`.
- **FR-reference-21** — `key` names the capture, the stream and the method.
- **FR-reference-22** — `capability` is `true` for a capability decline and `false` for a
  value decline.
- **FR-reference-23** — `ruling` names the issue that holds the ruling.
- **FR-reference-24** — `reason` holds one sentence.
- **FR-reference-25** — The conformance suite reads the file and expects the named
  comparison to differ.
- **FR-reference-26** — **A comparison the register names that now matches fails the
  suite.**
- **FR-reference-27** — A test asserts that every `ruling` value names an issue that
  exists.
- **FR-reference-28** — A test asserts that the file parses and that every entry holds
  every field.
- **FR-reference-29** — The middle part of `key` holds one of three things.
    - The stream number, for a per-stream comparison.
    - The endpoint key, where no vector entry names the connection.
    - The frame number, for a per-packet comparison.
- **FR-reference-29a** — `testdata/README.md` states the three meanings.
- **FR-reference-30** — **One key names one comparison.** A test asserts that no key of the
  corpus names a comparison in the per-stream set and in the per-packet set.
- **FR-reference-31** — The register holds each key once. The reader declines a second
  entry for one key.

### The issue namespace

`.claude/rules/rulings.md` `## A citation names its repository` states the second citation
rule of this project. A bare `#N` names an issue of this repository, and a citation of an
issue of the port names the port. #255 wrote that rule, and no guard held it anywhere.
FR-reference-18a scopes the guard of #335 to one directory, so every citation outside
`docs/specs/foxio/` was unchecked. #351 builds the guard below, and it reads the whole tree.

The failure the rule prevents is a reader who follows one number into the wrong repository.
`#127` names the JA4L part count here, and it names the JA4 ALPN value in the port. The
cross-member review of batch #342 found that breach inside the batch that wrote the rule.

- **FR-reference-32** — A bare `#N` of a file the guard reads names an issue of this
  repository. **No test bounds that number**, and FR-reference-35 below states why.
- **FR-reference-33** — A citation of an issue of the port carries one of the recorded
  forms.
- **FR-reference-34** — A shape that names the port beside a bare number fails a test. **One
  test case holds each recorded form, and one holds each malformed shape.**
- **FR-reference-38** — The guard reads no tracker. **A guard that reads a tracker fails
  when the network fails**, and it then reports a defect that the tree does not hold.
- **FR-reference-38a** — The guard holds no high-water mark. A test reads the source of the
  guard, and it fails when a later change restores one.
- **FR-reference-40** — The guard reads every file of the tree whose extension the test
  records.
- **FR-reference-41** — The guard enters neither the corpus directory nor a linked worktree.
- **FR-reference-42** — No test of the guard skips.
- **FR-reference-43** — An exclusion names one file and one reason.
- **FR-reference-44** — `docs/specs/foxio/port-register.md` is excluded, because it is a
  verbatim copy of a section of the port's specification.

#### The withdrawn requirements, and the measurement that withdrew them

**#759 withdrew FR-reference-35, FR-reference-36, FR-reference-37, FR-reference-39 and
FR-reference-45 through FR-reference-53 on 2026-08-16 UTC.** Each one specified the
high-water mark, or the reader that the mark bounded. **No number of the list is reused**, so
a reader who meets one of them in an older document finds it here.

| Withdrawn | What it specified |
|---|---|
| FR-reference-35, FR-reference-36, FR-reference-37, FR-reference-39 | The high-water mark, its record and its one-directional reading. |
| FR-reference-45, FR-reference-53 | The `Ruling` column exclusion, and the wrapped row that hid a cell from it. |
| FR-reference-46, FR-reference-47, FR-reference-48, FR-reference-49 | The shape that the bare-number reader declined. |
| FR-reference-50, FR-reference-51, FR-reference-52 | The exception table of a bare number above the mark. |

Three measurements withdrew them, each taken on 2026-08-16 UTC.

1. **The mark made `issue_citation_namespace_test.go` the second most-edited file of this
   repository.** It sits in 43 of the last 300 commits of `dev`, ahead of `CHANGELOG.md`.
2. **The tracker allocates numbers without a gap.** It reported 760 issues and pull requests
   together, and 760 as the highest number. So a bound reports a number above the highest
   allocated number alone.
3. **The mark reported no typo in its whole life.** Its comment recorded about 35 reports,
   and every one named a number that the tracker allocated minutes later. **The measured
   precision of the bound is zero.**

**A typo now reaches the tree, and FR-reference-32 accepts that cost.** A number that names
the wrong issue of this repository sits inside the allocated range, so no bound reported it
and no bound could. **A citation that names the wrong repository is the expensive failure**,
and FR-reference-34 still reports it.

**#759 is the reversal path.** A change that restores a bound states which typo the bound
caught.

## User flows

### An engineer writes a transcription

1. The engineer opens the FoxIO image at the pinned commit.
2. The engineer writes one numbered rule per fact the image states.
3. The engineer reads each FoxIO implementation for the same rule.
4. The engineer records agreement as corroboration, and disagreement as a reference split.
5. The engineer commits the page. **The page decides no value**; it records what each
   source states.

### An engineer records a decline

1. The conformance suite reports a deviation.
2. The engineer reads the transcription for the method.
3. If the reference is unanimous, the engineer changes the code. The register gains
   nothing.
4. If the references split, or the reference holds a proven defect, the engineer opens an
   issue for the maintainer to rule on.
5. The maintainer rules. The engineer adds one register entry that names the issue.

## Screens & states

This feature set changes no screen.

## Behaviour rules

- **A transcription records, and never decides.** A page states what each source holds. A
  ruling lives in an issue and in the register.
- **An image outranks a deleted text file.** The deleted file corroborates.
- **A Zeek baseline is not a reference value for every method.** `docs/specs/foxio/
  zeek.md` names the exceptions, and the JA4L and JA4LS values are among them.
- **A quotation is verbatim.** `.claude/rules/ste.md` bars a rewording of copied text,
  because a reworded quotation is no longer evidence.
- **A register entry is an accepted difference, not a hidden failure.** An entry that
  stops differing is a defect in the register.
- **A register key names one comparison, and the middle part of it names one thing.** The
  per-stream set writes the stream number there, and the per-packet set writes the frame
  number. Both are small integers, so a reader cannot tell them apart. FR-reference-30 keeps
  the two key spaces separate, because one register serves both sets.

## Data touched

| File | Change |
|---|---|
| `docs/specs/foxio/README.md` | New. The inventory and the procedure. |
| `docs/specs/foxio/JA4.md` and one page per image method | New. |
| `docs/specs/foxio/deleted-text-specifications.md` | New. |
| `docs/specs/foxio/zeek.md` | New. |
| `docs/specs/foxio/port-register.md` | New. |
| `testdata/deviations.json` | New. Tracked. |
| `testdata/README.md` | States the schema and the two meanings of the middle key part. |
| `conformance_test.go` | Reads the register. |
| `conformance_key_kind_test.go` | New. Holds FR-reference-30. |
| `foxio_citation_base_test.go` | New. Holds FR-reference-18a through FR-reference-18l. |
| `issue_citation_namespace_test.go` | Holds FR-reference-32 through FR-reference-34, and FR-reference-38 through FR-reference-44. |
| `mkdocs.yml` | `docs/specs/` is excluded from the site. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| FoxIO `technical_details/` | The commit in `testdata/foxio.pin` | <https://github.com/FoxIO-LLC/ja4/tree/main/technical_details> |
| FoxIO Python reference | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/python> |
| FoxIO Rust reference | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/rust> |
| FoxIO Wireshark dissector | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/wireshark> |
| FoxIO Zeek package | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/zeek> |
| The port's register | `v1.1.0`, read 2026-08-11 | <https://github.com/Crank-Git/ja4plus/blob/dev/docs/specs/spec.md> |

**The deleted text files are read at a commit before `b6f3ff4`.** That commit is not the
pin. FR-reference-12 records the commit it read, and the two commits differ on purpose.

## Edge cases & failures

| Case | Expected behavior |
|---|---|
| FoxIO moves the pin and an image changes. | FR-reference-5 fails. The engineer re-reads the image and re-measures the hash before moving the pin. |
| A rule appears in no image and in no deleted file. | The page records the gap and names the implementations that state the rule. `JA4SSH.md` R11 is such a rule in the port. |
| Two FoxIO implementations disagree and no vector separates them. | The page marks a reference split. A test builds the separating packet, because the corpus cannot. |
| The register names a capture the corpus does not hold. | The test that FR-reference-28 adds fails. |
| One key names a per-stream comparison and a per-packet comparison. | The test that FR-reference-30 adds fails, and it names the key. |
| Two entries hold one key. | The reader declines the register, and the test that FR-reference-31 adds fails. |
| A FoxIO image is unreadable at the pin. | The transcription stops, and the gap goes to `Risks & open questions` in the spec. |

## Acceptance criteria

1. `docs/specs/foxio/README.md` exists and its pinned commit equals `testdata/foxio.pin`.
2. Every method that an image specifies holds a transcription with numbered rules.
3. `docs/specs/foxio/deleted-text-specifications.md` holds the seven deleted files and
   names the commit it read them at.
4. `docs/specs/foxio/zeek.md` names every Zeek value this project declines to treat as a
   reference value.
5. `testdata/deviations.json` parses, and every entry holds every field.
6. The conformance suite reads the register, and a register entry that now matches fails
   the suite.
7. `docs/specs/foxio/port-register.md` is verbatim and names the port commit.
8. `mkdocs build --strict` succeeds with `docs/specs/` excluded.

## Out of scope

- Ruling on any value. This feature set records sources. `features/08-python-parity.md`
  and `features/05-conformance-gaps.md` close the rows.
- Reproducing a FoxIO image. The pages link to the images and copy no binary.
- Committing the corpus. It stays fetched, under `.claude/rules/external-apis.md`.
- A transcription of JA4TScan. FoxIO publishes no material for it.

## Open questions

1. **Is a verbatim copy of the deleted text specifications a redistribution that the FoxIO
   license governs?** The text is FoxIO-authored and it is deleted from the current tree.
   `features/01-licensing.md` decides whether the copy carries the FoxIO notice, or whether
   the page quotes the rules it needs and links to the historical commit.
2. **Does `docs/specs/foxio/` belong under `docs/`, where MkDocs would otherwise publish
   it?** FR-reference-28 excludes it from the site. The alternative is a directory outside
   `docs/`, which breaks the symmetry with the port.
