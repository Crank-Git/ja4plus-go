---
paths:
  - "*.md"
  - "docs/**/*.md"
  - ".claude/rules/*.md"
  - "**/*.go"
---

# Writing standard (STE)

Every spec file, issue body, pull-request description, manual page and **code comment** in
this project uses Simplified Technical English. A requirement that reads two ways gets
built two ways.

The project's controlled vocabulary is the `## Terms` table in `docs/specs/spec.md`. Read
it before you write a domain word. When you need a word that the table does not hold, add
it to the table.

## This project writes US English

**The maintainer decided the English question on 2026-08-13.** Comment 5286085774 of #439
holds the decision, and it states the rule:

> **This project writes US English, and the documentation round converts incrementally.**

Write `behavior`, and never `behaviour`. Write `license` for the noun and for the verb.
Write the `-ize` form where both forms exist.

**The round of a batch converts each file that the batch already touches, and no other
file.** The maintainer declined a repository-wide sweep, because a sweep edits a file that
a live batch member also edits. **Issue #388 asked for the sweep, and the maintainer closed
it on 2026-08-13.** So no issue holds the remaining files, and each round takes the files it
opens. **35 tracked files hold a British spelling**, measured on 2026-08-13 at commit
`6681d3e`.

**A verbatim quotation keeps the spelling of its source.** `## What is verbatim, and never
rewritten` below binds a quotation, an error message and a sentence copied from a
specification. A conversion of one of them destroys the evidence.

**A section heading that the spec template shares stays until one change converts every
file that carries it.** `## Behaviour rules` is that heading, and 17 tracked files carry it
as a heading, measured on 2026-08-13 at commit `b178cfd`. **The 17 are the feature files of
`docs/specs/features/`.** One file cites the heading of another file, so a partial
conversion breaks a citation. **A round converts the prose of a file it opens, and it leaves
that heading.**

**The count above names the heading form, and it never names the string form.** The two
forms reach two numbers, and a reader who measures the wrong one reads a disagreement that
does not exist.

| Form | Command | Files at `b178cfd` |
|---|---|---|
| The heading | `git grep -l -E '^## Behaviour rules'` | 17 |
| The string | `git grep -l -F '## Behaviour rules'` | 19 |

**Two files hold the string in a code span and not as a heading**, which is the whole
difference. They are this file and `docs/specs/spec.md`. **The rule binds a heading, so the
heading count is the count this file states.** Round 45 of the `## Changelog` of
`docs/specs/spec.md` measured 17 and recorded the disagreement, and #486 repaired this
sentence.

**`misspell` reads a Go file alone, so that linter reads no document.**
`.golangci.yml:32` states `# The maintainer writes US English.`, and `locale: US` on the
next line binds the Go files. Round 39 of the `## Changelog` of `docs/specs/spec.md`
records the same reading. **The sentence read `so no check of this repository reads a
document` until #697**, and the guard below falsified that wider claim.

**One word carries a guard, and every other British spelling carries none.**
`TestNoTrackedFileWritesTheBritishAcknowledgmentSpelling` in
`internal/repocheck/us_english_acknowledgment_test.go` reads every tracked file, and it fails on the British
spelling of `acknowledgment` as prose. #697 built it, because `misspell` at `locale: US`
flags neither spelling of that word and round 48 had already converted it once. **The guard
accepts an occurrence inside a code span, and it accepts one in a block-quote line.**
`## What is verbatim, and never rewritten` below holds both forms unchanged. **The guard
exempts no file today.** It exempted `docs/specs/foxio/port-register.md` until 2026-08-16
UTC, because that page was a verbatim copy that no change of this repository could edit, and
#758 removed the page. **Issue #697 is the reversal path.**

## What is verbatim, and never rewritten

Reproduce these without a change. Rewriting evidence destroys it, and rewriting a quote
misrepresents the person.

- Anything a person said: a user answer, a review comment, a dictated requirement.
- Evidence: an error message, a log excerpt, console output, a test name, a stack trace,
  command output, a `file:line` reference.
- Code, configuration, commands, JSON, file paths, identifiers, label names.
- Third-party product names and API field names.
- Text copied from a specification, including a FoxIO fingerprint value.

## How a citation names its target

**The maintainer adopted this convention on 2026-08-13.** An internal cross-reference cites
a stable target. An evidence citation cites `file:line`.

| Kind | What it cites | Why |
|---|---|---|
| **Evidence** — a FoxIO reference implementation, a FoxIO image, a deleted FoxIO text specification, the port at a tag | **`file:line`**, at the pinned commit | `testdata/foxio.pin` holds the commit, so the line never moves. |
| **Internal** — `.claude/rules/*` and `docs/specs/*` that cite each other, and a code comment that cites a rule file | **A stable target**: a section heading, a rule number, a requirement number, or an identifier | Each one names the text it points at, so it survives an edit above it. A line number does not. |
| **This library's own code, named in a document** | **The identifier**, and the file | `decideEndpoints` in `ja4ssh.go` finds the method after every edit. A line number finds it until the next edit. |

**A stable target is any name that the cited text carries.** `## Stop conditions` is a
section heading. `R18` of `docs/specs/foxio/JA4T.md` is a rule number. `FR-ja4ls-11` is a
requirement number. `decideEndpoints` is an identifier. **Pick the narrowest one the target
carries.** `docs/specs/foxio/*.md` holds numbered rules and few headings, so a citation
there names a rule number.

**`.claude/rules/rulings.md` `## A reading cites a file and a line` governs evidence, and
this convention does not touch it.** A reading of a FoxIO source keeps its `file:line`, and
`## What is verbatim, and never rewritten` above holds that citation verbatim.

The measurement that earned the convention: batch #421 found three stale line citations, and
each one named a line that the same batch moved. `docs/specs/spec.html` cited `ja4l.go:381`
for a `JA4L-S` write that now sits at `:413`. It cited `ja4ssh.go:176-180` for a cap that no
line holds. Its `Three defects` box named three defects that the code does not hold. **Each
of those three citations is the defect, and never a citation this file makes.**

## One document owns each measured count

**A count restated in three documents costs three repairs when the measurement moves.** The
third repair becomes a separate issue when a later reader finds it, so the backlog
regenerates itself.

**Issue #757 holds the measurement of 2026-08-16 UTC.** 365 issues were closed, and 67 of
them repaired a sentence, a citation, a count or a term. **46 of the 67 name an earlier
issue as their cause.**

**A measured count is a number that a command produces, and a later run moves it.** Each of
these is one.

- The conformance figures.
- The deviation counts, and the register key count.
- The mutation counts.
- The fuzz target count.
- The coverage total.
- A citation-site count, and a file count.

**A schema count is not a measured count, and this rule never reaches one.** No command
moves the eleven methods or the ten fingerprinters, because FoxIO and this project decide
them. `CLAUDE.md` states both, and it keeps them.

### One owner, and every other document cites it

**One file owns each measured count, and every other document cites that owner.** The
citation names the owner and a stable target under `## How a citation names its target`
above, and it states no number.

**The owner is the first of these three ranks that the count reaches.**

1. **The file that the command writes or reads.** The value lives where the command puts
   it, so no prose is more current than that file.
2. **The one document that states the rule the count measures.** The count exists to state
   how far the rule has reached, so it belongs beside the rule.
3. **The command, and no document at all.** A count that any commit moves is stale in every
   document within one batch. Each document names the command, and it states no value.

| Class of measured count | Owner | Rank | Why |
|---|---|---|---|
| The conformance figures — matches, deviations, accepted deviations, and each per-set split | `docs/audit/conformance.md` | 1 | `make conformance` rewrites the report on every run, and a CI job fails when the tracked report and the run disagree. |
| The register key count, and the entry count of one ruling | `testdata/deviations.json` | 1 | The register is the data, and the count is its length. `internal/repocheck/changelog_counts_freshness_test.go` derives both from it. |
| The coverage floor | `.coverage-floor` | 1 | The file holds one number, and `internal/repocheck/coverage_floor_test.go` reads it. |
| The mutation counts of the named package set | `docs/specs/features/15-mutation-sweep.md` | 2 | No cheap command produces the value, so a document holds it. That file states the package set the counts measure. |
| A file count or a citation-site count that one rule measures | The rule file that states the rule | 2 | This file owns the British-spelling file count for that reason. |
| The fuzz target count | **The command, and no document** | 3 | `make fuzz` reads the target list from the tree, so a new target moves the value without a document edit. |
| The coverage total | **No file** | 3 | The tree moves the total on any commit, and `.coverage-floor` holds the floor rather than the total. |

**`CLAUDE.md` owns no measured count.** Every session reads it, so an unrelated change edits
it most often, and the measurement of #757 gives it 25 documentation issues.

**`CLAUDE.md` still states the mutation counts today, and the conversion of that class has
not run.** `## Commands` of that file states the whole-set counts of 2026-08-14, and it
carries a table with a `Mutations` column. **The owner of that class is
`docs/specs/features/15-mutation-sweep.md`**, and the table above names it. That file holds
the `./internal/parser` figures of 2026-08-14, and it holds no whole-set figure. **So the
mutation class is unconverted on both sides**, and `CLAUDE.md` cites the owner of the fuzz
target count alone. **A conversion moves the whole-set counts to the owner, and it leaves a
citation in `CLAUDE.md`.** Issue #757 is the path that carries it.

**An unconverted class is the designed state of this rule, and never a defect of it.**
`### The guard` below states that the registry names the fuzz target count today, and that a
batch adds the entry for a class when it converts that class. **The batch #773 cross-member
review measured this exception on 2026-08-16 UTC**, and the round of that batch recorded it
here rather than converting a second class in the batch that ships `v1.1.0`.

### Two permitted restatements, and one date rule

**A guard makes a restatement safe, and nothing else does.** A document restates an owned
count when a test derives the expected value from the owner and fails on a disagreement.
`TestTheChangelogPreambleStatesTheCountsTheTreeProduces` in
`internal/repocheck/changelog_counts_freshness_test.go` holds the `## [Unreleased]` preamble of `CHANGELOG.md`
that way. **#752 built two `CHANGELOG.md` guards on the same principle in batch #760**, and
each one derives its expected value from `go.mod`.

**A dated record states what one run measured on one date, and no change edits it.** A
`## Changelog` row of `docs/specs/spec.md`, an entry of `CHANGELOG.md`, an acceptance
criterion of a feature file and a pull-request body each read that way. **A record that a
later fact falsifies is corrected in a later record, and never rewritten.** Round 72 and
round 73 of the `## Changelog` of `docs/specs/spec.md` set that precedent.

**A live measurement that no file owns carries its date.** `CLAUDE.md` `## Conventions`
states that rule, and the coverage total and the `govulncheck` count each read that way.

### A value of another repository is cited, and never mirrored

**This repository owns no value that the Python port owns.** A whole-page copy of the
port's material restates every value that page holds, so it carries the cost of this rule at
the largest size. **Cite the port at a tag instead**, under `.claude/rules/rulings.md`
`## A citation names its repository`.

### The conversion is incremental, and no sweep converts the tree

**The round of a batch converts each document that the batch already opens, and no other
document.** A standing sweep issue competes with a live batch for the same files.

**The maintainer closed #388 on 2026-08-13**, and `## This project writes US English` above
records that decline. **The project manager closed #749 on 2026-08-16 UTC**, and it filed
that issue itself. #749 asked for a repository-wide sweep of the citations of
`docs/specs/foxio/`, so it asked for a different sweep from this one. **Its closing comment
states the mechanism that both declines share**, and it quotes the record of #388.

### The guard

`internal/repocheck/measured_count_ownership_test.go` holds a registry of each owned count that a guard reaches.
It fails when a document states a value that the registry gives an owner. **The registry
names the fuzz target count today.** A batch that converts a class adds the entry for it.

**The registry names each surface whose statements are dated records, and it reads no
record.** `docs/specs/features/06-fuzz-testing.md` is one such surface, in full. Its
`## What Epic 6 built` section states
`The four members of Epic 6 landed on 2026-08-14, and this section states the result.`, and
its table gives every count the command that measured it. **So the guard reaches no
statement of that file at all**, and this sentence states that limit rather than a wider
claim.

## The rules

### Sentences

1. A procedure sentence is 20 words or fewer. A description sentence is 25 or fewer.
2. One instruction per sentence.
3. One topic per paragraph, six sentences at most.
4. Put the condition first, then the action. "If the test fails, revert the commit."
5. Put the warning before the step it applies to, never after.

### Words

6. One word, one meaning, one part of speech.
7. One concept, one word. Never rotate synonyms for variety.
8. Keep a noun cluster to three words.
9. No metaphor, idiom or slang. State the mechanism instead.
10. Define an abbreviation once, on first use, in the Terms table.

### Grammar

11. Active voice. The reader must know who acts.
12. Present tense for behavior. Imperative for an instruction.
13. Keep the articles. Write "the branch", not "branch".
14. No `-ing` form as a noun or as a heading.
15. Write positively. State what to do.
16. Use a vertical list when a sentence would carry more than two conditions.

## Patterns

### A functional requirement

One testable statement, active voice, present tense, no conjunction.

```
Bad:  FR-lookup-3 — The client should handle timeouts properly and not hang.
Good: FR-lookup-9 — A remote lookup uses a client with a timeout when the caller
                    supplies none.
      FR-lookup-10 — The default timeout is 10 seconds.
```

"should handle properly" is not testable. "not hang" is not a value. Two requirements
were hiding in one sentence.

### An acceptance criterion

Write the observable result, not the implementation.

```
Bad:  The remote lookup handles slow servers.
Good: A remote lookup against a server that never responds returns an error within
      11 seconds.
```

### An issue title

Imperative verb, one deliverable, 10 words or fewer.

```
Bad:  lookup improvements (part 2)
Good: Add a timeout to the remote database lookup
```

### A code comment

The rules above apply unchanged. Three do the most work in Go code.

**One sentence, one fact. Active voice. Say why, not what.**

```go
Bad:  // loop over the connections and clean them up if they are old
Good: // Remove a connection that has produced no packet for 5 minutes.
      // The map holds every connection it has seen, so an idle one leaks.
```

**Name the reason a reader cannot see.** The code already states what it does. A comment
that repeats the code is noise.

```go
Bad:  // set the limit to 4
Good: // A crafted packet can nest encapsulation without a bound.
      const maxTunnelDepth = 4
```

**A doc comment opens with the name it documents, and states the result.**

```go
Bad:  // This function does the lookup thing and gives back what it finds.
Good: // LookupFingerprint returns the database record for the fingerprint.
      // It returns nil when the database holds no record for it.
      // It performs no network input and no network output.
```

**A test name is a sentence.** One behavior, present tense, active voice:
`TestRemoteLookup_ReturnsErrorWhenServerNeverResponds`, not `TestLookup2`.

A marker comment keeps its conventional keyword, because tooling matches on it. Write the
body to this standard and name the issue:
`// TODO(#412): Replace the fixed 10-second timeout with the configured value.`

## Check before you write the file

- [ ] No sentence is longer than 25 words. No instruction is longer than 20.
- [ ] Every step holds one instruction.
- [ ] Every condition comes before its action. Every warning comes before its step.
- [ ] Every domain word is in the Terms table, with one meaning.
- [ ] No synonym rotation. One concept, one word, throughout.
- [ ] No noun cluster longer than three words.
- [ ] No metaphor, idiom or undefined abbreviation.
- [ ] Active voice, present tense, articles present, no `-ing` nouns or headings.
- [ ] A list carries anything with more than two conditions.
- [ ] Quotes, evidence, code, paths, identifiers and fingerprint values are verbatim.
- [ ] A code comment states the reason. A doc comment opens with the name and the result.
      A test name reads as one behavior.
