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
file that carries it.** `## Behaviour rules` is that heading, and 18 tracked files hold it,
measured on 2026-08-13 at commit `6681d3e`. One file cites the heading of another file, so
a partial conversion breaks a citation. **A round converts the prose of a file it opens, and
it leaves that heading.**

**`misspell` reads a Go file alone, so no check of this repository reads a document.**
`.golangci.yml:32` states `# The maintainer writes US English.`, and `locale: US` on the
next line binds the Go files. Round 39 of the `## Changelog` of `docs/specs/spec.md`
records the same reading.

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
