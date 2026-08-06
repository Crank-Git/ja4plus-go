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

## What is verbatim, and never rewritten

Reproduce these without a change. Rewriting evidence destroys it, and rewriting a quote
misrepresents the person.

- Anything a person said: a user answer, a review comment, a dictated requirement.
- Evidence: an error message, a log excerpt, console output, a test name, a stack trace,
  command output, a `file:line` reference.
- Code, configuration, commands, JSON, file paths, identifiers, label names.
- Third-party product names and API field names.
- Text copied from a specification, including a FoxIO fingerprint value.

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
12. Present tense for behaviour. Imperative for an instruction.
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

**A test name is a sentence.** One behaviour, present tense, active voice:
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
      A test name reads as one behaviour.
