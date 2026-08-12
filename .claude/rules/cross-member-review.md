# The cross-member review

**The project manager runs one cross-member review at every batch gate.** This file states
why, how to spawn one that reports, what the review must return, and what the project
manager does when the review returns nothing.

It carries no `paths` list, because every session must load it.

## Why the project runs one

**A cross-member review has found a real defect in seven consecutive batches.** Every one
of those defects passed CI, `go vet` and the member's own per-issue review. Each one is an
interaction between two members, and no narrower check reaches an interaction. The table
below names four of the seven.

| Batch | What the cross-member review found |
|---|---|
| #175 | A change that defeats the corpus cache permanently, and reports nothing. |
| #184 | A leak of one map entry for each tunneled connection, without a bound. |
| #230 | Two members that each write `eight` in the same comment. The merge is clean, so git shows nothing. |
| #321 | A guard that destroys the recovery path of `git merge --autostash`. |

Issue #260 records the first three. `.claude/rules/worktrees.md`
`### The autostash defect, and the repair` records the fourth, with the measurement.

**A batch gate that skips the cross-member review skips the only check that reads the
merged result.**

## Two spawn paths, and one of them reaches the spawner

**A cross-member review returned an idle signal and no text in eight consecutive
attempts**, across session 5 and session 6. The agent did not fail, and it did not time
out. Issue #260 records each silence.

### The measurement

**The worker of #260 spawned three agents on 2026-08-12 and varied one parameter at a
time.** Each spawn used agent type `general-purpose`, model `sonnet`, and
`run_in_background` set to true.

**Arm A and arm B carry the same brief, and they differ in the `name` parameter alone.**
Arm C carries a one-command brief, and it separates `name` from `isolation`.

| Arm | `name` | `isolation` | Spawn path | Where the result arrived |
|---|---|---|---|---|
| A | absent | absent | in-process | The spawner, unasked, in 140346 ms. |
| B | present | absent | cross-session | The project manager, unasked, once. Never the spawner. |
| C | present | `"worktree"` | in-process | The spawner, unasked, in 4065 ms. |

**Arm B and arm C both carry a name, and they reach different paths.** So a name alone
does not decide the path. `isolation` set to `"worktree"` holds a named spawn on the
in-process path.

**Arm A returned a complete report, and it met the return contract below without a
request.** It wrote `Nothing found in category 1.` for a category with no finding, and it
ended with a `NOT CHECKED` section.

**Arm B reported once, and the report reached the project manager rather than the worker
that spawned it.** The worker waited and received nothing. **The project manager then
replied to arm B with three corrections, and arm B returned two messages that held no
text:**

```
{"type":"idle_notification","from":"review-arm-b","timestamp":"2026-08-12T20:42:48.888Z","idleReason":"available"}
{"type":"idle_notification","from":"review-arm-b","timestamp":"2026-08-12T20:43:46.685Z","idleReason":"available"}
```

**That is the symptom of #260, reproduced under control.** There is no failure and no
timeout.

**An issue worker holds no tool that addresses a cross-session teammate.** The worker of
#260 searched for one and found none. So a worker whose spawn reaches the cross-session
path recovers nothing at all.

### The variable is the path, and it is not the name

The session-6 handoff states the cause as a name, and issue #260 carries that sentence.
**The measurement shows that the sentence names the wrong variable.**

- Session 7 ran nine issue workers. Each one carried a name, each one was in-process, and
  every one reported unasked.
- The batch #321 cross-member review carried no name, it was in-process, and it reported
  in full.
- Arm C carries a name, it is in-process, and it reported in 4065 ms.

**Every agent that reached its spawner was in-process, and the one that stopped without
text was cross-session.** The `name` parameter matters only because it moves a spawn that sets no
`isolation` onto the cross-session path.

**The in-process path has not gone silent once in this session.** That is the reason to
prefer it for anything that gates a merge.

### Two questions this measurement leaves open

**State both of these, and never write a tidier conclusion than the evidence carries.**

1. **Whether the eight earlier silences were cross-session is unmeasured.** Session 5
   recorded five, and session 6 recorded three. Those spawn records are not in this
   repository. The cross-session path explains them, and that is not proof.
2. **Whether a cross-session teammate reports reliably is unmeasured.** Arm B reported
   once and then returned two idle signals. Nothing here states a rate.

### The rule: read the spawn response, and never predict the path

**The harness states which path a spawn took, in the text it returns at the spawn.** The
two responses differ, and the difference is readable without a measurement.

- **The in-process path names an output file, and it states that a notification arrives at
  completion.**
- **The cross-session path names a mailbox, and it names no output file.** Issue #260
  quotes it as `Spawned successfully ... will receive instructions via mailbox`.

**Read that text at every spawn.** The parameter table above holds for one harness version,
and a later version can change it. The spawn response reports the path that the spawn
actually took.

**If the response names a mailbox, stop and spawn again on the in-process path.** Omit
`name`, or set `isolation` to `"worktree"`. **Never wait on a cross-session spawn**,
because it can return an idle signal and no text at any point.

**Give a cross-member review no name.** A name serves an agent the project manager must
address later, such as an issue worker that needs rework by message. A cross-member review
reports once and ends, so it needs no name.

## The five categories

The cross-member review checks each category below, and it reports on every one by name.

| N | Category | What it looks like |
|---|---|---|
| 1 | Contradiction | Two members state different facts about one thing. A count in words and the same count in digits is one. |
| 2 | Duplication | Two members add the same rule, term, section or helper under different names. |
| 3 | A broken cross-reference | One member names a file, a section, an issue or an anchor that another member moved, renamed or never created. |
| 4 | A violated rule | One member adds a rule, and the change of a sibling breaks it. |
| 5 | An unreleased resource | One member allocates a map entry, a handle or a file, and no member releases it. |

## The return contract

**The brief of every cross-member review states this contract, and the review meets it.**

1. The final message of the review is the whole report, as text.
2. The report holds one section for each of the five categories, numbered and named.
3. A category with a finding carries each finding, with a `file:line` citation and a
   verbatim quotation of the text at fault.
4. **A category with no finding carries the sentence `Nothing found in category N.`** That
   answer is valid and complete, and the report must never omit a category.
5. The report ends with a section headed `NOT CHECKED`. It names everything the review
   could not verify, and the reason for each one.
6. The review returns the report without a request.

**A report that omits a category is an incomplete report.** The project manager treats the
missing category as unchecked, and it runs that category by hand.

## What the project manager does when the review returns nothing

**Never record a cross-member review that produced no text as a review that found
nothing.** A review that found nothing says so, in text, and a review that produced no text
checked nothing. Session 5 and session 6 each ran the categories by hand, and each said so.

Run these five steps in order.

1. Read the spawn response. If it names a mailbox, spawn one more cross-member review on
   the in-process path, and wait for that one alone. **Never wait on a cross-session
   spawn, because it can stop without text at any point.**
2. If the second spawn also returns no text, run every one of the five categories by hand.
3. Read the merged result with `git diff <remote>/dev...<remote>/batch/<n>-<slug>`, and
   read each changed file at its merged state.
4. Write a gate comment on the batch pull request. Name each category the project manager
   ran by hand, and name each category nobody checked.
5. Carry the spawn response text into that gate comment, so the next session reads which
   path each spawn took.

**The gate comment of pull request #258 is the worked example.** It names what the project
manager checked by hand, and it names what nobody checked.

## What this file does not cover

**The issue-flow plugin lives outside this repository, and no session edits it from here.**
A change the plugin needs belongs in the verdict of the worker, and in an issue.
