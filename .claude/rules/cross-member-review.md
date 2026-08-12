# The cross-member review

**The project manager runs one cross-member review at every batch gate.** This file states
why the project runs one. It states how to spawn one that reports. It states the return
contract, and it states what the project manager does when a review returns no text.

It carries no `paths` list, because every session must load it.

**`review` in this file always names a cross-member review, and never an audit.**

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

**The worker of #260 spawned three agents on 2026-08-12.** Each spawn used agent type
`general-purpose`, model `sonnet`, and `run_in_background` set to true.

**Arm A and arm B carry the same brief, and they differ in the `name` parameter alone.**
**Arm C moves two variables at once.** It sets `isolation` to `"worktree"`, and it carries
a one-command brief in place of the review brief. So arm A against arm B is the one
contrast of this measurement that moves a single parameter.

| Arm | `name` | `isolation` | Brief | Spawn path | Where the result arrived |
|---|---|---|---|---|---|
| A | absent | absent | The review brief | in-process | The spawner, unasked, in 140346 ms. |
| B | present | absent | The review brief | cross-session | The project manager, unasked, once. Never the spawner. |
| C | present | `"worktree"` | One command | in-process | The spawner, unasked, in 4065 ms. |

**The two durations measure the two briefs, and they measure nothing about the spawn
path.** Arm A read a whole batch, and arm C ran one command. **This file draws no
conclusion from 140346 ms against 4065 ms.**

**Arm B and arm C both carry a name, and they reach different paths.** So a name alone
does not decide the path. That conclusion reads the path of each arm, and it reads no
duration. The brief of arm C therefore does not weaken it. **Arm C shows a named
in-process spawn that reports.** One arm that moves two variables proves no cause.

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

**An issue worker holds no tool that addresses a cross-session agent.** The worker of #260
searched for one and found none. So a worker whose spawn reaches the cross-session path
recovers nothing at all.

### The variable is the path, and it is not the name

The session-6 handoff states the cause as a name, and issue #260 carries that sentence.
**The measurement shows that the sentence names the wrong variable.**

- Session 7 ran nine issue workers. Each one carried a name, each one was in-process, and
  every one reported unasked.
- The batch #321 cross-member review carried no name, it was in-process, and it reported
  in full.
- Arm C carries a name, it is in-process, and it reported unasked.

**Every agent that reached its spawner was in-process.** The one agent that stopped without
text was cross-session, and it stopped after one report. The `name` parameter matters only
because it moves a spawn that sets no `isolation` onto the cross-session path.

**No in-process spawn of this session has stopped without text.** The record holds the
three arms above, the nine issue workers of session 7 and the batch #321 cross-member
review. **The nine spawns and the batch #321 spawn record no parameter set, so arm A
against arm B is the one contrast that moves a single parameter.**

### Three questions this measurement leaves open

**State all three of these, and never write a tidier conclusion than the evidence
carries.**

1. **Whether the eight earlier silences were cross-session is unmeasured.** Session 5
   recorded five, and session 6 recorded three. Those spawn records are not in this
   repository. The cross-session path explains them, and that is not proof.
2. **Whether a cross-session agent reports reliably is unmeasured.** Arm B reported once
   and then returned two idle signals. Nothing here states a rate.
3. **Whether `isolation` alone holds a named spawn on the in-process path is unmeasured.**
   Arm C moves `isolation` and the brief together, so the two are confounded in that arm.
   A fourth arm that sets `isolation` and carries the review brief separates them, and
   #331 records that nobody has run one.

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
| 4 | A violated rule | One member adds a rule, and a change breaks it. The change of a sibling breaks it, or the member's own change breaks it. |
| 5 | An unreleased resource | One member allocates a map entry, a handle or a file, and no member releases it. |

**Category 4 covers the member that breaks its own new rule.** A member that writes a rule
and then breaks it on the same page passes every per-issue check, because the rule and the
breach land in one pull request. Batch #331 found one: #254 wrote the citation rule of
`docs/specs/foxio/README.md`, and the pages of #254 use bases that the rule never names.

**Start at the surface that more than one member edited.** List the files the merged result
changes, count the members that touched each one, and read the shared files first. Every
defect of the table in `## Why the project runs one` sits on a shared surface.

## The return contract

**The brief of every cross-member review states this contract, and the review meets it.**
**This contract outranks any other report shape a brief names.** A brief that names a
different skeleton is wrong, and the review follows the eight items below. The project
manager repairs the brief.

1. The final message of the review is the whole report, as text.
2. The report opens with one line headed `VERDICT`. It states `clean` or `findings`, and
   it states the count of findings.
3. The report holds one section for each of the five categories, numbered and named.
4. A category with a finding carries each finding, with a `file:line` citation and a
   verbatim quotation of the text that holds the defect.
5. **A category with no finding carries the sentence `Nothing found in category N.`** That
   answer is valid and complete, and the report never omits a category.
6. **A category that the merged result gives no material for is answered in one line.**
   Category 5 reads code that owns a resource. A batch that changes no such code answers
   category 5 with `Nothing found in category 5.` and one sentence of reason.
7. The report ends with a section headed `NOT CHECKED`. It names everything the review
   could not verify, and the reason for each one.
8. The review returns the report without a request.

**A report that omits a category is an incomplete report.** The project manager treats the
missing category as unchecked, and it runs that category by hand.

**The rule keeps the contract, and the brief adopts it.** Batch #331 recorded the
disagreement: the brief named a `VERDICT / FINDINGS / CHECKED AND CLEAN / NOT CHECKED`
skeleton, and it named no per-category section. A list of clean categories can drop a
category and read as complete, and a numbered section for each of the five cannot. Item 2
carries the `VERDICT` line of that skeleton, so the two shapes now agree.

## What the project manager does when a review returns no text

**Never record a cross-member review that produced no text as a review that found
nothing.** A review that found nothing says so, in text. A review that produced no text
checked nothing. Session 5 and session 6 each ran the categories by hand, and each said so.

Run these steps in order.

1. Read the spawn response.
2. If it names a mailbox, spawn one more cross-member review on the in-process path.
3. **Never wait on a cross-session spawn.** It can stop without text at any point.
4. If the second spawn also returns no text, run every one of the five categories by hand.
5. Read the merged result with `git diff <remote>/dev...<remote>/batch/<n>-<slug>`.
6. Read each changed file at its merged state.
7. Write a gate comment on the batch pull request.
8. Name each category the project manager ran by hand.
9. Name each category nobody checked.
10. Carry the spawn response text into that gate comment.

**The gate comment of pull request #258 is the worked example.** It names what the project
manager checked by hand, and it names what nobody checked.

## What this file does not cover

**The issue-flow plugin lives outside this repository, and no session edits it from here.**
A change the plugin needs belongs in the verdict of the worker, and in an issue.
