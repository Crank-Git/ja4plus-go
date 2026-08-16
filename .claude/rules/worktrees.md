# Worktrees and the shared stash

**No agent runs `git stash` in a worktree of this repository.**

**The permission layer refuses `git stash` to an agent in every directory of this
repository.** `## The permission layer refuses the command` below states the entry, and it
states who holds each recovery path.

This file states the reason, the alternatives, and the two readings that #305 asked for.
It carries no `paths` list, because every session must load it.

## Why

Every worktree of one repository shares one stash ref. A stash written in one worktree is
visible in every other worktree, and a pop in any worktree takes it.

On 2026-08-12, in batch #293, the worker of #295 ran `git stash push` and then
`git stash pop`. The pop returned the change of #287 into the tree of #295. The work of
#295 was destroyed, and the tree of #287 was left in an unknown state. Neither worker saw
an error.

**The loss is silent.** Each worker sees a working tree that looks correct.

## Use one of these three instead

- Copy the file with `cp file file.bak`, change it, then restore it with `cp file.bak file`.
- Restore a committed file with `git checkout -- <file>`.
- Commit the change first, then run `git reset --hard` inside the worktree alone.

Each one reads and writes files of this worktree only. None of them writes a shared ref.

## The permission layer refuses the command

**`.claude/settings.json` holds `Bash(git stash:*)` in `permissions.deny`.** #355 added
that entry, and the maintainer approved it on 2026-08-12. **This project keeps the entry,
and it narrows it for no directory.** A permission pattern reads a command and not a
working directory. So no entry allows the main checkout and refuses a worktree.
`internal/repocheck/claude_settings_deny_test.go` holds the entry, and it fails when a later edit removes it.

**git tracks `.claude/settings.json`, so every worktree of this repository holds a
checkout of it.** A measurement in a linked worktree records both facts:

```
$ git ls-files .claude/settings.json
.claude/settings.json
$ git rev-parse --git-dir
/Users/christiancrank/Development/Personal/ja4plus-go/.git/worktrees/agent-a4b4617b5559cb1fb
```

**Claude Code enforces the entry, and it reads a deny rule before an allow rule.** So the
entry outranks the `Bash(git:*)` allow entry of the same file. The documentation states
the order:

> Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome, and rule specificity doesn't change the order.

The documentation states what the pattern matches:

> The `:*` suffix is an equivalent way to write a trailing wildcard, so `Bash(ls:*)` matches the same commands as `Bash(ls *)`.

> When `*` appears at the end with a space before it (like `Bash(ls *)`), it enforces a word boundary, requiring the prefix to be followed by a space or end-of-string.

So the entry matches `git stash`, and it matches every command that starts `git stash `.

> Permission rules are enforced by Claude Code, not by the model.

**This file records no live refusal of the permission layer.** The rule at the head of this
file bars the command, so no agent of this project runs `git stash` to observe one. Every
sentence above reads `.claude/settings.json` and the documentation.

Verified against: <https://code.claude.com/docs/en/permissions.md>, retrieved 2026-08-13.

### The hook and the permission layer reach different commands

| Mechanism | What it refuses | What it allows |
|---|---|---|
| `.githooks/reference-transaction` | A write to `refs/stash` from a linked worktree. | A stash from the main checkout, and an autostash store. |
| The deny entry of `.claude/settings.json` | Every `git stash` command of an agent, in every directory. | No command that starts `git stash`. |

**Each measurement of this file records the hook, and none of them records the permission
layer.** Where a measurement below states an allowance, it states what the hook allows.
**The permission layer still refuses the command to an agent.**

### The maintainer holds each recovery path

**A recovery path that needs `git stash` is a maintainer action.** The maintainer runs each
command of this section, and no agent runs one. Two paths need one.

- A stash from the main checkout, and a later `git stash pop` of it.
- A `git stash drop` of an autostash entry that the hook allowed.

**Claude Code enforces the entry for a tool call, and a person who types a command in a
terminal makes no tool call.** So each path survives, and this file instructs no agent to
run one.

## Reading: a worktree holds no stash of its own

**A worktree cannot be given its own stash. There is no option, and no configuration.**

`git-worktree(1)` at git 2.53.0 states the sharing rule:

> In general, all pseudo refs are per-worktree and all refs starting with `refs/` are
> shared. Pseudo refs are ones like `HEAD` which are directly under `$GIT_DIR` instead of
> inside `$GIT_DIR/refs`. There are exceptions, however: refs inside `refs/bisect`,
> `refs/worktree` and `refs/rewritten` are not shared.

`git-stash(1)` at git 2.53.0 names the ref it writes:

> The latest stash you created is stored in `refs/stash`

`refs/stash` starts with `refs/`, and the three exceptions do not name it, so it is shared.

A measurement in a linked worktree of this repository confirms the reading:

```
$ git rev-parse --git-dir
/Users/christiancrank/Development/Personal/ja4plus-go/.git/worktrees/agent-a3d2c16579396d637
$ git rev-parse --git-path refs/stash
/Users/christiancrank/Development/Personal/ja4plus-go/.git/refs/stash
```

The git directory of the worktree differs from the path of the stash ref. The stash ref
resolves to the common directory, which every worktree shares.

`extensions.worktreeConfig` gives a worktree its own configuration file. It gives a
worktree no ref of its own, and `git stash` reads no configuration key that names a ref.

## Reading: a Claude Code hook did not reach this worktree

`.claude/settings.json` holds a `PostToolUse` hook. It matches `Edit|Write`, and it runs
`gofmt -w` on each Go file the tool wrote.

A worker of batch #321 wrote this file into its own worktree with the `Write` tool:

```go
package p

func  F( ) int {
return 1
}
```

The bytes did not change. `command -v gofmt` reported `/opt/homebrew/bin/gofmt`, and
`gofmt -l` listed the file, so `gofmt` was present and it would have rewritten the file.

**A hook that `.claude/settings.json` configures did not run for a worktree-isolated
subagent.** So a `PreToolUse` hook stops no worker from running `git stash`.

**This reading states no result for a `deny` rule of `.claude/settings.json`.** The harness
refused two commands of that worker, and each refusal named the worktree. That refusal
comes from the worktree isolation of the harness, and not from a rule of
`.claude/settings.json`, so it measures nothing about a `deny` rule. #305 states the
proposal, and the maintainer owns that file.

**#355 landed that proposal on 2026-08-12**, and
`## The permission layer refuses the command` above states the entry it added.

## The git hook: `.githooks/reference-transaction`

git 2.53.0 defines no `pre-stash` hook. `man githooks | grep -i -c stash` reports `0`, so
the page never names the stash. `reference-transaction` is the one hook that reaches the
stash, because it runs for every ref update, and `githooks(5)` states the abort:

> The exit status of the hook is ignored for any state except for the "prepared" state.
> In the "prepared" state, a non-zero exit status will cause the transaction to be
> aborted.

`.githooks/reference-transaction` refuses a write to `refs/stash` from a linked worktree.
It leaves the main checkout alone, because a person who stashes there holds the whole
repository. **It lets an autostash store through.**
`### The autostash defect, and the repair` below states the reason and the measurement.

**The hook is inert until the maintainer installs it.** Install it with one command, from
the main checkout:

```
git config core.hooksPath .githooks
```

### What the first hook was watched doing

A throwaway repository with two linked worktrees produced each result below, at git 2.53.0.
That repository stood inside the worktree of the worker, and the worker removed it. **No
command of this watch reached the stash ref of this repository.**

**It refuses `git stash push`, and the working tree survives.**

```
=== git stash push in the linked worktree wtA:
refuse: this worktree must not write refs/stash.
refuse: every worktree of this repository shares that ref, so a stash here
refuse: destroys the work of another worktree. #305 records one such loss.
refuse: copy the file with cp, or restore it with git checkout -- <file>.
fatal: ref updates aborted by hook
=== exit code: 128
=== wtA f.txt after the refusal:
A third attempt
```

**It allows a stash from the main checkout, and it allows an ordinary commit in a linked
worktree.** Both reported exit code 0.

That result records the hook. **The permission layer refuses the same stash to an agent**,
and `## The permission layer refuses the command` above states the entry.

**It does not undo a `git stash pop`.** git applies the stash to the working tree before
it updates the ref, so the hook aborts the ref update after the files change. A pop in a
linked worktree left the file of the other worktree in place, and it emptied the stash
reflog while `refs/stash` survived. **The hook stops a worker from creating a shared stash,
and it repairs no pop.**

**A relative `core.hooksPath` resolves per worktree.** The hook did not run until the file
was committed, because each worktree looks for `.githooks` under its own root. A first
watch recorded that failure:

```
$ git rev-parse --git-path hooks
.githooks
$ ls -la .githooks
ls: .githooks: No such file or directory
```

### The autostash defect, and the repair

**The first hook destroyed the work that git saved for the user.** The cross-member review
of batch #321 measured it, and #321 repaired it. The first hook is commit `edae54e` of
#305.

`git-merge(1)` at git 2.53.0 states what `--autostash` writes:

> Automatically create a temporary stash entry before the operation begins, record it in
> the ref MERGE_AUTOSTASH and apply it after the operation ends.

When that entry cannot re-apply, git runs `git stash store` to keep it. The first hook
refused that ref write. `git merge --autostash`, `merge.autostash`, `rebase.autostash` and
`git pull --rebase --autostash` each reach the same fallback.

**The refusal loses the entry.** git removes the autostash file after the store, and it
removes the file whether the store succeeded or failed. So the saved state survives only
as the object id on the `error:` line. **The hook's own advice names `cp` and
`git checkout --`, and neither one reaches an autostash that the user never created.**

The watch below ran in a throwaway repository with two linked worktrees, at git 2.53.0,
outside this repository. A dirty worktree ran `git merge --autostash`, the merge
conflicted, and `git commit` concluded it.

```
=== git commit (concludes the conflicted merge):
refuse: this worktree must not write refs/stash.
refuse: every worktree of this repository shares that ref, so a stash here
refuse: destroys the work of another worktree. #305 records one such loss.
refuse: copy the file with cp, or restore it with git checkout -- <file>.
fatal: ref updates aborted by hook
error: cannot store 14dc222ce712faecf3889274bb3681d872bb7bfb
=== commit exit: 0
=== git stash list:
=== MERGE_AUTOSTASH:
ls: .../worktrees/wt/MERGE_AUTOSTASH: No such file or directory
```

#321 took the path that discriminates, and it declined the path that removes the hook. An
instrumented hook recorded what git gives it at the moment of the store:

```
--- hook fired ---
argv: prepared
stdin: 0000000000000000000000000000000000000000 14dc222ce712faecf3889274bb3681d872bb7bfb refs/stash
MERGE_AUTOSTASH exists: yes
GIT_REFLOG_ACTION: [unset]
--- end hook ---
```

**The ref name, the old value and the new value separate nothing.** A hand-written stash
presents the same three fields, and `GIT_REFLOG_ACTION` is unset. **The autostash file is
the one discriminator, and git writes it.** The hook tests `MERGE_AUTOSTASH`,
`rebase-merge/autostash` and `rebase-apply/autostash` under the git directory of the
worktree, and it exits 0 when one of them is present.

### What the repaired hook was watched doing

Each result below comes from the file this repository holds, at git 2.53.0, in a throwaway
repository with four linked worktrees.

**It allows the merge autostash store, and the entry survives.**

```
=== git commit (concludes the conflicted merge):
Applying autostash resulted in conflicts.
Your changes are safe in the stash.
You can run "git stash pop" or "git stash drop" at any time.
=== git stash list:
stash@{0}: autostash
```

**git prints that instruction, and the permission layer refuses both commands to an
agent.** The maintainer runs `git stash pop` or `git stash drop`, from the main checkout.

**It allows the rebase autostash store.** `git rebase --continue` reported exit code 0 and
the same three lines.

**It still refuses a hand-written `git stash push` in a linked worktree.**

```
=== git stash push:
refuse: this worktree must not write refs/stash.
refuse: every worktree of this repository shares that ref, so a stash here
refuse: destroys the work of another worktree. #305 records one such loss.
refuse: copy the file with cp, or restore it with git checkout -- <file>.
fatal: ref updates aborted by hook
=== exit code: 128
=== f.txt after the refusal:
line1
HAND-WRITTEN
line3
```

**It still allows a stash from the main checkout.** `git stash push` there reported exit
code 0.

That result records the hook. **The permission layer refuses that command to an agent**,
and the maintainer is the person who runs it.

### Two limits of the repaired hook

**1. The hook refuses `git stash drop` on the entry it allowed.** A drop writes
`refs/stash`, and no autostash file is present by then.

```
=== git stash drop:
Dropped refs/stash@{0} (567fb749452956a7a74b9a6365d1157ac202bb0b)
refuse: this worktree must not write refs/stash.
refuse: every worktree of this repository shares that ref, so a stash here
refuse: destroys the work of another worktree. #305 records one such loss.
refuse: copy the file with cp, or restore it with git checkout -- <file>.
fatal: ref updates aborted by hook
=== exit code: 128
```

The line above prints the object id, so the entry stays reachable. **The maintainer drops
the entry from the main checkout**, and no agent runs that command.

**2. The hook allows a hand-written stash while a rebase autostash is pending.** git
refuses a hand-written stash during a conflicted merge, so the merge case holds. A stopped
rebase with a clean index is the one case the hook does not cover:

```
=== rebase-merge/autostash present: yes
=== git stash push (hand-written, index clean, autostash pending):
Saved working directory and index state WIP on (no branch): 1e64ea7 other
=== exit code: 0
```

**That case misses a refusal, and it destroys nothing.** The rule at the head of this file
covers it, and the rule binds every agent whether or not the maintainer installs the hook.
**The deny entry of `.claude/settings.json` covers it too, and it needs no installation.**
