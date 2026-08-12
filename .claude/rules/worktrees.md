# Worktrees and the shared stash

**No agent runs `git stash` in a worktree of this repository.**

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

**The permission system does reach a worker.** A worker of this batch was refused a
command by the worktree guard, and the refusal named the worktree. A `deny` rule in
`.claude/settings.json` is therefore the mechanism that stops the command at the agent.
That change is the maintainer's, because it changes what every future session may run.
#305 states the proposal.

## The guard: `.githooks/reference-transaction`

git 2.53.0 defines no `pre-stash` hook. `githooks(5)` names 24 hooks, and none of them
runs before a stash. `reference-transaction` is the one hook that reaches the stash,
because it runs for every ref update, and `githooks(5)` states the abort:

> The exit status of the hook is ignored for any state except for the "prepared" state.
> In the "prepared" state, a non-zero exit status will cause the transaction to be
> aborted.

`.githooks/reference-transaction` refuses a write to `refs/stash` from a linked worktree.
It leaves the main checkout alone, because a person who stashes there holds the whole
repository.

**The hook is inert until the maintainer installs it.** Install it with one command, from
the main checkout:

```
git config core.hooksPath .githooks
```

### What the hook was watched doing

A throwaway repository with two linked worktrees produced each result below, at git 2.53.0.

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

**It does not undo a `git stash pop`.** git applies the stash to the working tree before
it updates the ref, so the hook aborts the ref update after the files change. A pop in a
linked worktree left the file of the other worktree in place, and it emptied the stash
reflog while `refs/stash` survived. **Read the hook as a guard against the creation of a
shared stash, and never as a repair of a pop.**

**A relative `core.hooksPath` resolves per worktree.** The hook did not run until the file
was committed, because each worktree looks for `.githooks` under its own root. A first
watch recorded that failure:

```
$ git rev-parse --git-path hooks
.githooks
$ ls -la .githooks
ls: .githooks: No such file or directory
```
