package ja4plus

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// A stash written in one worktree reaches every other worktree, because `refs/stash`
// lives in the common directory. #305 records one such loss, and #355 adds the deny
// entry that stops the command before git runs.
//
// `.githooks/reference-transaction` refuses the same write, and it cannot replace the
// deny entry. `core.hooksPath` is machine-local git configuration, so a clone that never
// runs the install command runs no hook. The deny entry travels with the checkout.
//
// These tests fail when a later edit removes the deny entry.

// theGitStashDenyEntry is the permission rule that refuses `git stash`.
//
// Claude Code evaluates a deny rule before an allow rule, so this entry narrows the
// broader `Bash(git:*)` entry of the allow list below. The trailing `:*` is a wildcard
// that matches a space or the end of the command. The entry therefore covers `git stash`
// and every subcommand of it. Claude Code reads a shell separator, so the entry also
// refuses the `git stash` half of a compound command.
//
// The entry matches one command prefix, and a caller that writes another prefix reaches
// the stash. `git -C . stash push` is one such command, and the rule at the head of
// `.claude/rules/worktrees.md` covers it.
//
// Verified against: <https://code.claude.com/docs/en/permissions.md> and
// <https://code.claude.com/docs/en/settings.md>, retrieved 2026-08-13.
const theGitStashDenyEntry = "Bash(git stash:*)"

// theGitAllowEntry permits every other git command, and the deny entry above narrows it.
const theGitAllowEntry = "Bash(git:*)"

// claudeSettings holds the two keys these tests read from `.claude/settings.json`.
type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
	Hooks struct {
		PostToolUse []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"PostToolUse"`
	} `json:"hooks"`
}

// readClaudeSettings returns the parsed content of `.claude/settings.json`.
// It fails the test when the file is absent, and when the file holds invalid JSON.
func readClaudeSettings(t *testing.T) claudeSettings {
	t.Helper()

	var settings claudeSettings
	if err := json.Unmarshal([]byte(readRepoFile(t, ".claude/settings.json")), &settings); err != nil {
		t.Fatalf(".claude/settings.json holds invalid JSON: %v", err)
	}

	return settings
}

func TestClaudeSettingsDeniesTheGitStashCommand(t *testing.T) {
	settings := readClaudeSettings(t)

	if !slices.Contains(settings.Permissions.Deny, theGitStashDenyEntry) {
		t.Errorf("permissions.deny of .claude/settings.json holds %v, and #355 requires %q",
			settings.Permissions.Deny, theGitStashDenyEntry)
	}
}

func TestClaudeSettingsAllowsEveryOtherGitCommand(t *testing.T) {
	settings := readClaudeSettings(t)

	if !slices.Contains(settings.Permissions.Allow, theGitAllowEntry) {
		t.Errorf("permissions.allow of .claude/settings.json holds no %q, so the deny entry of #355 narrows nothing",
			theGitAllowEntry)
	}
}

// theWorktreesRule is the file that states what an agent may run against the stash.
//
// The deny entry and this file must agree. #419 records the round where they did not.
// The file instructed a reader to drop a stash from the main checkout, and the deny entry
// refuses that command. No test read both files, so no test saw the disagreement.
//
// The two tests below read the file for the reconciliation, and never for the absence of
// a command name. A watched measurement in that file names `git stash`, and
// `.claude/rules/rulings.md` states that copied evidence stays verbatim. A test that
// declined the command name would force a change to that evidence.
const theWorktreesRule = ".claude/rules/worktrees.md"

// theMaintainerActionSentence names the person who runs each recovery command.
//
// The recovery path survives the deny entry because the maintainer types the command, and
// a person who types a command makes no tool call. This sentence is where the file states
// that, so a later edit that drops it restores the defect of #419.
const theMaintainerActionSentence = "The maintainer runs each command of this section, and no agent runs one."

// collapseWhitespace returns the text with each run of whitespace replaced by one space.
// A rule file wraps a sentence over two lines, so a match against the raw bytes fails
// after a rewrap that changes no word.
func collapseWhitespace(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func TestWorktreesRuleNamesTheGitStashDenyEntry(t *testing.T) {
	rule := collapseWhitespace(readRepoFile(t, theWorktreesRule))

	for _, want := range []string{theGitStashDenyEntry, ".claude/settings.json", "#355"} {
		if !strings.Contains(rule, want) {
			t.Errorf("%s names no %q, so it states no reason for the refusal of #419", theWorktreesRule, want)
		}
	}
}

func TestWorktreesRuleNamesTheMaintainerRecoveryPath(t *testing.T) {
	rule := collapseWhitespace(readRepoFile(t, theWorktreesRule))

	if !strings.Contains(rule, theMaintainerActionSentence) {
		t.Errorf("%s holds no %q, so a recovery path reads as an instruction to an agent",
			theWorktreesRule, theMaintainerActionSentence)
	}
}

func TestClaudeSettingsKeepsTheGofmtHook(t *testing.T) {
	settings := readClaudeSettings(t)

	for _, matcher := range settings.Hooks.PostToolUse {
		if matcher.Matcher != "Edit|Write" {
			continue
		}

		for _, hook := range matcher.Hooks {
			if hook.Type == "command" && strings.Contains(hook.Command, "gofmt") {
				return
			}
		}
	}

	t.Error("the PostToolUse hook of .claude/settings.json runs no gofmt command, and #355 must keep it")
}
