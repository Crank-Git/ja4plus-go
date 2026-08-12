#!/usr/bin/env bash
#
# The guard for #257.
#
# `golangci-lint` writes an absolute file path into each cached issue, and one cache serves
# the whole user account. Two checkouts of the same package content share cache entries, so
# the second one reads back a path inside the first one. A path inside a removed worktree
# stops the `nolint` processor. Every suppressed finding then leaks into the report, and
# the run fails against a file the reader cannot open.
#
# A guard nobody has watched fail is not a guard. This script therefore proves both halves.
# Step 1 shares one cache between two copies, and it requires the false finding.
# Step 2 gives each copy its own cache, and it requires no finding.
#
# The script reads no file of this repository. It builds its own package under a temporary
# directory, and that package carries a `nolint` directive. A correct run reports nothing.
set -euo pipefail

if ! command -v golangci-lint >/dev/null 2>&1; then
	echo "check-lint-cache: golangci-lint is not on PATH"
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# write_copy builds one copy of the probe package at the named directory.
write_copy() {
	local dir="$1"
	mkdir -p "$dir"

	cat >"$dir/go.mod" <<-'EOF'
		module probe

		go 1.24
	EOF

	cat >"$dir/.golangci.yml" <<-'EOF'
		version: "2"
		linters:
		  default: none
		  enable:
		    - errcheck
	EOF

	cat >"$dir/probe.go" <<-'EOF'
		package probe

		import "os"

		// Probe suppresses the errcheck finding, so a correct run reports nothing.
		func Probe() {
			f, _ := os.Open("/dev/null")
			f.Close() //nolint:errcheck // The directive is the subject under test.
		}
	EOF
}

# run_lint lints the named directory with the named cache. It returns the exit code of
# `golangci-lint`, and it writes the report to the named log.
run_lint() {
	local dir="$1" cache="$2" log="$3"
	(
		cd "$dir"
		GOLANGCI_LINT_CACHE="$cache" golangci-lint run
	) >"$log" 2>&1
}

echo "check-lint-cache: step 1 requires the defect, because one cache serves both copies"

write_copy "$work/first"
write_copy "$work/second"
run_lint "$work/first" "$work/shared-cache" "$work/first.log" || true
rm -rf "$work/first"

if run_lint "$work/second" "$work/shared-cache" "$work/shared.log"; then
	echo "check-lint-cache: the shared cache reported no finding, so this guard proves nothing."
	echo "check-lint-cache: read whether golangci-lint still caches an absolute path."
	exit 1
fi

# `head` closes the pipe early, and `pipefail` would read that as a failure of the whole
# script. The report is evidence for the reader, so it never decides the exit code.
echo "check-lint-cache: the shared cache reports a finding against the removed copy:"
grep "probe.go:" "$work/shared.log" | grep -v "^level=" | head -3 || true

echo "check-lint-cache: step 2 requires no finding, because each copy holds its own cache"

write_copy "$work/third"
write_copy "$work/fourth"
run_lint "$work/third" "$work/third-cache" "$work/third.log" || true
rm -rf "$work/third"

if ! run_lint "$work/fourth" "$work/fourth-cache" "$work/split.log"; then
	echo "check-lint-cache: one cache for each checkout still reports a finding:"
	cat "$work/split.log"
	exit 1
fi

echo "check-lint-cache: one cache for each checkout reports no finding"
echo "check-lint-cache: pass"
