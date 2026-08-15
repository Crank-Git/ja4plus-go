.PHONY: build test lint lint-cache-check bench clean corpus conformance cover docs fuzz prerelease vuln

# The generator of the documentation site. `docs/requirements.txt` pins it.
# Override it to reach a virtual environment that the PATH does not hold:
#   make docs MKDOCS=.venv/bin/mkdocs
MKDOCS ?= mkdocs

build:
	go build -o bin/ja4plus ./cmd/ja4plus

test:
	go test -v -race ./...

# `golangci-lint` writes an absolute file path into each cached issue. One cache serves the
# whole user account. A second checkout of the same package content reads back a path
# inside the first checkout.
# That first checkout is often a worktree the project manager has removed. The `nolint`
# processor then cannot open the file, so every suppressed finding leaks into the report.
# #257 measured 13 such findings against a path that did not exist.
# One cache for each checkout keeps every cached path inside the checkout that wrote it.
# `scripts/check-lint-cache.sh` proves both halves of this.
lint:
	GOLANGCI_LINT_CACHE=$(CURDIR)/.golangci-cache golangci-lint run

# The guard for #257. It reproduces the stale cache defect, then it proves that one cache
# for each checkout holds the defect back. It reads no file of this repository.
lint-cache-check:
	./scripts/check-lint-cache.sh

# `-run '^$$'` holds the unit tests back, so this target measures and does nothing else.
# `corpus_fetch_test.go` spawns `bash`, `curl` and `tar`, and one test resolves a name.
bench:
	go test -run '^$$' -bench=. -benchmem ./...

# The script fetches the corpus at the commit in `testdata/foxio.pin`.
# The script is idempotent: it downloads nothing on a second run.
# It names the network on a failure, so this target adds nothing of its own.
corpus:
	./scripts/fetch-corpus.sh

# Epic 4 adds the conformance suite behind the `conformance` build tag.
# `-count=1` defeats the test cache, because a cached run writes no conformance report.
# `-v` prints the skip message that names `make corpus` when the corpus is absent.
conformance:
	go test -tags conformance -count=1 -v ./...

# `go tool cover -func` writes the total statement coverage on its last line.
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep '^total:'

# `go test` fuzzes one target for each run, so this target runs each one in turn.
# Epic 6 adds the fuzz targets, and this target finds them without a change.
# `-run '^$$'` holds the unit tests back, so each run fuzzes and does nothing else.
# A package that does not compile fails the list, and `grep` alone would hide that.
#
# `-fuzzminimizetime 5s` bounds the coverage minimization, and the maintainer ruled it on
# 2026-08-14 under issue #568. `go help testflag` states
# `-fuzzminimizetime t ... The default is 60s.`, which is twice the 30 seconds this recipe
# gives each target. So one minimization attempt outlasts the whole run, and the engine
# reports a frozen execution count while the clock advances.
#
# The engine minimizes an interesting input, and never a crashing input alone. A target
# that finds no crash pays that cost on every run, against a 30-second budget. #568
# measured one minimization at 26.39531s of a 30-second run, and it measured two stalls in
# ten runs from an empty cache corpus.
#
# The cost of the bound: the engine minimizes the reproducer of a real crash less, so that
# input can land larger than a reader wants. The maintainer accepted that cost on
# 2026-08-14.
#
# A fresh CI runner holds no cache corpus, so a CI fuzz run always starts in the phase that
# stalls. That is why the bound is not academic.
#
# `.github/workflows/fuzz.yml` needs no such flag, and this recipe changes no line of it.
# That workflow gives each target `-fuzztime 10m`, so the 60-second default spends about a
# tenth of one run rather than twice one run. Its `timeout-minutes` comment already reads
# the default.
fuzz:
	@for package in $$(go list ./...); do \
		targets=$$(go test -list '^Fuzz' $$package) || exit 1; \
		for target in $$(echo "$$targets" | grep '^Fuzz' || true); do \
			echo "fuzz: $$target in $$package"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime 30s -fuzzminimizetime 5s $$package || exit 1; \
		done; \
	done

# FR-supply-4 holds the command that the `vuln` job of `.github/workflows/ci.yml` runs, so
# that job and a developer run one command.
#
# The exit status separates a called vulnerability from an uncalled one, and FR-supply-2
# and FR-supply-5 need that separation. Three sources of `golang.org/x/vuln` v1.6.0 state
# the rule.
#
#   1. `TextHandler.Flush` in `internal/scan/text.go` returns `errVulnerabilitiesFound`
#      only when a finding reaches the scan level.
#   2. `errVulnerabilitiesFound` in `internal/scan/errors.go` carries exit status 3.
#   3. `parseFlags` in `internal/scan/flags.go` sets the default scan level to `symbol`.
#
# So a called vulnerability exits 3. A vulnerability that reaches the build without a call
# exits 0, and the scanner prints a count of that second kind.
#
# The scanner names no uncalled vulnerability at the default setting. Run
# `govulncheck -show verbose ./...` to read that list.
#
# This target installs nothing, and it fails when the PATH holds no `govulncheck`. Install
# the version that `.github/workflows/ci.yml` pins, or a developer and the job measure two
# different tools.
#
# The scanner reads the Go version of the `go` command on the PATH, so a second toolchain
# reports a second result. The `vuln` job of `.github/workflows/ci.yml` records the
# measurement that separates three Go versions.
vuln:
	govulncheck ./...

# `docs/` is a directory of this repository, so make reads the target name as that
# directory and finds it already up to date. It then prints
# `make: Nothing to be done for 'docs'.` and it exits 0 without a build. The `docs` entry
# of the `.PHONY` line above is what makes this recipe run, and it is not decoration.
#
# `--strict` fails the build on a warning. `mkdocs.yml` raises a broken link and a broken
# anchor to a warning, so a broken link fails this target.
#
# This target installs nothing, and it fails when the PATH holds no `mkdocs`. Install the
# versions that `docs/requirements.txt` pins, or a developer and the CI job build the site
# with two different generators.
docs:
	$(MKDOCS) build --strict

# Epic 16 adds the pre-release cases behind the `prerelease` build tag. Each case builds a
# clean environment, so the tag keeps the cases out of `go test ./...`.
#
# `-count=1` defeats the test cache, because a cached run builds no clean environment and
# proves nothing about the artifact.
#
# `-v` prints the summary that `TestThePrereleaseRunReportsOneSummary` writes. That summary
# names one line for each case of `docs/specs/features/16-pre-release-validation.md`, and
# it separates a case that proves its requirement from a case that waits.
#
# Epic #94 built every case on 2026-08-14. `prereleaseCases` in
# `prerelease_registry_test.go` states which case proves its requirement today, and the
# summary prints that state. A count here would go stale at each such change, so the
# registry states the count and this comment states none.
#
# A case that reads a published tag reads `v0.3.0`, because this project has cut no tag
# since it. So a case can report a failure that the next tag repairs.
#
# FR-prerelease-26 states that this target passes before the maintainer creates the tag.
prerelease:
	go test -tags prerelease -count=1 -v ./...

clean:
	rm -rf bin/ coverage.out .golangci-cache site/
