.PHONY: build test lint lint-cache-check bench clean corpus conformance cover docs fuzz mutate prerelease vuln

# The generator of the documentation site. `docs/requirements.txt` pins it.
# Override it to reach a virtual environment that the PATH does not hold:
#   make docs MKDOCS=.venv/bin/mkdocs
MKDOCS ?= mkdocs

# FR-mutation-2 pins the mutation tool, and this variable is the pin. A minor release of
# `gremlins` can change a configuration key, and it can change a mutation set. So an
# unpinned tool measures a different thing on each run.
#
# The pin lives here and not in `.gremlins.yaml`, because the documented configuration
# schema holds no version key. Verified against
# <https://gremlins.dev/latest/usage/configuration/>, retrieved 2026-08-14.
#
# `v0.6.0` was published 2025-12-05, and the module proxy states that date.
#
# The `go.mod` of `gremlins` v0.6.0 declares `go 1.25`, so a toolchain below go1.25 installs
# no such binary. `CLAUDE.md` `## Stack` names go1.25.13 as the minimum build toolchain of
# this repository, so the two agree. **That figure is a toolchain and never the language
# version**, and `go.mod` of this repository still declares `go 1.24.0`.
GREMLINS_VERSION ?= v0.6.0

# `go install` writes the binary into the `bin` directory of `GOPATH`, and a developer PATH
# need not hold that directory. So the `mutate` recipe names the binary by its path.
GREMLINS ?= $(shell go env GOPATH)/bin/gremlins

# FR-mutation-4 names the package set, and FR-mutation-5 sweeps one package. This variable
# carries both: the default is the named set, and a command line overrides it.
#   make mutate PKG=./internal/parser
#
# The path argument of `gremlins unleash` reads a whole directory tree, so `.` names every
# package of the module. The `exclude-files` list of `.gremlins.yaml` holds `cmd/` and
# `examples/` back, and `docs/specs/features/15-mutation-sweep.md` `## Out of scope` states
# the reason for `cmd/`.
PKG ?= .

# FR-mutation-6 sends the report to `docs/mutation_reports/`, and FR-mutation-10 tracks it.
#
# `gremlins` writes the machine-readable half, and `internal/mutationreport` renders the
# tracked half. Two steps exist because the JSON of `gremlins` v0.6.0 records no tool version
# and no date, and FR-mutation-9 needs both. The doc comment of `internal/mutationreport`
# holds the reading, with the source citations.
#
# The JSON is scratch. `.gitignore` holds `.gremlins/` back, and a reader who wants the
# machine-readable form runs the sweep again.
MUTATION_SCRATCH ?= .gremlins
MUTATION_JSON ?= $(MUTATION_SCRATCH)/last-run.json
MUTATION_REPORT_DIR ?= docs/mutation_reports

# `$(PKG)` reaches both commands below without a quotation, and `$(MUTATION_EXCLUDED)` needs
# one. `PKG` holds a Go package path, which carries no space. `MUTATION_EXCLUDED` holds
# prose, which carries a space and a backtick, so a single quotation stops the shell from
# reading the backtick as a command substitution.
#
# The report states which paths the sweep does not read, under the edge case of
# `docs/specs/features/15-mutation-sweep.md` that names an unswept package.
#
# `TestTheMutationReportNamesEveryExcludedPath` in `mutation_sweep_test.go` fails when this
# value and the `exclude-files` list of `.gremlins.yaml` disagree.
MUTATION_EXCLUDED ?= `cmd/` and `examples/`

# **Never set a threshold key of `.gremlins.yaml` without a change to this recipe.** `Do` in
# `internal/report/report.go` of `gremlins` v0.6.0 calls `reportFindings` before `assess`, so
# the sweep writes a complete JSON file and then exits non-zero when a configured efficacy
# threshold or coverage threshold is not met. make halts a recipe on the first non-zero
# command, so the render step below would never run and the sweep would produce no tracked
# report. FR-mutation-19 states that the sweep blocks no merge, so this repository sets no
# threshold today and `assess` returns nil.

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

# FR-mutation-1 names `gremlins` as the mutation tool, and FR-mutation-3 names this target.
# The sweep changes one expression, runs the test suite, and records whether a test failed.
# A mutation that survives names a test that runs a line and asserts nothing about it.
#
# This target gates nothing. `CLAUDE.md` `## A change is done when` names six steps, and
# this target is none of them. `docs/specs/features/15-mutation-sweep.md` FR-mutation-19
# states that the sweep does not block a merge.
#
# This recipe installs the pinned tool, and the `vuln` recipe below installs nothing. The
# two differ because a `gremlins` binary cannot report its own version. `go install` of the
# module writes no version stamp, so the installed `v0.6.0` binary reports
# `gremlins version dev darwin/arm64`, measured on 2026-08-14. A recipe therefore cannot
# check the binary on the PATH against `GREMLINS_VERSION`. An install of the pin is the one
# path that makes the pin bind.
#
# `go install` reads the module cache on a second run, so it reaches the network once.
#
# The measurement of the first sweep, on 2026-08-14, at `gremlins` v0.6.0, on a 10-core
# machine. `docs/specs/features/15-mutation-sweep.md` `## Open questions` question 1 asked
# for it, and `internal/parser` is the package that question names.
#
#   | Path                 | Mutations | Wall clock | Killed | Lived | Not covered | Timed out |
#   |----------------------|-----------|------------|--------|-------|-------------|-----------|
#   | `./internal/dbcache` | 16        | 3s         | 15     | 1     | 0           | 0         |
#   | `./ja4db`            | 31        | 16s        | 26     | 1     | 4           | 0         |
#   | `./internal/parser`  | 882       | 2m47s      | 493    | 223   | 162         | 4         |
#   | the root package     | 663       | 15m24s     | 484    | 162   | 16          | 1         |
#
# A second sweep of `./internal/parser` ran on 2026-08-14, and it reports 289 s.
# `docs/mutation_reports/2026-08-14-internal-parser.md` holds that figure. **Both figures are
# wall clock, and neither one is a transcription defect.** `Run` in
# `internal/engine/engine.go` of `gremlins` v0.6.0 sets `Elapsed` from `time.Since`.
# `newReport` in `internal/report/report.go` parses that one value, and two readers report it.
# `fullRunReport` prints `Mutation testing completed in %s`, and `fileReport` writes the
# `elapsed_time` field of the JSON. `Duration` of `hako/durafmt` returns the parsed value
# without a rounding, so the two readers report one number. So one run reports one number, and
# two numbers name two runs. The four verdict counts agree, because the mutation set and its
# verdicts are deterministic. Wall clock is not deterministic, because the machine load moves
# it. Round 59 of the `## Changelog` of `docs/specs/spec.md` holds the reading.
#
# So `gremlins` completes a run over `internal/parser` in between 2m47s and 289 s on a
# 10-core machine. Question 1 asks for a run within the CI job limit, and
# `.github/workflows/mutation.yml` sets that limit at 60 minutes. Both runs meet it, so
# question 1 has its answer: the tool is viable for this repository.
#
# The root package costs 1.39 seconds for each mutation, and `internal/parser` costs between
# 0.19 and 0.33 seconds. That is a ratio of between about four and about seven. The reason is
# the suite and not the file count. `go test .` reported `ok 3.941s` and
# `go test ./internal/parser` reported under one second, measured on 2026-08-14. **The
# conformance suite does not reach the sweep**, because it sits behind the `conformance`
# build tag and `.gremlins.yaml` sets no `tags` key.
#
# The whole named set holds 1675 mutations, measured with `gremlins unleash --dry-run .` on
# 2026-08-14: 1473 runnable and 202 not covered. The four rows above hold 1592 of them, and
# the difference of 83 is `internal/capture` at 29, `internal/keylog` at 45 and
# `internal/fuzzprop` at 9. No sweep of those three has run.
#
# The four `TIMED OUT` verdicts of `internal/parser` are real hangs, and not tool artifacts.
# `internal/parser/x509_utils.go:64` holds `for val > 0`, and a `CONDITIONALS_BOUNDARY`
# mutation of it never terminates. The three others sit at
# `internal/parser/ssh_tracker.go:317` and `internal/parser/ssh_tracker.go:318`, which hold
# the loop of `readMessages` and its guard.
#
# **The sweep loads the machine.** The default worker count is the core count, and each
# worker runs its own `go test`. The load average reached 39.67 on a 10-core machine during
# the root sweep, measured on 2026-08-14. A developer who needs a quieter machine sets the
# `workers` key of `.gremlins.yaml`. This repository sets no such key. The schedule of #93
# runs the sweep on a CI runner, and a fixed count would bound that runner too.
mutate:
	go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VERSION)
	mkdir -p $(MUTATION_SCRATCH) $(MUTATION_REPORT_DIR)
	$(GREMLINS) unleash $(PKG) --output $(MUTATION_JSON)
	go run ./internal/mutationreport \
		-input $(MUTATION_JSON) \
		-dir $(MUTATION_REPORT_DIR) \
		-tool-version $(GREMLINS_VERSION) \
		-packages $(PKG) \
		-excluded '$(MUTATION_EXCLUDED)'

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
