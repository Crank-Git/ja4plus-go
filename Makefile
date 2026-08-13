.PHONY: build test lint lint-cache-check bench clean corpus conformance cover fuzz vuln

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
fuzz:
	@for package in $$(go list ./...); do \
		targets=$$(go test -list '^Fuzz' $$package) || exit 1; \
		for target in $$(echo "$$targets" | grep '^Fuzz' || true); do \
			echo "fuzz: $$target in $$package"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime 30s $$package || exit 1; \
		done; \
	done

# FR-supply-4 holds the command that the `vuln` job of `.github/workflows/ci.yml` runs, so
# that job and a developer run one command.
#
# The exit status separates a called vulnerability from an uncalled one, and FR-supply-2
# and FR-supply-5 need that separation. `TextHandler.Flush` in `internal/scan/text.go` of
# `golang.org/x/vuln` v1.6.0 returns `errVulnerabilitiesFound` only when a finding reaches
# the scan level, `errVulnerabilitiesFound` in `internal/scan/errors.go` carries exit
# status 3, and `parseFlags` in `internal/scan/flags.go` sets the default scan level to
# `symbol`. So a called vulnerability exits 3, and a vulnerability that reaches the build
# without a call exits 0 and prints a count.
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

clean:
	rm -rf bin/ coverage.out .golangci-cache
