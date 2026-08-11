.PHONY: build test lint bench clean corpus conformance cover fuzz

build:
	go build -o bin/ja4plus ./cmd/ja4plus

test:
	go test -v -race ./...

lint:
	golangci-lint run

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

clean:
	rm -rf bin/ coverage.out
