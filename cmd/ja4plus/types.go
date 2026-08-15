package main

import (
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go"
)

// methodTokens names every token that `--types` accepts, in the order the processor runs
// the fingerprinters.
// The list names a method rather than a fingerprinter, so it holds `ja4ls` beside `ja4l`.
// One fingerprinter writes those two methods, and the maintainer ruled on 2026-08-13 that
// each one reaches its own token. Issue #61 records the ruling.
var methodTokens = []string{
	"ja4",
	"ja4s",
	"ja4h",
	"ja4t",
	"ja4ts",
	"ja4l",
	"ja4ls",
	"ja4x",
	"ja4ssh",
	"ja4d",
	"ja4d6",
}

// serverLatencyPrefix opens the fingerprint that carries the JA4LS value.
// The JA4L fingerprinter reports the type `ja4l` for both latency methods, so the label of
// the fingerprint is the one discriminator the command holds. `conformance_test.go:347-362`
// reads the same label, and the Python port reads it at
// `ja4plus/fingerprinters/ja4l.py:182`.
const serverLatencyPrefix = "JA4L-S="

// parseTypes returns the set of method tokens that the `--types` argument names.
// It returns an error when one token names no method, and the error names every token the
// command accepts. Before issue #61 the command accepted such a token, printed no result
// and reported nothing, so a user read an empty table as a capture that holds no
// fingerprint.
// It returns an empty set for an argument that holds no token, which selects no result.
func parseTypes(argument string) (map[string]bool, error) {
	accepted := make(map[string]bool, len(methodTokens))
	for _, token := range methodTokens {
		accepted[token] = true
	}

	filter := make(map[string]bool)

	var unknown []string

	for _, token := range strings.Split(argument, ",") {
		token = strings.TrimSpace(strings.ToLower(token))
		if token == "" {
			continue
		}

		if !accepted[token] {
			unknown = append(unknown, token)
			continue
		}

		filter[token] = true
	}

	if len(unknown) > 0 {
		return nil, fmt.Errorf("--types names no method: %s\nthe methods are: %s",
			strings.Join(unknown, ", "), strings.Join(methodTokens, ", "))
	}

	return filter, nil
}

// admitsResult reports whether the filter selects the result.
// A nil filter admits every result, because the user passed no `--types` option.
// A result of the JA4L fingerprinter carries the type `ja4l` for both latency methods, so
// this function reads the label of the fingerprint. The token `ja4l` admits both values,
// and the token `ja4ls` admits the server value alone.
func admitsResult(filter map[string]bool, result ja4plus.FingerprintResult) bool {
	if filter == nil {
		return true
	}

	method := strings.ToLower(result.Type)
	if method == "ja4l" && strings.HasPrefix(result.Fingerprint, serverLatencyPrefix) {
		return filter["ja4l"] || filter["ja4ls"]
	}

	return filter[method]
}
