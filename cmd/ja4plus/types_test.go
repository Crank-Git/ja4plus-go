package main

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go"
)

// These tests hold the ruling of issue #61. The maintainer ruled on 2026-08-13 that
// `--types ja4l` prints both latency values and that `--types ja4ls` prints the server
// value alone. `Crank-Git/ja4plus#605` proposes the same token for the Python port.
// The tests also hold the second defect this issue closes: a token that names no method
// reports an error.

// clientLatencyResult returns one JA4L result that carries the client value.
func clientLatencyResult() ja4plus.FingerprintResult {
	return ja4plus.FingerprintResult{Type: "ja4l", Fingerprint: "JA4L-C=45_64"}
}

// serverLatencyResult returns one JA4L result that carries the server value.
func serverLatencyResult() ja4plus.FingerprintResult {
	return ja4plus.FingerprintResult{Type: "ja4l", Fingerprint: "JA4L-S=13532_57"}
}

func TestTheJA4LTokenAdmitsTheClientValueAndTheServerValue(t *testing.T) {
	filter, err := parseTypes("ja4l")
	if err != nil {
		t.Fatalf("parseTypes returned the error %v, and the token names a method", err)
	}

	if !admitsResult(filter, clientLatencyResult()) {
		t.Error("the token `ja4l` declined the client value, and the ruling admits it")
	}

	if !admitsResult(filter, serverLatencyResult()) {
		t.Error("the token `ja4l` declined the server value, and the ruling admits it")
	}
}

func TestTheJA4LSTokenAdmitsTheServerValueAlone(t *testing.T) {
	filter, err := parseTypes("ja4ls")
	if err != nil {
		t.Fatalf("parseTypes returned the error %v, and the token names a method", err)
	}

	if !admitsResult(filter, serverLatencyResult()) {
		t.Error("the token `ja4ls` declined the server value, and it selects that value")
	}

	if admitsResult(filter, clientLatencyResult()) {
		t.Error("the token `ja4ls` admitted the client value, and it selects the server value alone")
	}
}

func TestTheJA4LSTokenDeclinesTheResultOfAnotherMethod(t *testing.T) {
	filter, err := parseTypes("ja4ls")
	if err != nil {
		t.Fatalf("parseTypes returned the error %v, and the token names a method", err)
	}

	other := ja4plus.FingerprintResult{Type: "ja4t", Fingerprint: "8192_2_1460_2-4-8-1-3"}
	if admitsResult(filter, other) {
		t.Error("the token `ja4ls` admitted a JA4T value, and it names one method")
	}
}

func TestATokenOfAnotherMethodSelectsOnTheTypeAlone(t *testing.T) {
	filter, err := parseTypes("ja4t")
	if err != nil {
		t.Fatalf("parseTypes returned the error %v, and the token names a method", err)
	}

	other := ja4plus.FingerprintResult{Type: "ja4t", Fingerprint: "8192_2_1460_2-4-8-1-3"}
	if !admitsResult(filter, other) {
		t.Error("the token `ja4t` declined a JA4T value")
	}

	if admitsResult(filter, serverLatencyResult()) {
		t.Error("the token `ja4t` admitted a JA4L value")
	}
}

func TestTheCommandAdmitsEveryResultWhenItReadsNoTypesOption(t *testing.T) {
	if !admitsResult(nil, clientLatencyResult()) {
		t.Error("a nil filter declined the client value, and the command then prints nothing")
	}

	if !admitsResult(nil, serverLatencyResult()) {
		t.Error("a nil filter declined the server value, and the command then prints nothing")
	}
}

func TestTheFilterReadsATokenInUpperCase(t *testing.T) {
	filter, err := parseTypes("JA4LS")
	if err != nil {
		t.Fatalf("parseTypes returned the error %v, and the token names a method", err)
	}

	if !admitsResult(filter, serverLatencyResult()) {
		t.Error("the token `JA4LS` declined the server value, and the command reads a token in either case")
	}
}

func TestParseTypesReturnsAnErrorForATokenThatNamesNoMethod(t *testing.T) {
	// The command reported nothing for such a token before issue #61, and it printed no
	// result. The user then read an empty table as a capture that holds no fingerprint.
	filter, err := parseTypes("notatype")
	if err == nil {
		t.Fatal("parseTypes accepted the token `notatype`, and no method carries that name")
	}

	if filter != nil {
		t.Error("parseTypes returned a filter beside the error, and the caller must stop")
	}

	if !strings.Contains(err.Error(), "notatype") {
		t.Errorf("the error is %q, and it names no token the user wrote", err.Error())
	}
}

func TestTheErrorOfAnUnknownTokenNamesEveryMethodTheCommandAccepts(t *testing.T) {
	_, err := parseTypes("ja4l,notatype")
	if err == nil {
		t.Fatal("parseTypes accepted the token `notatype`, and no method carries that name")
	}

	for _, token := range methodTokens {
		if !strings.Contains(err.Error(), token) {
			t.Errorf("the error is %q, and it names no token %q", err.Error(), token)
		}
	}
}

func TestTheTokenListNamesTheServerLatencyMethod(t *testing.T) {
	found := false
	for _, token := range methodTokens {
		if token == "ja4ls" {
			found = true
		}
	}

	if !found {
		t.Error("the token list names no `ja4ls`, and FR-ja4ls-12 states that the command accepts it")
	}
}

func TestTheTokenListNamesEachMethodOnce(t *testing.T) {
	seen := make(map[string]bool, len(methodTokens))
	for _, token := range methodTokens {
		if seen[token] {
			t.Errorf("the token list names %q twice, and the error message then repeats it", token)
		}

		seen[token] = true
	}

	// The library writes eleven methods, and ten fingerprinters carry them. `CLAUDE.md`
	// states that count.
	if len(methodTokens) != 11 {
		t.Errorf("the token list holds %d tokens, and the library writes 11 methods", len(methodTokens))
	}
}
