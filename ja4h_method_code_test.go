package ja4plus

import (
	"strings"
	"testing"
)

// The port's register row `The JA4H method code for a method outside the nine the Rust
// reference names` holds this reading, and the port decided it at its issue #219 on
// 2026-08-08. The three FoxIO references disagree, so the port follows
// `python/ja4h.py:9`, which reads `method.lower()[:2]` and names no method. The
// maintainer ruled on 2026-08-13 that a row the port's register already holds lands in
// this repository as a reading. FR-parity-47 and FR-parity-48 of
// `docs/specs/features/08-python-parity.md` state the rule.
//
// No vector carries a method outside the nine, so these constructed requests are the
// separating input that `.claude/rules/rulings.md` requires.

// ja4hMethodCode returns the first two characters of part a of the JA4H value.
// It fails the test when the packet produces no JA4H value.
func ja4hMethodCode(t *testing.T, request string) string {
	t.Helper()
	pkt := buildTCPPacketWithPayload(t, []byte(request))
	fp := ComputeJA4H(pkt)
	if fp == "" {
		t.Fatalf("the request %q produced no JA4H value", request)
	}
	partA := strings.Split(fp, "_")[0]
	if len(partA) < 2 {
		t.Fatalf("part a %q holds fewer than two characters", partA)
	}
	return partA[:2]
}

// ja4hWebDAVRequest returns one HTTP request that carries the named method.
func ja4hWebDAVRequest(method string) string {
	return method + " /dav HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"\r\n"
}

func TestJA4HWritesPrForThePropfindMethod(t *testing.T) {
	if got := ja4hMethodCode(t, ja4hWebDAVRequest("PROPFIND")); got != "pr" {
		t.Errorf("PROPFIND writes the method code %q, want %q", got, "pr")
	}
}

func TestJA4HWritesMkForTheMkcolMethod(t *testing.T) {
	if got := ja4hMethodCode(t, ja4hWebDAVRequest("MKCOL")); got != "mk" {
		t.Errorf("MKCOL writes the method code %q, want %q", got, "mk")
	}
}

// TestJA4HWritesTwoLowerCaseCharactersForAnyMethodToken holds the rule that
// FR-parity-47 states. A method that the Wireshark map omits writes a code, and a method
// shorter than two characters writes the whole token.
func TestJA4HWritesTwoLowerCaseCharactersForAnyMethodToken(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{"PROPFIND", "pr"},
		{"MKCOL", "mk"},
		{"PROPPATCH", "pr"},
		{"REPORT", "re"},
		{"UNLOCK", "un"},
		{"GET", "ge"},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			if got := ja4hMethodCode(t, ja4hWebDAVRequest(c.method)); got != c.want {
				t.Errorf("%s writes the method code %q, want %q", c.method, got, c.want)
			}
		})
	}
}
