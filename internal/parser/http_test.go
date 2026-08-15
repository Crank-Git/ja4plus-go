package parser

import (
	"strconv"
	"strings"
	"testing"
)

// The mutation sweep of 2026-08-14 earned the two tests below. No test named
// `headerBlockTerminator` or `HTTPMessageIsComplete`, so the body boundary of JA4H reached
// no assertion of this package.
// `docs/mutation_settlements/2026-08-14-internal-parser.md` records them as S2.

// TestHeaderBlockTerminatorReadsTheEarliestTerminator holds the choice between the two
// terminators that `headerBlockTerminator` reads.
//
// A body holds any byte, so a body can hold `\n\n` after the header block ends at `\r\n\r\n`.
// The reader takes the earliest terminator, and `ja4h.go` measures the body from the returned
// offset. A reader that takes a later terminator therefore moves the JA4H completeness gate.
//
// **The comparison that the sweep of 2026-08-14 mutated no longer exists.** #298 replaced the
// two-literal loop with a byte scan, and `headerBlockTerminator` now states the choice. It
// returns the first line ending that another line ending follows. **#298 declined a regular
// expression on cost**, and the doc comment of that function holds the benchmark. This test
// holds the behavior, and it holds no mutant.
func TestHeaderBlockTerminatorReadsTheEarliestTerminator(t *testing.T) {
	text := "POST /x HTTP/1.1\r\nHost: example.com\r\n\r\nfirst\n\nsecond"

	want := strings.Index(text, "\r\n\r\n")
	if later := strings.Index(text, "\n\n"); later <= want {
		t.Fatalf("the test text holds `\\n\\n` at %d and `\\r\\n\\r\\n` at %d, and the case needs the later one second",
			later, want)
	}

	end, length := headerBlockTerminator(text)
	if end != want {
		t.Fatalf("headerBlockTerminator read the terminator at %d, and the earliest one sits at %d", end, want)
	}
	if length != 4 {
		t.Fatalf("headerBlockTerminator read a terminator of %d bytes, and `\\r\\n\\r\\n` holds 4", length)
	}
}

// TestHTTPMessageIsCompleteMeasuresTheBodyFromTheHeaderBlock holds the byte count that the
// completeness gate compares against `Content-Length`.
//
// The body of this request holds `\n\n`, so a reader that takes the latest terminator
// measures 2 body bytes where the request carries 6. The request is then never complete, and
// `ja4h.go` emits no JA4H value for it.
func TestHTTPMessageIsCompleteMeasuresTheBodyFromTheHeaderBlock(t *testing.T) {
	const body = "ab\n\ncd"
	payload := []byte("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\n" + body)

	req := ParseHTTPRequest(payload)
	if req == nil {
		t.Fatalf("ParseHTTPRequest read no request of the test payload")
	}
	if len(body) != 6 {
		t.Fatalf("the test body holds %d bytes, and the `Content-Length` header states 6", len(body))
	}

	if !HTTPMessageIsComplete(payload, req) {
		t.Fatalf("HTTPMessageIsComplete declined a request whose body holds the declared 6 bytes")
	}
}

// The four tests below hold the ruling of 2026-08-13 UTC. The maintainer ruled that the
// header block terminator is one line ending followed by another, and re-confirmed that
// ruling on 2026-08-15 UTC.
// Issue #298 holds the Go half. `Crank-Git/ja4plus#614` and `Crank-Git/ja4plus#604` hold
// the Python half, and the port owns the consolidation of those two.
// No capture of the FoxIO corpus reaches a mixed terminator, so a constructed request is
// the only thing that separates the two candidate answers.

// TestParseHTTPRequestReadsABlockThatEndsLineFeedThenCarriageReturnLineFeed builds the
// request that reached no value before the ruling.
//
// A sender ends the last header line with one line feed, and it ends the empty line with
// `\r\n`. The terminator is then `\n\r\n`, which neither `\r\n\r\n` nor `\n\n` matches. The
// parse returned nil, so the fingerprinter produced no JA4H value for the stream.
// #298 and `Crank-Git/ja4plus#614` hold the ruling, and each one is the reversal path.
func TestParseHTTPRequestReadsABlockThatEndsLineFeedThenCarriageReturnLineFeed(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: a\n\r\n")

	req := ParseHTTPRequest(payload)
	if req == nil {
		t.Fatalf("ParseHTTPRequest read no request of a header block that ends `\\n\\r\\n`")
	}
	if len(req.HeaderNames) != 1 || req.HeaderNames[0] != "Host" {
		t.Fatalf("ParseHTTPRequest read the header names %v, and the request holds `Host` alone", req.HeaderNames)
	}
	if req.Headers["host"] != "a" {
		t.Fatalf("ParseHTTPRequest read the `Host` value %q, and the request states `a`", req.Headers["host"])
	}
}

// TestParseHTTPRequestReadsABlockThatEndsCarriageReturnLineFeedThenLineFeed holds the case
// that passed by accident before the ruling.
//
// `\n\n` is a substring of `\r\n\n`, so the two literals found a terminator one byte late.
// The last header line then carried a trailing carriage return, and the value trim removed
// it. **The ruled pattern starts the match at the carriage return**, so the header block
// holds no part of the line ending. This test states that offset, because the old path
// depended on the value trim and no test held that dependency.
// #298 and `Crank-Git/ja4plus#614` hold the ruling, and each one is the reversal path.
func TestParseHTTPRequestReadsABlockThatEndsCarriageReturnLineFeedThenLineFeed(t *testing.T) {
	text := "GET / HTTP/1.1\r\nHost: a\r\n\n"

	end, length := headerBlockTerminator(text)
	want := strings.Index(text, "\r\n\n")
	if end != want {
		t.Fatalf("headerBlockTerminator read the terminator at %d, and the empty line starts at %d", end, want)
	}
	if length != 3 {
		t.Fatalf("headerBlockTerminator read a terminator of %d bytes, and `\\r\\n\\n` holds 3", length)
	}
	if header := text[:end]; strings.HasSuffix(header, "\r") {
		t.Fatalf("the header block %q ends with a carriage return, and the value trim must not be the thing that removes it", header)
	}

	req := ParseHTTPRequest([]byte(text))
	if req == nil {
		t.Fatalf("ParseHTTPRequest read no request of a header block that ends `\\r\\n\\n`")
	}
	if req.Headers["host"] != "a" {
		t.Fatalf("ParseHTTPRequest read the `Host` value %q, and the request states `a`", req.Headers["host"])
	}
}

// TestHeaderBlockTerminatorReadsEachPairOfLineEndings states the byte count of each of the
// four terminators, because a terminator now holds 2, 3 or 4 bytes.
//
// A caller measures the body from the sum of the offset and the count, so a fixed count
// moves the body boundary of JA4H.
// #298 and `Crank-Git/ja4plus#614` hold the ruling, and each one is the reversal path.
func TestHeaderBlockTerminatorReadsEachPairOfLineEndings(t *testing.T) {
	const head = "GET / HTTP/1.1\r\nHost: a"
	cases := []struct {
		name       string
		terminator string
		length     int
	}{
		{"carriage return line feed twice", "\r\n\r\n", 4},
		{"line feed twice", "\n\n", 2},
		{"line feed then carriage return line feed", "\n\r\n", 3},
		{"carriage return line feed then line feed", "\r\n\n", 3},
	}

	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			text := head + one.terminator + "body"

			end, length := headerBlockTerminator(text)
			if end != len(head) {
				t.Fatalf("headerBlockTerminator read the terminator at %d, and the empty line starts at %d", end, len(head))
			}
			if length != one.length {
				t.Fatalf("headerBlockTerminator read a terminator of %d bytes, and this one holds %d", length, one.length)
			}
			if body := text[end+length:]; body != "body" {
				t.Fatalf("the body starts at %q, and the request carries `body`", body)
			}
		})
	}
}

// TestHeaderBlockTerminatorEndsTheBlockAtTheFirstEmptyLine holds the body boundary of a
// request whose body starts with a line ending.
//
// The last header line of this request ends with one line feed, and two empty lines follow
// it. **The header block ends at the first of those two, and the second one is the first two
// bytes of the body.** The two literals read `\r\n\r\n` across both empty lines, so they
// started the body two bytes late.
//
// **This is the one shape where the ruling of #298 moves the body boundary.** A differential
// run of 3000000 random texts on 2026-08-15 UTC moved the body start on 75302 of them, and
// every one of those mixes the two line endings. **No text of one line ending moved.**
// #298 and `Crank-Git/ja4plus#614` hold the ruling, and each one is the reversal path.
func TestHeaderBlockTerminatorEndsTheBlockAtTheFirstEmptyLine(t *testing.T) {
	const head = "GET / HTTP/1.1\r\nHost: a"
	text := head + "\n\r\n" + "\r\nbody"

	end, length := headerBlockTerminator(text)
	if end != len(head) {
		t.Fatalf("headerBlockTerminator read the terminator at %d, and the first empty line starts at %d", end, len(head))
	}
	if length != 3 {
		t.Fatalf("headerBlockTerminator read a terminator of %d bytes, and `\\n\\r\\n` holds 3", length)
	}
	if body := text[end+length:]; body != "\r\nbody" {
		t.Fatalf("the body is %q, and the second empty line is the first two bytes of it", body)
	}
}

// TestHTTPMessageIsCompleteMeasuresTheBodyAfterAMixedTerminator holds the completeness gate
// against a terminator of three bytes.
//
// The gate adds the offset and the byte count of the terminator, so a mixed terminator
// reaches the same body boundary as an unmixed one.
// #298 and `Crank-Git/ja4plus#614` hold the ruling, and each one is the reversal path.
func TestHTTPMessageIsCompleteMeasuresTheBodyAfterAMixedTerminator(t *testing.T) {
	payload := []byte("POST /x HTTP/1.1\nHost: a\nContent-Length: 4\n\r\nabcd")

	req := ParseHTTPRequest(payload)
	if req == nil {
		t.Fatalf("ParseHTTPRequest read no request of a header block that ends `\\n\\r\\n`")
	}
	if !HTTPMessageIsComplete(payload, req) {
		t.Fatalf("HTTPMessageIsComplete declined a request whose body holds the declared 4 bytes")
	}

	short := []byte("POST /x HTTP/1.1\nHost: a\nContent-Length: 4\n\r\nabc")
	shortReq := ParseHTTPRequest(short)
	if shortReq == nil {
		t.Fatalf("ParseHTTPRequest read no request of the short payload")
	}
	if HTTPMessageIsComplete(short, shortReq) {
		t.Fatalf("HTTPMessageIsComplete admitted a request whose body holds 3 of the declared 4 bytes")
	}
}

// Benchmark_headerBlockTerminator measures the reader against the payload that costs the
// most: one that holds no terminator at all.
//
// **Every payload of a capture reaches this function, and an unterminated stream reaches it
// again at each segment.** So an attacker who never sends an empty line chooses this cost.
// #298 declined a regular expression for that reason, and this benchmark is the measurement.
// The self-review of #298 measured `(?:\r\n|\n)(?:\r\n|\n)` at 84 microseconds for the 8192
// byte case, against 247 nanoseconds for the two-literal reader it replaced, on 2026-08-15
// UTC.
func Benchmark_headerBlockTerminator(b *testing.B) {
	sizes := []int{8192, 1 << 20}
	for _, size := range sizes {
		text := strings.Repeat("A", size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if end, _ := headerBlockTerminator(text); end >= 0 {
					b.Fatalf("the benchmark payload holds a terminator at %d, and it must hold none", end)
				}
			}
		})
	}
}

func TestParseHTTPRequest_ValidGET(t *testing.T) {
	raw := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot/1.0\r\nAccept: text/html\r\n\r\n"
	req := ParseHTTPRequest([]byte(raw))
	if req == nil {
		t.Fatal("expected non-nil HTTPRequest")
	}
	if req.Method != "GET" {
		t.Errorf("Method: got %q, want %q", req.Method, "GET")
	}
	if req.Path != "/index.html" {
		t.Errorf("Path: got %q, want %q", req.Path, "/index.html")
	}
	if req.Version != "HTTP/1.1" {
		t.Errorf("Version: got %q, want %q", req.Version, "HTTP/1.1")
	}
	if len(req.HeaderNames) != 3 {
		t.Fatalf("HeaderNames: got %d, want 3", len(req.HeaderNames))
	}
	expected := []string{"Host", "User-Agent", "Accept"}
	for i, name := range expected {
		if req.HeaderNames[i] != name {
			t.Errorf("HeaderNames[%d]: got %q, want %q", i, req.HeaderNames[i], name)
		}
	}
}

func TestParseHTTPRequest_POSTWithCookies(t *testing.T) {
	raw := "POST /api/data HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; user=john\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"
	req := ParseHTTPRequest([]byte(raw))
	if req == nil {
		t.Fatal("expected non-nil HTTPRequest")
	}
	if req.Method != "POST" {
		t.Errorf("Method: got %q, want %q", req.Method, "POST")
	}
	if len(req.Cookies) != 2 {
		t.Fatalf("Cookies: got %d, want 2", len(req.Cookies))
	}
	if req.Cookies["session"] != "abc123" {
		t.Errorf("Cookies[session]: got %q, want %q", req.Cookies["session"], "abc123")
	}
	if req.Cookies["user"] != "john" {
		t.Errorf("Cookies[user]: got %q, want %q", req.Cookies["user"], "john")
	}
	if len(req.CookieNames) != 2 {
		t.Fatalf("CookieNames: got %d, want 2", len(req.CookieNames))
	}
	if req.CookieNames[0] != "session" || req.CookieNames[1] != "user" {
		t.Errorf("CookieNames: got %v, want [session user]", req.CookieNames)
	}
}

func TestParseHTTPRequest_NonHTTP(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01, 0x00, 0xFF} // TLS ClientHello prefix
	req := ParseHTTPRequest(data)
	if req != nil {
		t.Errorf("expected nil for non-HTTP data, got %+v", req)
	}
}

func TestParseHTTPRequest_EmptyPayload(t *testing.T) {
	req := ParseHTTPRequest(nil)
	if req != nil {
		t.Error("expected nil for nil payload")
	}
	req = ParseHTTPRequest([]byte{})
	if req != nil {
		t.Error("expected nil for empty payload")
	}
}

func TestParseHTTPRequest_HeaderOrderPreserved(t *testing.T) {
	// Critical: headers must appear in wire order, not sorted.
	raw := "GET / HTTP/1.1\r\nZebra: 1\r\nAlpha: 2\r\nMiddle: 3\r\nBeta: 4\r\n\r\n"
	req := ParseHTTPRequest([]byte(raw))
	if req == nil {
		t.Fatal("expected non-nil HTTPRequest")
	}
	expected := []string{"Zebra", "Alpha", "Middle", "Beta"}
	if len(req.HeaderNames) != len(expected) {
		t.Fatalf("HeaderNames count: got %d, want %d", len(req.HeaderNames), len(expected))
	}
	for i, name := range expected {
		if req.HeaderNames[i] != name {
			t.Errorf("HeaderNames[%d]: got %q, want %q", i, req.HeaderNames[i], name)
		}
	}
}

func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect bool
	}{
		{"GET", []byte("GET / HTTP/1.1\r\n"), true},
		{"POST", []byte("POST /api HTTP/1.1\r\n"), true},
		{"PUT", []byte("PUT /resource HTTP/1.1\r\n"), true},
		{"DELETE", []byte("DELETE /item HTTP/1.1\r\n"), true},
		{"TLS", []byte{0x16, 0x03, 0x01}, false},
		{"Empty", []byte{}, false},
		{"Nil", nil, false},
		{"Random", []byte("Hello World"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHTTPRequest(tt.input)
			if got != tt.expect {
				t.Errorf("IsHTTPRequest(%q): got %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestParseHTTPRequest_LanguageAndReferer(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nAccept-Language: en-US,en;q=0.9\r\nReferer: https://example.com\r\n\r\n"
	req := ParseHTTPRequest([]byte(raw))
	if req == nil {
		t.Fatal("expected non-nil HTTPRequest")
	}
	if req.Language != "en-US,en;q=0.9" {
		t.Errorf("Language: got %q, want %q", req.Language, "en-US,en;q=0.9")
	}
	if req.Referer != "https://example.com" {
		t.Errorf("Referer: got %q, want %q", req.Referer, "https://example.com")
	}
}
