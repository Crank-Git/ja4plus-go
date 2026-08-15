package parser

import (
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
// The reader takes the earliest terminator, and the mutant that reads `index >= end` takes
// the latest one. `ja4h.go` measures the body from the returned offset, so the mutant moves
// the JA4H completeness gate.
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
