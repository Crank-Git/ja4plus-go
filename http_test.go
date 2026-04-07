package ja4plus

import (
	"testing"
)

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
