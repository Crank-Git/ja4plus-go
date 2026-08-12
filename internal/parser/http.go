package parser

import (
	"regexp"
	"strings"
)

// HTTPRequest holds parsed HTTP request data with headers in original order.
// Parsed from raw TCP payload bytes without using net/http (which sorts headers).
type HTTPRequest struct {
	Method      string            // e.g. "GET", "POST"
	Path        string            // request path
	Version     string            // e.g. "HTTP/1.1"
	HeaderNames []string          // header names in original wire order, original case
	Headers     map[string]string // lowercase header name -> value
	Cookies     map[string]string // cookie name -> value
	CookieNames []string          // cookie field names in parse order
	Language    string            // Accept-Language value
	Referer     string            // Referer value
}

var requestLineRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+(\S+)\s+(HTTP/\d+\.\d+)`)
var headerLineRe = regexp.MustCompile(`^([^:]+):\s*(.*)$`)

// lineEndingRe matches the two line endings a sender uses.
//
// A sender ends a line with the two bytes `\r\n`, or with one line feed. A parser that
// reads `\r\n` alone reads a line-feed request as one line, so it finds no header.
// `testdata/foxio/pcap/http-empty-useragent.pcap` holds such a request, and FoxIO holds a
// JA4H value for it. #286 records the defect, and the Python port fixed the same defect in
// its issue #193.
var lineEndingRe = regexp.MustCompile(`\r\n|\n`)

// headerBlockEnd returns the index of the empty line that ends the header block.
// It returns -1 when the text holds no such line.
//
// A sender ends the block with `\r\n\r\n`, or with two line feeds. The function returns the
// first of the two, because a request that mixes the two line endings ends at the earlier
// one.
func headerBlockEnd(text string) int {
	end := -1
	for _, terminator := range []string{"\r\n\r\n", "\n\n"} {
		if index := strings.Index(text, terminator); index >= 0 && (end < 0 || index < end) {
			end = index
		}
	}
	return end
}

// IsHTTPRequest returns true if payload looks like an HTTP request.
func IsHTTPRequest(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	prefixes := []string{
		"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
	}
	s := string(payload)
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ParseHTTPRequest parses an HTTP request from raw TCP payload bytes.
// Returns nil if the payload is not a valid HTTP request.
// Returns nil when the header block has not ended, because a later segment carries a header
// that changes the fingerprint. #286 records the early answer this rule replaces.
// Headers are preserved in their original wire order in HeaderNames.
func ParseHTTPRequest(payload []byte) *HTTPRequest {
	if len(payload) == 0 {
		return nil
	}

	text := string(payload)

	match := requestLineRe.FindStringSubmatch(text)
	if match == nil {
		return nil
	}

	blockEnd := headerBlockEnd(text)
	if blockEnd < 0 {
		return nil
	}
	// The body holds any byte, so the header parse reads the header block alone.
	text = text[:blockEnd]

	req := &HTTPRequest{
		Method:  match[1],
		Path:    match[2],
		Version: match[3],
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
	}

	lines := lineEndingRe.Split(text, -1)

	for _, line := range lines[1:] {
		if line == "" || strings.TrimSpace(line) == "" {
			break
		}
		hm := headerLineRe.FindStringSubmatch(line)
		if hm != nil {
			name := strings.TrimSpace(hm[1])
			value := strings.TrimSpace(hm[2])
			req.Headers[strings.ToLower(name)] = value
			req.HeaderNames = append(req.HeaderNames, name)
		}
	}

	// Parse cookies from Cookie header.
	if cookieStr, ok := req.Headers["cookie"]; ok {
		for _, pair := range strings.Split(cookieStr, ";") {
			if idx := strings.Index(pair, "="); idx >= 0 {
				k := strings.TrimSpace(pair[:idx])
				v := strings.TrimSpace(pair[idx+1:])
				req.Cookies[k] = v
				req.CookieNames = append(req.CookieNames, k)
			}
		}
	}

	req.Language = req.Headers["accept-language"]
	req.Referer = req.Headers["referer"]

	return req
}
