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

	req := &HTTPRequest{
		Method:  match[1],
		Path:    match[2],
		Version: match[3],
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
	}

	lines := strings.Split(text, "\r\n")

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
