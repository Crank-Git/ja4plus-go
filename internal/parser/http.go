package parser

import (
	"regexp"
	"strconv"
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

// methodTokenCharacters holds the characters of a method token. RFC 9110 section 5.6.2
// names the set, and it omits `/`, so a response line such as `HTTP/1.1 200 OK` never
// reads as a request line.
const methodTokenCharacters = "!#$%&'*+\\-.^_`|~0-9A-Za-z"

// requestLineRe reads the method of any request line, and it names no method.
//
// A closed list of nine methods produced no JA4H value for a request that carries a
// method such as `PROPFIND`. FR-parity-47 of `docs/specs/features/08-python-parity.md`
// states the rule, and the port's register row `The JA4H method code for a method outside
// the nine the Rust reference names` holds the reading. The port decided it at its issue
// #219 on 2026-08-08, and `python/ja4h.py:9` reads `method.lower()[:2]` and names no
// method.
//
// The path group reads a path that holds a space. A path group of non-space characters
// read no request line of frame 4 of `testdata/foxio/pcap/gre-erspan-vxlan.pcap`, which
// holds `GET /Hello Arkime HTTP/1.0`, and FoxIO holds a JA4H value for that frame. #527
// records the defect. The group is lazy, so a first line that holds two version tokens
// reaches the earlier one, as the non-space group did.
//
// The expression reads the first line of the payload and no other line. Three parts hold
// that rule, and `ja4l.go` reads `IsHTTPRequest` to pick a measurement point, so a match
// that reads a second line moves a JA4L value. #527 measured each part on 2026-08-14.
//
//   - Each separator reads a space or a horizontal tab. A separator of `\s` reads a line
//     ending too, so the match crossed into the second line and read a request line that no
//     line of the payload holds. The payload `SSH-2.0-OpenSSH_9.6\r\n/a HTTP/1.1\r\n`
//     matched under `\s` and the path group of non-space characters.
//   - The path group reads no carriage return and no line feed. A group of any character
//     reads a bare carriage return, so `GET /a\rFAKE HTTP/1.1\r\n` reached a value and the
//     path held the smuggled text.
//   - The expression is anchored at the start of the payload.
var requestLineRe = regexp.MustCompile(`^([` + methodTokenCharacters + `]+)[ \t]+([^\r\n]+?)[ \t]+(HTTP/\d+\.\d+)`)
var headerLineRe = regexp.MustCompile(`^([^:]+):\s*(.*)$`)

// requestLineLimit bounds the text that IsHTTPRequest matches the request line against.
// IsHTTPRequest reads every TCP payload, and an unbounded match costs the whole stream.
// `ja4plus/utils/http_utils.py:182` of the port holds the same value.
const requestLineLimit = 8192

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
// It reads the two terminators `\r\n\r\n` and `\n\n`, and it returns the earlier of the two.
// `ja4plus/utils/http_utils.py:43` of the Python port holds the same two, so both
// implementations answer alike.
//
// TODO(#298): Read a terminator that mixes the two line endings. A block that ends
// `\n\r\n` matches neither literal, and it reaches no value.
func headerBlockEnd(text string) int {
	end, _ := headerBlockTerminator(text)
	return end
}

// headerBlockTerminator returns the index of the empty line that ends the header block, and
// the byte count of the terminator it reads.
// It returns -1 and 0 when the text holds no such line.
//
// The body starts at the sum of the two, so a caller that measures the body needs both.
func headerBlockTerminator(text string) (int, int) {
	end := -1
	length := 0
	for _, terminator := range []string{"\r\n\r\n", "\n\n"} {
		if index := strings.Index(text, terminator); index >= 0 && (end < 0 || index < end) {
			end = index
			length = len(terminator)
		}
	}
	return end, length
}

// HTTPMessageIsComplete reports whether the payload holds the whole HTTP request.
//
// A request that names a byte count in its `Content-Length` header is complete when the
// payload after the header block reaches that count. A request that names no count is
// complete at the end of the header block.
//
// The maintainer ruled this gate on 2026-08-13, at issue #455.
// The port's issue Crank-Git/ja4plus#607 carries the other half.
// `zeek/ja4h/main.zeek:186` computes the JA4H value in
// `event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)`.
// That file holds no handler that flushes a partial request.
// This gate follows that shape, so a request whose body never completes reaches no value.
//
// A `Content-Length` value that is not a byte count names no count, so the request is
// complete at the end of the header block. That reading keeps a malformed header from
// holding a value for the life of the stream.
func HTTPMessageIsComplete(payload []byte, req *HTTPRequest) bool {
	if req == nil {
		return false
	}

	blockEnd, terminatorLength := headerBlockTerminator(string(payload))
	if blockEnd < 0 {
		return false
	}

	declared, present := httpDeclaredBodyLength(req)
	if !present {
		return true
	}

	return len(payload)-(blockEnd+terminatorLength) >= declared
}

// httpDeclaredBodyLength returns the byte count that the `Content-Length` header of the
// request names.
// It returns false when the request holds no such header, and when the value is not a byte
// count.
func httpDeclaredBodyLength(req *HTTPRequest) (int, bool) {
	value, present := req.Headers["content-length"]
	if !present {
		return 0, false
	}

	count, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || count < 0 {
		return 0, false
	}

	return count, true
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

	// A method the nine prefixes omit reaches this line, and the payload must then hold a
	// whole request line. The nine-prefix test admits `GET ` on its own, and a wider test
	// of the same shape would admit an SSH banner, which starts with method characters and
	// one space. `ja4l.go:270` reads this function, so a payload it admits by mistake moves
	// a JA4L measurement point. `ja4plus/utils/http_utils.py:202-207` of the port holds the
	// same two-step test.
	if len(s) > requestLineLimit {
		s = s[:requestLineLimit]
	}
	return requestLineRe.MatchString(s)
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
	// A block that ends `\r\n\n` keeps the carriage return of the last line ending, so the
	// last header line carries one trailing carriage return. The value trim below removes it.
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
