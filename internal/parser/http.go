package parser

import (
	"bytes"
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

// HoldsAHeaderBlockTerminator reports whether the payload holds the empty line that ends an
// HTTP header block.
//
// `holdsACompleteHTTPRequest` in `ja4l.go` reads this function. That gate held its own pair
// of fixed byte groups until #685, and the pair declined the terminator `\n\r\n`. One reader
// now answers the question for every caller, so the JA4H value and the JA4L measurement
// point read one rule.
//
// **It converts no payload to text, and the JA4L packet path still pays one conversion
// before it reaches this function.** `holdsACompleteHTTPRequest` in `ja4l.go` calls
// `IsHTTPRequest` first on the same bytes, and `IsHTTPRequest` writes `s := string(payload)`.
// Escape analysis reports `internal/parser/http.go:212:14: string(payload) escapes to heap`,
// measured on an Apple M4 on 2026-08-15 UTC. #685 measured one 8192-byte conversion at
// 8192 B and one allocation on the same machine on the same day.
//
// **So the `[]byte` parameter saves a second conversion on the JA4L path, and it saves the
// only conversion of a caller that reads no request line first.** The doc comment of #685
// named the JA4L path as the reason for the whole saving, and batch #708 measured that the
// path already pays one. **Issue #685 is the reversal path.**
func HoldsAHeaderBlockTerminator(payload []byte) bool {
	return headerBlockEnd(payload) >= 0
}

// headerBlockEnd returns the index of the empty line that ends the header block.
// It returns -1 when the payload holds no such line.
func headerBlockEnd(data []byte) int {
	end, _ := headerBlockTerminator(data)
	return end
}

// headerBlockTerminator returns the index of the empty line that ends the header block, and
// the byte count of the terminator it reads.
// It returns -1 and 0 when the payload holds no such line.
//
// The body starts at the sum of the two, so a caller that measures the body needs both.
// A terminator holds 2, 3 or 4 bytes, so no caller computes the body start from a fixed
// count.
//
// **The terminator is one line ending followed by another**, and a sender may write a
// different line ending on each of the two. The maintainer ruled that pattern on 2026-08-13
// UTC, in the port, and re-confirmed it on 2026-08-15 UTC at issue #298.
// `Crank-Git/ja4plus#614` and `Crank-Git/ja4plus#604` hold the Python half.
//
// A pair of literals reads three of the four combinations, and it declines `\n\r\n`.
// `ja4plus/utils/http_utils.py:43` of the port at tag `v1.1.0` holds that pair as
// `HEADER_BLOCK_TERMINATORS = (b"\r\n\r\n", b"\n\n")`.
//
// **This reader answers exactly as the regular expression `(?:\r\n|\n)(?:\r\n|\n)` does.**
// #298 proved that on 349525 strings of length 0 through 9 over the four deciding bytes, and
// on 2000000 random strings, on 2026-08-15 UTC. The two disagree on none of them.
//
// **#298 declined that regular expression on cost.** One 8192-byte payload that holds no
// terminator costs 84 microseconds under the regular expression, 247 nanoseconds under the
// two literals this reader replaces, and 120 nanoseconds here. #298 measured all three on an
// Apple M4 on 2026-08-15 UTC, while this function took a `string`.
//
// **This function costs 91.43, 92.25 and 91.91 nanoseconds on that payload today**, at 0 B
// and 0 allocations, measured on an Apple M4 on 2026-08-15 UTC over three runs of
// `Benchmark_headerBlockTerminator/8192` at `-benchtime=2s`. **#685 moved the parameter from
// `string` to `[]byte`, and that move is why the figure fell from 120.** The two comparators
// above read the `string` form, so a reader who compares them to 92 compares two signatures.
//
// **Every payload of a capture reaches this function**, and an unterminated stream reaches
// it again at each segment, so an attacker who never sends an empty line chooses that cost.
// `Benchmark_headerBlockTerminator` holds the measurement.
func headerBlockTerminator(data []byte) (int, int) {
	for offset := 0; offset < len(data); {
		feed := bytes.IndexByte(data[offset:], '\n')
		if feed < 0 {
			return -1, 0
		}
		feed += offset
		offset = feed + 1

		// The first line ending starts at the carriage return when one precedes the line
		// feed, because the alternation reads `\r\n` before it reads `\n`. So the header
		// block keeps no part of the line ending, and no value trim is load-bearing.
		start := feed
		if feed > 0 && data[feed-1] == '\r' {
			start = feed - 1
		}

		// The second line ending starts at the byte after the first one, and it ends the
		// header block. A line feed that no line ending follows ends a header line instead.
		if offset < len(data) && data[offset] == '\n' {
			return start, offset + 1 - start
		}
		if offset+1 < len(data) && data[offset] == '\r' && data[offset+1] == '\n' {
			return start, offset + 2 - start
		}
	}
	return -1, 0
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

	blockEnd, terminatorLength := headerBlockTerminator(payload)
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

	blockEnd := headerBlockEnd(payload)
	if blockEnd < 0 {
		return nil
	}
	// The body holds any byte, so the header parse reads the header block alone.
	// The terminator match starts at the first line ending of the empty line, so the last
	// header line carries no part of that line ending. The ruling of #298 removed the
	// trailing carriage return that a `\r\n\n` block used to leave.
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
