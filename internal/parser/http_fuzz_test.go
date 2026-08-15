package parser

import (
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// FuzzParseHTTPRequestReadsAnyPayload proves that ParseHTTPRequest returns for any TCP
// payload. FR-fuzz-5 states the requirement.
func FuzzParseHTTPRequestReadsAnyPayload(f *testing.F) {
	// The parser accepts each seed below. The first ends its header block with a carriage
	// return and a line feed. The second ends it with a line feed alone, because the
	// parser reads both line endings. The third holds a header line with no colon, and
	// the parser skips that line and reads the request.
	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n" +
		"User-Agent: curl/8.4.0\r\nAccept-Language: en-US\r\nCookie: a=1\r\n\r\n"))
	f.Add([]byte("POST /submit HTTP/1.1\nHost: example.com\nContent-Length: 0\n\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost\r\nCookie: \r\n\r\n"))
	// The fourth seed ends its header block with `\n\r\n`, which mixes the two line endings.
	// #298 holds that ruling, and `Crank-Git/ja4plus#614` holds the
	// Python half. The seed corpus reached no mixed terminator before this line, so the
	// target explored the new branch by mutation alone.
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\n\r\n"))

	// The parser rejects each seed below. The first holds no request line. The second
	// ends no header block, so a later segment can carry one more header.
	f.Add([]byte{})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		input := fuzzprop.ExactInput(payload)

		fuzzprop.Check(t, len(input), func() any {
			return ParseHTTPRequest(input)
		})
	})
}
