package parser

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// http2TestBlock returns the HPACK field block of the name and value pairs.
//
// The test encodes with `golang.org/x/net/http2/hpack`, because the decoder under test
// reads that same wire format and a hand-written block would test the encoder instead.
func http2TestBlock(t *testing.T, encoder *hpack.Encoder, buffer *bytes.Buffer, fields ...string) []byte {
	t.Helper()

	if len(fields)%2 != 0 {
		t.Fatalf("the test states %d field words, and one pair states two", len(fields))
	}

	buffer.Reset()

	for i := 0; i < len(fields); i += 2 {
		if err := encoder.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}); err != nil {
			t.Fatalf("WriteField returned %v", err)
		}
	}

	return append([]byte{}, buffer.Bytes()...)
}

// http2TestEncoder returns one HPACK encoder and the buffer it writes to.
func http2TestEncoder() (*hpack.Encoder, *bytes.Buffer) {
	buffer := &bytes.Buffer{}

	return hpack.NewEncoder(buffer), buffer
}

// http2TestFrame returns one HTTP/2 frame. RFC 9113 section 4.1 states the 9-octet header.
func http2TestFrame(frameType byte, flags byte, streamID uint32, payload []byte) []byte {
	length := len(payload)

	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		frameType,
		flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}

	return append(frame, payload...)
}

// http2TestStream returns one client stream that opens with the connection preface.
func http2TestStream(frames ...[]byte) []byte {
	stream := []byte(HTTP2ClientPreface)

	for _, frame := range frames {
		stream = append(stream, frame...)
	}

	return stream
}

// http2TestRequestFields returns the four pseudo-header fields of one GET request.
func http2TestRequestFields(path string) []string {
	return []string{":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", path}
}

func TestHTTP2RequestsReadsTheHeaderNamesInWireOrder(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	fields := append(http2TestRequestFields("/one"),
		"user-agent", "probe", "accept", "*/*", "accept-language", "en-US,en;q=0.9")

	block := http2TestBlock(t, encoder, buffer, fields...)
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block))

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 1", len(requests))
	}

	request := requests[0]

	if request.Method != "GET" {
		t.Errorf("the request states the method %q, and the block states GET", request.Method)
	}

	if request.Path != "/one" {
		t.Errorf("the request states the path %q, and the block states /one", request.Path)
	}

	if request.Version != http2VersionToken {
		t.Errorf("the request states the version %q, and an HTTP/2 request states %q",
			request.Version, http2VersionToken)
	}

	wanted := []string{":method", ":authority", ":scheme", ":path", "user-agent", "accept", "accept-language"}
	if len(request.HeaderNames) != len(wanted) {
		t.Fatalf("the request holds %d header names, and the block holds %d",
			len(request.HeaderNames), len(wanted))
	}

	for index, name := range wanted {
		if request.HeaderNames[index] != name {
			t.Errorf("header name %d reads %q, and the block writes %q",
				index, request.HeaderNames[index], name)
		}
	}

	if request.Language != "en-US,en;q=0.9" {
		t.Errorf("the request states the language %q, and the block states en-US,en;q=0.9",
			request.Language)
	}
}

func TestHTTP2RequestsReadsOneCookiePairFromEachCookieField(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	fields := append(http2TestRequestFields("/two"),
		"cookie", "a=1", "cookie", "b=2", "referer", "https://example.test/")

	block := http2TestBlock(t, encoder, buffer, fields...)
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block))

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 1", len(requests))
	}

	request := requests[0]

	if len(request.CookieNames) != 2 {
		t.Fatalf("the request holds %d cookie names, and the block holds 2", len(request.CookieNames))
	}

	if request.CookieNames[0] != "a" || request.CookieNames[1] != "b" {
		t.Errorf("the cookie names read %v, and the block writes a and b", request.CookieNames)
	}

	if request.Cookies["a"] != "1" || request.Cookies["b"] != "2" {
		t.Errorf("the cookie values read %v, and the block writes 1 and 2", request.Cookies)
	}

	if request.Referer != "https://example.test/" {
		t.Errorf("the request states the referer %q, and the block states https://example.test/",
			request.Referer)
	}
}

func TestHTTP2RequestsSplitsNoCookieFieldOnASemicolon(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1174` splits one
	// `http2.headers.cookie` field on `=` into two parts, and it reads no semicolon.
	fields := append(http2TestRequestFields("/three"), "cookie", "a=1; b=2")

	block := http2TestBlock(t, encoder, buffer, fields...)
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block))

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 1", len(requests))
	}

	request := requests[0]

	if len(request.CookieNames) != 1 || request.CookieNames[0] != "a" {
		t.Fatalf("the cookie names read %v, and the reference reads one name a", request.CookieNames)
	}

	if request.Cookies["a"] != "1; b=2" {
		t.Errorf("the cookie value reads %q, and the reference reads `1; b=2`", request.Cookies["a"])
	}
}

func TestHTTP2RequestsDropsACookieFieldThatHoldsNoEqualsSign(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	fields := append(http2TestRequestFields("/four"), "cookie", "novalue")

	block := http2TestBlock(t, encoder, buffer, fields...)
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block))

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 1", len(requests))
	}

	if len(requests[0].CookieNames) != 0 {
		t.Errorf("the request holds %d cookie names, and the reference reads none",
			len(requests[0].CookieNames))
	}
}

func TestHTTP2RequestsReadsAHeaderBlockThatOneContinuationFrameCompletes(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, append(http2TestRequestFields("/five"),
		"user-agent", "probe")...)

	split := len(block) / 2

	stream := http2TestStream(
		http2TestFrame(http2FrameTypeHeaders, 0, 1, block[:split]),
		http2TestFrame(http2FrameTypeContinuation, http2FlagEndHeaders, 1, block[split:]),
	)

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the two frames carry 1", len(requests))
	}

	if requests[0].Path != "/five" {
		t.Errorf("the request states the path %q, and the block states /five", requests[0].Path)
	}
}

func TestHTTP2RequestsReadsAHeadersFrameThatCarriesPaddingAndPriority(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/six")...)

	payload := []byte{0x04}
	payload = append(payload, 0x00, 0x00, 0x00, 0x00, 0x10)
	payload = append(payload, block...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders,
		http2FlagEndHeaders|http2FlagPadded|http2FlagPriority, 1, payload))

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the frame carries 1", len(requests))
	}

	if requests[0].Path != "/six" {
		t.Errorf("the request states the path %q, and the block states /six", requests[0].Path)
	}
}

func TestHTTP2RequestsReturnsNoRequestForATruncatedHeaderBlock(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/seven")...)

	// The frame header states the whole block, and the stream stops inside it. Every
	// length field of the walk is bounds-checked, so this stream reaches no slice.
	frame := http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block)
	stream := http2TestStream(frame[:len(frame)-3])

	if requests := HTTP2Requests(stream); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests, and the block is truncated", len(requests))
	}
}

func TestHTTP2RequestsReturnsNoRequestForAStreamTruncatedInsideAFrameHeader(t *testing.T) {
	stream := append([]byte(HTTP2ClientPreface), 0x00, 0x00, 0x10, 0x01)

	if requests := HTTP2Requests(stream); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests, and the frame header is truncated",
			len(requests))
	}
}

func TestHTTP2RequestsReturnsNoRequestForAPadLengthThatPassesTheFrame(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/eight")...)

	payload := append([]byte{0xff}, block...)
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders,
		http2FlagEndHeaders|http2FlagPadded, 1, payload))

	if requests := HTTP2Requests(stream); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests, and the pad length passes the frame",
			len(requests))
	}
}

func TestHTTP2RequestsReturnsNoRequestForAStreamThatCarriesNoPreface(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/nine")...)
	stream := http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block)

	if requests := HTTP2Requests(stream); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests, and the stream carries no preface",
			len(requests))
	}
}

func TestHTTP2RequestsKeepsTheDynamicTableAcrossTwoHeaderBlocks(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	// One encoder writes both blocks, so the second block names an entry that the first
	// block inserted. A decoder that starts a new dynamic table for each block reads no
	// such entry. RFC 7541 section 2.3.2 states that the table serves the whole connection.
	first := http2TestBlock(t, encoder, buffer, append(http2TestRequestFields("/ten"),
		"x-probe", "a-value-that-the-static-table-does-not-hold")...)
	second := http2TestBlock(t, encoder, buffer, append(http2TestRequestFields("/eleven"),
		"x-probe", "a-value-that-the-static-table-does-not-hold")...)

	if len(second) >= len(first) {
		t.Fatalf("the second block holds %d bytes and the first holds %d, so the encoder indexed nothing",
			len(second), len(first))
	}

	stream := http2TestStream(
		http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, first),
		http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 3, second),
	)

	requests := HTTP2Requests(stream)
	if len(requests) != 2 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 2", len(requests))
	}

	if requests[1].Headers["x-probe"] != "a-value-that-the-static-table-does-not-hold" {
		t.Errorf("the second request states the probe value %q, and the first block inserted it",
			requests[1].Headers["x-probe"])
	}
}

func TestHTTP2RequestsReturnsNoRequestForAHeaderBlockThatNamesNoMethod(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, "x-trailer", "value")
	stream := http2TestStream(http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block))

	if requests := HTTP2Requests(stream); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests, and the block names no method",
			len(requests))
	}
}

func TestHTTP2RequestsStepsOverAFrameOfAnotherType(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/twelve")...)

	stream := http2TestStream(
		// A SETTINGS frame opens every connection, and this walk reads no setting.
		http2TestFrame(0x04, 0x00, 0, []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x64}),
		http2TestFrame(http2FrameTypeHeaders, http2FlagEndHeaders, 1, block),
		http2TestFrame(0x00, 0x01, 1, []byte("a body")),
	)

	requests := HTTP2Requests(stream)
	if len(requests) != 1 {
		t.Fatalf("HTTP2Requests returned %d requests, and the stream carries 1", len(requests))
	}

	if requests[0].Path != "/twelve" {
		t.Errorf("the request states the path %q, and the block states /twelve", requests[0].Path)
	}
}

func TestHTTP2RequestsReturnsNoRequestForAnEmptyStream(t *testing.T) {
	if requests := HTTP2Requests(nil); len(requests) != 0 {
		t.Errorf("HTTP2Requests returned %d requests for a nil stream", len(requests))
	}
}
