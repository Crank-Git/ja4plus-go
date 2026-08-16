package parser

import (
	"bytes"
	"fmt"
	"testing"
)

// http2TestPaths returns the requests that one reader test decodes, in order.
func http2TestPaths(t *testing.T, requests []*HTTPRequest) []string {
	t.Helper()

	paths := make([]string, 0, len(requests))

	for _, request := range requests {
		paths = append(paths, request.Path)
	}

	return paths
}

// TestTheHTTP2ReaderReadsAPrefaceThatTwoChunksCarry states that the preface reaches the
// reader across a chunk boundary. A TCP segment ends at any byte, so the 24 octets of RFC
// 9113 section 3.4 reach the reader in two parts.
func TestTheHTTP2ReaderReadsAPrefaceThatTwoChunksCarry(t *testing.T) {
	encoder, buffer := http2TestEncoder()
	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/one")...)
	stream := http2TestStream(http2TestFrame(0x01, 0x04, 1, block))

	reader := NewHTTP2Reader()

	if requests := reader.Read(stream[:10]); len(requests) != 0 {
		t.Fatalf("the first chunk produced %d requests, and it carries a part of the preface",
			len(requests))
	}

	requests := reader.Read(stream[10:])
	if paths := http2TestPaths(t, requests); len(paths) != 1 || paths[0] != "/one" {
		t.Errorf("the second chunk produced %v, and the stream carries [/one]", paths)
	}
}

// TestTheHTTP2ReaderReadsAFrameThatTwoChunksCarry states that a HEADERS frame reaches the
// reader across a chunk boundary. The reader holds the part it has, and it decodes the
// frame at the chunk that completes it.
func TestTheHTTP2ReaderReadsAFrameThatTwoChunksCarry(t *testing.T) {
	encoder, buffer := http2TestEncoder()
	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/split")...)
	stream := http2TestStream(http2TestFrame(0x01, 0x04, 1, block))

	cut := len(stream) - 3

	reader := NewHTTP2Reader()

	if requests := reader.Read(stream[:cut]); len(requests) != 0 {
		t.Fatalf("the first chunk produced %d requests, and the frame is 3 bytes short",
			len(requests))
	}

	requests := reader.Read(stream[cut:])
	if paths := http2TestPaths(t, requests); len(paths) != 1 || paths[0] != "/split" {
		t.Errorf("the second chunk produced %v, and the stream carries [/split]", paths)
	}
}

// TestTheHTTP2ReaderKeepsTheDynamicTableAcrossTwoChunks holds the state that spans chunks.
//
// RFC 7541 section 2.3.2 states that the dynamic table serves the whole connection, so the
// second block names an entry that the first block inserted. A reader that starts a decoder
// at each chunk reads the wrong header names here.
func TestTheHTTP2ReaderKeepsTheDynamicTableAcrossTwoChunks(t *testing.T) {
	encoder, buffer := http2TestEncoder()

	first := http2TestBlock(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/one",
		"x-probe", "one")
	second := http2TestBlock(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/two",
		"x-probe", "one")

	reader := NewHTTP2Reader()

	opening := reader.Read(append([]byte(HTTP2ClientPreface), http2TestFrame(0x01, 0x04, 1, first)...))
	if len(opening) != 1 {
		t.Fatalf("the first chunk produced %d requests, and it carries 1", len(opening))
	}

	requests := reader.Read(http2TestFrame(0x01, 0x04, 3, second))
	if len(requests) != 1 {
		t.Fatalf("the second chunk produced %d requests, and it carries 1", len(requests))
	}

	if value := requests[0].Headers["x-probe"]; value != "one" {
		t.Errorf("the second block reads x-probe as %q, and the encoder wrote %q", value, "one")
	}

	if requests[0].Path != "/two" {
		t.Errorf("the second block reads the path %q, and the encoder wrote %q",
			requests[0].Path, "/two")
	}
}

// TestTheHTTP2ReaderReturnsTheRequestsAboveTheCallBoundAtTheNextCall states that the
// request bound of one call delays a request, and that it stops no connection. #753 records
// the permanent stop that the bound produced.
func TestTheHTTP2ReaderReturnsTheRequestsAboveTheCallBoundAtTheNextCall(t *testing.T) {
	const total = http2MaxRequests + 44

	encoder, buffer := http2TestEncoder()

	stream := []byte(HTTP2ClientPreface)

	for index := range total {
		block := http2TestBlock(t, encoder, buffer,
			http2TestRequestFields(fmt.Sprintf("/r%d", index))...)
		stream = append(stream, http2TestFrame(0x01, 0x04, uint32(1+2*index), block)...)
	}

	reader := NewHTTP2Reader()

	first := reader.Read(stream)
	if len(first) != http2MaxRequests {
		t.Fatalf("the first call returned %d requests, and the bound is %d",
			len(first), http2MaxRequests)
	}

	second := reader.Read(nil)
	if len(second) != total-http2MaxRequests {
		t.Fatalf("the second call returned %d requests, and the stream holds %d above the bound",
			len(second), total-http2MaxRequests)
	}

	if second[0].Path != fmt.Sprintf("/r%d", http2MaxRequests) {
		t.Errorf("the second call opens at the path %q, and the first call ended at request %d",
			second[0].Path, http2MaxRequests)
	}
}

// TestTheHTTP2ReaderStoresNoByteOfADataFrame states the bound of the reader.
//
// A client sends a request body in a DATA frame, and RFC 9113 section 6.5.2 permits a frame
// of 16777215 octets. The reader counts the payload down and it stores no byte of it, so one
// large body costs no memory.
func TestTheHTTP2ReaderStoresNoByteOfADataFrame(t *testing.T) {
	encoder, buffer := http2TestEncoder()
	block := http2TestBlock(t, encoder, buffer, http2TestRequestFields("/after-the-body")...)

	body := http2TestFrame(0x00, 0x00, 1, bytes.Repeat([]byte{0x5a}, 100000))

	reader := NewHTTP2Reader()
	reader.Read([]byte(HTTP2ClientPreface))

	for offset := 0; offset < len(body); offset += 10000 {
		end := offset + 10000
		if end > len(body) {
			end = len(body)
		}

		reader.Read(body[offset:end])

		if pending := reader.Pending(); pending > http2MaxFieldBlockBytes {
			t.Fatalf("the reader holds %d bytes of the body, and its bound is %d",
				pending, http2MaxFieldBlockBytes)
		}
	}

	if pending := reader.Pending(); pending != 0 {
		t.Errorf("the reader holds %d bytes after the whole body, and the body is complete",
			pending)
	}

	requests := reader.Read(http2TestFrame(0x01, 0x04, 3, block))
	if paths := http2TestPaths(t, requests); len(paths) != 1 || paths[0] != "/after-the-body" {
		t.Errorf("the frame after the body produced %v, and it carries [/after-the-body]", paths)
	}
}

// TestTheHTTP2ReaderReadsNoRequestOfAStreamThatCarriesNoPreface states the gate of the
// walk. A decrypted stream that carries another protocol costs one prefix comparison.
func TestTheHTTP2ReaderReadsNoRequestOfAStreamThatCarriesNoPreface(t *testing.T) {
	reader := NewHTTP2Reader()

	if requests := reader.Read([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); len(requests) != 0 {
		t.Errorf("the reader produced %d requests, and the stream carries no preface", len(requests))
	}

	if !reader.Failed() {
		t.Error("the reader reports no failure, and the stream carries no preface")
	}

	if pending := reader.Pending(); pending != 0 {
		t.Errorf("the reader holds %d bytes of a stream it declined", pending)
	}
}

// TestTheHTTP2ReaderReadsNoFieldBlockAboveTheBlockBound states the second bound of the
// reader. Every packet is untrusted input, and a frame states its own length.
func TestTheHTTP2ReaderReadsNoFieldBlockAboveTheBlockBound(t *testing.T) {
	length := http2MaxFieldBlockBytes + 1

	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		0x01,
		0x04,
		0x00, 0x00, 0x00, 0x01,
	}

	reader := NewHTTP2Reader()

	if requests := reader.Read(append([]byte(HTTP2ClientPreface), frame...)); len(requests) != 0 {
		t.Errorf("the reader produced %d requests, and the frame states %d octets",
			len(requests), length)
	}

	if !reader.Failed() {
		t.Errorf("the reader reports no failure, and the frame states %d octets", length)
	}
}
