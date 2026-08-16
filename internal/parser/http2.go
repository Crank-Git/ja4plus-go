package parser

import (
	"bytes"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// HTTP2ClientPreface holds the 24 octets that open the client half of every HTTP/2
// connection.
//
// RFC 9113 section 3.4 states them: `The client connection preface starts with a sequence
// of 24 octets, which in hex notation is: 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a`.
// The reader uses the preface as the gate of the whole walk, because a decrypted stream
// that carries another protocol then costs one prefix comparison.
const HTTP2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// http2VersionToken names the HTTP version of every request this reader returns.
//
// `ja4hNormalizeVersion` in `ja4h.go` reads this token and writes the JA4H version code
// `20`. `testdata/foxio/reference/wireshark/source/packet-ja4.c:1152` writes that code for
// a frame that carries `http2.headers.method`, and
// `testdata/foxio/reference/python/ja4h.py:31` writes it for the `http2` layer.
const http2VersionToken = "HTTP/2"

// The frame header of RFC 9113 section 4.1, and the two frame types that carry a field
// block.
//
// The header holds `Length (24)`, `Type (8)`, `Flags (8)`, `Reserved (1)` and
// `Stream Identifier (31)`, which is 9 octets. RFC 9113 section 6.2 states the HEADERS
// type as `0x01`, and section 6.10 states the CONTINUATION type as `0x09`.
const (
	http2FrameHeaderLength     = 9
	http2FrameTypeHeaders      = 0x01
	http2FrameTypeContinuation = 0x09
)

// The HEADERS frame flags of RFC 9113 section 6.2.
//
// The section states `END_HEADERS (0x04)`, `PADDED (0x08)` and `PRIORITY (0x20)`. A
// CONTINUATION frame defines END_HEADERS alone, and section 6.10 states the same value.
const (
	http2FlagEndHeaders = 0x04
	http2FlagPadded     = 0x08
	http2FlagPriority   = 0x20
)

// http2PriorityFieldLength is the byte count of the three fields that the PRIORITY flag
// adds. RFC 9113 section 6.2 states `[Exclusive (1)]`, `[Stream Dependency (31)]` and
// `[Weight (8)]`.
const http2PriorityFieldLength = 5

// http2MaxDynamicTableSize bounds the HPACK dynamic table of one decode.
//
// **The table is the state that spans packets, and this constant is its bound.** RFC 7541
// section 4.2 states that HTTP/2 sets the maximum with `SETTINGS_HEADER_TABLE_SIZE`, and
// that setting travels on the reverse stream. This reader reads the client stream alone, so
// it never sees the setting and it bounds the table itself.
//
// The value is 16 times the 4096 that RFC 9113 section 6.5.2 states as the initial value,
// so a peer that negotiated a larger table still decodes. A dynamic table size update above
// this bound makes the decoder report an error, and the walk then stops.
const http2MaxDynamicTableSize = 65536

// http2MaxStringLength bounds one header name and one header value.
//
// Every packet is untrusted input, and an HPACK literal states its own length. A crafted
// literal would otherwise allocate whatever length it states.
const http2MaxStringLength = 16384

// http2MaxRequests bounds the requests one call returns.
//
// One decrypted stream carries any number of header blocks, and the caller bounds the
// stream. This bound holds the returned slice as well, so a stream of small blocks costs a
// bounded allocation.
const http2MaxRequests = 256

// HTTP2Requests returns one HTTPRequest for each request that the client half of one
// HTTP/2 connection carries.
//
// stream holds the decrypted client bytes from the first byte of the connection preface. A
// longer buffer is allowed, because the caller passes the whole stream it holds.
// It returns nil for a stream that carries no connection preface, and nil for a stream that
// completes no header block.
// It reads no length field before it bounds that field, and it never panics.
//
// **The whole stream reaches one decoder, and that is not an optimization.** RFC 7541
// section 2.3.2 states that the dynamic table serves the whole connection, so a block that
// names an entry of an earlier block decodes only after that earlier block. A caller that
// passes a suffix of the stream therefore reads wrong header names.
//
// **The dynamic table lives for the length of this call, and the return is its removal
// path.** The decoder is a local value, so the table needs no entry in `CleanupConnection`
// and no entry in `Reset`. `.claude/rules/concurrency.md` states that a new state map needs
// both, and this reader adds no map.
//
// It stops at the first frame whose length passes the end of the stream, and at the first
// header block the decoder does not read. It returns the requests it read up to that frame.
func HTTP2Requests(stream []byte) []*HTTPRequest {
	if !bytes.HasPrefix(stream, []byte(HTTP2ClientPreface)) {
		return nil
	}

	decoder := hpack.NewDecoder(http2MaxDynamicTableSize, nil)
	decoder.SetMaxStringLength(http2MaxStringLength)

	var requests []*HTTPRequest

	var block []byte

	for pos := len(HTTP2ClientPreface); pos+http2FrameHeaderLength <= len(stream); {
		length := int(stream[pos])<<16 | int(stream[pos+1])<<8 | int(stream[pos+2])
		frameType := stream[pos+3]
		flags := stream[pos+4]

		payloadStart := pos + http2FrameHeaderLength

		next := payloadStart + length
		if next > len(stream) {
			break
		}

		payload := stream[payloadStart:next]
		pos = next

		if frameType != http2FrameTypeHeaders && frameType != http2FrameTypeContinuation {
			continue
		}

		if frameType == http2FrameTypeHeaders {
			fragment, ok := http2HeadersFragment(payload, flags)
			if !ok {
				break
			}

			block = append(block[:0], fragment...)
		} else {
			block = append(block, payload...)
		}

		if flags&http2FlagEndHeaders == 0 {
			continue
		}

		fields, err := decoder.DecodeFull(block)
		if err != nil {
			// The dynamic table now disagrees with the encoder, so every later block of this
			// stream decodes to the wrong names. The walk stops rather than reporting them.
			break
		}

		if request := http2RequestOfFields(fields); request != nil {
			requests = append(requests, request)
			if len(requests) >= http2MaxRequests {
				break
			}
		}
	}

	return requests
}

// http2HeadersFragment returns the field block fragment of one HEADERS frame payload.
//
// RFC 9113 section 6.2 states that the PADDED flag adds `[Pad Length (8)]` before the
// fragment and the padding after it, and that the PRIORITY flag adds five more octets
// before the fragment.
// It returns false for a payload whose pad length or priority fields pass the end of the
// frame, because every packet is untrusted input.
func http2HeadersFragment(payload []byte, flags byte) ([]byte, bool) {
	padding := 0

	if flags&http2FlagPadded != 0 {
		if len(payload) < 1 {
			return nil, false
		}

		padding = int(payload[0])
		payload = payload[1:]
	}

	if flags&http2FlagPriority != 0 {
		if len(payload) < http2PriorityFieldLength {
			return nil, false
		}

		payload = payload[http2PriorityFieldLength:]
	}

	if padding > len(payload) {
		return nil, false
	}

	return payload[:len(payload)-padding], true
}

// http2RequestOfFields returns the HTTPRequest of one decoded header block.
//
// It returns nil for a block that names no `:method` pseudo-header, because a trailer
// section and a response section each reach this function and neither one is a request.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1152` reads
// `http2.headers.method` the same way.
//
// The header name list holds the wire order and it holds every name, including each
// pseudo-header and each cookie field. `ja4hHeaderNames` in `ja4h.go` drops the three sets
// that JA4H excludes, so one filter serves the HTTP/1.x path and this path.
func http2RequestOfFields(fields []hpack.HeaderField) *HTTPRequest {
	request := &HTTPRequest{
		Version: http2VersionToken,
		Headers: make(map[string]string, len(fields)),
		Cookies: make(map[string]string),
	}

	for _, field := range fields {
		request.HeaderNames = append(request.HeaderNames, field.Name)

		switch field.Name {
		case ":method":
			request.Method = field.Value
		case ":path":
			request.Path = field.Value
		case "cookie":
			http2AddCookie(request, field.Value)
		default:
			request.Headers[field.Name] = field.Value
		}
	}

	if request.Method == "" {
		return nil
	}

	request.Language = request.Headers["accept-language"]
	request.Referer = request.Headers["referer"]

	return request
}

// http2AddCookie stores one cookie field of an HTTP/2 request.
//
// **One cookie field states one cookie pair, and this reader splits no field on a
// semicolon.** RFC 9113 section 8.2.3 permits a sender to split the Cookie header field
// into separate fields, and this capture shape is what the reference reads.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1174` splits one
// `http2.headers.cookie` field on `=` into two parts and reads no semicolon, and
// `testdata/foxio/reference/python/ja4h.py:59` reads one pair from each entry of the list
// that `tshark` supplies. The HTTP/1.x reader splits the one Cookie header on a semicolon,
// which is what RFC 9113 section 8.2.3 states for that context.
//
// A field that holds no `=` reaches no cookie name.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1176` states the same decline,
// and `ParseHTTPRequest` declines the same field of an HTTP/1.x request.
func http2AddCookie(request *HTTPRequest, field string) {
	index := strings.Index(field, "=")
	if index < 0 {
		return
	}

	name := strings.TrimSpace(field[:index])
	value := strings.TrimSpace(field[index+1:])

	request.Cookies[name] = value
	request.CookieNames = append(request.CookieNames, name)
}
