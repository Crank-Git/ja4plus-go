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
// `20`. `testdata/foxio/reference/wireshark/source/packet-ja4.c:1152-1153` writes that code
// for a frame that carries `http2.headers.method`, and
// `testdata/foxio/reference/python/ja4h.py:31-32` writes it for the `http2` layer.
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
// One decrypted stream carries any number of header blocks, and one call reads any number of
// them. This bound holds the returned slice, so a chunk of small blocks costs a bounded
// allocation.
//
// **The bound delays a request, and it stops no connection.** The reader keeps the bytes it
// has not read, so the next call returns the requests above the bound. **#753 records the
// permanent stop that this bound produced**, and `HTTP2Reader` is the repair.
const http2MaxRequests = 256

// http2MaxFieldBlockBytes bounds the field block that one reader holds.
//
// The bound covers one HEADERS or CONTINUATION frame payload, and it covers the block that
// several CONTINUATION frames build. Every packet is untrusted input, and a frame states its
// own length, so a frame above this bound would otherwise hold whatever length it states.
//
// RFC 9113 section 6.5.2 states the initial SETTINGS_MAX_FRAME_SIZE as 16384 octets, and it
// permits a peer to raise that setting to 16777215. **This reader sees no setting of the
// server**, because it reads the client stream alone. So it bounds the block itself, at four
// times the initial frame size.
const http2MaxFieldBlockBytes = 65536

// HTTP2Reader decodes the client half of one HTTP/2 connection, one chunk at a time.
//
// **One reader holds one HPACK decoder, and that is the reason this type exists.** RFC 7541
// section 2.3.2 states that the dynamic table serves the whole connection, so a block that
// names an entry of an earlier block decodes only after that earlier block. A caller that
// starts a decoder at each chunk therefore reads wrong header names.
//
// The reader holds the bytes of one field block that no chunk completed, and
// http2MaxFieldBlockBytes bounds them. It stores no byte of a frame that carries no field
// block, so a request body of any length costs no memory.
//
// One HTTP2Reader serves one connection, and one goroutine.
// `.claude/rules/concurrency.md` states that contract.
type HTTP2Reader struct {
	decoder *hpack.Decoder
	// prefaceRead reports whether the stream opened with the 24 octets of RFC 9113
	// section 3.4.
	prefaceRead bool
	// tail holds the bytes that no call read. It holds one incomplete frame at most.
	tail []byte
	// skipRemaining counts the payload octets of a frame that carries no field block. The
	// reader drops those octets as they arrive, and it stores none of them.
	skipRemaining int
	// block holds the field block that the HEADERS frame opened, and that a CONTINUATION
	// frame continues.
	block  []byte
	failed bool
}

// NewHTTP2Reader returns a reader of the client half of one HTTP/2 connection.
func NewHTTP2Reader() *HTTP2Reader {
	decoder := hpack.NewDecoder(http2MaxDynamicTableSize, nil)
	decoder.SetMaxStringLength(http2MaxStringLength)

	return &HTTP2Reader{decoder: decoder}
}

// Read returns one HTTPRequest for each request that the chunk completes.
//
// chunk holds the decrypted client bytes that follow the bytes of every earlier call. The
// first call opens at the first byte of the connection preface.
// It returns nil for a stream that carries no connection preface, and nil for a chunk that
// completes no header block.
// It reads no length field before it bounds that field, and it never panics.
//
// It returns http2MaxRequests requests at most. The reader holds the bytes above that bound,
// so the next call returns the requests they carry.
// It stops at the first header block the decoder does not read, because the dynamic table
// then disagrees with the encoder and every later block decodes to the wrong names.
func (r *HTTP2Reader) Read(chunk []byte) []*HTTPRequest {
	if r.failed {
		return nil
	}

	r.tail = append(r.tail, chunk...)

	if !r.prefaceRead && !r.readPreface() {
		return nil
	}

	var requests []*HTTPRequest

	pos := r.walk(&requests)

	r.tail = append(r.tail[:0], r.tail[pos:]...)

	return requests
}

// Failed reports whether the reader stopped. A reader that stopped reads no later request.
func (r *HTTP2Reader) Failed() bool {
	return r.failed
}

// Pending returns the bytes that no call read.
func (r *HTTP2Reader) Pending() int {
	return len(r.tail)
}

// stop ends the walk, and it drops the bytes the reader holds.
func (r *HTTP2Reader) stop() {
	r.failed = true
	r.tail = nil
	r.block = nil
}

// readPreface reports whether the stream opened with the connection preface.
//
// The preface is the gate of the whole walk, because a decrypted stream that carries another
// protocol then costs one prefix comparison. The reader waits for the 24 octets, and it
// stops at the first octet that names another protocol.
func (r *HTTP2Reader) readPreface() bool {
	preface := []byte(HTTP2ClientPreface)

	if len(r.tail) < len(preface) {
		if !bytes.HasPrefix(preface, r.tail) {
			r.stop()
		}

		return false
	}

	if !bytes.HasPrefix(r.tail, preface) {
		r.stop()

		return false
	}

	r.tail = append(r.tail[:0], r.tail[len(preface):]...)
	r.prefaceRead = true

	return true
}

// walk reads the frames the tail completes, and it returns the count of octets it read.
//
// It appends one request for each field block that ends with the END_HEADERS flag and names
// a `:method` pseudo-header.
func (r *HTTP2Reader) walk(requests *[]*HTTPRequest) int {
	pos := 0

	for {
		if r.skipRemaining > 0 {
			dropped := min(r.skipRemaining, len(r.tail)-pos)
			pos += dropped
			r.skipRemaining -= dropped

			if r.skipRemaining > 0 {
				return pos
			}
		}

		if pos+http2FrameHeaderLength > len(r.tail) {
			return pos
		}

		length := int(r.tail[pos])<<16 | int(r.tail[pos+1])<<8 | int(r.tail[pos+2])
		frameType := r.tail[pos+3]
		flags := r.tail[pos+4]

		payloadStart := pos + http2FrameHeaderLength

		if frameType != http2FrameTypeHeaders && frameType != http2FrameTypeContinuation {
			// The reader stores no byte of this frame, because a client sends a request body in
			// a DATA frame and RFC 9113 section 6.5.2 permits 16777215 octets of it.
			pos = payloadStart
			r.skipRemaining = length

			continue
		}

		if length > http2MaxFieldBlockBytes {
			r.stop()

			return 0
		}

		if payloadStart+length > len(r.tail) {
			return pos
		}

		pos = payloadStart + length

		if !r.readFieldBlock(r.tail[payloadStart:pos], frameType, flags, requests) {
			return 0
		}

		if len(*requests) >= http2MaxRequests {
			return pos
		}
	}
}

// readFieldBlock reads one HEADERS or CONTINUATION frame payload, and it reports whether the
// walk continues.
//
// It appends one request where the flags end the field block and the block names a `:method`
// pseudo-header.
func (r *HTTP2Reader) readFieldBlock(
	payload []byte,
	frameType byte,
	flags byte,
	requests *[]*HTTPRequest,
) bool {
	if frameType == http2FrameTypeHeaders {
		fragment, ok := http2HeadersFragment(payload, flags)
		if !ok {
			r.stop()

			return false
		}

		r.block = append(r.block[:0], fragment...)
	} else {
		if len(r.block)+len(payload) > http2MaxFieldBlockBytes {
			r.stop()

			return false
		}

		r.block = append(r.block, payload...)
	}

	if flags&http2FlagEndHeaders == 0 {
		return true
	}

	fields, err := r.decoder.DecodeFull(r.block)
	if err != nil {
		// The dynamic table now disagrees with the encoder, so every later block of this
		// stream decodes to the wrong names. The walk stops rather than reporting them.
		r.stop()

		return false
	}

	if request := http2RequestOfFields(fields); request != nil {
		*requests = append(*requests, request)
	}

	return true
}

// HTTP2Requests returns one HTTPRequest for each request that the client half of one
// HTTP/2 connection carries.
//
// stream holds the decrypted client bytes from the first byte of the connection preface, and
// it holds the whole connection.
// It returns nil for a stream that carries no connection preface, and nil for a stream that
// completes no header block.
//
// **A caller that reads one connection over several packets calls `HTTP2Reader` instead.**
// This function starts one decoder, so it reads the whole stream at each call and a suffix
// of the stream decodes to wrong header names.
// It returns http2MaxRequests requests at most.
func HTTP2Requests(stream []byte) []*HTTPRequest {
	return NewHTTP2Reader().Read(stream)
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
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1174-1175` splits one
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
