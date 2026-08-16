package ja4plus

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"golang.org/x/net/http2/hpack"
)

// ja4hHTTP2DataFrame returns one DATA frame of the length that the caller states.
//
// RFC 9113 section 6.1 states the DATA type as `0x0`. A client sends a request body in this
// frame, so a long connection carries far more DATA than HEADERS.
func ja4hHTTP2DataFrame(streamID byte, length int) []byte {
	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		0x00,
		0x00,
		0x00, 0x00, 0x00, streamID,
	}

	return append(frame, bytes.Repeat([]byte{0x5a}, length)...)
}

// ja4hHTTP2Run returns the JA4H fingerprint of each packet of one run, in order.
func ja4hHTTP2Run(t *testing.T, processor *Processor, packets []gopacket.Packet) []string {
	t.Helper()

	var values []string

	for index, packet := range packets {
		results, errs := processor.ProcessPacket(packet)
		if len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v for packet %d", errs, index+1)
		}

		values = append(values, ja4hHTTP2Fingerprints(results)...)
	}

	return values
}

// TestTheProcessorReadsAnHTTP2RequestOfAStreamAbove64Kilobytes holds the byte bound of
// limit 1 of #753.
//
// The reader decoded the whole stream at each packet, so a bound of 65536 bytes held that
// cost. The bound stopped the connection rather than delaying it, and every later request of
// a long connection reached no value.
func TestTheProcessorReadsAnHTTP2RequestOfAStreamAbove64Kilobytes(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/late",
		"user-agent", "probe")

	content := [][]byte{[]byte(parser.HTTP2ClientPreface)}

	// Five records of about 16 kB each carry the stream past 65536 bytes. RFC 8446 section
	// 5.2 bounds one record at 16384 octets of plaintext.
	for range 5 {
		content = append(content, ja4hHTTP2DataFrame(1, 16000))
	}

	content = append(content, ja4hHTTP2HeadersFrame(3, block))

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application, content)

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, packets)

	if len(values) != 1 {
		t.Fatalf("the run produced %d values %v, and the connection carries 1 request past 65536 bytes",
			len(values), values)
	}
}

// TestTheProcessorReadsMoreRequestsThanTheCallBoundOfOneConnection holds the request bound
// of limit 1 of #753.
//
// `http2MaxRequests` bounds the requests one decode returns. The caller counted the requests
// the stream already published, so a decode that stopped at the bound stopped that counter
// too. The connection then reached no later value.
func TestTheProcessorReadsMoreRequestsThanTheCallBoundOfOneConnection(t *testing.T) {
	const total = 300

	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	frames := []byte(parser.HTTP2ClientPreface)

	for index := range total {
		block := ja4hHTTP2Block(t, encoder, buffer,
			":method", "GET", ":authority", "example.test", ":scheme", "https",
			":path", fmt.Sprintf("/r%d", index))
		frames = append(frames, ja4hHTTP2HeadersFrame(1, block)...)
	}

	// The second record carries one PING frame, which RFC 9113 section 6.7 states as type
	// `0x6`. It reaches the reader with the requests that the first record left unread.
	ping := []byte{0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}
	ping = append(ping, bytes.Repeat([]byte{0x00}, 8)...)

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application,
		[][]byte{frames, ping})

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, packets)

	if len(values) != total {
		t.Fatalf("the run produced %d values, and the connection carries %d requests",
			len(values), total)
	}
}

// TestTheProcessorReadsAnHTTP2RequestOfAReorderedConnection states that a segment which
// arrives out of order costs no value.
//
// The decode reads each byte of the stream once, so it holds the sequence number of the
// first byte it has not read. A segment above that number leaves a hole, and the decode waits
// for the segment that fills it. TCP reorders a segment of any connection, so a decode that
// stopped at a hole would stop most connections.
func TestTheProcessorReadsAnHTTP2RequestOfAReorderedConnection(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/one",
		"user-agent", "probe")

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	// Packet 1 carries the ClientHello and packet 2 the Finished message. The last two arrive
	// in the reverse order, so the HEADERS record reaches the fingerprinter before the preface.
	reordered := []gopacket.Packet{packets[0], packets[1], packets[3], packets[2]}

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, reordered)

	if len(values) != 1 {
		t.Fatalf("the run produced %d values %v, and the connection carries 1 request",
			len(values), values)
	}
}

// TestTheProcessorReadsASecondHTTP2ConnectionOfOneFourTuple holds limit 2 of #753.
//
// The HTTP/2 path wrote no consumed range, so `segmentCarriesNoNewRequest` removed no entry
// for it. A second connection of one address pair and port pair therefore read the buffer and
// the counter of the first. It produced no value of its own.
//
// A second connection starts at an initial sequence number of its own. That number sits below
// the number of the first connection about half the time. Each case reaches this test.
func TestTheProcessorReadsASecondHTTP2ConnectionOfOneFourTuple(t *testing.T) {
	cases := []struct {
		name   string
		first  uint32
		second uint32
	}{
		{name: "the second connection opens below the first", first: 500000, second: 1000},
		{name: "the second connection opens above the first", first: 1000, second: 4000000},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			random := bytes.Repeat([]byte{0x2c}, 32)
			handshake := bytes.Repeat([]byte{0x71}, 32)
			application := bytes.Repeat([]byte{0x35}, 32)

			buffer := &bytes.Buffer{}
			encoder := hpack.NewEncoder(buffer)

			block := ja4hHTTP2Block(t, encoder, buffer,
				":method", "GET", ":authority", "example.test", ":scheme", "https",
				":path", "/one", "user-agent", "probe")

			content := [][]byte{
				[]byte(parser.HTTP2ClientPreface),
				ja4hHTTP2HeadersFrame(1, block),
			}

			processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

			opening := ja4hHTTP2Run(t, processor,
				ja4hHTTP2ConnectionFrom(t, testCase.first, random, handshake, application, content))
			if len(opening) != 1 {
				t.Fatalf("the first connection produced %d values, and it carries 1 request",
					len(opening))
			}

			// The second connection encodes its own field block, because RFC 7541 section
			// 2.3.2 gives each connection a dynamic table of its own.
			second := &bytes.Buffer{}
			secondBlock := ja4hHTTP2Block(t, hpack.NewEncoder(second), second,
				":method", "GET", ":authority", "example.test", ":scheme", "https",
				":path", "/one", "user-agent", "probe")

			reuse := ja4hHTTP2Run(t, processor, ja4hHTTP2ConnectionFrom(t, testCase.second,
				random, handshake, application, [][]byte{
					[]byte(parser.HTTP2ClientPreface),
					ja4hHTTP2HeadersFrame(1, secondBlock),
				}))

			if len(reuse) != 1 {
				t.Fatalf("the second connection produced %d values, and it carries 1 request",
					len(reuse))
			}

			if reuse[0] != opening[0] {
				t.Errorf("the second connection produced %q, and the first produced %q for the same request",
					reuse[0], opening[0])
			}
		})
	}
}
