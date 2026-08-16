package ja4plus

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"golang.org/x/net/http2/hpack"
)

// ja4hHTTP2KeyLog returns the KeyLog that names the handshake secret and the application
// secret of one connection.
//
// A TLS 1.3 client writes the Finished message under the handshake traffic key and the
// HTTP/2 request under the application traffic key, so the reader needs both.
func ja4hHTTP2KeyLog(t *testing.T, random, handshake, application []byte) *KeyLog {
	t.Helper()

	lines := parser.TLS13ClientHandshakeSecretLabel + " " + hex.EncodeToString(random) + " " +
		hex.EncodeToString(handshake) + "\n" +
		parser.TLS13ClientApplicationSecretLabel + " " + hex.EncodeToString(random) + " " +
		hex.EncodeToString(application) + "\n"

	keyLog, err := ParseKeyLog(strings.NewReader(lines))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	return keyLog
}

// ja4hHTTP2Block returns the HPACK field block of the name and value pairs.
func ja4hHTTP2Block(t *testing.T, encoder *hpack.Encoder, buffer *bytes.Buffer, fields ...string) []byte {
	t.Helper()

	buffer.Reset()

	for i := 0; i < len(fields); i += 2 {
		if err := encoder.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}); err != nil {
			t.Fatalf("WriteField returned %v", err)
		}
	}

	return append([]byte{}, buffer.Bytes()...)
}

// ja4hHTTP2HeadersFrame returns one HEADERS frame that carries the whole field block.
// RFC 9113 section 4.1 states the 9-octet header, and section 6.2 states END_HEADERS as
// `0x04`.
func ja4hHTTP2HeadersFrame(streamID byte, block []byte) []byte {
	length := len(block)

	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		0x01,
		0x04,
		0x00, 0x00, 0x00, streamID,
	}

	return append(frame, block...)
}

// ja4hHTTP2Fingerprints returns the JA4H fingerprint of each result.
func ja4hHTTP2Fingerprints(results []FingerprintResult) []string {
	var values []string

	for _, result := range results {
		if result.Type == "ja4h" {
			values = append(values, result.Fingerprint)
		}
	}

	return values
}

// ja4hHTTP2Connection returns the packets of one synthetic HTTP/2 request stream, and the
// client random of that connection.
//
// The stream carries the ClientHello in the clear, then one protected handshake record, then
// one protected application record for each element of content. The application records
// number from 0, because RFC 8446 section 5.3 restarts the sequence number at the key
// change.
func ja4hHTTP2Connection(t *testing.T, random, handshake, application []byte, content [][]byte) []gopacket.Packet {
	t.Helper()

	handshakeKeys := tls13TestKeys(t, handshake)
	applicationKeys := tls13TestKeys(t, application)

	payloads := [][]byte{
		tls13TestClientHelloRecord(random),
		tls13TestProtectRecord(t, handshakeKeys, []byte{0x14, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00},
			parser.TLSRecordTypeHandshake, 0),
	}

	for index, part := range content {
		payloads = append(payloads, tls13TestProtectRecord(t, applicationKeys, part,
			parser.TLSRecordTypeApplicationData, uint64(index)))
	}

	var packets []gopacket.Packet

	seq := uint32(1)

	for _, payload := range payloads {
		packets = append(packets, tls13TestPacket(t, tls13TestClientIP, tls13TestServerIP,
			tls13TestClientPort, tls13TestServerPort, seq, payload))
		seq += uint32(len(payload))
	}

	return packets
}

// TestTheProcessorReadsAnHTTP2RequestOfAProtectedTLS13Record holds the acceptance criterion
// of #529: the library decrypts a protected TLS application record on TCP where the key log
// holds the secret, and it decodes the HPACK header block inside it.
//
// The test states the two raw values in full, because a raw value states the header order
// and the cookie handling that the FoxIO reference decides. A test that stated the hashed
// value alone would pass on a wrong order.
func TestTheProcessorReadsAnHTTP2RequestOfAProtectedTLS13Record(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	first := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/",
		"user-agent", "probe", "accept", "*/*", "accept-language", "en-US", "cookie", "a=1")

	second := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/two",
		"user-agent", "probe", "referer", "https://example.test/")

	preface := append([]byte(parser.HTTP2ClientPreface),
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		preface,
		ja4hHTTP2HeadersFrame(1, first),
		ja4hHTTP2HeadersFrame(3, second),
	})

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	var raw []string

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		for _, result := range results {
			if result.Type != "ja4h" {
				continue
			}

			raw = append(raw, result.RawOriginalOrder)

			if !strings.HasPrefix(result.Fingerprint, strings.SplitN(result.RawOriginalOrder, "_", 2)[0]+"_") {
				t.Errorf("the value %q and the raw value %q state different part a values",
					result.Fingerprint, result.RawOriginalOrder)
			}
		}
	}

	wanted := []string{
		"ge20cn03enus_user-agent,accept,accept-language_a_a=1",
		"ge20nr010000_user-agent_",
	}

	if len(raw) != len(wanted) {
		t.Fatalf("the run produced %d JA4H values %v, and the stream carries %d requests",
			len(raw), raw, len(wanted))
	}

	for index, value := range wanted {
		if raw[index] != value {
			t.Errorf("request %d produced the raw value %q, and the block states %q",
				index+1, raw[index], value)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueWithoutAKeyLog states that the decode needs the
// secret. The FoxIO reference reads the plaintext that `tshark` supplies, and this library
// decrypts the record itself.
func TestTheProcessorProducesNoHTTP2ValueWithoutAKeyLog(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	processor := NewProcessor()

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the processor holds no key log", index+1, values)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueForASecretThatOpensNoRecord states that a key log of
// another connection produces no value and no panic. A fingerprinter returns a non-fatal
// error, and never a panic.
func TestTheProcessorProducesNoHTTP2ValueForASecretThatOpensNoRecord(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	wrong := bytes.Repeat([]byte{0x99}, 32)
	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, wrong, wrong)))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the key log names another secret", index+1, values)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueForASecretOfTheWrongLength states the decline that
// `DeriveTLS13RecordKeys` holds. The library reads the SHA-256 key schedule of
// TLS_AES_128_GCM_SHA256 alone, and a SHA-384 suite states a 48-byte secret. Issue #492 is
// the reversal path.
func TestTheProcessorProducesNoHTTP2ValueForASecretOfTheWrongLength(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	long := bytes.Repeat([]byte{0x88}, 48)
	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, long, long)))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the secret holds 48 bytes", index+1, values)
		}
	}
}

// TestTheHTTP2ReaderRepublishesNoRequestOfAnEarlierPacket states the emission rule. The
// reader decodes the whole stream at each packet, because the HPACK dynamic table of RFC
// 7541 section 2.3.2 serves the whole connection. So a counter, and never the decode, is
// what separates a new request from one the stream already published.
func TestTheHTTP2ReaderRepublishesNoRequestOfAnEarlierPacket(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	blocks := make([][]byte, 0, 3)
	for _, path := range []string{"/one", "/two", "/three"} {
		blocks = append(blocks, ja4hHTTP2Block(t, encoder, buffer,
			":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", path))
	}

	content := [][]byte{[]byte(parser.HTTP2ClientPreface)}
	for index, block := range blocks {
		content = append(content, ja4hHTTP2HeadersFrame(byte(1+2*index), block))
	}

	packets := ja4hHTTP2Connection(t, random, handshake, application, content)

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	perPacket := make([]int, 0, len(packets))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		perPacket = append(perPacket, len(ja4hHTTP2Fingerprints(results)))
	}

	// Packet 1 carries the ClientHello, packet 2 the Finished message and packet 3 the
	// preface. Each of the last three carries one HEADERS frame.
	wanted := []int{0, 0, 0, 1, 1, 1}

	if len(perPacket) != len(wanted) {
		t.Fatalf("the run read %d packets, and the connection holds %d", len(perPacket), len(wanted))
	}

	for index, count := range wanted {
		if perPacket[index] != count {
			t.Errorf("packet %d produced %d values, and the stream newly carries %d",
				index+1, perPacket[index], count)
		}
	}
}
