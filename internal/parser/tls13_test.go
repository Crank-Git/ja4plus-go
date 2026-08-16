package parser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// tls13TestSecret is one traffic secret of the SHA-256 key schedule.
// A test builds the protected record, because the corpus is not tracked in git.
var tls13TestSecret = bytes.Repeat([]byte{0x3c}, 32)

// tls13TestProtect returns one protected TLS 1.3 record that carries the content.
//
// It builds the record that RFC 8446 section 5.2 states. The inner plaintext holds the
// content, then the inner content type, then the padding of zero bytes. The additional
// data is the 5-byte record header, and the nonce follows section 5.3.
func tls13TestProtect(
	t *testing.T,
	keys *TLS13RecordKeys,
	content []byte,
	innerType byte,
	sequence uint64,
	padding int,
) []byte {
	t.Helper()

	plaintext := make([]byte, 0, len(content)+1+padding)
	plaintext = append(plaintext, content...)
	plaintext = append(plaintext, innerType)
	plaintext = append(plaintext, make([]byte, padding)...)

	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		t.Fatalf("aes.NewCipher returned %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM returned %v", err)
	}

	length := len(plaintext) + aead.Overhead()
	header := []byte{
		TLSRecordTypeApplicationData,
		0x03, 0x03,
		byte(length >> 8), byte(length),
	}

	nonce := make([]byte, len(keys.IV))
	copy(nonce, keys.IV)

	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}

	return aead.Seal(header, nonce, plaintext, header)
}

// TestDeriveTLS13RecordKeysReadsTheKeyAndTheInitializationVector holds the two lengths of
// TLS_AES_128_GCM_SHA256.
func TestDeriveTLS13RecordKeysReadsTheKeyAndTheInitializationVector(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	if len(keys.Key) != tls13KeyLength {
		t.Errorf("the key holds %d bytes, and the suite states %d", len(keys.Key), tls13KeyLength)
	}

	if len(keys.IV) != tls13IVLength {
		t.Errorf("the initialization vector holds %d bytes, and the suite states %d",
			len(keys.IV), tls13IVLength)
	}
}

// TestDeriveTLS13RecordKeysRefusesASecretOfAnotherLength holds the decline of every cipher
// suite outside TLS_AES_128_GCM_SHA256.
func TestDeriveTLS13RecordKeysRefusesASecretOfAnotherLength(t *testing.T) {
	if _, err := DeriveTLS13RecordKeys(bytes.Repeat([]byte{0x3c}, 48)); err == nil {
		t.Error("DeriveTLS13RecordKeys read a 48-byte secret, and the library reads the SHA-256 schedule")
	}

	if _, err := DeriveTLS13RecordKeys(nil); err == nil {
		t.Error("DeriveTLS13RecordKeys read an empty secret")
	}
}

// TestOpenReadsTheContentAndTheInnerTypeOfAProtectedRecord holds the record deprotection
// of RFC 8446 section 5.2.
func TestOpenReadsTheContentAndTheInnerTypeOfAProtectedRecord(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	want := []byte{0x08, 0x00, 0x00, 0x02, 0x00, 0x00}
	record := tls13TestProtect(t, keys, want, TLSRecordTypeHandshake, 0, 7)

	content, innerType, err := keys.Open(record, 0)
	if err != nil {
		t.Fatalf("Open returned %v", err)
	}

	if !bytes.Equal(content, want) {
		t.Errorf("Open returned %x, and the record carries %x", content, want)
	}

	if innerType != TLSRecordTypeHandshake {
		t.Errorf("Open returned the inner type %#x, and the record carries %#x",
			innerType, TLSRecordTypeHandshake)
	}
}

// TestOpenRefusesARecordOfTheWrongSequenceNumber holds the per-record nonce of RFC 8446
// section 5.3.
func TestOpenRefusesARecordOfTheWrongSequenceNumber(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	record := tls13TestProtect(t, keys, []byte{0x0b, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 3, 0)

	if _, _, err := keys.Open(record, 3); err != nil {
		t.Fatalf("Open returned %v at the sequence number the sender used", err)
	}

	if _, _, err := keys.Open(record, 2); err == nil {
		t.Error("Open read the record at a sequence number the sender did not use")
	}
}

// TestOpenRefusesKeysOfTheWrongLength holds the two field lengths.
//
// The two fields are exported, so a caller builds this value without
// DeriveTLS13RecordKeys. `crypto/cipher` panics on a nonce of the wrong length, and the
// nonce loop indexes a nonce of fewer than 8 bytes at a negative position. The library
// returns a non-fatal error and it never panics.
func TestOpenRefusesKeysOfTheWrongLength(t *testing.T) {
	derived, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	record := tls13TestProtect(t, derived, []byte{0x0b, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 0, 0)

	cases := map[string]*TLS13RecordKeys{
		"the zero value":     {},
		"a nonce of 4 bytes": {Key: derived.Key, IV: derived.IV[:4]},
		"a nonce of 8 bytes": {Key: derived.Key, IV: derived.IV[:8]},
		"a key of 8 bytes":   {Key: derived.Key[:8], IV: derived.IV},
	}

	for name, keys := range cases {
		if _, _, err := keys.Open(record, 0); err == nil {
			t.Errorf("Open read a record under %s", name)
		}
	}
}

// TestTLS13ContentOfStreamRefusesKeysOfTheWrongLength holds the same bound on the walk.
func TestTLS13ContentOfStreamRefusesKeysOfTheWrongLength(t *testing.T) {
	derived, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	stream := tls13TestProtect(t, derived, []byte{0x0b, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 0, 0)

	content, opened := TLS13ContentOfStream(stream, &TLS13RecordKeys{}, 0, TLSRecordTypeHandshake)
	if len(content) != 0 || opened != 0 {
		t.Errorf("TLS13ContentOfStream read %d bytes under the zero value of the keys", len(content))
	}
}

// TestOpenRefusesATruncatedRecord holds the bound of every length field.
func TestOpenRefusesATruncatedRecord(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	record := tls13TestProtect(t, keys, []byte{0x0b, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 0, 0)

	for _, length := range []int{0, 1, 4, 5, len(record) - 1} {
		if _, _, err := keys.Open(record[:length], 0); err == nil {
			t.Errorf("Open read a record of %d bytes, and the record holds %d", length, len(record))
		}
	}
}

// TestOpenRefusesAPlaintextOfZeroBytesAlone holds the inner content type of RFC 8446
// section 5.2. A plaintext of padding alone names no content type.
func TestOpenRefusesAPlaintextOfZeroBytesAlone(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	record := tls13TestProtect(t, keys, nil, 0x00, 0, 4)

	if _, _, err := keys.Open(record, 0); err == nil {
		t.Error("Open read a plaintext that holds zero bytes alone")
	}
}

// TestTLS13ContentOfStreamReadsEachRecordInSequenceOrder holds the sequence number rule of
// RFC 8446 section 5.3: the first record under one traffic key uses the number 0.
func TestTLS13ContentOfStreamReadsEachRecordInSequenceOrder(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	// The stream opens with an unprotected handshake record and a ChangeCipherSpec
	// record, as a TLS 1.3 server in compatibility mode writes them. Neither one carries
	// a sequence number, so the first protected record below is number 0.
	stream := []byte{TLSRecordTypeHandshake, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}
	stream = append(stream, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

	first := []byte{0x08, 0x00, 0x00, 0x00}
	second := []byte{0x0b, 0x00, 0x00, 0x01, 0x00}

	stream = append(stream, tls13TestProtect(t, keys, first, TLSRecordTypeHandshake, 0, 0)...)
	stream = append(stream, tls13TestProtect(t, keys, second, TLSRecordTypeHandshake, 1, 3)...)

	content, opened := TLS13ContentOfStream(stream, keys, 0, TLSRecordTypeHandshake)

	want := append(append([]byte{}, first...), second...)
	if !bytes.Equal(content, want) {
		t.Errorf("TLS13ContentOfStream returned %x, and the stream carries %x", content, want)
	}

	if opened != 2 {
		t.Errorf("TLS13ContentOfStream opened %d records, and the stream carries 2", opened)
	}
}

// TestTLS13ContentOfStreamSkipsTheRecordsOfAnEarlierKey holds the restart of the sequence
// number at a key change. RFC 8446 section 5.3 states that restart.
func TestTLS13ContentOfStreamSkipsTheRecordsOfAnEarlierKey(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	// The first record stands for one the earlier key protects, so this key opens neither
	// its bytes nor its sequence number.
	stream := tls13TestProtect(t, keys, []byte{0x14, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 9, 0)

	want := []byte{0x41, 0x42, 0x43}
	stream = append(stream, tls13TestProtect(t, keys, want, TLSRecordTypeApplicationData, 0, 0)...)

	content, opened := TLS13ContentOfStream(stream, keys, 1, TLSRecordTypeApplicationData)
	if !bytes.Equal(content, want) {
		t.Errorf("TLS13ContentOfStream returned %x, and the stream carries %x", content, want)
	}

	if opened != 1 {
		t.Errorf("TLS13ContentOfStream opened %d records, and this key protects 1", opened)
	}
}

// TestTLS13ContentOfStreamStopsAtARecordTheKeyDoesNotOpen holds the end of the handshake.
// The sender changes the traffic key, so a later record opens under another key.
func TestTLS13ContentOfStreamStopsAtARecordTheKeyDoesNotOpen(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	other, err := DeriveTLS13RecordKeys(bytes.Repeat([]byte{0x5e}, 32))
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	want := []byte{0x14, 0x00, 0x00, 0x20}
	stream := tls13TestProtect(t, keys, want, TLSRecordTypeHandshake, 0, 0)
	stream = append(stream, tls13TestProtect(t, other, []byte{0x41}, TLSRecordTypeHandshake, 0, 0)...)

	content, opened := TLS13ContentOfStream(stream, keys, 0, TLSRecordTypeHandshake)
	if !bytes.Equal(content, want) {
		t.Errorf("TLS13ContentOfStream returned %x, and this key protects %x", content, want)
	}

	if opened != 1 {
		t.Errorf("TLS13ContentOfStream opened %d records, and this key protects 1", opened)
	}
}

// TestTLS13ContentOfStreamReadsNoRecordOfATruncatedStream holds the bound of the record
// length field. Every packet is untrusted input.
func TestTLS13ContentOfStreamReadsNoRecordOfATruncatedStream(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	record := tls13TestProtect(t, keys, []byte{0x0b, 0x00, 0x00, 0x00}, TLSRecordTypeHandshake, 0, 0)

	for length := range len(record) {
		content, opened := TLS13ContentOfStream(record[:length], keys, 0, TLSRecordTypeHandshake)
		if len(content) != 0 || opened != 0 {
			t.Errorf("TLS13ContentOfStream read %d bytes of a stream of %d bytes", len(content), length)
		}
	}
}

// TestTLS13ContentOfStreamRefusesALengthFieldThatPassesTheStream holds the record length
// bound against a crafted stream.
func TestTLS13ContentOfStreamRefusesALengthFieldThatPassesTheStream(t *testing.T) {
	keys, err := DeriveTLS13RecordKeys(tls13TestSecret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	stream := []byte{TLSRecordTypeApplicationData, 0x03, 0x03, 0xff, 0xff, 0x41, 0x42}

	content, opened := TLS13ContentOfStream(stream, keys, 0, TLSRecordTypeHandshake)
	if len(content) != 0 || opened != 0 {
		t.Errorf("TLS13ContentOfStream read %d bytes past the end of the stream", len(content))
	}
}

// TestParseClientHelloReadsTheRandom holds the field that names the connection in a key
// log. `internal/keylog` keys every secret on it.
func TestParseClientHelloReadsTheRandom(t *testing.T) {
	random := bytes.Repeat([]byte{0x7a}, 32)

	hello, err := ParseClientHello(tls13TestClientHello(random))
	if err != nil {
		t.Fatalf("ParseClientHello returned %v", err)
	}

	if hello == nil {
		t.Fatal("ParseClientHello read no ClientHello")
	}

	if !bytes.Equal(hello.Random, random) {
		t.Errorf("ParseClientHello returned the random %x, and the message carries %x",
			hello.Random, random)
	}
}

// TestParseClientHelloReadsNoRandomOfATruncatedMessage holds the bound of the random.
func TestParseClientHelloReadsNoRandomOfATruncatedMessage(t *testing.T) {
	payload := tls13TestClientHello(bytes.Repeat([]byte{0x7a}, 32))

	for length := 11; length < 43; length++ {
		truncated := make([]byte, length)
		copy(truncated, payload[:length])

		// The record length still names the whole message, so the parser reports the
		// truncation rather than a random it did not read.
		hello, _ := ParseClientHello(truncated)
		if hello != nil && len(hello.Random) != 0 {
			t.Errorf("ParseClientHello read a random from %d bytes", length)
		}
	}
}

// tls13TestClientHello returns one TLS 1.3 ClientHello record that carries the random.
// The message holds no extension, because the test reads the random alone.
func tls13TestClientHello(random []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	// The session identifier, one cipher suite, one compression method, no extension.
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, 0x00, 0x00)

	message := []byte{TLSHandshakeClientHello, 0x00, byte(len(body) >> 8), byte(len(body))}
	message = append(message, body...)

	record := []byte{TLSRecordTypeHandshake, 0x03, 0x01, byte(len(message) >> 8), byte(len(message))}

	return append(record, message...)
}
