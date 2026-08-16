package parser

import (
	"bytes"
	"testing"
)

// tls13StreamTestKeys returns the record keys of one traffic secret.
func tls13StreamTestKeys(t *testing.T, secret []byte) *TLS13RecordKeys {
	t.Helper()

	keys, err := DeriveTLS13RecordKeys(secret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	return keys
}

// TestTheTLS13StreamReaderOpensARecordThatTwoChunksCarry states that one record reaches the
// reader across a chunk boundary. A TCP segment ends at any byte, so a record of 16384
// octets reaches the reader in several parts.
func TestTheTLS13StreamReaderOpensARecordThatTwoChunksCarry(t *testing.T) {
	keys := tls13StreamTestKeys(t, tls13TestSecret)
	record := tls13TestProtect(t, keys, []byte("hello"), TLSRecordTypeApplicationData, 0, 0)

	reader := NewTLS13StreamReader(nil, keys)

	if content := reader.Read(record[:4]); len(content) != 0 {
		t.Fatalf("the first chunk returned %x, and it carries a part of the record header", content)
	}

	if content := reader.Read(record[4 : len(record)-1]); len(content) != 0 {
		t.Fatalf("the second chunk returned %x, and the record is 1 byte short", content)
	}

	content := reader.Read(record[len(record)-1:])
	if !bytes.Equal(content, []byte("hello")) {
		t.Errorf("the third chunk returned %x, and the record carries %x", content, "hello")
	}
}

// TestTheTLS13StreamReaderCountsTheSequenceNumberAcrossChunks holds the per-record nonce of
// RFC 8446 section 5.3. The number counts the records of one key, and never the calls.
func TestTheTLS13StreamReaderCountsTheSequenceNumberAcrossChunks(t *testing.T) {
	keys := tls13StreamTestKeys(t, tls13TestSecret)

	reader := NewTLS13StreamReader(nil, keys)

	for sequence := range uint64(3) {
		record := tls13TestProtect(t, keys, []byte{byte(sequence)}, TLSRecordTypeApplicationData,
			sequence, 0)

		content := reader.Read(record)
		if !bytes.Equal(content, []byte{byte(sequence)}) {
			t.Fatalf("record %d returned %x, and it carries %x", sequence, content,
				[]byte{byte(sequence)})
		}
	}
}

// TestTheTLS13StreamReaderMovesFromTheHandshakeKeyToTheApplicationKey holds the key change.
// RFC 8446 section 5.3 restarts the sequence number at each key, and no record states which
// key protects it.
func TestTheTLS13StreamReaderMovesFromTheHandshakeKeyToTheApplicationKey(t *testing.T) {
	handshakeKeys := tls13StreamTestKeys(t, bytes.Repeat([]byte{0x71}, 32))
	applicationKeys := tls13StreamTestKeys(t, bytes.Repeat([]byte{0x35}, 32))

	finished := tls13TestProtect(t, handshakeKeys, []byte{0x14, 0x00, 0x00, 0x04},
		TLSRecordTypeHandshake, 0, 0)
	request := tls13TestProtect(t, applicationKeys, []byte("request"),
		TLSRecordTypeApplicationData, 0, 0)

	reader := NewTLS13StreamReader(handshakeKeys, applicationKeys)

	if content := reader.Read(finished); len(content) != 0 {
		t.Fatalf("the handshake record returned %x, and the reader reads application data", content)
	}

	content := reader.Read(request)
	if !bytes.Equal(content, []byte("request")) {
		t.Errorf("the application record returned %x, and it carries %x", content, "request")
	}
}

// TestTheTLS13StreamReaderReadsNoRecordAfterARecordItDoesNotOpen states the end of the walk.
// The sequence number of every later record then disagrees with the sender, so a later
// record decodes to the wrong bytes.
func TestTheTLS13StreamReaderReadsNoRecordAfterARecordItDoesNotOpen(t *testing.T) {
	keys := tls13StreamTestKeys(t, tls13TestSecret)
	other := tls13StreamTestKeys(t, bytes.Repeat([]byte{0x44}, 32))

	reader := NewTLS13StreamReader(nil, keys)

	if content := reader.Read(tls13TestProtect(t, other, []byte("wrong"),
		TLSRecordTypeApplicationData, 0, 0)); len(content) != 0 {
		t.Fatalf("the reader returned %x of a record that another key protects", content)
	}

	if !reader.Failed() {
		t.Fatal("the reader reports no failure, and it opened no record")
	}

	if content := reader.Read(tls13TestProtect(t, keys, []byte("later"),
		TLSRecordTypeApplicationData, 0, 0)); len(content) != 0 {
		t.Errorf("the reader returned %x after a record it did not open", content)
	}
}

// TestTheTLS13StreamReaderReadsNoRecordAboveTheRecordBound states the bound of the reader.
// RFC 8446 section 5.2 bounds one record, and a length field that never completes would
// otherwise grow the stored bytes without a bound.
func TestTheTLS13StreamReaderReadsNoRecordAboveTheRecordBound(t *testing.T) {
	keys := tls13StreamTestKeys(t, tls13TestSecret)

	header := []byte{TLSRecordTypeApplicationData, 0x03, 0x03, 0xff, 0xff}

	reader := NewTLS13StreamReader(nil, keys)
	reader.Read(header)
	reader.Read(bytes.Repeat([]byte{0x00}, TLS13MaxRecordBytes))

	if pending := reader.Pending(); pending != 0 {
		t.Errorf("the reader holds %d bytes, and its bound is %d", pending, TLS13MaxRecordBytes)
	}

	if !reader.Failed() {
		t.Error("the reader reports no failure, and it passed its record bound")
	}
}
