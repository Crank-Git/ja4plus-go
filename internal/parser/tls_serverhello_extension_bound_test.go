package parser

import "testing"

// serverHelloWithUnbackedSupportedVersions returns the 53-byte record of #556.
//
// The record declares a supported_versions length of 2, and the record length stops at the
// end of the extension header. So the extension carries no data, and the declared length
// disagrees with the data the record holds. `ParseServerHello` clamps the extension data to
// the end of the record, and the supported_versions branch read the declared length before
// #556. That branch then indexed an empty slice.
func serverHelloWithUnbackedSupportedVersions() []byte {
	body := []byte{}
	body = append(body, 0x03, 0x03)             // The version.
	body = append(body, make([]byte, 32)...)    // The random.
	body = append(body, 0x00)                   // The session identifier length.
	body = append(body, 0x13, 0x01)             // The cipher suite.
	body = append(body, 0x00)                   // The compression method.
	body = append(body, 0x00, 0x08)             // The extensions length.
	body = append(body, 0x00, 0x2b, 0x00, 0x02) // supported_versions, declared length 2.

	handshake := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)

	return record
}

func TestParseServerHelloReturnsForARecordThatBacksNoSupportedVersionsData(t *testing.T) {
	// #556. The record below made `extLen >= 2` true while the clamped slice held no byte,
	// and `ParseServerHello` panicked with `index out of range [0] with length 0`.
	record := serverHelloWithUnbackedSupportedVersions()
	if len(record) != 53 {
		t.Fatalf("record length = %d, want 53", len(record))
	}

	sh, err := ParseServerHello(record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh == nil {
		t.Fatal("expected a ServerHello, got nil")
	}

	// The extension carries no version, so the parser keeps the version of the record.
	if len(sh.SupportedVersions) != 0 {
		t.Errorf("SupportedVersions = %v, want none", sh.SupportedVersions)
	}
	if sh.Version != 0x0303 {
		t.Errorf("Version = %#04x, want 0x0303", sh.Version)
	}
}

func TestParseServerHelloReturnsForTheCrashInputOfTheFuzzTarget(t *testing.T) {
	// #556. `FuzzParseServerHelloReadsAnyPayload` wrote this input on its first run, in
	// 1.14 seconds. The bytes `\x00+` are the supported_versions extension type, and the
	// two bytes that follow declare a length of 12336.
	payload := []byte("\x1600\x009\x020000000000000000000000000000000000000\x000000000\x00\x0500000\x00+0000")
	if len(payload) != 64 {
		t.Fatalf("payload length = %d, want 64", len(payload))
	}

	if _, err := ParseServerHello(payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServerHelloReadsTheVersionOfAWellFormedSupportedVersionsExtension(t *testing.T) {
	// #556 bounds the extension, and it moves no value of a record that backs its own
	// declared length. This test fails when the repair drops a version the parser must read.
	record := BuildServerHello(0x0303, 0x1301, []TLSExtension{
		MakeSupportedVersionsServerExtension(0x0304),
	})

	sh, err := ParseServerHello(record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh == nil {
		t.Fatal("expected a ServerHello, got nil")
	}
	if len(sh.SupportedVersions) != 1 || sh.SupportedVersions[0] != 0x0304 {
		t.Errorf("SupportedVersions = %v, want [0x0304]", sh.SupportedVersions)
	}
	if sh.Version != 0x0304 {
		t.Errorf("Version = %#04x, want 0x0304", sh.Version)
	}
}
