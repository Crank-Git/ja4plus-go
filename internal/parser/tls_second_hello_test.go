package parser

import (
	"testing"
)

// changeCipherSpecRecord returns the six bytes of a TLS ChangeCipherSpec record.
//
// A TLS 1.3 client in compatibility mode sends this record before its second client
// hello. `testdata/foxio/pcap/tls-handshake.pcapng` packet 125 carries it at offset 0,
// and the second client hello at offset 6.
func changeCipherSpecRecord() []byte {
	return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
}

func TestParseClientHelloReadsTheHelloAfterAChangeCipherSpecRecord(t *testing.T) {
	// Issue #295. The library read one client hello on a stream that carries two,
	// because a ChangeCipherSpec record precedes the second one in the same segment.
	hello := BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, []TLSExtension{
		MakeSNIExtension("mem.gfx.ms"),
		MakeSupportedVersionsClientExtension(0x0304),
	})
	payload := append(changeCipherSpecRecord(), hello...)

	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch == nil {
		t.Fatal("expected a ClientHello after the ChangeCipherSpec record, got nil")
	}
	if ch.SNI != "mem.gfx.ms" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "mem.gfx.ms")
	}
	if len(ch.CipherSuites) != 2 || ch.CipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites = %v, want [0x1301 0x1302]", ch.CipherSuites)
	}
}

func TestParseClientHelloReadsNoHelloFromARecordThatCarriesNone(t *testing.T) {
	// The skip must not invent a client hello. Each payload below holds no client
	// hello, so each one reaches nil and no error.
	serverHello := BuildServerHello(0x0303, 0x1301, []TLSExtension{
		MakeSupportedVersionsServerExtension(0x0304),
	})

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "a ChangeCipherSpec record alone",
			payload: changeCipherSpecRecord(),
		},
		{
			name:    "a ChangeCipherSpec record before a server hello",
			payload: append(changeCipherSpecRecord(), serverHello...),
		},
		{
			name:    "an application data record",
			payload: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:    "an alert record",
			payload: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(tt.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ch != nil {
				t.Errorf("expected nil, got a ClientHello with SNI %q", ch.SNI)
			}
		})
	}
}

func TestParseClientHelloReadsNoHelloPastATruncatedLeadingRecord(t *testing.T) {
	// A crafted length must never move the reader past the end of the payload.
	// Each payload below is untrusted input, and each one reaches nil and no panic.
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "a leading record whose length passes the end",
			payload: []byte{0x14, 0x03, 0x03, 0x7f, 0xff, 0x01},
		},
		{
			name:    "a leading record header that the payload cuts short",
			payload: []byte{0x14, 0x03, 0x03},
		},
		{
			name:    "a leading record that ends at the last byte",
			payload: []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
		},
		{
			name:    "a zero-length leading record before a short tail",
			payload: []byte{0x14, 0x03, 0x03, 0x00, 0x00, 0x16},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(tt.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ch != nil {
				t.Error("expected nil for a payload that holds no whole client hello")
			}
		})
	}
}

func TestParseServerHelloReadsNoHelloAfterAChangeCipherSpecRecord(t *testing.T) {
	// JA4S is out of the scope of #295, so the server path skips no record. This test
	// fails when a later change moves the skip into ParseServerHello, which would move
	// a JA4S value.
	serverHello := BuildServerHello(0x0303, 0x1301, []TLSExtension{
		MakeSupportedVersionsServerExtension(0x0304),
	})
	payload := append(changeCipherSpecRecord(), serverHello...)

	sh, err := ParseServerHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh != nil {
		t.Error("expected nil, because the server path reads only the first record")
	}
}
