package parser

import (
	"testing"
)

func TestParseClientHello_Valid(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02c}
	exts := []TLSExtension{
		MakeSNIExtension("example.com"),
		MakeALPNExtension("h2", "http/1.1"),
		MakeSupportedVersionsClientExtension(0x0304, 0x0303),
		MakeSignatureAlgorithmsExtension(0x0403, 0x0804),
	}
	payload := BuildClientHello(0x0303, ciphers, exts)

	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch == nil {
		t.Fatal("expected ClientHello, got nil")
	}

	if ch.Version != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", ch.Version)
	}
	if len(ch.CipherSuites) != 4 {
		t.Fatalf("cipher count = %d, want 4", len(ch.CipherSuites))
	}
	if ch.CipherSuites[0] != 0x1301 {
		t.Errorf("cipher[0] = 0x%04x, want 0x1301", ch.CipherSuites[0])
	}
	if ch.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "example.com")
	}
	if !ch.HasSNI {
		t.Error("HasSNI = false, want true")
	}
	if len(ch.ALPNProtocols) != 2 || ch.ALPNProtocols[0] != "h2" || ch.ALPNProtocols[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", ch.ALPNProtocols)
	}
	if len(ch.SupportedVersions) != 2 || ch.SupportedVersions[0] != 0x0304 {
		t.Errorf("SupportedVersions = %v, want [0x0304 0x0303]", ch.SupportedVersions)
	}
	if len(ch.SignatureAlgorithms) != 2 || ch.SignatureAlgorithms[0] != 0x0403 {
		t.Errorf("SignatureAlgorithms = %v, want [0x0403 0x0804]", ch.SignatureAlgorithms)
	}
	if len(ch.Extensions) != 4 {
		t.Errorf("extension count = %d, want 4", len(ch.Extensions))
	}
}

func TestParseServerHello_Valid(t *testing.T) {
	exts := []TLSExtension{
		MakeSupportedVersionsServerExtension(0x0304),
		MakeALPNExtension("h2"),
	}
	payload := BuildServerHello(0x0303, 0x1301, exts)

	sh, err := ParseServerHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh == nil {
		t.Fatal("expected ServerHello, got nil")
	}

	// Version should be updated to 0x0304 from supported_versions
	if sh.Version != 0x0304 {
		t.Errorf("version = 0x%04x, want 0x0304", sh.Version)
	}
	if sh.CipherSuite != 0x1301 {
		t.Errorf("cipher = 0x%04x, want 0x1301", sh.CipherSuite)
	}
	if sh.ALPNProtocol != "h2" {
		t.Errorf("ALPN = %q, want %q", sh.ALPNProtocol, "h2")
	}
	if len(sh.SupportedVersions) != 1 || sh.SupportedVersions[0] != 0x0304 {
		t.Errorf("SupportedVersions = %v, want [0x0304]", sh.SupportedVersions)
	}
	if len(sh.Extensions) != 2 {
		t.Errorf("extension count = %d, want 2", len(sh.Extensions))
	}
}

func TestParseClientHello_NonTLS(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for non-TLS payload")
	}
}

func TestParseClientHello_Truncated(t *testing.T) {
	// Valid record header pointing to 100 bytes, but only 10 provided
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03}
	_, err := ParseClientHello(payload)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestParseClientHello_GREASEPresent(t *testing.T) {
	// GREASE values should be preserved in parser output (filtering is JA4's job)
	ciphers := []uint16{0x0A0A, 0x1301, 0x1302}
	greaseExt := TLSExtension{Typ: 0x2A2A, Data: []byte{}}
	exts := []TLSExtension{
		greaseExt,
		MakeSNIExtension("test.com"),
	}
	payload := BuildClientHello(0x0303, ciphers, exts)

	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch.CipherSuites) != 3 {
		t.Errorf("cipher count = %d, want 3 (GREASE should be preserved)", len(ch.CipherSuites))
	}
	if ch.CipherSuites[0] != 0x0A0A {
		t.Errorf("cipher[0] = 0x%04x, want 0x0A0A (GREASE)", ch.CipherSuites[0])
	}
	if len(ch.Extensions) != 2 {
		t.Errorf("extension count = %d, want 2 (GREASE ext should be preserved)", len(ch.Extensions))
	}
	if ch.Extensions[0] != 0x2A2A {
		t.Errorf("ext[0] = 0x%04x, want 0x2A2A (GREASE)", ch.Extensions[0])
	}
}

func TestIsTLSHandshake(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{"ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01}, true},
		{"ServerHello", []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x02}, true},
		{"Not handshake", []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x01}, false},
		{"Too short", []byte{0x16, 0x03}, false},
		{"Unknown type", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x0B}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTLSHandshake(tt.data)
			if got != tt.expect {
				t.Errorf("IsTLSHandshake = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestParseClientHello_NoExtensions(t *testing.T) {
	payload := BuildClientHello(0x0303, []uint16{0x002f}, nil)
	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch == nil {
		t.Fatal("expected ClientHello, got nil")
	}
	if len(ch.Extensions) != 0 {
		t.Errorf("extension count = %d, want 0", len(ch.Extensions))
	}
	if ch.HasSNI {
		t.Error("HasSNI should be false with no extensions")
	}
}

func TestParseClientHello_MalformedSNI(t *testing.T) {
	sniExt := TLSExtension{Typ: ExtSNI, Data: []byte{0x00}}
	payload := BuildClientHello(0x0303, []uint16{0x002f}, []TLSExtension{sniExt})
	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ch.HasSNI {
		t.Error("HasSNI should be true even for malformed SNI")
	}
	if ch.SNI != "" {
		t.Errorf("SNI = %q, want empty for malformed SNI", ch.SNI)
	}
}
