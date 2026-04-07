package ja4plus

import (
	"testing"
)

// buildClientHello constructs a raw TLS ClientHello payload from components.
func buildClientHello(version uint16, ciphers []uint16, extensions []tlsExtension) []byte {
	// Build inner ClientHello body (after handshake header)
	var body []byte

	// Version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// Random (32 bytes of zeros)
	body = append(body, make([]byte, 32)...)

	// Session ID length = 0
	body = append(body, 0x00)

	// Cipher suites
	csLen := len(ciphers) * 2
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}

	// Compression methods: 1 method, null
	body = append(body, 0x01, 0x00)

	// Extensions
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.typ>>8), byte(ext.typ))
		extBytes = append(extBytes, byte(len(ext.data)>>8), byte(len(ext.data)))
		extBytes = append(extBytes, ext.data...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	// Handshake header: type(1) + length(3)
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header: type(1) + version(2) + length(2)
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// buildServerHello constructs a raw TLS ServerHello payload.
func buildServerHello(version uint16, cipher uint16, extensions []tlsExtension) []byte {
	var body []byte

	// Version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// Random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// Session ID length = 0
	body = append(body, 0x00)

	// Single cipher suite
	body = append(body, byte(cipher>>8), byte(cipher))

	// Compression method: null
	body = append(body, 0x00)

	// Extensions
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.typ>>8), byte(ext.typ))
		extBytes = append(extBytes, byte(len(ext.data)>>8), byte(len(ext.data)))
		extBytes = append(extBytes, ext.data...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	// Handshake header
	var handshake []byte
	handshake = append(handshake, 0x02) // ServerHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header
	var record []byte
	record = append(record, 0x16)
	record = append(record, 0x03, 0x03)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

type tlsExtension struct {
	typ  uint16
	data []byte
}

func makeSNIExtension(hostname string) tlsExtension {
	hBytes := []byte(hostname)
	hLen := len(hBytes)
	// SNI list: list_length(2) + type(1) + hostname_length(2) + hostname
	totalLen := 1 + 2 + hLen // type + len + hostname
	var data []byte
	data = append(data, byte((totalLen)>>8), byte(totalLen)) // list length
	data = append(data, 0x00)                                // type = hostname
	data = append(data, byte(hLen>>8), byte(hLen))           // hostname length
	data = append(data, hBytes...)
	return tlsExtension{typ: extSNI, data: data}
}

func makeALPNExtension(protocols ...string) tlsExtension {
	var list []byte
	for _, p := range protocols {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	var data []byte
	data = append(data, byte(len(list)>>8), byte(len(list)))
	data = append(data, list...)
	return tlsExtension{typ: extALPN, data: data}
}

func makeSupportedVersionsClientExtension(versions ...uint16) tlsExtension {
	listLen := len(versions) * 2
	data := []byte{byte(listLen)}
	for _, v := range versions {
		data = append(data, byte(v>>8), byte(v))
	}
	return tlsExtension{typ: extSupportedVersions, data: data}
}

func makeSupportedVersionsServerExtension(version uint16) tlsExtension {
	return tlsExtension{
		typ:  extSupportedVersions,
		data: []byte{byte(version >> 8), byte(version)},
	}
}

func makeSignatureAlgorithmsExtension(algs ...uint16) tlsExtension {
	listLen := len(algs) * 2
	var data []byte
	data = append(data, byte(listLen>>8), byte(listLen))
	for _, a := range algs {
		data = append(data, byte(a>>8), byte(a))
	}
	return tlsExtension{typ: extSignatureAlgorithms, data: data}
}

func TestParseClientHello_Valid(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02c}
	exts := []tlsExtension{
		makeSNIExtension("example.com"),
		makeALPNExtension("h2", "http/1.1"),
		makeSupportedVersionsClientExtension(0x0304, 0x0303),
		makeSignatureAlgorithmsExtension(0x0403, 0x0804),
	}
	payload := buildClientHello(0x0303, ciphers, exts)

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
	exts := []tlsExtension{
		makeSupportedVersionsServerExtension(0x0304),
		makeALPNExtension("h2"),
	}
	payload := buildServerHello(0x0303, 0x1301, exts)

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
	greaseExt := tlsExtension{typ: 0x2A2A, data: []byte{}}
	exts := []tlsExtension{
		greaseExt,
		makeSNIExtension("test.com"),
	}
	payload := buildClientHello(0x0303, ciphers, exts)

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
	// Build a ClientHello with no extensions
	payload := buildClientHello(0x0303, []uint16{0x002f}, nil)
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
	// SNI extension present but with too-short data
	sniExt := tlsExtension{typ: extSNI, data: []byte{0x00}}
	payload := buildClientHello(0x0303, []uint16{0x002f}, []tlsExtension{sniExt})
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
