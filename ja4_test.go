package ja4plus

import (
	"strings"
	"testing"
)

func TestComputeJA4FromClientHello_TLS13(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c},
		Extensions: []uint16{
			extSNI,                // 0x0000
			extALPN,               // 0x0010
			extSupportedVersions,  // 0x002b
			extSignatureAlgorithms, // 0x000d
			0x0017,                // extended_master_secret
		},
		SNI:                 "example.com",
		HasSNI:              true,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}

	fp := computeJA4FromClientHello(ch)

	// Format: {proto}{ver}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}

	partA := parts[0]
	// proto=t, ver=13 (from supported_versions max), sni=d, ciphers=04, exts=05, alpn=h2
	if partA != "t13d0405h2" {
		t.Errorf("part_a = %q, want %q", partA, "t13d0405h2")
	}

	// Cipher hash and ext hash should be 12 hex chars
	if len(parts[1]) != 12 {
		t.Errorf("cipher hash length = %d, want 12", len(parts[1]))
	}
	if len(parts[2]) != 12 {
		t.Errorf("ext hash length = %d, want 12", len(parts[2]))
	}
}

func TestComputeJA4_GREASEFiltering(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x0A0A, 0x1301, 0x2A2A, 0x1302},
		Extensions: []uint16{
			0x3A3A,               // GREASE
			extSNI,               // 0x0000
			0x4A4A,               // GREASE
			extSupportedVersions, // 0x002b
		},
		HasSNI:            true,
		SNI:               "test.com",
		SupportedVersions: []uint16{0x7A7A, 0x0304, 0x0303}, // GREASE + real versions
	}

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	partA := parts[0]

	// proto=t, ver=13 (0x0304, ignoring GREASE 0x7A7A), sni=d
	// ciphers: 2 non-GREASE (0x1301, 0x1302)
	// extensions: 2 non-GREASE (0x0000, 0x002b)
	// alpn: "00" (no ALPN)
	if partA != "t13d020200" {
		t.Errorf("part_a = %q, want %q", partA, "t13d020200")
	}
}

func TestJA4_EmptyCiphers(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{},
		Extensions:   []uint16{extSNI},
		HasSNI:       true,
		SNI:          "x.com",
	}

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	if parts[1] != "000000000000" {
		t.Errorf("cipher hash = %q, want %q", parts[1], "000000000000")
	}
}

func TestJA4_NoALPN(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		HasSNI:       true,
		SNI:          "x.com",
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// ALPN should be "00"
	if !strings.HasSuffix(partA, "00") {
		t.Errorf("part_a = %q, should end with 00 for no ALPN", partA)
	}
}

func TestJA4_ALPNSingleChar(t *testing.T) {
	ch := &ClientHello{
		Version:       0x0303,
		CipherSuites:  []uint16{0x002f},
		ALPNProtocols: []string{"x"},
		HasSNI:        true,
		SNI:           "d.com",
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// Single char "x" should be doubled to "xx"
	if !strings.HasSuffix(partA, "xx") {
		t.Errorf("part_a = %q, should end with xx for single-char ALPN", partA)
	}
}

func TestJA4_ExtensionHash_SNIAndALPNExcluded(t *testing.T) {
	// With sig algs, the ext hash string is: sorted_exts_sigalgs
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		Extensions: []uint16{
			extSNI,                // should be excluded from hash
			extALPN,               // should be excluded from hash
			0x0017,                // should be included
			extSignatureAlgorithms, // should be included
		},
		HasSNI:              true,
		SNI:                 "x.com",
		ALPNProtocols:       []string{"h2"},
		SignatureAlgorithms: []uint16{0x0804, 0x0403}, // original order preserved
	}

	// Compute manually what the hash should be:
	// Filtered exts (no SNI, no ALPN): 0x0017, 0x000d
	// Sorted: 0x000d, 0x0017
	// Ext string: "000d,0017"
	// Sig algs in original order: "0804,0403"
	// Combined: "000d,0017_0804,0403"
	expectedInput := "000d,0017_0804,0403"
	expectedHash := TruncatedHash(expectedInput)

	fp := computeJA4FromClientHello(ch)
	parts := strings.Split(fp, "_")
	if parts[2] != expectedHash {
		t.Errorf("ext hash = %q, want %q (from input %q)", parts[2], expectedHash, expectedInput)
	}
}

func TestJA4_VersionFromSupportedVersions(t *testing.T) {
	ch := &ClientHello{
		Version:           0x0301, // TLS 1.0 in handshake
		CipherSuites:      []uint16{0x002f},
		SupportedVersions: []uint16{0x0303, 0x0304}, // TLS 1.2, TLS 1.3
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// Should use max supported version = 0x0304 = "13"
	if !strings.HasPrefix(partA, "t13") {
		t.Errorf("part_a = %q, should start with t13 (version from supported_versions)", partA)
	}
}

func TestJA4_RawFingerprint(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1302, 0x1301},
		Extensions: []uint16{
			extSNI,
			extALPN,
			0x0017,
			extSignatureAlgorithms,
		},
		HasSNI:              true,
		SNI:                 "test.com",
		ALPNProtocols:       []string{"h2"},
		SignatureAlgorithms: []uint16{0x0403},
	}

	raw := computeJA4RawFromClientHello(ch)
	parts := strings.Split(raw, "_")
	// Should have 4 parts: partA, sorted ciphers, sorted exts (no SNI/ALPN), sig algs
	if len(parts) != 4 {
		t.Fatalf("raw parts = %d, want 4: %s", len(parts), raw)
	}

	// Ciphers sorted: 0x1301, 0x1302
	if parts[1] != "1301,1302" {
		t.Errorf("raw ciphers = %q, want %q", parts[1], "1301,1302")
	}

	// Extensions (no SNI/ALPN), sorted: 0x000d, 0x0017
	if parts[2] != "000d,0017" {
		t.Errorf("raw exts = %q, want %q", parts[2], "000d,0017")
	}

	// Sig algs in original order
	if parts[3] != "0403" {
		t.Errorf("raw sig algs = %q, want %q", parts[3], "0403")
	}
}

func TestAlpnValue(t *testing.T) {
	tests := []struct {
		name      string
		protocols []string
		want      string
	}{
		{"empty", nil, "00"},
		{"h2", []string{"h2"}, "h2"},
		{"http/1.1", []string{"http/1.1"}, "h1"},
		{"single char", []string{"x"}, "xx"},
		{"empty first", []string{""}, "00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := alpnValue(tt.protocols)
			if got != tt.want {
				t.Errorf("alpnValue(%v) = %q, want %q", tt.protocols, got, tt.want)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0200, "s2"},
		{0xfeff, "d1"},
		{0xfefd, "d2"},
		{0xfefc, "d3"},
		{0x0000, "00"},
		{0x1234, "00"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestJA4_FullIntegration(t *testing.T) {
	// Build a real ClientHello packet as bytes and verify end-to-end
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	exts := []tlsExtension{
		makeSNIExtension("example.com"),
		makeALPNExtension("h2", "http/1.1"),
		makeSupportedVersionsClientExtension(0x0304, 0x0303),
		makeSignatureAlgorithmsExtension(0x0403, 0x0804, 0x0401),
	}
	payload := buildClientHello(0x0303, ciphers, exts)

	ch, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	fp := computeJA4FromClientHello(ch)

	// Verify format: proto(1) + ver(2) + sni(1) + ciphers(2) + exts(2) + alpn(2) = 10 chars
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("fingerprint parts = %d, want 3", len(parts))
	}
	if len(parts[0]) != 10 {
		t.Errorf("part_a length = %d, want 10: %q", len(parts[0]), parts[0])
	}

	// Expected part_a: t13d0304h2
	// proto=t, ver=13, sni=d, ciphers=03, exts=04, alpn=h2
	if parts[0] != "t13d0304h2" {
		t.Errorf("part_a = %q, want %q", parts[0], "t13d0304h2")
	}
}

func TestJA4_NoSNI(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// SNI char should be 'i'
	if partA[3] != 'i' {
		t.Errorf("SNI char = %c, want 'i'", partA[3])
	}
}

func TestJA4_HasSNIMalformed(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x002f},
		HasSNI:       true,
		SNI:          "", // malformed but present
	}

	fp := computeJA4FromClientHello(ch)
	partA := strings.Split(fp, "_")[0]
	// SNI char should be 'd' because HasSNI is true
	if partA[3] != 'd' {
		t.Errorf("SNI char = %c, want 'd' for HasSNI=true", partA[3])
	}
}
