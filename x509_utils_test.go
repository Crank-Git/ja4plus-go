package ja4plus

import "testing"

func TestOIDToHex_KnownOIDs(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		want string
	}{
		{name: "commonName", oid: "2.5.4.3", want: "550403"},
		{name: "countryName", oid: "2.5.4.6", want: "550406"},
		{name: "organizationName", oid: "2.5.4.10", want: "55040a"},
		{name: "organizationalUnit", oid: "2.5.4.11", want: "55040b"},
		{name: "stateOrProvince", oid: "2.5.4.8", want: "550408"},
		{name: "locality", oid: "2.5.4.7", want: "550407"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OIDToHex(tt.oid)
			if got != tt.want {
				t.Errorf("OIDToHex(%q) = %q, want %q", tt.oid, got, tt.want)
			}
		})
	}
}

func TestOIDToHex_VLQEncoding(t *testing.T) {
	// RSA encryption OID: 1.2.840.113549.1.1.1
	// First two: 1*40+2 = 42 = 0x2a
	// 840: VLQ → 0x86, 0x48
	// 113549: VLQ → 0x86, 0xf7, 0x0d
	// 1, 1, 1: single bytes
	got := OIDToHex("1.2.840.113549.1.1.1")
	want := "2a864886f70d010101"
	if got != want {
		t.Errorf("OIDToHex(RSA) = %q, want %q", got, want)
	}
}

func TestOIDToHex_SHA256WithRSA(t *testing.T) {
	// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
	got := OIDToHex("1.2.840.113549.1.1.11")
	want := "2a864886f70d01010b"
	if got != want {
		t.Errorf("OIDToHex(SHA256WithRSA) = %q, want %q", got, want)
	}
}

func TestOIDToHex_SingleComponent(t *testing.T) {
	got := OIDToHex("0")
	if got != "00" {
		t.Errorf("OIDToHex(\"0\") = %q, want \"00\"", got)
	}
}

func TestOIDToHex_SubjectKeyIdentifier(t *testing.T) {
	// subjectKeyIdentifier: 2.5.29.14
	got := OIDToHex("2.5.29.14")
	want := "551d0e"
	if got != want {
		t.Errorf("OIDToHex(subjectKeyIdentifier) = %q, want %q", got, want)
	}
}

func TestOIDToHex_AuthorityKeyIdentifier(t *testing.T) {
	// authorityKeyIdentifier: 2.5.29.35
	got := OIDToHex("2.5.29.35")
	want := "551d23"
	if got != want {
		t.Errorf("OIDToHex(authorityKeyIdentifier) = %q, want %q", got, want)
	}
}
