package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func expectedHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func TestTruncatedHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "cipher list", input: "0035,009c,009d,c013,c014"},
		{name: "single value", input: "c02c"},
		{name: "extension list", input: "0005,000a,000b,000d,0017"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncatedHash(tt.input)
			want := expectedHash(tt.input)
			if got != want {
				t.Errorf("TruncatedHash(%q) = %q, want %q", tt.input, got, want)
			}
			if len(got) != 12 {
				t.Errorf("TruncatedHash length = %d, want 12", len(got))
			}
		})
	}
}

func TestTruncatedHashEmpty(t *testing.T) {
	got := TruncatedHash("")
	want := "000000000000"
	if got != want {
		t.Errorf("TruncatedHash(\"\") = %q, want %q", got, want)
	}
}

func TestTruncatedHashLowercase(t *testing.T) {
	got := TruncatedHash("test")
	for _, c := range got {
		if c >= 'A' && c <= 'F' {
			t.Errorf("TruncatedHash contains uppercase hex: %q", got)
			break
		}
	}
}
