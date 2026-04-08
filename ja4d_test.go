package ja4plus

import (
	"testing"
)

func TestJA4D_MessageTypeMapping(t *testing.T) {
	tests := []struct {
		code byte
		want string
	}{
		{1, "disco"},
		{2, "offer"},
		{3, "reqst"},
		{4, "decln"},
		{5, "dpack"},
		{6, "dpnak"},
		{7, "relse"},
		{8, "infor"},
		{9, "frenw"},
		{10, "lqery"},
		{18, "dhtls"},
	}
	for _, tt := range tests {
		got, ok := dhcpMessageMap[tt.code]
		if !ok {
			t.Errorf("missing message type %d", tt.code)
			continue
		}
		if got != tt.want {
			t.Errorf("message type %d: got %q, want %q", tt.code, got, tt.want)
		}
		if len(got) != 5 {
			t.Errorf("message type %d: abbreviation %q is not 5 chars", tt.code, got)
		}
	}
}

func TestJA4D_BuildOptionList(t *testing.T) {
	tests := []struct {
		name    string
		options []byte
		want    string
	}{
		{"empty", nil, "00"},
		{"all skipped", []byte{53, 255, 50, 81}, "00"},
		{"single", []byte{53, 61, 255}, "61"},
		{"multiple", []byte{53, 61, 57, 60, 12, 55, 255}, "61-57-60-12-55"},
		{"with skipped mixed", []byte{53, 50, 61, 81, 57, 255}, "61-57"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ja4dBuildOptionList(tt.options, dhcpSkipOptions)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJA4D_BuildParamList(t *testing.T) {
	tests := []struct {
		name   string
		params []byte
		want   string
	}{
		{"empty", nil, "00"},
		{"single", []byte{1}, "1"},
		{"multiple", []byte{1, 3, 6, 15, 26, 28, 51, 58, 59}, "1-3-6-15-26-28-51-58-59"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ja4dBuildParamList(tt.params)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJA4D_Reset(t *testing.T) {
	f := NewJA4D()
	f.results = []FingerprintResult{{Type: "ja4d"}}
	f.Reset()
	if f.results != nil {
		t.Errorf("expected nil results after reset, got %v", f.results)
	}
}

func TestJA4D_ImplementsFingerprinter(t *testing.T) {
	var _ Fingerprinter = NewJA4D()
}
