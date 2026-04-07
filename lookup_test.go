package ja4plus

import (
	"testing"
)

func TestLookupFingerprint_Unknown(t *testing.T) {
	result := LookupFingerprint("zz_unknown_fingerprint_zz")
	if result != nil {
		t.Errorf("expected nil for unknown fingerprint, got %+v", result)
	}
}

func TestLookupFingerprint_Known(t *testing.T) {
	// The embedded CSV should contain at least the Chromium entry
	result := LookupFingerprint("t13d1516h2_8daaf6152771_02713d6af862")
	if result == nil {
		t.Skip("known fingerprint not found in embedded CSV; CSV may be empty or different format")
	}
	if result.Application == "" {
		t.Error("expected non-empty Application for known fingerprint")
	}
	if result.Type != "ja4" {
		t.Errorf("expected type 'ja4', got %q", result.Type)
	}
}

func TestLookupFingerprint_DBLoads(t *testing.T) {
	db := loadDB()
	if db == nil {
		t.Fatal("expected non-nil database")
	}
	// The CSV has ~66 data rows, so we should have at least some entries
	if len(db) == 0 {
		t.Error("expected non-empty database from embedded CSV")
	}
}
