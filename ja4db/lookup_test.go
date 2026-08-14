package ja4db

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestLookupFingerprintRemote_Mock uses an httptest server to verify the
// remote-lookup decoding logic without making any external network calls.
func TestLookupFingerprintRemote_Mock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/read/known_fp":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"application": "Chromium Browser",
				"library":     "BoringSSL",
				"notes":       "test",
			})
		case "/api/read/unknown_fp":
			w.WriteHeader(http.StatusNotFound)
		case "/api/read/empty_fp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	// Hit found.
	got, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp")
	if err != nil {
		t.Fatalf("known_fp: %v", err)
	}
	if got == nil {
		t.Fatal("known_fp: expected result, got nil")
	}
	if got.Application != "Chromium Browser / BoringSSL" {
		t.Errorf("known_fp Application = %q, want %q", got.Application, "Chromium Browser / BoringSSL")
	}

	// 404 -> nil, nil.
	got, err = LookupFingerprintRemote(context.Background(), cfg, "unknown_fp")
	if err != nil {
		t.Errorf("unknown_fp: unexpected error %v", err)
	}
	if got != nil {
		t.Errorf("unknown_fp: expected nil, got %+v", got)
	}

	// Empty body -> nil, nil.
	got, err = LookupFingerprintRemote(context.Background(), cfg, "empty_fp")
	if err != nil {
		t.Errorf("empty_fp: unexpected error %v", err)
	}
	if got != nil {
		t.Errorf("empty_fp: expected nil, got %+v", got)
	}

	// Empty fingerprint -> error.
	if _, err := LookupFingerprintRemote(context.Background(), cfg, ""); err == nil {
		t.Error("empty fingerprint: expected error, got nil")
	}
}

// TestLookupFingerprintRemote_LiveJA4DB hits the real ja4db.com endpoint.
// Gated behind JA4PLUS_NETWORK_TESTS=1.
func TestLookupFingerprintRemote_LiveJA4DB(t *testing.T) {
	if os.Getenv("JA4PLUS_NETWORK_TESTS") != "1" {
		t.Skip("skipping live network test; set JA4PLUS_NETWORK_TESTS=1 to enable")
	}
	got, err := LookupFingerprintRemote(context.Background(), nil, "t13d1516h2_8daaf6152771_02713d6af862")
	if err != nil {
		t.Fatalf("live lookup: %v", err)
	}
	if got == nil {
		t.Log("live lookup: not found (this is okay; the remote DB may have rotated)")
	}
}
