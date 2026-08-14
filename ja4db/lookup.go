package ja4db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	ja4plus "github.com/Crank-Git/ja4plus-go"
)

// RemoteLookupConfig configures opt-in remote lookups against ja4db.com.
// A nil http.Client falls back to http.DefaultClient.
type RemoteLookupConfig struct {
	// Endpoint is the base URL of the lookup service. If empty, defaults to
	// "https://ja4db.com/api/read/" (the GET-by-fingerprint endpoint).
	Endpoint string
	// HTTPClient is the client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// LookupFingerprintRemote performs an opt-in HTTP lookup against ja4db.com
// (or another configured endpoint) for the given fingerprint. Callers must
// supply a context and a config; this function does NOT change the default
// behavior of ja4plus.LookupFingerprint, which remains offline-only.
//
// Returns nil and a non-nil error on transport / non-200 / decoding failures.
// Returns nil and nil when the fingerprint is not found.
func LookupFingerprintRemote(ctx context.Context, cfg *RemoteLookupConfig, fingerprint string) (*ja4plus.LookupResult, error) {
	if fingerprint == "" {
		return nil, errors.New("ja4plus: empty fingerprint")
	}
	if cfg == nil {
		cfg = &RemoteLookupConfig{}
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://ja4db.com/api/read/"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	url := strings.TrimRight(endpoint, "/") + "/" + fingerprint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ja4plus: remote lookup status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// The ja4db.com API returns JSON with at least one of these fields populated.
	// Be permissive: collapse Application/Library/Device/OS into one identifier.
	var raw struct {
		Application string `json:"application"`
		Library     string `json:"library"`
		Device      string `json:"device"`
		OS          string `json:"os"`
		Notes       string `json:"notes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ja4plus: decode remote lookup: %w", err)
	}
	var parts []string
	for _, p := range []string{raw.Application, raw.Library, raw.Device, raw.OS} {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return &ja4plus.LookupResult{
		Application: strings.Join(parts, " / "),
		Notes:       strings.TrimSpace(raw.Notes),
	}, nil
}
