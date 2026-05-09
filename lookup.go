package ja4plus

import (
	"context"
	"encoding/csv"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed data/ja4plus-mapping.csv
var mappingCSV []byte

// LookupResult holds the result of a fingerprint database lookup.
type LookupResult struct {
	Application string
	Type        string
	Notes       string
}

var (
	lookupDB    map[string]*LookupResult
	lookupOnce  sync.Once
	dbSource    = "embedded" // "embedded" or "cache"
	dbCachePath string
)

func loadDB() map[string]*LookupResult {
	lookupOnce.Do(func() {
		lookupDB = make(map[string]*LookupResult)

		// Prefer the cache file if it exists and is non-empty.
		var data []byte = mappingCSV
		if cp, err := CachedDatabasePath(); err == nil {
			if b, rerr := os.ReadFile(cp); rerr == nil && len(b) > 0 {
				data = b
				dbSource = "cache"
				dbCachePath = cp
			}
		}

		r := csv.NewReader(strings.NewReader(string(data)))

		// Read header
		header, err := r.Read()
		if err != nil {
			return
		}

		// Build column index
		colIdx := make(map[string]int)
		for i, h := range header {
			colIdx[strings.TrimSpace(h)] = i
		}

		fpTypes := []string{"ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan"}

		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}

			// Build identification string from available fields
			var identParts []string
			for _, field := range []string{"Application", "Library", "Device", "OS"} {
				idx, ok := colIdx[field]
				if !ok || idx >= len(row) {
					continue
				}
				val := strings.TrimSpace(row[idx])
				if val != "" {
					identParts = append(identParts, val)
				}
			}
			if len(identParts) == 0 {
				continue
			}

			ident := strings.Join(identParts, " / ")
			notes := ""
			if idx, ok := colIdx["Notes"]; ok && idx < len(row) {
				notes = strings.TrimSpace(row[idx])
			}

			// Index by each fingerprint type present
			for _, fpType := range fpTypes {
				idx, ok := colIdx[fpType]
				if !ok || idx >= len(row) {
					continue
				}
				fpVal := strings.TrimSpace(row[idx])
				if fpVal != "" {
					lookupDB[fpVal] = &LookupResult{
						Application: ident,
						Type:        fpType,
						Notes:       notes,
					}
				}
			}
		}
	})
	return lookupDB
}

// LookupFingerprint looks up a JA4+ fingerprint in the local FoxIO database.
// If a cached database file is present at the user-cache path
// (see CachedDatabasePath), it is used; otherwise the embedded database is
// used. Returns nil if the fingerprint is not found. This function never
// makes network calls.
func LookupFingerprint(fingerprint string) *LookupResult {
	db := loadDB()
	return db[fingerprint]
}

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
// behavior of LookupFingerprint, which remains offline-only.
//
// Returns nil and a non-nil error on transport / non-200 / decoding failures.
// Returns nil and nil when the fingerprint is not found.
func LookupFingerprintRemote(ctx context.Context, cfg *RemoteLookupConfig, fingerprint string) (*LookupResult, error) {
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
	defer resp.Body.Close()

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
	return &LookupResult{
		Application: strings.Join(parts, " / "),
		Notes:       strings.TrimSpace(raw.Notes),
	}, nil
}

// CachedDatabasePath returns the path where a cached ja4plus-mapping.csv
// downloaded by `ja4plus db update` is stored. The directory is created if
// it does not already exist.
func CachedDatabasePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, "ja4plus")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "ja4plus-mapping.csv"), nil
}

// DatabaseInfo describes the active lookup database.
type DatabaseInfo struct {
	// Source is "embedded" or "cache".
	Source string
	// Path is the cache path when Source == "cache", empty otherwise.
	Path string
	// Entries is the number of fingerprints loaded.
	Entries int
	// ModTime is the modification time of the cache file (zero for embedded).
	ModTime time.Time
}

// GetDatabaseInfo returns metadata about the currently-active database.
func GetDatabaseInfo() DatabaseInfo {
	db := loadDB()
	info := DatabaseInfo{Source: dbSource, Entries: len(db)}
	if dbSource == "cache" {
		info.Path = dbCachePath
		if st, err := os.Stat(dbCachePath); err == nil {
			info.ModTime = st.ModTime()
		}
	}
	return info
}
